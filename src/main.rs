use anyhow::Context;
use clap::{Parser, Subcommand};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use oci_spec::image::{DescriptorBuilder, ImageConfiguration, ImageIndex, ImageManifest};
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use sha2::{digest::FixedOutput, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Seek, SeekFrom, Write},
    str::FromStr,
    time::Instant,
};

pub mod analyze;
pub mod docker_registry_v2;
pub mod response_async_reader;
pub mod ye_old_docker;

use docker_registry_v2::{ParsedDomain, ParsedImageReference};

const IMAGE_MANIFEST_CONTENT_TYPES: &str = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json";

/// Convert a hash-digest
fn layer_digest_to_blob_path(digest: &str) -> String {
    format!("blobs/{}", digest.replace(':', "/"))
}

fn hash_string(src: &str) -> String {
    let mut hasher = Sha256::default();
    let _ = hasher.write(src.as_bytes());
    let digest = hasher.finalize_fixed();
    let byte_strings: Vec<_> = digest
        .as_slice()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    byte_strings.join("")
}

// # Get Docker token (this function is useless for unauthenticated registries like Microsoft)
// def get_auth_head(type):
// 	resp = requests.get('{}?service={}&scope=repository:{}:pull'.format(auth_url, reg_service, repository), verify=False)
// 	access_token = resp.json()['token']
// 	auth_head = {'Authorization':'Bearer '+ access_token, 'Accept': type}
// 	return auth_head
fn parse_authentication_header(source: &str) -> HashMap<&str, &str> {
    let mut map = HashMap::new();
    for component in source.split(',') {
        if let Some((key, value)) = component.split_once('=') {
            map.insert(key, value.trim_matches('"'));
        } else {
            eprintln!("Malformed component '{component}'");
        }
    }
    map
}

#[derive(Debug, Clone, Deserialize)]
#[allow(unused)]
struct AuthToken {
    access_token: Option<String>,
    issued_at: Option<String>,
    token: String,
    expires_in: Option<usize>,
}

/// Probe the target registry for authentication.
/// If necessary, request for an OAuth token for pulling from the specified repositories.
///
/// https://docs.docker.com/registry/spec/auth/token/#how-to-authenticate
async fn get_auth_token(
    client: reqwest::Client,
    registry: &str,
    repository_namespace: &str,
    repositories: impl Iterator<Item = &str>,
) -> anyhow::Result<Option<AuthToken>> {
    let url = format!("https://{registry}/v2/");

    let response = client.get(url).send().await?;

    if response.status() == StatusCode::UNAUTHORIZED {
        let auth = response.headers().get("WWW-Authenticate").unwrap();
        let auth = parse_authentication_header(auth.to_str()?);
        let auth_url = auth["Bearer realm"];
        let reg_service = auth["service"];

        let scopes = repositories
            .map(|repository| format!("repository:{repository_namespace}{repository}:pull"))
            .collect::<Vec<_>>()
            .join(",");

        let response = client
            .get(auth_url)
            .query(&[("service", reg_service), ("scope", scopes.as_str())])
            .send()
            .await?
            .text()
            .await?;

        let parsed_response = serde_json::from_str::<AuthToken>(&response);
        if let Err(_e) = &parsed_response {
            println!("{response}");
        };
        Ok(Some(parsed_response?))
    } else {
        Ok(None)
    }
}

fn get_registry(parsed_domain: &Option<ParsedDomain>) -> (String, &'static str) {
    if let Some(registry) = parsed_domain {
        (registry.to_string(), "")
    } else {
        ("registry-1.docker.io".to_string(), "library/")
    }
}

fn push_file_data<W: Write>(
    builder: &mut tar::Builder<W>,
    path: &str,
    data: &[u8],
) -> anyhow::Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, path, data)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct ManifestBundle {
    manifest: ImageManifest,
    raw_manifest: String,
    #[allow(unused)]
    config: ImageConfiguration,
    raw_config: String,
}

async fn get_manifest(
    client: Client,
    // url_base: String,
    // tag: &str,
    img_ref: &ParsedImageReference,
    token: Option<&AuthToken>,
) -> anyhow::Result<ManifestBundle> {
    let (registry, repository_namespace) = get_registry(&img_ref.registry);

    let url_base = format!(
        "https://{registry}/v2/{repository_namespace}{}/",
        img_ref.repository,
    );

    let tag = img_ref
        .tag
        .as_ref()
        .map_or_else(|| "latest", |t| t.digest.as_ref().unwrap_or(&t.tag));

    // Retrieve root manifest
    let url = format!("{url_base}/manifests/{tag}");
    let mut request = client
        .request(Method::GET, &url)
        .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
    if let Some(token) = token {
        request = request.bearer_auth(&token.token);
    };

    let response = request.send().await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await;
        anyhow::bail!("Failed getting manifest (STATUS={status}): {error_text:?}");
    }

    let raw_manifest = response.text().await?;
    let manifest = serde_json::from_str::<ImageManifest>(&raw_manifest)
        .with_context(|| format!("Failed parsing image manifest for {url}: {raw_manifest}"))?;

    // Retrieve image config
    let config_digest = manifest.config().digest();
    let config_url = format!("{url_base}/blobs/{config_digest}");

    let mut request = client.request(Method::GET, &config_url);
    if let Some(token) = token {
        request = request.bearer_auth(&token.token);
    };
    let response = request.send().await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await;
        anyhow::bail!("Failed getting image config (STATUS={status}): {error_text:?}");
    }
    let raw_config = response.text().await?;
    let config = serde_json::from_str::<ImageConfiguration>(&raw_config).with_context(|| {
        format!("Failed to parse image configuration {config_url}: {raw_config}")
    })?;

    Ok(ManifestBundle {
        manifest,
        raw_manifest,
        config,
        raw_config,
    })
}

async fn download_a_bunch(
    images: &[ParsedImageReference],
    deduplicate_layers: bool,
    rename_registry: Option<&str>,
) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut registries = HashMap::new();

    for img_ref in images {
        let (registry, repository_namespace) = get_registry(&img_ref.registry);
        let (_, repositories) = registries
            .entry(registry)
            .or_insert((repository_namespace, Vec::new()));
        repositories.push((img_ref.repository.clone(), img_ref.tag.clone()));
    }

    let client = reqwest::Client::new();

    // Get auth tokens for each repository.
    let token_futures = registries
        .iter()
        .map(|(registry, (namespace, repositories))| {
            let future = get_auth_token(
                client.clone(),
                registry,
                namespace,
                repositories.iter().map(|(repo, _tag)| repo.as_str()),
            );
            async { future.await.map(|token| (registry.clone(), token)) }
        });
    let tokens: HashMap<_, _> = futures::future::try_join_all(token_futures)
        .await?
        .into_iter()
        .collect();

    // Get manifest for each image
    let manifest_requests = images.iter().map(|img_ref| {
        let (registry, _repository_namespace) = get_registry(&img_ref.registry);
        let token = tokens.get(&registry).and_then(|t| t.as_ref());
        get_manifest(client.clone(), img_ref, token)
    });
    let manifests = futures::future::try_join_all(manifest_requests).await?;

    let multi_progress_bar = &indicatif::MultiProgress::new();
    let progress_style = ProgressStyle::with_template(
        "{msg}\t{percent:>3}% {bar:40.cyan/blue} {binary_bytes_per_sec}",
    )
    .unwrap();

    // Aggregate layer digests to download.
    eprintln!("Downloading layers");
    let mut layer_digests = HashMap::new();
    for (idx, (manifest_bundle, img_ref)) in manifests.iter().zip(images.iter()).enumerate() {
        for layer in manifest_bundle.manifest.layers() {
            let prog = multi_progress_bar.insert(
                idx,
                ProgressBar::new(layer.size() as u64).with_style(progress_style.clone()),
            );
            prog.set_message(layer.digest().clone());
            layer_digests.insert(layer.digest().clone(), (img_ref, prog));
        }
    }

    // Create a download-future for each layer
    let layer_futures = layer_digests.into_iter().map(|(digest, (img_ref, prog))| {
        let (registry, repository_namespace) = get_registry(&img_ref.registry);

        let url = format!(
            "https://{registry}/v2/{repository_namespace}{}/blobs/{digest}",
            img_ref.repository
        );
        let token = tokens.get(&registry).unwrap();
        let mut request = client
            .request(Method::GET, url)
            .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
        if let Some(token) = &token {
            request = request.bearer_auth(&token.token);
        }

        async move {
            let mut file = File::options()
                .create(true)
                .write(true)
                .truncate(true)
                .read(true)
                .open(&digest)?;
            let response = request.send().await?;

            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk?;
                file.write_all(&chunk)?;
                prog.inc(chunk.len() as u64);
            }

            prog.finish();

            // eprintln!(">> Finished downloading {digest}");
            Ok::<_, anyhow::Error>((digest, file))
        }
    });

    let mut used_layers = HashSet::new();
    let mut layers: HashMap<_, _> = futures::future::try_join_all(layer_futures)
        .await?
        .into_iter()
        .collect();

    for (manifest_bundle, img_ref) in manifests.iter().zip(images.iter()) {
        let file_name = format!(
            "{}:{}.tar",
            img_ref.repository,
            img_ref.tag.as_ref().map(|x| &*x.tag).unwrap_or("latest")
        );
        eprintln!("Generating `{file_name}`");
        let mut file = File::create(file_name)?;

        let mut image_tar = tar::Builder::new(&mut file);
        for layer in manifest_bundle.manifest.layers() {
            let digest = layer.digest();
            if deduplicate_layers && used_layers.contains(digest) {
                eprintln!("\tSkipping {digest}");
                continue;
            }
            let layer_file = layers.get_mut(digest).unwrap();

            layer_file.seek(SeekFrom::Start(0))?;
            image_tar.append_file(layer_digest_to_blob_path(digest), layer_file)?;
            used_layers.insert(digest);
        }

        // Write image config to blobs
        push_file_data(
            &mut image_tar,
            &layer_digest_to_blob_path(manifest_bundle.manifest.config().digest()),
            manifest_bundle.raw_config.as_bytes(),
        )?;

        // Write image manifest to blobs
        let manifest_digest = hash_string(&manifest_bundle.raw_manifest);
        push_file_data(
            &mut image_tar,
            &format!("blobs/sha256/{manifest_digest}"),
            manifest_bundle.raw_manifest.as_bytes(),
        )?;

        // Write "oci-layout" file
        push_file_data(
            &mut image_tar,
            "oci-layout",
            b"{\"imageLayoutVersion\":\"1.0.0\"}",
        )?;

        // Write index.json
        let ref_name = img_ref
            .tag
            .as_ref()
            .map(|t| &*t.tag)
            .unwrap_or("latest")
            .to_string();

        let mut image_name = String::new();

        if let Some(registry) = rename_registry {
            image_name.push_str(registry);
            image_name.push('/');
        } else if let Some(registry) = &img_ref.registry {
            image_name.push_str(&registry.to_string());
            image_name.push('/');
        }
        image_name.push_str(&img_ref.repository);
        image_name.push(':');
        image_name.push_str(&ref_name);

        let mut index = ImageIndex::default();
        let manifest_descriptor = DescriptorBuilder::default()
            .digest(format!("sha256:{manifest_digest}"))
            .size(manifest_bundle.raw_manifest.len() as i64)
            .media_type(
                manifest_bundle
                    .manifest
                    .media_type()
                    .as_ref()
                    .unwrap()
                    .clone(),
            )
            .annotations(HashMap::from([
                ("io.containerd.image.name".into(), image_name.clone()),
                ("org.opencontainers.image.ref.name".into(), ref_name),
            ]))
            .build()
            .unwrap();
        index.set_manifests(vec![manifest_descriptor]);
        let raw_index = serde_json::to_string(&index).unwrap();

        push_file_data(&mut image_tar, "index.json", raw_index.as_bytes())?;

        // Write legacy docker `manifest.json`
        let ye_old_manifest = ye_old_docker::YeOldManifest::from_oci_manifest(
            &manifest_bundle.manifest,
            image_name.clone(),
        );
        let ye_old_manifest = serde_json::to_string(&ye_old_manifest)?;
        let ye_old_manifest = format!("[{ye_old_manifest}]");
        push_file_data(&mut image_tar, "manifest.json", ye_old_manifest.as_bytes())?;

        image_tar.finish()?;
    }

    for layer in layers.keys() {
        std::fs::remove_file(layer)?;
    }

    println!("Basically done {:?}", start.elapsed());

    Ok(())
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Download an image-set from a registry to local tar-balls.
    ///
    /// The output image format conforms to the OCI [image-layout][1] with an added
    /// shim to support older Docker versions.
    ///
    /// [1]: https://github.com/opencontainers/image-spec/blob/main/image-layout.md
    Download {
        images: Vec<String>,

        /// Do not write duplicate layers to multiple images.
        ///
        /// A base-layer will only be add to the `.tar` of the first image that contains it.
        /// Missing layer blobs in OCI images are valid as long as the layer can be sourced from somewhere.
        ///
        /// Using this option might result in an image set that needs to be loaded in the same order as the input.
        #[arg(long)]
        deduplicate: bool,

        /// Rename and set the registry when tagging the images
        #[arg(long)]
        rename_registry: Option<String>,
    },
    Analyze {
        tar_file: String,
    },
}

#[tokio::main/*(worker_threads = 4)*/]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // analyze(&image_tar_name);
    match args.command {
        SubCommand::Analyze { tar_file } => {
            analyze::analyze(&tar_file);
        }
        SubCommand::Download {
            images,
            deduplicate,
            rename_registry,
        } => {
            let mut references = Vec::new();
            for img in images {
                references.push(docker_registry_v2::ParsedImageReference::from_str(&img)?);
            }

            let f = download_a_bunch(&references, deduplicate, rename_registry.as_deref()).await;

            match &f {
                Ok(_) => {}
                Err(e) => {
                    dbg!(&e, e.backtrace());
                }
            }
            f?;
            println!("Basically done 2")
        }
    }

    Ok(())
}
