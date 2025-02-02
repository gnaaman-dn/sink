use anyhow::{bail, Context};
use bytes::Bytes;
use clap::{Parser, Subcommand};
use futures::{Stream, StreamExt};
use indicatif::{ProgressBar, ProgressStyle};
use oci_spec::image::{
    Descriptor, DescriptorBuilder, ImageConfiguration, ImageIndex, ImageManifest, MediaType,
};
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use sha2::{digest::FixedOutput, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str::FromStr,
};

pub mod analyze;
pub mod docker_registry_v2;
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

fn is_media_type_gzipped(media_type: &MediaType) -> bool {
    match media_type {
        MediaType::ImageLayerGzip => true,
        MediaType::Other(s) if s == "application/vnd.docker.image.rootfs.diff.tar.gzip" => true,
        _ => false,
    }
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

#[derive(Debug, Clone)]
pub struct RegistryAuthInfo {
    registry: String,
    repository_namespace: String,
    uses_https: bool,
    auth_token: Option<AuthToken>,
}

impl RegistryAuthInfo {
    pub fn protocol(&self) -> &'static str {
        if self.uses_https {
            "https"
        } else {
            "http"
        }
    }
}

/// Probe the target registry for authentication.
/// If necessary, request for an OAuth token for pulling from the specified repositories.
///
/// https://docs.docker.com/registry/spec/auth/token/#how-to-authenticate
async fn get_auth_info(
    client: reqwest::Client,
    registry: &str,
    repository_namespace: &str,
    repositories: impl Iterator<Item = &str>,
) -> anyhow::Result<RegistryAuthInfo> {
    let url = format!("https://{registry}/v2/");

    let mut uses_https = true;
    let response = match client.get(url).send().await {
        Err(e) => {
            // If we got a connection error, try downgrading to http
            if e.is_connect() {
                let url = format!("http://{registry}/v2/");
                uses_https = false;
                client.get(url).send().await?
            } else {
                bail!(e);
            }
        }
        Ok(r) => r,
    };

    let auth_token = if response.status() == StatusCode::UNAUTHORIZED {
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
        Some(parsed_response?)
    } else {
        None
    };

    if !uses_https {
        eprintln!("WARNING: Registry {registry} is using unencrypted HTTP");
    }

    Ok(RegistryAuthInfo {
        auth_token,
        uses_https,
        registry: registry.into(),
        repository_namespace: repository_namespace.into(),
    })
}

fn get_registry(parsed_domain: &Option<ParsedDomain>) -> (String, &'static str) {
    if let Some(registry) = parsed_domain {
        (registry.to_string(), "")
    } else {
        ("registry-1.docker.io".to_string(), "library/")
    }
}

async fn get_registries_for_image_set(
    client: &reqwest::Client,
    images: &[ParsedImageReference],
) -> anyhow::Result<HashMap<String, RegistryAuthInfo>> {
    let mut registry_to_repositories = HashMap::new();
    for img_ref in images {
        let (registry, repository_namespace) = get_registry(&img_ref.registry);
        let (_, repositories) = registry_to_repositories
            .entry(registry)
            .or_insert((repository_namespace, Vec::new()));
        repositories.push(img_ref.repository.clone());
    }

    // Get auth tokens for each repository.
    let token_futures =
        registry_to_repositories
            .iter()
            .map(|(registry, (namespace, repositories))| {
                get_auth_info(
                    client.clone(),
                    registry,
                    namespace,
                    repositories.iter().map(|repo| repo.as_str()),
                )
            });

    let registry_info: HashMap<_, _> = futures::future::try_join_all(token_futures)
        .await?
        .into_iter()
        .map(|auth_info| (auth_info.registry.clone(), auth_info))
        .collect();

    Ok(registry_info)
}

/// Download a set of layers into the output directory.
///
/// Each layer digest must be paired with *an* image reference of one of the images
/// that referenced that layer, since the registry protocol requires it as an index.
/// It doesn't matter which image, though.
async fn download_layers(
    client: &reqwest::Client,
    output_dir: &Path,
    decompress_layers: bool,

    layer_digests: impl Iterator<Item = (Descriptor, &ParsedImageReference)>,
    registries: &HashMap<String, RegistryAuthInfo>,
) -> anyhow::Result<HashMap<String, File>> {
    eprintln!("Downloading layers");

    let multi_progress_bar = &indicatif::MultiProgress::new();
    let progress_style = ProgressStyle::with_template(
        "{msg}\t{percent:>3}% {bar:40.cyan/blue} {binary_bytes_per_sec}",
    )
    .unwrap();

    // Create a download-future for each layer
    let layer_futures = layer_digests.into_iter().map(|(layer, img_ref)| {
        let prog = multi_progress_bar.insert(
            1000,
            ProgressBar::new(layer.size() as u64).with_style(progress_style.clone()),
        );
        let digest = layer.digest().clone();
        prog.set_message(layer.digest().clone());
        let (registry, repository_namespace) = get_registry(&img_ref.registry);

        let token = registries.get(&registry).unwrap();
        let url = format!(
            "{protocol}://{registry}/v2/{repository_namespace}{}/blobs/{digest}",
            img_ref.repository,
            protocol = token.protocol(),
        );
        let mut request = client
            .request(Method::GET, url)
            .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
        if let Some(token) = &token.auth_token {
            request = request.bearer_auth(&token.token);
        }

        async move {
            let layer_path = {
                let mut p = output_dir.to_path_buf();
                p.push(&digest);
                p
            };
            let mut file = File::options()
                .create(true)
                .write(true)
                .truncate(true)
                .read(true)
                .open(layer_path)?;
            let response = request.send().await?;

            let stream = response.bytes_stream();
            if decompress_layers && is_media_type_gzipped(layer.media_type()) {
                let mut decoder = flate2::write::GzDecoder::new(&mut file);
                stream_to_output(stream, &mut decoder, prog.clone()).await?;
                decoder.finish()?;
            } else if decompress_layers && layer.media_type() == &MediaType::ImageLayerZstd {
                let mut decoder = zstd::stream::write::Decoder::new(&mut file).unwrap();
                stream_to_output(stream, &mut decoder, prog.clone()).await?;
                decoder.flush()?;
            } else {
                stream_to_output(stream, &mut file, prog.clone()).await?;
            }

            prog.finish();

            Ok::<_, anyhow::Error>((digest, file))
        }
    });

    let layers: HashMap<_, _> = futures::future::try_join_all(layer_futures)
        .await?
        .into_iter()
        .collect();
    Ok(layers)
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
    img_ref: ParsedImageReference,
    manifest: ImageManifest,
    raw_manifest: String,
    manifest_content_type: String,
    #[allow(unused)]
    config: ImageConfiguration,
    raw_config: String,
}

async fn push_manifest(
    client: Client,
    img_ref: &ParsedImageReference,
    auth_info: &RegistryAuthInfo,
    raw_manifest: &str,
    manifest_content_type: &str,
) -> anyhow::Result<()> {
    let tag = img_ref
        .tag
        .as_ref()
        .map_or_else(|| "latest", |t| t.digest.as_ref().unwrap_or(&t.tag));

    let url = format!(
        "{protocol}://{registry}/v2/{repository_namespace}{}/manifests/{tag}",
        img_ref.repository,
        protocol = auth_info.protocol(),
        registry = auth_info.registry,
        repository_namespace = auth_info.repository_namespace,
    );

    let mut request = client
        .put(url)
        .header("Content-Type", manifest_content_type)
        .body(raw_manifest.to_string());
    if let Some(token) = &auth_info.auth_token {
        request = request.bearer_auth(&token.token);
    };
    let resp = request.send().await?;

    let response_status = resp.status();
    let response_text = resp.text().await;

    if !response_status.is_success() {
        bail!("[{response_status}] Wew wewe wewe we can't retag: {response_text:?}");
    }

    Ok(())
}

async fn get_manifest(
    client: Client,
    img_ref: &ParsedImageReference,
    auth_info: &RegistryAuthInfo,
) -> anyhow::Result<ManifestBundle> {
    let url_base = format!(
        "{protocol}://{registry}/v2/{repository_namespace}{}/",
        img_ref.repository,
        protocol = auth_info.protocol(),
        registry = auth_info.registry,
        repository_namespace = auth_info.repository_namespace,
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
    if let Some(token) = &auth_info.auth_token {
        request = request.bearer_auth(&token.token);
    };

    let response = request.send().await?;

    let status = response.status();
    if !status.is_success() {
        let error_text = response.text().await;
        anyhow::bail!("Failed getting manifest (STATUS={status}): {error_text:?}");
    }

    let manifest_content_type = response
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()
        .unwrap()
        .to_string();

    let raw_manifest = response.text().await?;
    let manifest = serde_json::from_str::<ImageManifest>(&raw_manifest)
        .with_context(|| format!("Failed parsing image manifest for {url}: {raw_manifest}"))?;

    // Retrieve image config
    let config_digest = manifest.config().digest();
    let config_url = format!("{url_base}/blobs/{config_digest}");

    let mut request = client.request(Method::GET, &config_url);
    if let Some(token) = &auth_info.auth_token {
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
        img_ref: img_ref.clone(),
        manifest,
        raw_manifest,
        manifest_content_type,
        config,
        raw_config,
    })
}

async fn stream_to_output(
    mut stream: impl Stream<Item = Result<Bytes, reqwest::Error>> + Unpin,
    mut output: impl Write,
    prog: ProgressBar,
) -> anyhow::Result<()> {
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        output.write_all(&chunk)?;
        prog.inc(chunk.len() as u64);
    }
    Ok(())
}

fn package_single_image(
    img_ref: &ParsedImageReference,
    output_dir: &Path,
    manifest_bundle: &ManifestBundle,
    ignored_layers: &HashSet<&String>,
    layers: &mut HashMap<String, File>,
    decompress_layers: bool,
    rename_registry: Option<&str>,
) -> Result<(), anyhow::Error> {
    let file_name = format!(
        "{}:{}.tar",
        img_ref.repository,
        img_ref.tag.as_ref().map(|x| &*x.tag).unwrap_or("latest")
    );
    eprintln!("Generating `{file_name}`");
    let file_path = {
        let mut path = output_dir.to_path_buf();
        path.push(&file_name);
        path
    };
    let mut file = File::create(file_path)?;
    let mut image_tar = tar::Builder::new(&mut file);
    for layer in manifest_bundle.manifest.layers() {
        let digest = layer.digest();
        if ignored_layers.contains(digest) {
            eprintln!("\tSkipping {digest}");
            continue;
        }
        let layer_file = layers.get_mut(digest).unwrap();

        layer_file.seek(SeekFrom::Start(0))?;
        image_tar.append_file(layer_digest_to_blob_path(digest), layer_file)?;
    }
    push_file_data(
        &mut image_tar,
        &layer_digest_to_blob_path(manifest_bundle.manifest.config().digest()),
        manifest_bundle.raw_config.as_bytes(),
    )?;
    let mut manifest = manifest_bundle.manifest.clone();
    if decompress_layers {
        manifest.layers_mut().iter_mut().for_each(|layer| {
            if is_media_type_gzipped(layer.media_type()) {
                layer.set_media_type(MediaType::ImageLayer);
            }
        });
    }
    let raw_manifest = serde_json::to_string(&manifest)?;
    let manifest_digest = hash_string(&raw_manifest);
    push_file_data(
        &mut image_tar,
        &format!("blobs/sha256/{manifest_digest}"),
        raw_manifest.as_bytes(),
    )?;
    push_file_data(
        &mut image_tar,
        "oci-layout",
        b"{\"imageLayoutVersion\":\"1.0.0\"}",
    )?;
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
    let ye_old_manifest =
        ye_old_docker::YeOldManifest::from_oci_manifest(&manifest, image_name.clone());
    let ye_old_manifest = serde_json::to_string(&ye_old_manifest)?;
    let ye_old_manifest = format!("[{ye_old_manifest}]");
    push_file_data(&mut image_tar, "manifest.json", ye_old_manifest.as_bytes())?;
    image_tar.finish()?;
    Ok(())
}

async fn download_a_bunch(
    images: &[ParsedImageReference],
    deduplicate_layers: bool,
    decompress_layers: bool,
    rename_registry: Option<&str>,
    output_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let output_dir = output_dir.unwrap_or(Path::new("."));

    std::fs::create_dir_all(output_dir)?;
    let client = reqwest::Client::new();

    let registries = get_registries_for_image_set(&client, images).await?;

    // Get manifest for each image
    let manifest_requests = images.iter().map(|img_ref| {
        let (registry, _repository_namespace) = get_registry(&img_ref.registry);
        let token = registries.get(&registry).unwrap();
        get_manifest(client.clone(), img_ref, token)
    });
    let manifests = futures::future::try_join_all(manifest_requests).await?;

    // Aggregate layer digests to download - create a hashmap to deduplicate layers between images.
    let layer_digests: HashMap<_, _> = manifests
        .iter()
        .flat_map(|manifest_bundle| {
            manifest_bundle.manifest.layers().iter().map(|layer| {
                (
                    layer.digest().clone(),
                    (layer.clone(), &manifest_bundle.img_ref),
                )
            })
        })
        .collect();

    let mut layers = download_layers(
        &client,
        output_dir,
        decompress_layers,
        layer_digests.into_values(),
        &registries,
    )
    .await?;
    let mut used_layers = HashSet::new();

    for (manifest_bundle, img_ref) in manifests.iter().zip(images.iter()) {
        package_single_image(
            img_ref,
            output_dir,
            manifest_bundle,
            &used_layers,
            &mut layers,
            decompress_layers,
            rename_registry,
        )?;

        if deduplicate_layers {
            used_layers.extend(
                manifest_bundle
                    .manifest
                    .layers()
                    .iter()
                    .map(|layer| layer.digest()),
            );
        }
    }

    for layer in layers.keys() {
        let file_path = {
            let mut path = output_dir.to_path_buf();
            path.push(layer);
            path
        };
        std::fs::remove_file(file_path)?;
    }

    Ok(())
}

async fn download_delta(
    from: ParsedImageReference,
    to: ParsedImageReference,
    decompress_layers: bool,
    rename_registry: Option<&str>,
    output_dir: Option<&Path>,
) -> anyhow::Result<()> {
    let output_dir = output_dir.unwrap_or(Path::new("."));

    std::fs::create_dir_all(output_dir)?;
    let client = reqwest::Client::new();

    let images = [from.clone(), to.clone()];

    let registries = get_registries_for_image_set(&client, &images).await?;

    // Get manifest for each image
    let [to_request, from_request] = images.map(|img_ref| {
        let (registry, _repository_namespace) = get_registry(&img_ref.registry);
        let token = registries.get(&registry).unwrap();
        let client = client.clone();
        async move { get_manifest(client.clone(), &img_ref, token).await }
    });

    let (from_manifest, to_manifest) = futures::try_join!(to_request, from_request)?;

    let to_layers: HashSet<_> = to_manifest
        .manifest
        .layers()
        .iter()
        .map(|layer| layer.digest())
        .collect();
    let from_layers: HashSet<_> = from_manifest
        .manifest
        .layers()
        .iter()
        .map(|layer| layer.digest())
        .collect();

    /*
     * Assuming our images look like so:
     *
     * ```
     *  Original    Patch
     *     Image    Image
     *      ┌─┐     ┌─┐
     *      │C│     │D│
     *      └┬┘     └┬┘
     *       ▼       │
     *      ┌─┐      │
     *      │B│◄─────┘
     *      └┬┘
     *       ▼
     *      ┌─┐
     *      │A│
     *      └─┘
     * ```
     *
     * `needed_delta` will be a set containing `D`,
     * and `removed_layers` will be a set containing 'C'.
     *
     * `prefix`, containing `{A, B}`, is the set of layers shared by both images.
     *
     * If the new image is strictly an addition on top of the previous one,
     * `removed_layers` will be empty.
     */
    let prefix: HashSet<_> = to_layers.intersection(&from_layers).copied().collect();
    let needed_delta = to_layers.difference(&prefix);
    let removed_layers = from_layers.difference(&prefix);
    if removed_layers.count() > 0 {
        eprintln!("WARNING: Patched image isn't a strict superset of the base image");
    }

    // Aggregate layer digests to download - create a hashmap to deduplicate layers between images.
    let layer_digests = needed_delta.map(|digest| {
        let layer = to_manifest
            .manifest
            .layers()
            .iter()
            .find(|layer| layer.digest() == *digest)
            .unwrap();
        (layer.clone(), &to)
    });

    let mut layers = download_layers(
        &client,
        output_dir,
        decompress_layers,
        layer_digests.clone(),
        &registries,
    )
    .await?;

    // Package the patch tarball, ignoring layers in `prefix`.
    package_single_image(
        &to,
        output_dir,
        &to_manifest,
        &prefix,
        &mut layers,
        decompress_layers,
        rename_registry,
    )?;

    for (layer, _) in layer_digests {
        let file_path = {
            let mut path = output_dir.to_path_buf();
            path.push(layer.digest());
            path
        };
        std::fs::remove_file(file_path)?;
    }

    Ok(())
}

async fn retag(
    old_tag: ParsedImageReference,
    new_tag: ParsedImageReference,
    overwrite: bool,
) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let images = [old_tag.clone(), new_tag.clone()];

    let registries = get_registries_for_image_set(&client, &images).await?;

    // Get manifest for each image
    let [old_tag_request, new_tag_request] = images.map(|img_ref| {
        let (registry, _repository_namespace) = get_registry(&img_ref.registry);
        let token = registries.get(&registry).unwrap();
        let client = client.clone();
        async move { get_manifest(client.clone(), &img_ref, token).await }
    });

    let (old_manifest, new_manifest) = futures::join!(old_tag_request, new_tag_request);
    if new_manifest.is_ok() && !overwrite {
        bail!("New tag already exists!!!! not overwriting without --overwrite");
    }
    let old_manifest = old_manifest.unwrap();

    let (registry, _repository_namespace) = get_registry(&new_tag.registry);
    push_manifest(
        client,
        &new_tag,
        registries.get(&registry).unwrap(),
        &old_manifest.raw_manifest,
        &old_manifest.manifest_content_type,
    )
    .await?;

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

        /// Decompress the downloaded layers if they are gzipped.
        #[arg(long)]
        decompress_layers: bool,

        /// Rename and set the registry when tagging the images
        #[arg(long)]
        rename_registry: Option<String>,

        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Create a tarball for an image, sans any layers present in another image.
    /// This can be used to deliver small "patches" containing only layers appeneded to an existing image.
    Delta {
        base_image: String,
        image: String,

        /// Decompress the downloaded layers if they are gzipped.
        #[arg(long)]
        decompress_layers: bool,

        /// Rename and set the registry when tagging the images
        #[arg(long)]
        rename_registry: Option<String>,

        #[arg(long)]
        output_dir: Option<PathBuf>,
    },
    /// Retag
    Retag {
        old_tag: String,
        new_tag: String,

        /// Overwrite target tag if it already exists.
        #[arg(long)]
        overwrite: bool,
    },
    /// Analyze an image.
    /// If no `output` is specified, the results will be shown in a TUI, otherwise
    /// they will be written to the specified path in JSON format.
    ///
    /// The file can later be passed to `show-analysis`.
    ///
    /// # Note #
    /// Due to limitations of JSON, saving the report will cause non-UTF-8 file names to be
    /// changed.
    Analyze {
        tar_file: String,

        /// Save analysis results
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    ShowAnalysis {
        analysis_file: PathBuf,
    },
}

#[tokio::main/*(worker_threads = 4)*/]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // analyze(&image_tar_name);
    match args.command {
        SubCommand::Analyze { tar_file, output } => {
            analyze::analyze(&tar_file, output.as_deref()).await;
        }
        SubCommand::ShowAnalysis { analysis_file } => {
            analyze::display_saved_analysis(&analysis_file).await;
        }
        SubCommand::Download {
            images,
            deduplicate,
            rename_registry,
            decompress_layers,
            output_dir,
        } => {
            let mut references = Vec::new();
            for img in images {
                references.push(docker_registry_v2::ParsedImageReference::from_str(&img)?);
            }

            let f = download_a_bunch(
                &references,
                deduplicate,
                decompress_layers,
                rename_registry.as_deref(),
                output_dir.as_deref(),
            )
            .await;

            match &f {
                Ok(_) => {}
                Err(e) => {
                    dbg!(&e, e.backtrace());
                }
            }
            f?;
        }
        SubCommand::Delta {
            image,
            base_image,
            decompress_layers,
            rename_registry,
            output_dir,
        } => {
            let from = docker_registry_v2::ParsedImageReference::from_str(&base_image)?;
            let to = docker_registry_v2::ParsedImageReference::from_str(&image)?;
            let f = download_delta(
                from,
                to,
                decompress_layers,
                rename_registry.as_deref(),
                output_dir.as_deref(),
            )
            .await;
            match &f {
                Ok(_) => {}
                Err(e) => {
                    dbg!(&e, e.backtrace());
                }
            }
            f?;
        }
        SubCommand::Retag {
            old_tag,
            new_tag,
            overwrite,
        } => {
            let old_tag = docker_registry_v2::ParsedImageReference::from_str(&old_tag)?;
            let new_tag = docker_registry_v2::ParsedImageReference::from_str(&new_tag)?;
            let f = retag(old_tag, new_tag, overwrite).await;
            match &f {
                Ok(_) => {}
                Err(e) => {
                    dbg!(&e, e.backtrace());
                }
            }
            f?;
        }
    }

    Ok(())
}
