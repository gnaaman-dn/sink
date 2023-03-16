use clap::{Parser, Subcommand};
use futures::StreamExt;
use oci_spec::image::{ImageConfiguration, ImageManifest, Descriptor, DescriptorBuilder};
use rayon::prelude::*;
use reqwest::{Client, Method, StatusCode};
use serde::Deserialize;
use sha2::{Sha256, digest::FixedOutput};
use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::{Seek, Write},
    str::FromStr,
    time::Instant,
};
use tar::Archive;
use tokio::io::AsyncReadExt;

pub mod oci;
use oci::*;
pub mod docker_registry_v2;
pub mod response_async_reader;

use docker_registry_v2::{ParsedDomain, ParsedImageReference};
use response_async_reader::ResponseAsyncReader;

const IMAGE_MANIFEST_CONTENT_TYPES: &str = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json";

fn bytes_to_human_size(byte_size: u64) -> (f64, &'static str) {
    if byte_size > 1024 * 1024 * 1024 {
        (byte_size as f64 / (1024.0 * 1024.0 * 1024.0), "GiB")
    } else if byte_size > 1024 * 1024 {
        (byte_size as f64 / (1024.0 * 1024.0), "MiB")
    } else if byte_size > 1024 {
        (byte_size as f64 / (1024.0), "KiB")
    } else {
        (byte_size as f64, "B")
    }
}

fn hash_string(src: &str) -> String {
    let mut hasher = Sha256::default();
    let _ = hasher.write(src.as_bytes());
    let digest = hasher.finalize_fixed();
    let byte_strings: Vec<_> = digest.as_slice().into_iter().map(|b| format!("{b:02x}")).collect();
    byte_strings.join("")
}

fn analyze(tar_path: &str) {
    let file = File::open(tar_path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let cursor = std::io::Cursor::new(&mmap);
    let mut a = Archive::new(cursor);

    let mut layer_ranges = Vec::new();
    let mut layer_metadata = HashMap::new();

    let mut manifset = None;

    for entry in a.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap();

        let pos = entry.raw_file_position() as usize;
        let size = entry.size() as usize;

        match &*path.file_name().unwrap().to_string_lossy() {
            "manifest.json" => {
                manifset =
                    Some(serde_json::from_slice::<Vec<Manifest>>(&mmap[pos..pos + size]).unwrap());
            }
            "json" => {
                let layer = serde_json::from_slice::<Layer>(&mmap[pos..pos + size]).unwrap();
                layer_metadata.insert(layer.id.clone(), layer);
            }
            "layer.tar" => {
                layer_ranges.push((
                    path.parent().unwrap().to_string_lossy().into_owned(),
                    pos,
                    size,
                    std::io::Cursor::new(&mmap[pos..pos + size]),
                ));
            }
            _ => {
                continue;
            }
        }
    }

    let layer_data: HashMap<_, _> = layer_ranges
        .into_par_iter()
        .map(|(name, pos, size, cursor)| {
            println!("{name:?} pos={pos} size={size}");
            let mut layer_archive = Archive::new(cursor.clone());
            let mut path_map = HashMap::new();
            let mut dirs_to_calculate = Vec::new();
            let mut dir_sizes = HashMap::new();
            let mut total_size = 0;
            for entry in layer_archive.entries().unwrap() {
                let entry = entry.unwrap();
                let path = entry.path().unwrap().into_owned();

                if entry.header().entry_type().is_dir() {
                    dirs_to_calculate.push(path.clone());
                }

                for parent in path.ancestors().skip(1) {
                    // Skip "" tar (root)
                    if parent.as_os_str().len() == 0 {
                        continue;
                    }

                    *dir_sizes.entry(parent.to_owned()).or_insert(0) += entry.size();
                }

                path_map.insert(path, entry.size());
                total_size += entry.size();
            }
            dirs_to_calculate.sort_unstable();
            (
                name,
                (total_size, path_map, dirs_to_calculate.len(), dir_sizes),
            )
        })
        .collect();

    for layer in manifset.unwrap()[0].layers.iter() {
        let layer_name = layer.parent().unwrap().to_string_lossy();
        let Some((total_size, _, _, dir_sizes)) = layer_data.get(&*layer_name) else {
            println!("Found no data for layer {layer_name:?}");
            continue;
        };
        let Some(metadata) = layer_metadata.get(&*layer_name) else {
            println!("Found no metadata for layer {layer_name:?}");
            continue;
        };

        let (size, unit) = bytes_to_human_size(*total_size);
        println!("{layer_name:?} {size:.2} {unit} {metadata:?}");
        let mut dir_sizes: Vec<_> = dir_sizes.iter().collect();
        dir_sizes.sort_by(|(_, size_a), (_, size_b)| size_b.cmp(size_a));
        for (dir_name, total_size) in dir_sizes.iter().take(10) {
            let (size, unit) = bytes_to_human_size(**total_size);
            println!("\t>> {dir_name:?} {size:.2} {unit}");
        }
    }

    // dbg!(layer_data);
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
/*
response = {
    "access_token": String("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDK1RDQ0FwK2dBd0lCQWdJQkFEQUtCZ2dxaGtqT1BRUURBakJHTVVRd1FnWURWUVFERXp0U1RVbEdPbEZNUmpRNlEwZFFNenBSTWtWYU9sRklSRUk2VkVkRlZUcFZTRlZNT2taTVZqUTZSMGRXV2pwQk5WUkhPbFJMTkZNNlVVeElTVEFlRncweU16QXhNRFl3TkRJM05EUmFGdzB5TkRBeE1qWXdOREkzTkRSYU1FWXhSREJDQmdOVkJBTVRPME5EVlVZNlNqVkhOanBGUTFORU9rTldSRWM2VkRkTU1qcEtXa1pST2xOTk0wUTZXRmxQTkRwV04wTkhPa2RHVjBJNldsbzFOam8wVlVSRE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBek4wYjBqN1V5L2FzallYV2gyZzNxbzZKaE9rQWpYV0FVQmNzSHU2aFlaUkZMOXZlODEzVEI0Y2w4UWt4Q0k0Y1VnR0duR1dYVnhIMnU1dkV0eFNPcVdCcnhTTnJoU01qL1ZPKzYvaVkrOG1GRmEwR2J5czF3VDVjNlY5cWROaERiVGNwQXVYSjFSNGJLdSt1VGpVS0VIYXlqSFI5TFBEeUdnUC9ubUFadk5PWEdtclNTSkZJNnhFNmY3QS8rOVptcWgyVlRaQlc0cXduSnF0cnNJM2NveDNQczMwS2MrYUh3V3VZdk5RdFNBdytqVXhDVVFoRWZGa0lKSzh6OVdsL1FjdE9EcEdUeXNtVHBjNzZaVEdKWWtnaGhGTFJEMmJQTlFEOEU1ZWdKa2RQOXhpaW5sVGx3MjBxWlhVRmlqdWFBcndOR0xJbUJEWE0wWlI1YzVtU3Z3SURBUUFCbzRHeU1JR3ZNQTRHQTFVZER3RUIvd1FFQXdJSGdEQVBCZ05WSFNVRUNEQUdCZ1JWSFNVQU1FUUdBMVVkRGdROUJEdERRMVZHT2tvMVJ6WTZSVU5UUkRwRFZrUkhPbFEzVERJNlNscEdVVHBUVFRORU9saFpUelE2VmpkRFJ6cEhSbGRDT2xwYU5UWTZORlZFUXpCR0JnTlZIU01FUHpBOWdEdFNUVWxHT2xGTVJqUTZRMGRRTXpwUk1rVmFPbEZJUkVJNlZFZEZWVHBWU0ZWTU9rWk1WalE2UjBkV1dqcEJOVlJIT2xSTE5GTTZVVXhJU1RBS0JnZ3Foa2pPUFFRREFnTklBREJGQWlFQW1RNHhsQXZXVlArTy9hNlhDU05pYUFYRU1Bb1RQVFRYRWJYMks2RVU4ZTBDSUg0QTAwSVhtUndjdGtEOHlYNzdkTVoyK0pEY1FGdDFxRktMZFR5SnVzT1UiXX0.eyJhY2Nlc3MiOltdLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuaW8iLCJleHAiOjE2Nzg0Mjg1ODYsImlhdCI6MTY3ODQyODI4NiwiaXNzIjoiYXV0aC5kb2NrZXIuaW8iLCJqdGkiOiJkY2tyX2p0aV9GR0tzalg3aXk3MFNSOEl2ZEltaG42aXY2V2c9IiwibmJmIjoxNjc4NDI3OTg2LCJzdWIiOiIifQ.OH_S-PKZoPSY0PG-9SXBCHaK59oIACEkZZ_yK_hRGRSIn0FfQyLFxDCakvkBD8rlGVKO-Sb3JA0cFRSyqbwj_UscZklOAEpGZ5bXaQu1xuR6tgAeAb1yQS91HHEVTVwhjTuyfNoDUrULfZY_M7dWbuIVB4QV_XVYNzXlaHV2DHG9DiUPnF4gQXI7l_gV0o06ajvZmDXRKtbZLBYMQgG-3qOU7_eaU9S0IQ63v79nTEKvEoAcC8XNHEGHRNI6HNuLXKJtb3eM5PmL3MsGYFmoradDJN7scAqo6rzznuzBxYce642N96Dw7rccCJppsWtL3MIjitO1oRrKErCB2AOdNQ"),
    "issued_at": String("2023-03-10T06:04:46.228904662Z"),
    "token": String("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDK1RDQ0FwK2dBd0lCQWdJQkFEQUtCZ2dxaGtqT1BRUURBakJHTVVRd1FnWURWUVFERXp0U1RVbEdPbEZNUmpRNlEwZFFNenBSTWtWYU9sRklSRUk2VkVkRlZUcFZTRlZNT2taTVZqUTZSMGRXV2pwQk5WUkhPbFJMTkZNNlVVeElTVEFlRncweU16QXhNRFl3TkRJM05EUmFGdzB5TkRBeE1qWXdOREkzTkRSYU1FWXhSREJDQmdOVkJBTVRPME5EVlVZNlNqVkhOanBGUTFORU9rTldSRWM2VkRkTU1qcEtXa1pST2xOTk0wUTZXRmxQTkRwV04wTkhPa2RHVjBJNldsbzFOam8wVlVSRE1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBek4wYjBqN1V5L2FzallYV2gyZzNxbzZKaE9rQWpYV0FVQmNzSHU2aFlaUkZMOXZlODEzVEI0Y2w4UWt4Q0k0Y1VnR0duR1dYVnhIMnU1dkV0eFNPcVdCcnhTTnJoU01qL1ZPKzYvaVkrOG1GRmEwR2J5czF3VDVjNlY5cWROaERiVGNwQXVYSjFSNGJLdSt1VGpVS0VIYXlqSFI5TFBEeUdnUC9ubUFadk5PWEdtclNTSkZJNnhFNmY3QS8rOVptcWgyVlRaQlc0cXduSnF0cnNJM2NveDNQczMwS2MrYUh3V3VZdk5RdFNBdytqVXhDVVFoRWZGa0lKSzh6OVdsL1FjdE9EcEdUeXNtVHBjNzZaVEdKWWtnaGhGTFJEMmJQTlFEOEU1ZWdKa2RQOXhpaW5sVGx3MjBxWlhVRmlqdWFBcndOR0xJbUJEWE0wWlI1YzVtU3Z3SURBUUFCbzRHeU1JR3ZNQTRHQTFVZER3RUIvd1FFQXdJSGdEQVBCZ05WSFNVRUNEQUdCZ1JWSFNVQU1FUUdBMVVkRGdROUJEdERRMVZHT2tvMVJ6WTZSVU5UUkRwRFZrUkhPbFEzVERJNlNscEdVVHBUVFRORU9saFpUelE2VmpkRFJ6cEhSbGRDT2xwYU5UWTZORlZFUXpCR0JnTlZIU01FUHpBOWdEdFNUVWxHT2xGTVJqUTZRMGRRTXpwUk1rVmFPbEZJUkVJNlZFZEZWVHBWU0ZWTU9rWk1WalE2UjBkV1dqcEJOVlJIT2xSTE5GTTZVVXhJU1RBS0JnZ3Foa2pPUFFRREFnTklBREJGQWlFQW1RNHhsQXZXVlArTy9hNlhDU05pYUFYRU1Bb1RQVFRYRWJYMks2RVU4ZTBDSUg0QTAwSVhtUndjdGtEOHlYNzdkTVoyK0pEY1FGdDFxRktMZFR5SnVzT1UiXX0.eyJhY2Nlc3MiOltdLCJhdWQiOiJyZWdpc3RyeS5kb2NrZXIuaW8iLCJleHAiOjE2Nzg0Mjg1ODYsImlhdCI6MTY3ODQyODI4NiwiaXNzIjoiYXV0aC5kb2NrZXIuaW8iLCJqdGkiOiJkY2tyX2p0aV9GR0tzalg3aXk3MFNSOEl2ZEltaG42aXY2V2c9IiwibmJmIjoxNjc4NDI3OTg2LCJzdWIiOiIifQ.OH_S-PKZoPSY0PG-9SXBCHaK59oIACEkZZ_yK_hRGRSIn0FfQyLFxDCakvkBD8rlGVKO-Sb3JA0cFRSyqbwj_UscZklOAEpGZ5bXaQu1xuR6tgAeAb1yQS91HHEVTVwhjTuyfNoDUrULfZY_M7dWbuIVB4QV_XVYNzXlaHV2DHG9DiUPnF4gQXI7l_gV0o06ajvZmDXRKtbZLBYMQgG-3qOU7_eaU9S0IQ63v79nTEKvEoAcC8XNHEGHRNI6HNuLXKJtb3eM5PmL3MsGYFmoradDJN7scAqo6rzznuzBxYce642N96Dw7rccCJppsWtL3MIjitO1oRrKErCB2AOdNQ"),
    "expires_in": Number(300),
}
 */

#[derive(Debug, Clone, Deserialize)]
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

#[derive(Clone, Debug)]
struct ImageManifests {
    manifest: ImageManifest,
    raw_manifest: String,
    config: ImageConfiguration,
    raw_config: String
}

async fn get_manifest(
    client: Client,
    url_base: String,
    tag: &str,
    token: Option<&AuthToken>,
) -> anyhow::Result<ImageManifests> {
    let url = format!("{url_base}/manifests/{tag}");
    let mut request = client
        .request(Method::GET, url)
        .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);

    if let Some(token) = token {
        request = request.bearer_auth(&token.token);
    };

    let response = request.send().await?;
    let status = response.status();
    let raw_manifest = response.text().await?;

    let manifest = serde_json::from_str::<oci_spec::image::ImageManifest>(&raw_manifest).map_err(|e| {
        eprintln!("FUCKITY FUCK: {url_base} {tag} {raw_manifest}, {:?}", status);
        e
    })?;

    let config_digest = manifest.config().digest();
    let config_url = format!("{url_base}/blobs/{config_digest}");

    let mut request = client.request(Method::GET, config_url);
    if let Some(token) = token {
        request = request.bearer_auth(&token.token);
    };
    let response = request.send().await?;
    let raw_config = response.text().await?;
    let config = serde_json::from_str::<oci_spec::image::ImageConfiguration>(&raw_config)?;

    let manifests = ImageManifests {
        manifest,
        raw_manifest,
        config,
        raw_config,
    };
    Ok(manifests)
}

async fn download_a_bunch(images: &[ParsedImageReference]) -> anyhow::Result<()> {
    let start = Instant::now();
    let mut registries = HashMap::new();

    for img_ref in images {
        let (registry, repository_namespace) = get_registry(&img_ref.registry);
        let f = registries
            .entry((registry, repository_namespace))
            .or_insert(Vec::new());
        f.push((img_ref.repository.clone(), img_ref.tag.clone()));
    }

    let client = reqwest::Client::new();

    // Get auth tokens for each repository.
    let token_futures = registries
        .iter()
        .map(|((registry, namespace), repositories)| {
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
        let (registry, repository_namespace) = get_registry(&img_ref.registry);

        let tag = img_ref
            .tag
            .as_ref()
            .map_or_else(|| "latest", |t| &*t.digest.as_ref().unwrap_or(&t.tag));

        let url = format!(
            "https://{registry}/v2/{repository_namespace}{}/manifests/{tag}",
            img_ref.repository,
        );

        let url_base = format!(
            "https://{registry}/v2/{repository_namespace}{}/",
            img_ref.repository,
        );

        let token = tokens.get(&registry).map(|t| t.as_ref()).flatten();
        get_manifest(client.clone(), url_base, tag, token)
    });
    let manifests = futures::future::try_join_all(manifest_requests).await?;

    let mut layer_digests = HashMap::new();
    for (manifest_bundle, img_ref) in manifests.iter().zip(images.iter()) {
        for layer in manifest_bundle.manifest.layers() {
            layer_digests.insert(layer.digest().clone(), img_ref);
        }
    }

    dbg!(&manifests);

    let layer_futures = layer_digests.iter().map(|(digest, img_ref)| {
        let (registry, repository_namespace) = get_registry(&img_ref.registry);

        let url = dbg!(format!(
            "https://{registry}/v2/{repository_namespace}{}/blobs/{digest}",
            img_ref.repository
        ));
        let token = tokens.get(&registry).unwrap();
        let mut request = client
            .request(Method::GET, url)
            .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
        if let Some(token) = &token {
            request = request.bearer_auth(&token.token);
        }

        async move {
            eprintln!(">> Starting to download {digest}");
            let mut file = File::options()
                .create(true)
                .write(true)
                .truncate(true)
                .read(true)
                .open(digest)?;
            let response = request.send().await?;
            // let reader = ResponseAsyncReader::new(response);
            // let mut decomp = async_compression::tokio::bufread::GzipDecoder::new(reader);

            // let mut buf = [0u8; 4096 * 16];

            // loop {
            //     let size = decomp.read(&mut buf).await?;
            //     if size == 0 {
            //         break;
            //     }
            //     let buf = &buf[..size];
            //     file.write(buf)?;
            // }
            let mut stream = response.bytes_stream();
            while let Some(chunk) = stream.next().await {
                file.write(&*chunk?)?;
            }

            eprintln!(">> Finished downloading {digest}");
            Ok::<_, anyhow::Error>((digest, file))
        }
    });

    let mut used_layers = HashSet::new();
    let mut layers: HashMap<_, _> = futures::future::try_join_all(layer_futures)
        .await?
        .into_iter()
        .collect();

    for (manifest_bundle, img_ref) in manifests.iter().zip(images.iter()) {
        let mut file = File::create(format!("{}.tar", img_ref.repository))?;
        let mut image_tar = tar::Builder::new(&mut file);
        for layer in manifest_bundle.manifest.layers() {
            let digest = layer.digest();
            if used_layers.contains(&*digest) {
                eprintln!("Skipping {digest}, it was already used in one of the previous layers");
                continue;
            }
            let layer_file = layers.get_mut(digest).unwrap();

            layer_file.seek(std::io::SeekFrom::Start(0))?;
            image_tar.append_file(
                format!("blobs/sha256/{}", digest.split(':').nth(1).unwrap()),
                layer_file,
            )?;
            used_layers.insert(&*digest);
        }

        // Write image config to blobs
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bundle.raw_config.len() as u64);
        header.set_cksum();
        image_tar.append_data(
            &mut header,
            format!(
                "blobs/sha256/{}",
                manifest_bundle.manifest.config().digest().split(':').nth(1).unwrap()
            ),
            manifest_bundle.raw_config.as_bytes(),
        )?;

        // Write image manifest to blobs
        let manifest_digest = hash_string(&manifest_bundle.raw_manifest);
        let mut header = tar::Header::new_gnu();
        header.set_size(manifest_bundle.raw_manifest.len() as u64);
        header.set_cksum();
        image_tar.append_data(
            &mut header,
            format!(
                "blobs/sha256/{manifest_digest}",
            ),
            manifest_bundle.raw_manifest.as_bytes(),
        )?;

        // Write "oci-layout" file
        let layout_data = "{\"imageLayoutVersion\":\"1.0.0\"}";
        let mut header = tar::Header::new_gnu();
        header.set_size(layout_data.len() as u64);
        header.set_cksum();
        image_tar.append_data(&mut header, "oci-layout", layout_data.as_bytes())?;

        /*
        {
  "schemaVersion": 2,
  "manifests": [
    {
      "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
      "size": 954,
      "digest": "sha256:f34ab33ed0e034163ff180b5caa056fc806dfadeeab27f5a40616af951ae7ab8",
      "annotations": {
        "io.containerd.image.name": "pr-registry.dev.drivenets.net/gi_dev_v18_1:18.1.0.199_dev.dev_v18_1",
        "org.opencontainers.image.ref.name": "18.1.0.199_dev.dev_v18_1"
      }
    }
  ]
} */

        // Write index.json
        let ref_name = img_ref.tag.as_ref().map(|t| &*t.tag).unwrap_or("latest").to_string();

        let mut image_name = String::new();
        if let Some(registry) = &img_ref.registry{
            image_name.push_str(&registry.to_string());
            image_name.push('/');
        }
        image_name.push_str(&img_ref.repository);
        image_name.push(':');
        image_name.push_str(&ref_name);
        
        let mut index = oci_spec::image::ImageIndex::default();
        index.set_manifests(vec![
            DescriptorBuilder::default()
                .digest(format!("sha256:{manifest_digest}"))
                .size(manifest_bundle.raw_manifest.len() as i64)
                .media_type(manifest_bundle.manifest.media_type().as_ref().unwrap().clone())
                .annotations(HashMap::from([
                    ("io.containerd.image.name".into(), image_name),
                    ("org.opencontainers.image.ref.name".into(), ref_name),
                ]))
                .build().unwrap()   
        ]);
        let raw_index = serde_json::to_string(&index).unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(raw_index.len() as u64);
        header.set_cksum();
        image_tar.append_data(&mut header, "index.json", raw_index.as_bytes())?;

        image_tar.finish()?;
    }

    for layer in layers.keys() {
        std::fs::remove_file(layer)?;
    }

    println!("Basically done {:?}", start.elapsed());

    Ok(())
}

async fn download(
    image_reference: ParsedImageReference,
) -> anyhow::Result<oci_spec::image::ImageManifest> {
    let (registry, repository_namespace) = if let Some(registry) = image_reference.registry {
        (registry.to_string(), "")
    } else {
        ("registry-1.docker.io".to_string(), "library/")
    };

    let tag = image_reference
        .tag
        .map_or_else(|| "latest".to_string(), |t| t.to_string());
    let url = format!(
        "https://{registry}/v2/{repository_namespace}{}/manifests/{tag}",
        image_reference.repository
    );

    dbg!(&url);

    let client = reqwest::Client::new();

    let token = dbg!(
        get_auth_token(
            client.clone(),
            &registry,
            repository_namespace,
            Some(image_reference.repository.as_str()).into_iter(),
        )
        .await?
    );

    let mut request = client
        .request(Method::GET, url)
        .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
    if let Some(token) = &token {
        request = request.bearer_auth(&token.token);
    }
    let request = request.build()?;
    let response = dbg!(client.execute(request).await?);
    let text = response.text().await?;
    let manifest = serde_json::from_str::<oci_spec::image::ImageManifest>(&text)?;

    for layer in manifest.layers() {
        // dbg!(layer);
        let digest = layer.digest();

        let url = dbg!(format!(
            "https://{registry}/v2/{repository_namespace}{}/blobs/{digest}",
            image_reference.repository
        ));
        let mut request = client
            .request(Method::GET, url)
            .header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
        if let Some(token) = &token {
            request = request.bearer_auth(&token.token);
        }
        let request = request.build()?;
        let response = client.execute(request).await?;

        let mut file = File::create(digest)?;
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            file.write(&*chunk?)?;
        }
        // let reader = ResponseAsyncReader::new(response);
        // let mut decomp = async_compression::tokio::bufread::GzipDecoder::new(reader);
        // let mut buf = [0u8; 4096];
        // loop {
        //     let size = decomp.read(&mut buf).await?;
        //     if size == 0 {
        //         break;
        //     }
        //     let buf = &buf[..size];
        //     file.write(buf)?;
        // }
    }
    Ok(manifest)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: SubCommand,
}

#[derive(Subcommand, Debug)]
enum SubCommand {
    Download { images: Vec<String> },
    Analyze { tar_file: String },
}

#[tokio::main(worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    let args = dbg!(Args::parse());

    // analyze(&image_tar_name);
    match args.command {
        SubCommand::Analyze { tar_file } => {
            analyze(&tar_file);
        }
        SubCommand::Download { images } => {
            let mut references = Vec::new();
            for img in images {
                references.push(docker_registry_v2::ParsedImageReference::from_str(&img)?);
            }

            let f = download_a_bunch(&references).await;

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
