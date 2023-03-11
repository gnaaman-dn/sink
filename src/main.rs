use rayon::prelude::*;
use reqwest::{StatusCode, Method};
use serde::Deserialize;
use tokio::io::AsyncReadExt;
use std::{collections::HashMap, fs::File, str::FromStr, io::Write};
use tar::Archive;
use clap::{Parser, Subcommand};

pub mod oci;
use oci::*;
pub mod docker_registry_v2;
pub mod response_async_reader;

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

/// https://docs.docker.com/registry/spec/auth/token/#how-to-authenticate
async fn get_auth_token(registry: &str, repository_namespace: &str, repository: &str) -> anyhow::Result<Option<AuthToken>> {
    // let registry = "registry-1.docker.io";
    let url = format!("https://{registry}/v2/");
    let response = reqwest::get(url).await?;
    if response.status() == StatusCode::UNAUTHORIZED {
        let auth = response.headers().get("WWW-Authenticate").unwrap();
        let auth = parse_authentication_header(auth.to_str()?);
        let auth_url = auth["Bearer realm"];
        let reg_service = auth["service"];
        let url = format!("{auth_url}?service={reg_service}&scope=repository:{repository_namespace}{repository}:pull");
        dbg!(&url);
        let response = reqwest::get(url).await?.text().await?;
        let parsed_response = serde_json::from_str::<AuthToken>(&response);
        if let Err(_e) = &parsed_response {
            println!("{response}");
        };
        Ok(Some(parsed_response?))
    } else {
        Ok(None)
    }
}

async fn download(image_reference: &str) -> anyhow::Result<oci_spec::image::ImageManifest> {
    let image_reference = docker_registry_v2::ParsedImageReference::from_str(image_reference)?;
    dbg!(&image_reference);

    let (registry, repository_namespace) = if let Some(registry) = image_reference.registry {
        (registry.to_string(), "")
    } else {
        ("registry-1.docker.io".to_string(), "library/")
    };

    let tag = image_reference.tag.map_or_else(|| "latest".to_string(), |t| t.to_string());
    let url = format!("https://{registry}/v2/{repository_namespace}{}/manifests/{tag}", image_reference.repository);

    dbg!(&url);

    let token = dbg!(get_auth_token(&registry, repository_namespace, &image_reference.repository).await?);

    let client = reqwest::Client::new();
    let mut request = client.request(Method::GET, url).header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
    if let Some(token) = &token {
        request = request.bearer_auth(&token.token);
    }
    let request = request.build()?;
    let response = dbg!(client.execute(request).await?);
    let text = response.text().await?;
    let manifest  = serde_json::from_str::<oci_spec::image::ImageManifest>(&text)?;

    for layer in manifest.layers() {
        // dbg!(layer);
        let digest = layer.digest();
        
        let url = dbg!(format!("https://{registry}/v2/{repository_namespace}{}/blobs/{digest}", image_reference.repository));
        let mut request = client.request(Method::GET, url).header("Accept", IMAGE_MANIFEST_CONTENT_TYPES);
        if let Some(token) = &token {
            request = request.bearer_auth(&token.token);
        }
        let request = request.build()?;
        let response = client.execute(request).await?;
        
        let reader = ResponseAsyncReader::new(response);
        let mut decomp = async_compression::tokio::bufread::GzipDecoder::new(reader);
        let mut buf = [0u8; 4096];
        let mut file = File::create(digest)?;
        loop {
            let size = decomp.read(&mut buf).await?;
            if size == 0 {
                break;
            }
            let buf = &buf[..size];
            file.write(buf)?;
        }
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
    Download {
        images: Vec<String>
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = dbg!(Args::parse());
    
    // analyze(&image_tar_name);
    match args.command {
        SubCommand::Download { images } => {
            let futures: Vec<_> = images.into_iter().map(|img| tokio::spawn(async move {
                download(&img).await
            })).collect();

            let mut layers = Vec::new();
            for f in futures {
                let m = f.await??;
                layers.extend(m.layers().iter().map(|l| l.digest().clone()));
            }
        }
    }
    
    Ok(())
}
