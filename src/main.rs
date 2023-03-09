use std::{fs::File, collections::HashMap, path::PathBuf};
use serde::{Deserialize, Serialize};
use tar::{Archive, EntryType};
use rayon::prelude::*;

/*
[
  {
    "Config": "3dd02e63cf7b74292e50041d1cc0030f28553afc27716b0516f2c0d09b9cf2fa.json",
    "RepoTags": [
      "localhost/wb_salmon_split_dbg_info:18.1.0.2_priv.salmon-split-dbg-info"
    ],
    "Layers": [
      "af4c704c52a2e380ccfda31b4b58c502b1cd5d015059f2824afbc09dd3577008/layer.tar",
      "554c7ada7542bf42fabfc508063d0f6010b8c709bf8c015642f20cba586e5847/layer.tar",
      "0bf3442b97fa48fc5189c186072072012977eb02d509e0ac7c67ace9eeb53151/layer.tar",
      "8cf3a014e8a042c129842576a651cbf62b0444227705272e3d9da99622c5a06c/layer.tar"
    ]
  }
] */
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")] 
struct Manifest {
    config: String,
    repo_tags: Vec<String>,
    layers: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct Layer {
    id: String,
    created: String,
    os: String,
    container_config: ContainerConfig
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")] 
struct ContainerConfig {
    // "Hostname": "",
    hostname: String,
    user: String,
    attach_stdin: bool,
    attach_stdout: bool,
    attach_stderr: bool,
    tty: bool,
    open_stdin: bool,
    stdin_once: bool,
    env: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    image: String,
    // "Volumes": null,
    working_dir: String,
    entry_point: Option<Vec<String>>,
    // "OnBuild": null,
    labels: Option<HashMap<String, String>>,
}


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

fn main() {
    let image_tar_name = std::env::args().nth(1).unwrap();
    let file = File::open(image_tar_name).unwrap();
    let mmap = unsafe { 
        memmap2::Mmap::map(&file)
    }.unwrap();
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
                manifset = Some(serde_json::from_slice::<Vec<Manifest>>(&mmap[pos..pos+size]).unwrap());
            },
            "json" => {
                let layer = serde_json::from_slice::<Layer>(&mmap[pos..pos+size]).unwrap();
                layer_metadata.insert(layer.id.clone(), layer);
            },
            "layer.tar" => {
                layer_ranges.push((path.parent().unwrap().to_string_lossy().into_owned(), pos, size, std::io::Cursor::new(&mmap[pos..pos+size])));
            }
            _ => {
                continue;
            }
        }
        
    }

    let layer_data: HashMap<_, _> = layer_ranges.into_par_iter().map(|(name, pos, size, cursor)| {
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
        (name, (total_size, path_map, dirs_to_calculate.len(), dir_sizes))
    }).collect();

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
