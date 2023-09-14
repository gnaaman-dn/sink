use oci_spec::{
    image::{ImageConfiguration, MediaType},
    image::{ImageIndex, ImageManifest},
};
use ratatui::style::Style;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use serde::Serialize;
use std::collections::HashMap;
use std::{
    ffi::OsString,
    fs::File,
    io::Read,
    ops::Range,
    path::{Path, PathBuf},
};
use tar::Archive;

mod tui;

const TAR_MAGIC: &[u8] = b"ustar\000";
const TAR_MAGIC_SPAN: Range<usize> = 257..265;

#[allow(unused)]
pub(crate) fn bytes_to_human_size(byte_size: u64) -> (f64, &'static str) {
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

#[derive(Serialize, Debug)]
pub(crate) struct DirectoryMetadata {
    size: u64,
    children: HashMap<OsString, LayerFsNode>,
}

impl DirectoryMetadata {
    pub fn into_tui_tree_item(&self) -> Vec<tui_tree_widget::TreeItem> {
        use tui_tree_widget::TreeItem;

        let mut children: Vec<_> = self.children.iter().collect();
        children.sort_unstable_by_key(|(_k, v)| std::cmp::Reverse(v.size()));

        children
            .into_iter()
            .map(|(k, v)| {
                let k = Path::new(k).display();
                match v {
                    LayerFsNode::File { size } => {
                        let (magnitude, unit) = bytes_to_human_size(*size);
                        TreeItem::new_leaf(format!("{k} ({magnitude:.2} {unit})",))
                    }
                    LayerFsNode::Symlink { target } => {
                        TreeItem::new_leaf(format!("{k} -> {}", target.display()))
                            .style(Style::default().fg(ratatui::style::Color::Cyan))
                    }
                    LayerFsNode::Directory(metadata) => {
                        let (magnitude, unit) = bytes_to_human_size(metadata.size);
                        TreeItem::new(
                            format!("{k} ({magnitude:.2} {unit})"),
                            metadata.into_tui_tree_item(),
                        )
                    }
                }
            })
            .collect()
    }
}

#[derive(Serialize, Debug)]
pub(crate) enum LayerFsNode {
    File { size: u64 },
    Symlink { target: PathBuf },
    Directory(DirectoryMetadata),
}

impl LayerFsNode {
    fn new_dir() -> Self {
        LayerFsNode::Directory(DirectoryMetadata {
            size: 0,
            children: HashMap::new(),
        })
    }

    fn size(&self) -> u64 {
        match self {
            LayerFsNode::File { size } => *size,
            LayerFsNode::Symlink { .. } => 0,
            LayerFsNode::Directory(metadata) => metadata.size,
        }
    }

    pub fn unwrap_dir(&self) -> &DirectoryMetadata {
        match self {
            LayerFsNode::Directory(metadata) => metadata,
            _ => panic!("Called unwrap_dir on a non-directory"),
        }
    }

    pub fn unwrap_dir_mut(&mut self) -> &mut DirectoryMetadata {
        match self {
            LayerFsNode::Directory(metadata) => metadata,
            _ => panic!("Called unwrap_dir on a non-directory"),
        }
    }

    fn goto_mut(&mut self, path: &Path) -> &mut LayerFsNode {
        let mut current = self;
        for segment in path.components() {
            if let LayerFsNode::Directory(metadata) = current {
                current = metadata
                    .children
                    .entry(segment.as_os_str().to_os_string())
                    .or_insert_with(Self::new_dir);
            } else {
                panic!("Cannot go down into a non-directory");
            }
        }

        current
    }

    fn add_file(&mut self, file_path: &Path, size: u64) {
        let mut current = self.unwrap_dir_mut();

        current.size += size;

        if let Some(file_dir) = file_path.parent() {
            for segment in file_dir.components() {
                current = current
                    .children
                    .entry(segment.as_os_str().to_os_string())
                    .or_insert_with(Self::new_dir)
                    .unwrap_dir_mut();
                current.size += size;
            }
        };

        let old_one = current.children.insert(
            file_path.file_name().unwrap().to_os_string(),
            LayerFsNode::File { size },
        );
        if let Some(_file) = old_one {
            panic!("File for path {file_path:?} specified twice!");
        }
    }

    fn add_symlink(&mut self, file_path: &Path, target: &Path) {
        let dir = match file_path.parent().map(|dir_path| self.goto_mut(dir_path)) {
            Some(dir) => dir,
            None => self,
        };
        let metadata = dir.unwrap_dir_mut();
        let old_one = metadata.children.insert(
            file_path.as_os_str().to_os_string(),
            LayerFsNode::Symlink {
                target: target.to_owned(),
            },
        );
        if let Some(_file) = old_one {
            panic!("File for path {file_path:?} specified twice!");
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct LayerAnalysisResult {
    pub digest: String,
    pub file_system: LayerFsNode,
}

fn analyze_tar_layer<R: Read>(digest: String, r: R) -> LayerAnalysisResult {
    let mut layer_archive = Archive::new(r);
    let mut file_system = LayerFsNode::new_dir();

    for entry in layer_archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().into_owned();

        if entry.header().entry_type().is_file() {
            file_system.add_file(&path, entry.size());
        }
        if entry.header().entry_type().is_symlink() {
            file_system.add_symlink(&path, &entry.header().link_name().unwrap().unwrap());
        }
    }

    LayerAnalysisResult {
        digest,
        file_system,
    }
}

pub fn analyze(tar_path: &str) {
    let file = File::open(tar_path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let cursor = std::io::Cursor::new(&mmap);
    let mut a = Archive::new(cursor);

    // let mut layer_ranges = Vec::new();
    // let mut layer_metadata = HashMap::new();

    // let mut manifset = None;

    // Gather files in this tar archive and their spans.
    let files: HashMap<String, Range<usize>> = a
        .entries()
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let pos = entry.raw_file_position() as usize;
            let size = entry.size() as usize;
            let path = path;
            (path, (pos..(pos + size)))
        })
        .collect();

    fn digest_to_blob_path(digest: &str) -> String {
        let mut digest_path_component = digest.replace(":", "/");
        digest_path_component.insert_str(0, "blobs/");
        digest_path_component
    }

    if files.contains_key("oci-layout") {
        let index_range = files
            .get("index.json")
            .expect("OCI images must have an `index.json` file");
        let index: ImageIndex = serde_json::from_slice(&mmap[index_range.clone()]).unwrap();

        // Yeah, I ain't going to find something more complex lol
        assert!(index.manifests().len() == 1);
        let manifest_path = digest_to_blob_path(index.manifests()[0].digest());
        let manifest_range = files.get(&manifest_path).expect("Missing manifest blob");
        let manifest: ImageManifest =
            serde_json::from_slice(&mmap[manifest_range.clone()]).unwrap();

        let config_path = digest_to_blob_path(manifest.config().digest());
        let config_range = files.get(&config_path).expect("Missing config blob");
        let config: ImageConfiguration =
            serde_json::from_slice(&mmap[config_range.clone()]).unwrap();

        let layers = manifest
            .layers()
            .par_iter()
            .map(|layer| {
                let layer_path = digest_to_blob_path(layer.digest());
                let layer_range = files.get(&layer_path).expect("Missing layer blob");
                match *layer.media_type() {
                    MediaType::ImageLayer => {
                        analyze_tar_layer(layer.digest().clone(), &mmap[layer_range.clone()])
                    }
                    MediaType::ImageLayerGzip => {
                        // It looks like both Docker and Podman work fine with layers where the mediaType is gzip,
                        // but the actual layer data is a regualr tar.
                        // Podman will happily create such imaages with `podman save --uncompressed`;
                        // I assume it's somehow significant, so we try to detect a tar file and avoid gunzipping.
                        let tar_magic_maybe = &mmap[TAR_MAGIC_SPAN.clone()];
                        assert!(tar_magic_maybe.len() == TAR_MAGIC.len());
                        if tar_magic_maybe == TAR_MAGIC {
                            analyze_tar_layer(layer.digest().clone(), &mmap[layer_range.clone()])
                        } else {
                            let reader = flate2::read::GzDecoder::new(&mmap[layer_range.clone()]);
                            analyze_tar_layer(layer.digest().clone(), reader)
                        }
                    }
                    MediaType::ImageLayerZstd => todo!(),
                    _ => todo!(),
                }
            })
            .collect::<Vec<_>>();
        drop(mmap);
        tui::run_tui(&config, &layers).unwrap();
        // let json = serde_json::to_string_pretty(&layers).unwrap();
        // println!("{json}");
    }
}
