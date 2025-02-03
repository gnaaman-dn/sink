use crate::layer_digest_to_blob_path;
use crate::ye_old_docker::YeOldManifest;
use oci_spec::{
    image::{ImageConfiguration, MediaType},
    image::{ImageIndex, ImageManifest},
};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    ffi::OsString,
    time::Instant,
};
use std::{
    fs::File,
    io::Read,
    ops::Range,
    path::{Path, PathBuf},
};
use tar::Archive;

mod serde_lossy;
mod tui;

const TAR_MAGIC: &[u8] = b"ustar\x0000";
const TAR_MAGIC_SPAN: Range<usize> = 257..265;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct AnalysisResult {
    pub image_config: ImageConfiguration,
    pub layers: Vec<LayerAnalysisResult>,
}

type FileSystemSummary = HashMap<PathBuf, u32>;

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct LayerAnalysisResult {
    pub digest: String,
    pub file_system: LayerFsNode,
    #[serde(
        serialize_with = "serde_lossy::serialize_path_map",
        deserialize_with = "serde_lossy::deserialize_path_map"
    )]
    pub file_system_summary: FileSystemSummary,

    /// Directory paths that has the opaque `.wh..wh..opq` marker, which
    /// tells us that the entire directory path was deleted.
    ///
    /// This is needed if we want to calculate a unified file-system.
    #[serde(
        serialize_with = "serde_lossy::serialize_path_set",
        deserialize_with = "serde_lossy::deserialize_path_set"
    )]
    pub cleared_directories: HashSet<PathBuf>,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct LayerFsNode {
    mode: u32,
    size: u64,
    node_type: LayerFsNodeType,
    state: LayerFsNodeState,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub(crate) enum LayerFsNodeState {
    Created,
    Modified,
    ModeChanged,
    Deleted,
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) enum LayerFsNodeType {
    File,
    Symlink { target: PathBuf },
    Directory(DirectoryMetadata),
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DirectoryMetadata {
    #[serde(
        serialize_with = "serde_lossy::serialize_path_map",
        deserialize_with = "serde_lossy::deserialize_path_map"
    )]
    children: HashMap<OsString, LayerFsNode>,
}

impl LayerFsNode {
    fn new_dir() -> Self {
        LayerFsNode {
            mode: 0,
            size: 0,
            node_type: LayerFsNodeType::Directory(DirectoryMetadata {
                children: HashMap::new(),
            }),
            state: LayerFsNodeState::Created,
        }
    }

    fn new_file(size: u64, mode: u32, state: LayerFsNodeState) -> Self {
        LayerFsNode {
            mode,
            size,
            node_type: LayerFsNodeType::File,
            state,
        }
    }

    fn new_symlink(target: PathBuf, mode: u32) -> Self {
        LayerFsNode {
            mode,
            size: 0,
            node_type: LayerFsNodeType::Symlink { target },
            state: LayerFsNodeState::Created,
        }
    }

    fn size(&self) -> u64 {
        self.size
    }

    pub fn unwrap_dir(&self) -> &DirectoryMetadata {
        match &self.node_type {
            LayerFsNodeType::Directory(metadata) => metadata,
            _ => panic!("Called unwrap_dir on a non-directory"),
        }
    }

    pub fn unwrap_dir_mut(&mut self) -> &mut DirectoryMetadata {
        match &mut self.node_type {
            LayerFsNodeType::Directory(metadata) => metadata,
            _ => panic!("Called unwrap_dir on a non-directory"),
        }
    }

    fn goto_mut(&mut self, path: &Path) -> &mut LayerFsNode {
        let mut current = self;
        for segment in path.components() {
            if let LayerFsNodeType::Directory(metadata) = &mut current.node_type {
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

    fn add_file(&mut self, file_path: &Path, size: u64, mode: u32) {
        self.add_file_with_state(file_path, size, mode, LayerFsNodeState::Created);
    }

    fn add_file_with_state(
        &mut self,
        file_path: &Path,
        size: u64,
        mode: u32,
        state: LayerFsNodeState,
    ) {
        self.size += size;

        let mut current = self.unwrap_dir_mut();

        if let Some(file_dir) = file_path.parent() {
            for segment in file_dir.components() {
                let next = current
                    .children
                    .entry(segment.as_os_str().to_os_string())
                    .or_insert_with(Self::new_dir);
                next.size += size;
                current = next.unwrap_dir_mut();
            }
        };

        let old_one = current.children.insert(
            file_path.as_os_str().to_os_string(),
            Self::new_file(size, mode, state),
        );
        if let Some(_file) = old_one {
            panic!("File for path {file_path:?} specified twice!");
        }
    }

    fn add_symlink(&mut self, file_path: &Path, target: &Path, mode: u32) {
        let dir = match file_path.parent().map(|dir_path| self.goto_mut(dir_path)) {
            Some(dir) => dir,
            None => self,
        };
        let metadata = dir.unwrap_dir_mut();
        let old_one = metadata.children.insert(
            file_path.as_os_str().to_os_string(),
            Self::new_symlink(target.to_owned(), mode),
        );
        if let Some(_file) = old_one {
            panic!("File for path {file_path:?} specified twice!");
        }
    }

    fn add_dir_metadata(&mut self, dir_path: &Path, mode: u32) {
        self.goto_mut(dir_path).mode = mode;
    }
}

fn analyze_tar_layer_auto_detect_gzip(digest: String, buffer: &[u8]) -> LayerAnalysisResult {
    // It looks like both Docker and Podman work fine with layers where the mediaType is gzip,
    // but the actual layer data is a regualr tar.
    // Podman will happily create such images with `podman save --uncompressed`;
    // I assume it's somehow significant, so we try to detect a tar file and avoid gunzipping.
    let tar_magic_maybe = buffer.get(TAR_MAGIC_SPAN.clone());

    if tar_magic_maybe == Some(TAR_MAGIC) {
        analyze_tar_layer(digest, buffer)
    } else {
        let reader = flate2::read::GzDecoder::new(buffer);
        analyze_tar_layer(digest, reader)
    }
}

fn analyze_tar_layer_auto_detect_zstd(digest: String, buffer: &[u8]) -> LayerAnalysisResult {
    let tar_magic_maybe = buffer.get(TAR_MAGIC_SPAN.clone());

    if tar_magic_maybe == Some(TAR_MAGIC) {
        analyze_tar_layer(digest, buffer)
    } else {
        let reader = zstd::stream::Decoder::new(buffer).unwrap();
        analyze_tar_layer(digest, reader)
    }
}

fn analyze_tar_layer<R: Read>(digest: String, r: R) -> LayerAnalysisResult {
    let mut layer_archive = Archive::new(r);
    let mut file_system = LayerFsNode::new_dir();
    let mut file_system_summary = HashMap::new();
    let mut cleared_directories = HashSet::new();

    for entry in layer_archive.entries().unwrap() {
        let entry = entry.unwrap();
        let path = entry.path().unwrap().into_owned();
        let header = entry.header();
        let mode = header.mode().unwrap();

        // Handle whiteoute (".wh.<filename>") files, which mark
        // files from previous layers as deleted.
        if let Some(file_name) = path.file_name() {
            let file_name = file_name.to_str().unwrap();

            // This special marker tells that the entire contents of a directory got deleted.
            // Can't really handle it without knowledge about the prior layer, so we must do it
            // in post-processing, when we have all layers
            //
            // In practice we don't really have to do it because we don't show a unified view of the file system.
            if file_name == ".wh..wh..opq" {
                cleared_directories.insert(path.clone());
                continue;
            }

            if let Some(real_file_name) = file_name.strip_prefix(".wh.") {
                let path = path.with_file_name(real_file_name);
                file_system.add_file_with_state(
                    &path,
                    entry.size(),
                    mode,
                    LayerFsNodeState::Deleted,
                );
                continue;
            }
        }

        if entry.header().entry_type().is_file() {
            file_system.add_file(&path, entry.size(), mode);
        }
        if entry.header().entry_type().is_symlink() {
            file_system.add_symlink(&path, &header.link_name().unwrap().unwrap(), mode);
        }
        if entry.header().entry_type().is_dir() {
            file_system.add_dir_metadata(&path, mode)
        }

        file_system_summary.insert(path, mode);
    }

    LayerAnalysisResult {
        digest,
        file_system,
        file_system_summary,
        cleared_directories,
    }
}

pub async fn analyze(tar_path: &str, output: Option<&Path>) {
    let file = File::open(tar_path).unwrap();
    let mmap = unsafe { memmap2::Mmap::map(&file) }.unwrap();
    let cursor = std::io::Cursor::new(&mmap);
    let mut a = Archive::new(cursor);

    // Gather files in this tar archive and their spans.
    let start_time = Instant::now();
    let files: HashMap<String, Range<usize>> = a
        .entries()
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let pos = entry.raw_file_position() as usize;
            let size = entry.size() as usize;
            (path, (pos..(pos + size)))
        })
        .collect();

    let (image_config, layer_decsriptions) = if files.contains_key("oci-layout") {
        get_oci_archive_description(&files, &mmap)
    } else {
        get_docker_archive_description(&files, &mmap)
    };

    let layer_count = layer_decsriptions.len();

    // For each known layer, we create a future that analyzes it, giving each
    // a oneshot to send a summary to the next.
    // The summary is needed for each layer to know about files existing in previous layers,
    // so it can mark a file as "new" or "modified".
    let (summary_tx, mut summary_rx) = tokio::sync::oneshot::channel();
    summary_tx.send(FileSystemSummary::new()).unwrap();
    let mut summary_channels = vec![];
    for _ in 0..layer_count {
        let (summary_tx, new_summary_rx) = tokio::sync::oneshot::channel();
        summary_channels.push((summary_tx, summary_rx));
        summary_rx = new_summary_rx;
    }

    let (result_tx, mut result_rx) = tokio::sync::mpsc::channel(layer_count * 10);

    // Start TUI while we're analyzing.
    let final_task = match output {
        Some(output) => {
            let output = output.to_path_buf();
            tokio::spawn(async move {
                let mut layers: Vec<_> = (0..layer_count).map(|_| None).collect();
                for _ in 0..layer_count {
                    let (index, result) = result_rx.recv().await.unwrap();
                    layers[index] = Some(result);
                }
                let contents = serde_json::to_vec(&AnalysisResult {
                    image_config,
                    layers: layers.into_iter().map(Option::unwrap).collect(),
                })
                .unwrap();
                std::fs::write(output, contents).unwrap();
                anyhow::Result::<()>::Ok(())
            })
        }
        None => {
            tokio::spawn(async move { tui::run_tui_with_channel(&image_config, result_rx).await })
        }
    };

    layer_decsriptions
        .into_par_iter()
        .zip(summary_channels.into_par_iter())
        .enumerate()
        .map(
            |(index, ((digest, media_type, layer_range), (summary_tx, summary_rx)))| {
                let analysis_start = std::time::Instant::now();
                let mut analysis_result =
                    analyze_single_layer(digest, media_type, &mmap, layer_range);
                let analysis_duration = analysis_start.elapsed();
                let mut merged_fs = summary_rx.blocking_recv().unwrap();

                for (path, _mode) in analysis_result.file_system_summary.iter_mut() {
                    if merged_fs.contains_key(path) {
                        let file = analysis_result.file_system.goto_mut(&path);
                        if file.state == LayerFsNodeState::Created {
                            file.state = LayerFsNodeState::Modified;
                        }
                    }
                }
                merged_fs.extend(analysis_result.file_system_summary.drain());
                summary_tx.send(merged_fs).unwrap();

                result_tx.blocking_send((index, analysis_result)).unwrap();
            },
        )
        .collect_into_vec(&mut Vec::new());

    drop(mmap);
    final_task.await.unwrap().unwrap();
    let duration = start_time.elapsed();
    dbg!(duration);
}

pub async fn display_saved_analysis(path: &Path) {
    let AnalysisResult {
        image_config,
        layers,
    } = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    tui::run_tui(&image_config, layers).await.unwrap();
}

fn get_oci_archive_description(
    files: &HashMap<String, Range<usize>>,
    mmap: &memmap2::Mmap,
) -> (ImageConfiguration, Vec<(String, MediaType, Range<usize>)>) {
    let index_range = files
        .get("index.json")
        .expect("OCI images must have an `index.json` file");
    let index: ImageIndex = serde_json::from_slice(&mmap[index_range.clone()]).unwrap();

    // Yeah, I ain't going to find something more complex lol
    assert!(index.manifests().len() == 1);
    let manifest_path = layer_digest_to_blob_path(index.manifests()[0].digest());
    let manifest_range = files.get(&manifest_path).expect("Missing manifest blob");
    let manifest: ImageManifest = serde_json::from_slice(&mmap[manifest_range.clone()]).unwrap();

    let config_path = layer_digest_to_blob_path(manifest.config().digest());
    let config_range = files.get(&config_path).expect("Missing config blob");
    let config: ImageConfiguration = serde_json::from_slice(&mmap[config_range.clone()]).unwrap();

    let layers = manifest
        .layers()
        .par_iter()
        .filter_map(|layer| {
            let layer_path = layer_digest_to_blob_path(layer.digest());
            let layer_range = files.get(&layer_path)?;
            Some((
                layer.digest().clone(),
                layer.media_type().clone(),
                layer_range.clone(),
            ))
        })
        .collect::<Vec<_>>();

    (config, layers)
}

fn get_docker_archive_description(
    files: &HashMap<String, Range<usize>>,
    mmap: &memmap2::Mmap,
) -> (ImageConfiguration, Vec<(String, MediaType, Range<usize>)>) {
    let index_range = files
        .get("manifest.json")
        .expect("OCI images must have an `index.json` file");
    let manifests: Vec<YeOldManifest> = serde_json::from_slice(&mmap[index_range.clone()]).unwrap();
    assert!(manifests.len() == 1);

    let config_range = files
        .get(&manifests[0].config)
        .expect("Missing config blob");
    let config: ImageConfiguration = serde_json::from_slice(&mmap[config_range.clone()]).unwrap();

    let layers = manifests[0]
        .layers
        .par_iter()
        .map(|layer| {
            /*
            Digest can be obtained from whatever/json as:

                rootfs: RootFs {
                    typ: "layers",
                    diff_ids: [
                        "sha256:4693057ce2364720d39e57e85a5b8e0bd9ac3573716237736d6470ec5b7b7230",
                    ],
                },
            */
            let layer_range = files
                .get(&layer.to_string_lossy().to_string())
                .expect("Missing layer descriptor");
            (
                "<NOT_YET_IMPL>".to_string(),
                MediaType::ImageLayer,
                layer_range.clone(),
            )
        })
        .collect::<Vec<_>>();

    (config, layers)
}

fn analyze_single_layer(
    digest: String,
    media_type: MediaType,
    mmap: &memmap2::Mmap,
    layer_range: Range<usize>,
) -> LayerAnalysisResult {
    let layer = match media_type {
        MediaType::ImageLayer => analyze_tar_layer(digest, &mmap[layer_range.clone()]),
        MediaType::ImageLayerGzip => {
            analyze_tar_layer_auto_detect_gzip(digest, &mmap[layer_range.clone()])
        }
        MediaType::Other(e) if e == "application/vnd.docker.image.rootfs.diff.tar.gzip" => {
            analyze_tar_layer_auto_detect_gzip(digest, &mmap[layer_range.clone()])
        }
        MediaType::ImageLayerZstd => {
            analyze_tar_layer_auto_detect_zstd(digest, &mmap[layer_range.clone()])
        }
        f => todo!("{f:?}"),
    };

    layer
}
