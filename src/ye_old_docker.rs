use std::{collections::HashMap, path::PathBuf};

use super::layer_digest_to_blob_path;
use serde::{Deserialize, Serialize};

/*
[
    {
    "Config": "blobs/sha256/75e5df5e8a806ebec1f8369351ffb9ce16830faaee122e05ea74d6fd0077e170",
    "RepoTags": [
      "pr-registry.dev.drivenets.net/wb_dev_v18_1:18.1.0.222_dev.dev_v18_1"
    ],
    "Layers": [
      "blobs/sha256/d19f32bd9e4106d487f1a703fc2f09c8edadd92db4405d477978e8e466ab290d",
      "blobs/sha256/47f12d8fb5800dd85f38f310e3da9a0cda13ef017f837ea5b5aec12e024c2e94",
      "blobs/sha256/36c52aa7d9f0c6c71af49b6bdfc6dffea1ed8d7a4e98172f005a7c5360b9b298",
      "blobs/sha256/342c621b1e30e8bfaa83977a7299e55cbdd7d83080524d0d87f55b426f13416c"
    ],
    "LayerSources": {
      "sha256:342c621b1e30e8bfaa83977a7299e55cbdd7d83080524d0d87f55b426f13416c": {
        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "size": 855750687,
        "digest": "sha256:342c621b1e30e8bfaa83977a7299e55cbdd7d83080524d0d87f55b426f13416c"
      },
      "sha256:36c52aa7d9f0c6c71af49b6bdfc6dffea1ed8d7a4e98172f005a7c5360b9b298": {
        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "size": 15940692,
        "digest": "sha256:36c52aa7d9f0c6c71af49b6bdfc6dffea1ed8d7a4e98172f005a7c5360b9b298"
      },
      "sha256:47f12d8fb5800dd85f38f310e3da9a0cda13ef017f837ea5b5aec12e024c2e94": {
        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "size": 340542098,
        "digest": "sha256:47f12d8fb5800dd85f38f310e3da9a0cda13ef017f837ea5b5aec12e024c2e94"
      },
      "sha256:d19f32bd9e4106d487f1a703fc2f09c8edadd92db4405d477978e8e466ab290d": {
        "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
        "size": 30426136,
        "digest": "sha256:d19f32bd9e4106d487f1a703fc2f09c8edadd92db4405d477978e8e466ab290d"
      }
    }
  }
] */
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct YeOldManifest {
    pub config: String,
    pub repo_tags: Option<Vec<String>>,
    pub layers: Vec<PathBuf>,
    pub layer_sources: HashMap<String, oci_spec::image::Descriptor>,
}

impl YeOldManifest {
    pub fn from_oci_manifest(
        ye_new_manifest: &oci_spec::image::ImageManifest,
        img_ref_name: String,
    ) -> Self {
        YeOldManifest {
            config: layer_digest_to_blob_path(ye_new_manifest.config().digest()),
            repo_tags: Some(vec![img_ref_name]),
            layers: ye_new_manifest
                .layers()
                .iter()
                .map(|layer| layer_digest_to_blob_path(layer.digest()))
                .map(PathBuf::from)
                .collect(),
            layer_sources: ye_new_manifest
                .layers()
                .iter()
                .map(|layer| (layer.digest().clone(), layer.clone()))
                .collect(),
        }
    }
}
