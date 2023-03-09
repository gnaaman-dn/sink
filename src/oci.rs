use std::{collections::HashMap, path::PathBuf};

use serde::{Deserialize, Serialize};

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
pub struct Manifest {
    pub config: String,
    pub repo_tags: Option<Vec<String>>,
    pub layers: Vec<PathBuf>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Layer {
    pub id: String,
    pub created: String,
    pub os: String,
    pub container_config: ContainerConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct ContainerConfig {
    // "Hostname": "",
    pub hostname: String,
    pub user: String,
    pub attach_stdin: bool,
    pub attach_stdout: bool,
    pub attach_stderr: bool,
    pub tty: bool,
    pub open_stdin: bool,
    pub stdin_once: bool,
    pub env: Option<Vec<String>>,
    pub cmd: Option<Vec<String>>,
    pub image: String,
    // "Volumes": null,
    pub working_dir: String,
    pub entry_point: Option<Vec<String>>,
    // "OnBuild": null,
    pub labels: Option<HashMap<String, String>>,
}
