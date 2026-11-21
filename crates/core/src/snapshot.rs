//! Snapshots of format versions 1 and 2 (FORMAT.md section 9,
//! FORMAT-v2.md section 5).

use serde::{Deserialize, Serialize};

use crate::tree::Meta;

pub const V1_AAD_PREFIX: &str = "xkyhold/v1/snapshot/";
pub const V2_AAD_PREFIX: &str = "xkyhold/v2/snapshot/";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Home {
    pub path: String,
    pub user: String,
    pub uid: u32,
    pub gid: u32,
}

/// Where a Windows backup came from (FORMAT-v2-windows.md 3.1). Windows
/// snapshots carry this instead of `home`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Origin {
    /// `"windows"`.
    pub os: String,
    /// The user folder as Windows writes it, with `\`.
    pub path: String,
    pub user: String,
    pub sid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub kind: String,
    /// Relative to `home.path`; "" is the home folder itself.
    pub path: String,
}

/// One exclusion rule in force for a root (FORMAT-v2.md 5.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub patterns: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_bytes: Option<String>,
}

/// An item the user chose to save (FORMAT-v2-chosen.md 2): a path
/// relative to the root's source, or its bytes when not valid UTF-8.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Chosen {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_bytes: Option<String>,
}

impl Chosen {
    pub fn new(path: &[u8]) -> Self {
        match std::str::from_utf8(path) {
            Ok(text) => Chosen { path: Some(text.to_owned()), path_bytes: None },
            Err(_) => Chosen { path: None, path_bytes: Some(crate::bytes::to_base64(path)) },
        }
    }

    /// The path's bytes; `None` when the item is malformed.
    pub fn bytes(&self) -> Option<Vec<u8>> {
        match (&self.path, &self.path_bytes) {
            (Some(text), _) => Some(text.as_bytes().to_vec()),
            (None, Some(b64)) => crate::bytes::from_base64(b64).ok(),
            (None, None) => None,
        }
    }
}

/// What a root records of the user's choice: nothing when the whole source
/// folder was saved (FORMAT-v2-chosen.md 2).
pub fn chosen_of(selection: Option<&[Vec<u8>]>) -> Option<Vec<Chosen>> {
    let paths = selection?;
    if paths.is_empty() || paths.iter().any(|p| p.is_empty()) {
        return None;
    }
    Some(paths.iter().map(|p| Chosen::new(p)).collect())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Root {
    pub name: String,
    pub tree: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<Source>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Meta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub left_out: Option<Vec<Rule>>,
    /// The items the user chose, when not the whole folder
    /// (FORMAT-v2-chosen.md).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen: Option<Vec<Chosen>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct Stats {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub changed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub special: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub symlinks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<u64>,
    /// Files held by another program (FORMAT-v2-windows.md 3.3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub locked: Option<u64>,
    /// Online-only cloud files, never read (FORMAT-v2-windows.md 3.3).
    #[serde(rename = "cloudOnly", skip_serializing_if = "Option::is_none")]
    pub cloud_only: Option<u64>,
    /// Names that are not valid UTF-16 (FORMAT-v2-windows.md 4.1).
    #[serde(rename = "badNames", skip_serializing_if = "Option::is_none")]
    pub bad_names: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// 2 for version 2 snapshots; absent in version 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub format: Option<u32>,
    pub id: String,
    pub time: String,
    pub device: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home: Option<Home>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
    pub roots: Vec<Root>,
    pub stats: Stats,
    pub parent: Option<String>,
}

impl Snapshot {
    pub fn version(&self) -> u32 {
        self.format.unwrap_or(1)
    }
}

#[cfg(test)]
mod chosen_tests {
    use super::*;

    #[test]
    fn chosen_items_as_json() {
        let items = chosen_of(Some(&[b"Documents/Photos".to_vec(), b"bad\xff".to_vec()])).unwrap();
        let json = serde_json::to_string(&items).unwrap();
        assert_eq!(json, r#"[{"path":"Documents/Photos"},{"pathBytes":"YmFk/w=="}]"#);
        let back: Vec<Chosen> = serde_json::from_str(&json).unwrap();
        assert_eq!(back[1].bytes().unwrap(), b"bad\xff");
        // The whole folder, or nothing chosen, records nothing.
        assert!(chosen_of(None).is_none());
        assert!(chosen_of(Some(&[])).is_none());
        assert!(chosen_of(Some(&[Vec::new()])).is_none());
        // A root written before the field reads as before.
        let root: Root =
            serde_json::from_str(r#"{"name":"home","tree":"ab","source":{"kind":"home","path":""}}"#).unwrap();
        assert!(root.chosen.is_none());
        assert!(!serde_json::to_string(&root).unwrap().contains("chosen"));
    }
}
