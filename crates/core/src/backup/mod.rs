//! Backup of the home folder (FORMAT.md 10.1, FORMAT-v2.md 4 and 5,
//! FORMAT-v2-windows.md). The walk is per platform; what is shared lives
//! here and in the repository code.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::AtomicBool;

use crate::crypto::CHUNK_SIZE;
use crate::rules::Exclusions;
use crate::snapshot::Snapshot;
use crate::tree::valid_name;
use crate::{Error, Result};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::{backup, mount_points};

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::backup;

/// The root name XkyHold-lx gives the home folder in a snapshot.
pub const HOME_ROOT: &str = "home";

/// Why an item was not stored, for the list the app shows after a backup
/// (FORMAT-v2-windows.md 3.3, 4.1). The snapshot keeps only the counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IssueKind {
    /// Held by another program.
    Locked,
    /// An online-only cloud file, not downloaded.
    CloudOnly,
    /// A name that is not valid UTF-16.
    BadName,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Issue {
    /// Relative to the home folder, `/` between names.
    pub path: String,
    pub kind: IssueKind,
}

#[derive(Debug, Clone, Default)]
pub struct Progress {
    pub files: u64,
    pub bytes: u64,
    pub skipped: u64,
    pub changed: u64,
    pub special: u64,
    pub symlinks: u64,
    pub mounts: u64,
    /// Files held by another program (Windows).
    pub locked: u64,
    /// Online-only cloud files, never read (Windows).
    pub cloud_only: u64,
    /// Names that are not valid UTF-16 (Windows).
    pub bad_names: u64,
    /// The items behind `locked`, `cloud_only` and `bad_names`.
    pub issues: Vec<Issue>,
    /// Files whose content was read (new or changed).
    pub files_read: u64,
    /// Path being read, relative to the home folder.
    pub current: String,
}

pub struct BackupOptions<'a> {
    pub device: String,
    /// Time of the snapshot, ISO 8601.
    pub time: String,
    /// The previous snapshot; unchanged files are taken from it unread.
    pub parent: Option<&'a Snapshot>,
    pub exclusions: Exclusions,
    /// Paths inside the home folder to back up; `None` is the whole folder.
    pub selection: Option<Vec<Vec<u8>>>,
    pub chunk_size: usize,
    /// Absolute paths of mount points; `None` reads `/proc/self/mountinfo`.
    /// Not used on Windows.
    pub mount_points: Option<HashSet<Vec<u8>>>,
    pub cancel: Option<&'a AtomicBool>,
}

impl BackupOptions<'_> {
    pub fn new(device: String, time: String) -> Self {
        Self {
            device,
            time,
            parent: None,
            exclusions: Exclusions::default(),
            selection: None,
            chunk_size: CHUNK_SIZE as usize,
            mount_points: None,
            cancel: None,
        }
    }
}

/// The chosen items, as a tree of names. A `whole` node takes everything
/// below it.
#[derive(Default, Debug)]
pub(crate) struct Selection {
    pub(crate) whole: bool,
    pub(crate) children: BTreeMap<Vec<u8>, Selection>,
}

impl Selection {
    pub(crate) fn build(paths: &[Vec<u8>]) -> Result<Self> {
        let mut root = Selection::default();
        for path in paths {
            if path.is_empty() {
                root.whole = true;
                continue;
            }
            let mut node = &mut root;
            for name in path.split(|&b| b == b'/') {
                if !valid_name(name) {
                    return Err(Error::OutsideHome(String::from_utf8_lossy(path).into_owned()));
                }
                node = node.children.entry(name.to_vec()).or_default();
            }
            node.whole = true;
        }
        Ok(root)
    }
}

pub(crate) fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}
