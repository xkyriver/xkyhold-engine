//! Restore (FORMAT-v2.md 6, FORMAT-v2-windows.md 5). Writing to disk is
//! per platform; options, the report and lookups are shared.

use std::sync::atomic::AtomicBool;

use crate::Result;
use crate::destination::Destination;
use crate::repo::Repository;
use crate::tree::{Entry, EntryKind};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::restore;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::restore;

/// What to do when an item already exists in the target folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conflict {
    Skip,
    Replace,
    /// Restore next to it, as "name (restored)".
    KeepBoth,
}

pub struct RestoreOptions<'a> {
    pub conflict: Conflict,
    pub cancel: Option<&'a AtomicBool>,
}

impl Default for RestoreOptions<'_> {
    fn default() -> Self {
        Self { conflict: Conflict::KeepBoth, cancel: None }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub files: u64,
    pub bytes: u64,
    pub folders: u64,
    pub symlinks: u64,
    /// Mount points recreated as empty folders.
    pub mounts: u64,
    /// Entries with a name that cannot be created safely.
    pub bad_names: u64,
    /// Entries of a type this version does not know.
    pub unknown: u64,
    /// Items left alone because they already existed.
    pub existing: u64,
    /// Extended attributes the target could not take.
    pub xattr_failures: u64,
    /// Items restored under another name because Windows cannot create
    /// theirs (FORMAT-v2-windows.md 5): (name in the backup, name used),
    /// both as paths below the target.
    pub renamed: Vec<(String, String)>,
    /// Symbolic links Windows refused to create (no Developer Mode):
    /// (path below the target, stored target).
    pub links_refused: Vec<(String, String)>,
    pub current: String,
}

/// "notes (restored).txt", "notes (restored 2).txt": the suffix goes before
/// a file's extension so the copy still opens with the same app. Folders
/// and names without an extension (".bashrc") get it at the end.
pub(crate) fn keep_both_name(name: &[u8], n: u32, folder: bool) -> Vec<u8> {
    let suffix = if n == 1 { " (restored)".to_owned() } else { format!(" (restored {n})") };
    let dot = name.iter().rposition(|&b| b == b'.').filter(|&i| !folder && i > 0 && i + 1 < name.len());
    match dot {
        Some(i) => [&name[..i], suffix.as_bytes(), &name[i..]].concat(),
        None => [name, suffix.as_bytes()].concat(),
    }
}

/// Finds an entry by its path of names below a tree.
pub fn find<D: Destination + 'static>(repo: &Repository<D>, tree: &str, path: &[&[u8]]) -> Result<Option<Entry>> {
    let Some((first, rest)) = path.split_first() else { return Ok(None) };
    let Some(entry) = repo.load_tree(tree)?.into_iter().find(|e| e.name == *first) else { return Ok(None) };
    match (&entry.kind, rest.is_empty()) {
        (_, true) => Ok(Some(entry)),
        (EntryKind::Dir { subtree, .. }, false) => find(repo, subtree, rest),
        _ => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::keep_both_name;

    #[test]
    fn keep_both_keeps_the_extension() {
        assert_eq!(keep_both_name(b"notes.txt", 1, false), b"notes (restored).txt");
        assert_eq!(keep_both_name(b"notes.txt", 2, false), b"notes (restored 2).txt");
        assert_eq!(keep_both_name(b".bashrc", 1, false), b".bashrc (restored)");
        assert_eq!(keep_both_name(b"Makefile", 1, false), b"Makefile (restored)");
        assert_eq!(keep_both_name(b"odd.", 1, false), b"odd. (restored)");
        assert_eq!(keep_both_name(b"my.folder", 1, true), b"my.folder (restored)");
    }
}
