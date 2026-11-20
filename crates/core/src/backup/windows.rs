//! Backup on Windows (FORMAT-v2-windows.md).
//!
//! The walk never follows a reparse point: symbolic links and junctions are
//! stored as links, online-only cloud files are never opened (opening them
//! downloads them), and files are opened with
//! `FILE_FLAG_OPEN_REPARSE_POINT`, so a link swapped in while the backup
//! runs is not followed. Files held by another program are skipped and
//! counted. Nothing is ever written to the source.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use super::{BackupOptions, HOME_ROOT, Issue, IssueKind, Progress, Selection, lossy};
use crate::destination::Destination;
use crate::pack::BlobType;
use crate::repo::Repository;
use crate::rules::{CACHEDIR_SIGNATURE, Matcher, Verdict};
use crate::snapshot::{Origin, Root, Snapshot, Source, Stats};
use crate::tree::{Change, Entry, EntryKind, Meta, split_ns};
use crate::win::{FileInfo, current_sid, file_info, is_elevated, verbatim};
use crate::{Error, Result};

// File attributes (winnt.h).
const READONLY: u32 = 0x1;
const HIDDEN: u32 = 0x2;
const SYSTEM: u32 = 0x4;
const DIRECTORY: u32 = 0x10;
const ARCHIVE: u32 = 0x20;
const NOT_CONTENT_INDEXED: u32 = 0x2000;
const RECALL_ON_OPEN: u32 = 0x4_0000;
const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;

// Reparse tags (winnt.h).
const TAG_SYMLINK: u32 = 0xA000_000C;
const TAG_MOUNT_POINT: u32 = 0xA000_0003;
const TAG_DEDUP: u32 = 0x8000_0013;
/// `IO_REPARSE_TAG_CLOUD` and its sixteen variants `0x9000_X01A`.
fn is_cloud_tag(tag: u32) -> bool {
    tag & 0xFFFF_0FFF == 0x9000_001A
}

// Open flags.
const FILE_SHARE_ALL: u32 = 0x1 | 0x2 | 0x4;
const FILE_READ_ATTRIBUTES: u32 = 0x80;
const FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;

// Errors that say "not now" rather than "unreadable".
const ERROR_SHARING_VIOLATION: i32 = 32;
const ERROR_LOCK_VIOLATION: i32 = 33;
const ERROR_CLOUD_FILE_ACCESS_DENIED: i32 = 395;

/// Unix time in nanoseconds from Windows 100 ns units since 1601.
fn filetime_ns(ft: i64) -> i128 {
    (i128::from(ft) - 116_444_736_000_000_000) * 100
}

fn change_of(info: &FileInfo) -> Change {
    let (ctime, ctime_nanos) = split_ns(filetime_ns(info.change));
    Change { ctime, ctime_nanos, ino: info.file_id.to_string() }
}

fn win_attrs(attributes: u32) -> Option<Vec<String>> {
    // Sorted by name (FORMAT-v2-windows.md 4.2).
    let kept = [
        (ARCHIVE, "archive"),
        (HIDDEN, "hidden"),
        (NOT_CONTENT_INDEXED, "notIndexed"),
        (READONLY, "readonly"),
        (SYSTEM, "system"),
    ];
    let names: Vec<String> =
        kept.iter().filter(|(bit, _)| attributes & bit != 0).map(|(_, n)| (*n).to_owned()).collect();
    (!names.is_empty()).then_some(names)
}

fn meta_of(info: &FileInfo) -> Meta {
    let mut meta = Meta { win_attrs: win_attrs(info.attributes), ..Meta::default() };
    meta.set_time_ns(filetime_ns(info.last_write));
    let (btime, rest) = split_ns(filetime_ns(info.creation));
    meta.btime = Some(btime);
    meta.btime_nanos = (rest != 0).then_some(rest);
    meta
}

/// Opens an item for its metadata only: never follows a reparse point,
/// works on folders, and is not refused by a program holding the file.
fn open_attributes(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .access_mode(FILE_READ_ATTRIBUTES)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT)
        .open(path)
}

fn open_content(path: &Path) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_ALL)
        .custom_flags(FLAG_OPEN_REPARSE_POINT | FLAG_SEQUENTIAL_SCAN)
        .open(path)
}

/// A link target as Windows reports it, without the `\\?\` or `\??\`
/// prefix of the substitute name (FORMAT-v2-windows.md 4.3).
fn link_target(path: &Path) -> Option<Vec<u8>> {
    let target = std::fs::read_link(path).ok()?;
    let text = target.to_str()?.to_owned();
    let text = text.strip_prefix(r"\\?\").or_else(|| text.strip_prefix(r"\??\")).unwrap_or(&text).to_owned();
    Some(text.into_bytes())
}

/// What a failed open or read means for the counts.
enum Failure {
    Locked,
    CloudOnly,
    Unreadable,
}

fn failure(e: &std::io::Error) -> Failure {
    match e.raw_os_error() {
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => Failure::Locked,
        Some(ERROR_CLOUD_FILE_ACCESS_DENIED) => Failure::CloudOnly,
        _ => Failure::Unreadable,
    }
}

struct Walker<'r, 'o, D: Destination + 'static> {
    repo: &'r mut Repository<D>,
    matcher: Matcher,
    chunk_size: usize,
    cancel: Option<&'o AtomicBool>,
    progress: Progress,
    on_progress: &'o mut dyn FnMut(&Progress),
}

impl<D: Destination + 'static> Walker<'_, '_, D> {
    fn check_cancel(&self) -> Result<()> {
        match self.cancel {
            Some(flag) if flag.load(Ordering::Relaxed) => Err(Error::Aborted),
            _ => Ok(()),
        }
    }

    fn report(&mut self) {
        (self.on_progress)(&self.progress);
    }

    fn note(&mut self, rel: &[u8], kind: IssueKind) {
        match kind {
            IssueKind::Locked => self.progress.locked += 1,
            IssueKind::CloudOnly => self.progress.cloud_only += 1,
            IssueKind::BadName => self.progress.bad_names += 1,
        }
        self.progress.issues.push(Issue { path: lossy(rel), kind });
    }

    fn read_error(rel: &[u8], source: std::io::Error) -> Error {
        Error::Read { path: lossy(rel), source }
    }

    fn previous(&self, tree: Option<&str>) -> HashMap<Vec<u8>, Entry> {
        tree.and_then(|id| self.repo.load_tree(id).ok())
            .map(|entries| entries.into_iter().map(|e| (e.name.clone(), e)).collect())
            .unwrap_or_default()
    }

    fn has_cachedir_tag(dir: &Path) -> bool {
        let Ok(mut file) = open_content(&dir.join("CACHEDIR.TAG")) else { return false };
        let mut head = vec![0u8; CACHEDIR_SIGNATURE.len()];
        file.read_exact(&mut head).is_ok() && head == CACHEDIR_SIGNATURE
    }

    /// Stores one folder and returns its tree id. `required` folders (the
    /// user folder and chosen ones) fail the backup if unreadable.
    fn walk_dir(&mut self, dir: &Path, rel: &[u8], old_tree: Option<&str>, sel: Option<&Selection>) -> Result<String> {
        let old = self.previous(old_tree);
        let mut children: Vec<(Vec<u8>, std::ffi::OsString)> = Vec::new();
        for item in std::fs::read_dir(dir).map_err(|e| Self::read_error(rel, e))? {
            let item = item.map_err(|e| Self::read_error(rel, e))?;
            let os_name = item.file_name();
            match os_name.to_str() {
                Some(name) => children.push((name.as_bytes().to_vec(), os_name)),
                None => {
                    // Not valid UTF-16 (FORMAT-v2-windows.md 4.1): not stored.
                    let shown: Vec<u16> = os_name.encode_wide().collect();
                    let shown = String::from_utf16_lossy(&shown).into_bytes();
                    let path = if rel.is_empty() { shown } else { [rel, b"/", &shown].concat() };
                    self.note(&path, IssueKind::BadName);
                }
            }
        }
        children.sort();

        let mut entries = Vec::new();
        for (name, os_name) in children {
            self.check_cancel()?;
            let child_sel = match sel {
                None => None,
                Some(s) if s.whole => None,
                Some(s) => match s.children.get(&name) {
                    Some(child) => Some(child),
                    None => continue,
                },
            };
            let child_rel = if rel.is_empty() { name.clone() } else { [rel, b"/", &name].concat() };
            let path = dir.join(&os_name);
            let sibling_file = |file: &[u8]| {
                std::str::from_utf8(file)
                    .is_ok_and(|f| std::fs::symlink_metadata(dir.join(f)).is_ok_and(|m| m.is_file()))
            };
            if self.matcher.check_beside(&child_rel, sibling_file) == Verdict::LeaveOut {
                continue;
            }
            let required = child_sel.is_some();
            // The listing's attributes are enough to spot online-only items
            // without opening them.
            let listed = match std::fs::symlink_metadata(&path) {
                Ok(m) => m.file_attributes(),
                Err(e) if required => return Err(Self::read_error(&child_rel, e)),
                Err(_) => {
                    self.progress.skipped += 1;
                    continue;
                }
            };
            if listed & (RECALL_ON_DATA_ACCESS | RECALL_ON_OPEN) != 0 {
                self.note(&child_rel, IssueKind::CloudOnly);
                continue;
            }
            let info = match open_attributes(&path).and_then(|f| file_info(&f)) {
                Ok(info) => info,
                Err(e) if required => return Err(Self::read_error(&child_rel, e)),
                Err(_) => {
                    self.progress.skipped += 1;
                    continue;
                }
            };
            let before = old.get(&name);
            let is_dir = info.attributes & DIRECTORY != 0;
            let tag = info.reparse_tag;
            let entry = if tag == TAG_SYMLINK || tag == TAG_MOUNT_POINT {
                let Some(target) = link_target(&path) else {
                    self.progress.skipped += 1;
                    continue;
                };
                let link = match (tag, is_dir) {
                    (TAG_MOUNT_POINT, _) => "junction",
                    (_, true) => "dir",
                    (_, false) => "file",
                };
                self.progress.symlinks += 1;
                Entry { name, kind: EntryKind::Symlink { target, link: Some(link.into()) }, meta: meta_of(&info) }
            } else if tag != 0 && !is_cloud_tag(tag) && tag != TAG_DEDUP {
                // App execution aliases and other reparse points.
                self.progress.special += 1;
                continue;
            } else if is_dir {
                match self.store_dir(&path, &name, &child_rel, &info, before, child_sel)? {
                    Some(entry) => entry,
                    None => continue,
                }
            } else {
                match self.store_file(&path, &name, &child_rel, &info, before)? {
                    Some(entry) => entry,
                    None if required => {
                        return Err(Error::Read {
                            path: lossy(&child_rel),
                            source: std::io::Error::other("unreadable"),
                        });
                    }
                    None => continue,
                }
            };
            entries.push(entry);
            self.report();
        }
        self.repo.save_tree(&mut entries)
    }

    fn store_dir(
        &mut self,
        path: &Path,
        name: &[u8],
        rel: &[u8],
        info: &FileInfo,
        before: Option<&Entry>,
        sel: Option<&Selection>,
    ) -> Result<Option<Entry>> {
        if Self::has_cachedir_tag(path) {
            return Ok(None);
        }
        let old_subtree = match before.map(|e| &e.kind) {
            Some(EntryKind::Dir { subtree, mount: false }) => Some(subtree.as_str()),
            _ => None,
        };
        let subtree = match self.walk_dir(path, rel, old_subtree, sel) {
            Ok(id) => id,
            Err(Error::Read { .. }) if sel.is_none() => {
                self.progress.skipped += 1;
                return Ok(None);
            }
            Err(e) => return Err(e),
        };
        Ok(Some(Entry { name: name.to_vec(), kind: EntryKind::Dir { subtree, mount: false }, meta: meta_of(info) }))
    }

    /// Stores one file. `None` means it was not stored and has been
    /// counted (skipped, locked or online-only).
    fn store_file(
        &mut self,
        path: &Path,
        name: &[u8],
        rel: &[u8],
        info: &FileInfo,
        before: Option<&Entry>,
    ) -> Result<Option<Entry>> {
        let size = std::fs::symlink_metadata(path).map(|m| m.len()).unwrap_or(0);
        if let Some(Entry { kind: EntryKind::File { size: old_size, content }, meta: old_meta, .. }) = before
            && *old_size == size
            && old_meta.time_ns() == Some(filetime_ns(info.last_write))
            && old_meta.change.as_ref() == Some(&change_of(info))
            && content.iter().all(|id| self.repo.has(id))
        {
            let mut meta = meta_of(info);
            meta.change = Some(change_of(info));
            self.progress.files += 1;
            self.progress.bytes += size;
            let kind = EntryKind::File { size, content: content.clone() };
            return Ok(Some(Entry { name: name.to_vec(), kind, meta }));
        }

        self.progress.current = lossy(rel);
        self.progress.files_read += 1;
        self.report();
        let mut file = match open_content(path) {
            Ok(f) => f,
            Err(e) => return self.not_stored(rel, &e),
        };
        let mut stored = None;
        for attempt in 0..2 {
            let start = match file_info(&file) {
                Ok(i) => i,
                Err(e) => return self.not_stored(rel, &e),
            };
            if start.file_id != info.file_id || start.volume != info.volume {
                self.progress.skipped += 1;
                return Ok(None); // swapped since it was listed
            }
            let content = match self.read_content(&mut file, rel) {
                Ok(c) => c,
                // Never a partial file (FORMAT-v2-windows.md 3.3).
                Err(Error::Read { source, .. }) => return self.not_stored(rel, &source),
                Err(e) => return Err(e),
            };
            let end = file_info(&file).ok();
            let unchanged = end.is_some_and(|e| e.last_write == start.last_write && e.change == start.change);
            stored = Some((content, start));
            if unchanged {
                break;
            }
            if attempt == 1 {
                self.progress.changed += 1;
            }
        }
        let ((content, read), start) = stored.expect("at least one attempt");
        let mut meta = meta_of(&start);
        meta.change = Some(change_of(&start));
        self.progress.files += 1;
        self.progress.bytes += read;
        Ok(Some(Entry { name: name.to_vec(), kind: EntryKind::File { size: read, content }, meta }))
    }

    fn not_stored(&mut self, rel: &[u8], e: &std::io::Error) -> Result<Option<Entry>> {
        match failure(e) {
            Failure::Locked => self.note(rel, IssueKind::Locked),
            Failure::CloudOnly => self.note(rel, IssueKind::CloudOnly),
            Failure::Unreadable => self.progress.skipped += 1,
        }
        Ok(None)
    }

    fn read_content(&mut self, file: &mut File, rel: &[u8]) -> Result<(Vec<String>, u64)> {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(0)).map_err(|e| Self::read_error(rel, e))?;
        let mut content = Vec::new();
        let mut total = 0u64;
        let mut chunk = vec![0u8; self.chunk_size];
        loop {
            self.check_cancel()?;
            let mut filled = 0;
            while filled < chunk.len() {
                match file.read(&mut chunk[filled..]) {
                    Ok(0) => break,
                    Ok(n) => filled += n,
                    Err(e) if e.kind() == ErrorKind::Interrupted => {}
                    Err(e) => return Err(Self::read_error(rel, e)),
                }
            }
            if filled == 0 {
                break;
            }
            content.push(self.repo.save_blob(BlobType::Data, &chunk[..filled])?);
            total += filled as u64;
            let done = self.progress.bytes;
            self.progress.bytes += total;
            self.report();
            self.progress.bytes = done;
            if filled < chunk.len() {
                break;
            }
        }
        Ok((content, total))
    }
}

/// Backs up the user folder (or the chosen items inside it) and writes a
/// version 2 snapshot with `origin` (FORMAT-v2-windows.md 3).
pub fn backup<D: Destination + 'static>(
    repo: &mut Repository<D>,
    home: &Path,
    options: BackupOptions<'_>,
    on_progress: &mut dyn FnMut(&Progress),
) -> Result<Snapshot> {
    if is_elevated() {
        return Err(Error::Root);
    }
    if !repo.writable() {
        return Err(Error::ReadOnly);
    }
    if !home.is_absolute() || home.parent().is_none() {
        return Err(Error::OutsideHome(home.display().to_string()));
    }
    let selection = options.selection.as_deref().map(Selection::build).transpose()?;
    let root = verbatim(home);
    let root_info = open_attributes(&root)
        .and_then(|f| file_info(&f))
        .map_err(|e| Error::Read { path: home.display().to_string(), source: e })?;
    let matcher = Matcher::new(&options.exclusions);
    let left_out = matcher.rules();
    let parent_tree = options.parent.and_then(|p| {
        p.roots
            .iter()
            .find(|r| r.source.as_ref().is_some_and(|s| s.kind == "home" && s.path.is_empty()))
            .map(|r| r.tree.clone())
    });

    let mut walker = Walker {
        repo,
        matcher,
        chunk_size: options.chunk_size,
        cancel: options.cancel,
        progress: Progress::default(),
        on_progress,
    };
    let result = (|| {
        let sel = selection.as_ref().filter(|s| !s.whole);
        let tree = walker.walk_dir(&root, b"", parent_tree.as_deref(), sel)?;
        walker.repo.flush()?;
        let p = &walker.progress;
        let stats = Stats {
            files: p.files,
            bytes: p.bytes,
            skipped: p.skipped,
            changed: Some(p.changed),
            special: Some(p.special),
            symlinks: Some(p.symlinks),
            mounts: None,
            locked: Some(p.locked),
            cloud_only: Some(p.cloud_only),
            bad_names: Some(p.bad_names),
        };
        let origin = Origin {
            os: "windows".into(),
            path: home.display().to_string(),
            user: std::env::var("USERNAME").unwrap_or_default(),
            sid: current_sid().unwrap_or_default(),
        };
        walker.repo.save_snapshot(Snapshot {
            format: Some(2),
            id: String::new(),
            time: options.time.clone(),
            device: options.device.clone(),
            home: None,
            origin: Some(origin),
            roots: vec![Root {
                name: HOME_ROOT.into(),
                tree,
                source: Some(Source { kind: "home".into(), path: String::new() }),
                meta: Some(meta_of(&root_info)),
                left_out: Some(left_out),
            }],
            stats,
            parent: options.parent.map(|p| p.id.clone()),
        })
    })();
    if result.is_err() {
        walker.repo.abandon();
    }
    result
}
