//! Restore on Windows (FORMAT-v2-windows.md 5).
//!
//! Files are written under a temporary name and renamed into place when
//! complete. A restore never goes through a reparse point: an existing
//! junction or link where a folder is to be merged is left alone, and
//! files are created with `FILE_FLAG_OPEN_REPARSE_POINT`. Owner and
//! permissions are never set (items inherit them from the target folder).
//! Names Windows cannot create are restored under a safe name and listed;
//! symbolic links Windows refuses are listed with their targets.

use std::collections::HashSet;
use std::fs::{File, FileTimes, OpenOptions};
use std::io::Write;
use std::os::windows::fs::{FileTimesExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::{Conflict, RestoreOptions, RestoreReport, keep_both_name};
use crate::crypto::random_id;
use crate::destination::Destination;
use crate::pack::BlobType;
use crate::repo::Repository;
use crate::tree::{Entry, EntryKind, Meta, valid_name};
use crate::win::{is_elevated, make_junction, set_attributes, verbatim};
use crate::{Error, Result};

const FILE_THREADS: usize = 6;
const CHUNK_WINDOW: usize = 4;

const READONLY: u32 = 0x1;
const HIDDEN: u32 = 0x2;
const SYSTEM: u32 = 0x4;
const ARCHIVE: u32 = 0x20;
const NORMAL: u32 = 0x80;
const REPARSE_POINT: u32 = 0x400;
const NOT_CONTENT_INDEXED: u32 = 0x2000;

const FILE_WRITE_ATTRIBUTES: u32 = 0x100;
const FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
const FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const ERROR_PRIVILEGE_NOT_HELD: i32 = 1314;

fn system_time(ns: i128) -> Option<SystemTime> {
    let abs = Duration::from_nanos(u64::try_from(ns.unsigned_abs()).ok()?);
    if ns >= 0 { UNIX_EPOCH.checked_add(abs) } else { UNIX_EPOCH.checked_sub(abs) }
}

fn btime_ns(meta: &Meta) -> Option<i128> {
    meta.btime.map(|ms| i128::from(ms) * 1_000_000 + i128::from(meta.btime_nanos.unwrap_or(0)))
}

fn attribute_bits(names: &[String]) -> u32 {
    let bits = names
        .iter()
        .map(|n| match n.as_str() {
            "readonly" => READONLY,
            "hidden" => HIDDEN,
            "system" => SYSTEM,
            "archive" => ARCHIVE,
            "notIndexed" => NOT_CONTENT_INDEXED,
            _ => 0,
        })
        .fold(0, |a, b| a | b);
    if bits == 0 { NORMAL } else { bits }
}

/// Times first, then attributes, read-only included, last of all
/// (FORMAT-v2-windows.md 5). Works on files and folders, never through a
/// reparse point.
fn apply_meta(path: &Path, meta: &Meta) -> Result<()> {
    let mut times = FileTimes::new();
    let mut any = false;
    if let Some(t) = meta.time_ns().and_then(system_time) {
        times = times.set_modified(t).set_accessed(t);
        any = true;
    }
    if let Some(t) = btime_ns(meta).and_then(system_time) {
        times = times.set_created(t);
        any = true;
    }
    if any {
        let handle = OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FLAG_BACKUP_SEMANTICS | FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        handle.set_times(times)?;
    }
    if let Some(names) = &meta.win_attrs {
        set_attributes(path, attribute_bits(names))?;
    }
    Ok(())
}

const RESERVED: &[&str] = &[
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9", "COM¹", "COM²",
    "COM³", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9", "LPT¹", "LPT²", "LPT³",
];

/// A name Windows can create (FORMAT-v2-windows.md 5): forbidden
/// characters become `_`, a reserved device name gets `_` appended, a
/// trailing space or dot becomes `_`, and a long name is cut to 255 UTF-16
/// units. A name that is already fine comes back unchanged.
pub(crate) fn safe_name(name: &str) -> String {
    let mut out: String = name.chars().map(|c| if c < ' ' || r#"<>:"\|?*"#.contains(c) { '_' } else { c }).collect();
    if out.ends_with(' ') || out.ends_with('.') {
        out.pop();
        out.push('_');
    }
    let stem_end = out.find('.').unwrap_or(out.len());
    let stem = out[..stem_end].trim_end_matches(' ');
    if RESERVED.iter().any(|r| r.to_uppercase() == stem.to_uppercase()) {
        out.insert(stem_end, '_');
    }
    let mut units = 0;
    out.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= 255
        })
        .collect()
}

/// "notes (2).txt", "notes (3).txt": for names that differ only in case.
fn case_copy_name(name: &str, n: u32) -> String {
    let dot = name.rfind('.').filter(|&i| i > 0 && i + 1 < name.len());
    match dot {
        Some(i) => format!("{} ({n}){}", &name[..i], &name[i..]),
        None => format!("{name} ({n})"),
    }
}

fn join(path: &str, name: &str) -> String {
    if path.is_empty() { name.to_owned() } else { format!("{path}/{name}") }
}

/// Writes one file under a temporary name and renames it into place.
#[allow(clippy::too_many_arguments)]
fn write_file<D: Destination + 'static>(
    repo: &Repository<D>,
    dir: &Path,
    name: &str,
    entry: &Entry,
    content: &[String],
    replace: bool,
    cancelled: &dyn Fn() -> Result<()>,
    sent: &dyn Fn(u64),
) -> Result<()> {
    let temp = dir.join(format!(".xkyhold-{}.tmp", random_id()));
    let written = (|| {
        let mut file: File =
            OpenOptions::new().write(true).create_new(true).custom_flags(FLAG_OPEN_REPARSE_POINT).open(&temp)?;
        for window in content.chunks(CHUNK_WINDOW) {
            cancelled()?;
            let chunks: Vec<Result<Vec<u8>>> = std::thread::scope(|scope| {
                let jobs: Vec<_> =
                    window.iter().map(|id| scope.spawn(move || repo.load_blob(BlobType::Data, id))).collect();
                jobs.into_iter().map(|j| j.join().unwrap_or(Err(Error::Bug("download thread failed")))).collect()
            });
            for chunk in chunks {
                let chunk = chunk?;
                file.write_all(&chunk)?;
                sent(chunk.len() as u64);
            }
        }
        file.sync_all()?;
        drop(file);
        let place = dir.join(name);
        if replace
            && let Ok(m) = std::fs::symlink_metadata(&place)
            && m.file_attributes() & READONLY != 0
        {
            // A read-only file refuses to be replaced.
            set_attributes(&place, m.file_attributes() & !READONLY)?;
        }
        std::fs::rename(&temp, &place)?;
        apply_meta(&place, &entry.meta)
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    written
}

/// A symbolic link to create once everything else is in place.
struct PendingLink {
    dir: PathBuf,
    name: String,
    path: String,
    target: String,
    link: Option<String>,
    meta: Meta,
}

struct Restorer<'r, 'o, D: Destination + 'static> {
    repo: &'r Repository<D>,
    options: &'o RestoreOptions<'o>,
    report: RestoreReport,
    on_progress: &'o mut dyn FnMut(&RestoreReport),
    links: Vec<PendingLink>,
}

impl<D: Destination + 'static> Restorer<'_, '_, D> {
    fn check_cancel(&self) -> Result<()> {
        match self.options.cancel {
            Some(flag) if flag.load(Ordering::Relaxed) => Err(Error::Aborted),
            _ => Ok(()),
        }
    }

    /// Decides the name to create. `None`: leave the existing item alone.
    /// The bool says the folder already exists and is merged into.
    fn place(&mut self, dir: &Path, name: &str, want_dir: bool) -> Result<Option<(String, bool)>> {
        let existing = match std::fs::symlink_metadata(dir.join(name)) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Some((name.to_owned(), false))),
            Err(e) => return Err(e.into()),
        };
        let is_link = existing.file_attributes() & REPARSE_POINT != 0;
        // Folders merge, but never through a junction or link.
        if want_dir && existing.is_dir() && !is_link {
            return Ok(Some((name.to_owned(), true)));
        }
        match self.options.conflict {
            Conflict::Skip => {
                self.report.existing += 1;
                Ok(None)
            }
            // Never remove a folder or a link to put something in its place.
            Conflict::Replace if existing.is_dir() || is_link || want_dir => {
                self.report.existing += 1;
                Ok(None)
            }
            Conflict::Replace => Ok(Some((name.to_owned(), false))),
            Conflict::KeepBoth => {
                for n in 1.. {
                    let candidate = keep_both_name(name.as_bytes(), n, want_dir);
                    let candidate = String::from_utf8(candidate).expect("built from a str");
                    match std::fs::symlink_metadata(dir.join(&candidate)) {
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Some((candidate, false))),
                        Err(e) => return Err(e.into()),
                        Ok(_) => {}
                    }
                }
                unreachable!()
            }
        }
    }

    /// The names this folder's entries get on Windows: safe, and unique
    /// without regard to case. Records every change in the report.
    fn windows_names(&mut self, entries: &[Entry], path: &str) -> Vec<Option<String>> {
        let mut used: HashSet<String> = HashSet::new();
        entries
            .iter()
            .map(|entry| {
                if !valid_name(&entry.name) {
                    self.report.bad_names += 1;
                    return None;
                }
                let shown = entry.display_name();
                let mut name = safe_name(&shown);
                if used.contains(&name.to_lowercase()) {
                    let base = name.clone();
                    name = (2..).map(|n| case_copy_name(&base, n)).find(|c| !used.contains(&c.to_lowercase()))?;
                }
                used.insert(name.to_lowercase());
                if name != shown {
                    self.report.renamed.push((join(path, &shown), join(path, &name)));
                }
                Some(name)
            })
            .collect()
    }

    fn restore_files(&mut self, dir: &Path, files: Vec<(&Entry, &[String], String, String)>) -> Result<()> {
        let mut jobs = Vec::new();
        for (entry, content, name, path) in files {
            if let Some((placed, _)) = self.place(dir, &name, false)? {
                let replace = placed == name;
                jobs.push((placed, entry, content, path, replace));
            }
        }
        enum Event {
            Bytes(u64),
            Done(String, Result<()>),
        }
        let (repo, user_cancel) = (self.repo, self.options.cancel);
        let next = AtomicUsize::new(0);
        let stop = AtomicBool::new(false);
        let (tx, rx) = mpsc::channel::<Event>();
        let mut failure: Option<Error> = None;
        std::thread::scope(|scope| {
            for _ in 0..FILE_THREADS.min(jobs.len()) {
                let (tx, jobs, next, stop) = (tx.clone(), &jobs, &next, &stop);
                scope.spawn(move || {
                    loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        if i >= jobs.len() || stop.load(Ordering::SeqCst) {
                            break;
                        }
                        let (name, entry, content, path, replace) = &jobs[i];
                        let cancelled = || {
                            if stop.load(Ordering::SeqCst) || user_cancel.is_some_and(|c| c.load(Ordering::Relaxed)) {
                                Err(Error::Aborted)
                            } else {
                                Ok(())
                            }
                        };
                        let result = write_file(repo, dir, name, entry, content, *replace, &cancelled, &|n| {
                            let _ = tx.send(Event::Bytes(n));
                        });
                        let _ = tx.send(Event::Done(path.clone(), result));
                    }
                });
            }
            drop(tx);
            for event in rx {
                match event {
                    Event::Bytes(n) => self.report.bytes += n,
                    Event::Done(path, Ok(())) => {
                        self.report.files += 1;
                        self.report.current = path;
                    }
                    Event::Done(_, Err(err)) => {
                        stop.store(true, Ordering::SeqCst);
                        if failure.is_none() || matches!(failure, Some(Error::Aborted)) {
                            failure = Some(err);
                        }
                    }
                }
                (self.on_progress)(&self.report);
            }
        });
        match failure {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn restore_dir(&mut self, dir: &Path, entry: &Entry, name: &str, subtree: &str, path: &str) -> Result<()> {
        let Some((placed, exists)) = self.place(dir, name, true)? else { return Ok(()) };
        let folder = dir.join(&placed);
        if !exists {
            std::fs::create_dir(&folder)?;
        }
        let children = self.repo.load_tree(subtree)?;
        self.restore_entries(&folder, &children, path)?;
        // Last, so writing the contents does not change the folder's time.
        if !exists {
            apply_meta(&folder, &entry.meta)?;
        }
        self.report.folders += 1;
        Ok(())
    }

    fn restore_entries(&mut self, dir: &Path, entries: &[Entry], path: &str) -> Result<()> {
        let names = self.windows_names(entries, path);
        let files: Vec<(&Entry, &[String], String, String)> = entries
            .iter()
            .zip(&names)
            .filter_map(|(e, name)| match (&e.kind, name) {
                (EntryKind::File { content, .. }, Some(name)) => {
                    Some((e, content.as_slice(), name.clone(), join(path, name)))
                }
                _ => None,
            })
            .collect();
        self.restore_files(dir, files)?;
        for (entry, name) in entries.iter().zip(names) {
            self.check_cancel()?;
            let Some(name) = name else { continue };
            let child = join(path, &name);
            match &entry.kind {
                EntryKind::File { .. } => continue,
                EntryKind::Dir { subtree, mount } => {
                    if *mount {
                        self.report.mounts += 1;
                    }
                    self.restore_dir(dir, entry, &name, subtree, &child)?;
                }
                EntryKind::Symlink { target, link } => self.links.push(PendingLink {
                    dir: dir.to_path_buf(),
                    name,
                    path: child,
                    target: String::from_utf8_lossy(target).into_owned(),
                    link: link.clone(),
                    meta: entry.meta.clone(),
                }),
                EntryKind::Unknown(_) => self.report.unknown += 1,
            }
            (self.on_progress)(&self.report);
        }
        Ok(())
    }

    /// Creates the links last (FORMAT-v2-windows.md 5), so that a link made
    /// on Linux can point to a folder restored just now.
    fn restore_links(&mut self) -> Result<()> {
        for link in std::mem::take(&mut self.links) {
            self.check_cancel()?;
            let Some((name, _)) = self.place(&link.dir, &link.name, false)? else { continue };
            let at = link.dir.join(&name);
            let points_to_dir = || {
                let target = Path::new(&link.target);
                let resolved = if target.is_absolute() { target.to_path_buf() } else { link.dir.join(target) };
                resolved.is_dir()
            };
            let made = match link.link.as_deref() {
                Some("junction") => std::fs::create_dir(&at).and_then(|()| {
                    make_junction(&at, &link.target).inspect_err(|_| {
                        let _ = std::fs::remove_dir(&at);
                    })
                }),
                Some("dir") => std::os::windows::fs::symlink_dir(&link.target, &at),
                Some(_) => std::os::windows::fs::symlink_file(&link.target, &at),
                None if points_to_dir() => std::os::windows::fs::symlink_dir(&link.target, &at),
                None => std::os::windows::fs::symlink_file(&link.target, &at),
            };
            match made {
                Ok(()) => {
                    let _ = apply_meta(&at, &link.meta);
                    self.report.symlinks += 1;
                }
                // No Developer Mode: the user is told (decision D3).
                Err(e) if e.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD) => {
                    self.report.links_refused.push((link.path, link.target));
                }
                Err(e) => return Err(e.into()),
            }
            (self.on_progress)(&self.report);
        }
        Ok(())
    }
}

/// Restores `entries` (a folder's listing, or part of it) into `target`,
/// which must be an existing folder.
pub fn restore<D: Destination + 'static>(
    repo: &Repository<D>,
    entries: &[Entry],
    target: &Path,
    options: &RestoreOptions<'_>,
    on_progress: &mut dyn FnMut(&RestoreReport),
) -> Result<RestoreReport> {
    if is_elevated() {
        return Err(Error::Root);
    }
    if !std::fs::metadata(target)?.is_dir() {
        return Err(Error::Io(std::io::Error::new(std::io::ErrorKind::NotADirectory, "not a folder")));
    }
    // `\\?\` so that every path below works past 260 characters, also in
    // the Windows calls the standard library does not wrap.
    let target = verbatim(&std::path::absolute(target)?);
    let mut restorer = Restorer { repo, options, report: RestoreReport::default(), on_progress, links: Vec::new() };
    restorer.restore_entries(&target, entries, "")?;
    restorer.restore_links()?;
    Ok(restorer.report)
}

#[cfg(test)]
mod tests {
    use super::{case_copy_name, safe_name};

    #[test]
    fn names_windows_cannot_create() {
        assert_eq!(safe_name("notes.txt"), "notes.txt");
        assert_eq!(safe_name("a:b?.txt"), "a_b_.txt");
        assert_eq!(safe_name("CON"), "CON_");
        assert_eq!(safe_name("nul.txt"), "nul_.txt");
        assert_eq!(safe_name("com1.tar.gz"), "com1_.tar.gz");
        assert_eq!(safe_name("ends."), "ends_");
        assert_eq!(safe_name("ends "), "ends_");
        assert_eq!(safe_name("x".repeat(300).as_str()).len(), 255);
        assert_eq!(case_copy_name("Notes.txt", 2), "Notes (2).txt");
        assert_eq!(case_copy_name("README", 3), "README (3)");
    }
}
