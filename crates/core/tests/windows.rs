//! Backup and restore on Windows (FORMAT-v2-windows.md), in temporary
//! folders only. Runs on Windows; the test VM and CI run it.

#![cfg(windows)]

use std::fs::{File, FileTimes, OpenOptions};
use std::os::windows::fs::{FileTimesExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use xkyhold_core::backup::{BackupOptions, IssueKind, Progress, backup};
use xkyhold_core::crypto::Argon2Params;
use xkyhold_core::destination::MemoryDestination;
use xkyhold_core::pack::BlobType;
use xkyhold_core::repo::{Options, Repository};
use xkyhold_core::restore::{Conflict, RestoreOptions, restore};
use xkyhold_core::tree::{Entry, EntryKind, Meta};

const FAST: Argon2Params = Argon2Params { memory_kib: 1024, iterations: 1, parallelism: 1 };
const CHUNK: usize = 1000;

const READONLY: u32 = 0x1;
const HIDDEN: u32 = 0x2;
const SYSTEM: u32 = 0x4;
const REPARSE_POINT: u32 = 0x400;

fn noise(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x & 255) as u8
        })
        .collect()
}

fn new_repo() -> Repository<MemoryDestination> {
    let options = Options { pack_size: 4096, index_every: 2, ..Options::default() };
    Repository::create(MemoryDestination::default(), "pw", FAST, "2026-11-20T00:00:00Z".into(), options).unwrap().0
}

fn options<'a>(time: &str, parent: Option<&'a xkyhold_core::snapshot::Snapshot>) -> BackupOptions<'a> {
    let mut o = BackupOptions::new("TEST-PC".into(), time.into());
    o.parent = parent;
    o.chunk_size = CHUNK;
    o
}

fn at(secs: u64, hundreds_of_ns: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs) + Duration::from_nanos(hundreds_of_ns * 100)
}

fn set_times(path: &Path, modified: SystemTime, created: SystemTime) {
    let file = OpenOptions::new().write(true).custom_flags(0x0200_0000).open(path).unwrap();
    file.set_times(FileTimes::new().set_modified(modified).set_created(created)).unwrap();
}

fn attrib(args: &[&str], path: &Path) {
    let ok = Command::new("attrib").args(args).arg(path).status().unwrap().success();
    assert!(ok, "attrib {args:?}");
}

fn attributes(path: &Path) -> u32 {
    std::fs::symlink_metadata(path).unwrap().file_attributes()
}

fn junction(link: &Path, target: &Path) {
    let ok = Command::new("cmd").arg("/c").arg("mklink").arg("/J").arg(link).arg(target).output().unwrap();
    assert!(ok.status.success(), "mklink /J");
}

struct Fixture {
    _tmp: tempfile::TempDir,
    home: PathBuf,
    out: PathBuf,
}

fn fixture() -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let out = tmp.path().join("restored");
    std::fs::create_dir(&home).unwrap();
    std::fs::create_dir(&out).unwrap();
    Fixture { home, out, _tmp: tmp }
}

/// The test user folder. Returns the file held open by `locked`.
fn build_home(home: &Path) -> File {
    std::fs::create_dir_all(home.join("Documents/empty")).unwrap();
    std::fs::create_dir_all(home.join("AppData/Local/Temp")).unwrap();
    std::fs::write(home.join("Documents/big.bin"), noise(5_500, 1)).unwrap();
    std::fs::write(home.join("Documents/empty.txt"), b"").unwrap();
    std::fs::write(home.join("readonly.txt"), b"keep me").unwrap();
    std::fs::write(home.join("desktop.ini"), b"[.ShellClassInfo]").unwrap();
    std::fs::write(home.join("AppData/Local/Temp/scratch.tmp"), b"left out").unwrap();
    std::fs::write(home.join("locked.pst"), b"mailbox").unwrap();
    set_times(&home.join("Documents/big.bin"), at(1_600_000_000, 1_234_567), at(1_500_000_000, 7));
    set_times(&home.join("Documents/empty"), at(1_610_000_000, 5), at(1_400_000_000, 3));
    attrib(&["+r"], &home.join("readonly.txt"));
    attrib(&["+h", "+s"], &home.join("desktop.ini"));
    junction(&home.join("Docs link"), &home.join("Documents"));
    // Held without sharing, like Outlook holds a .pst.
    OpenOptions::new().read(true).write(true).share_mode(0).open(home.join("locked.pst")).unwrap()
}

#[test]
fn backup_then_restore_on_windows() {
    let f = fixture();
    let held = build_home(&f.home);
    let mut repo = new_repo();
    let mut last = Progress::default();
    let snap = backup(&mut repo, &f.home, options("2026-11-20T10:00:00Z", None), &mut |p| last = p.clone()).unwrap();
    drop(held);

    assert!(snap.home.is_none(), "Windows snapshots carry origin, not home");
    let origin = snap.origin.as_ref().unwrap();
    assert_eq!(origin.os, "windows");
    assert!(origin.sid.starts_with("S-1-"));
    assert_eq!(snap.stats.locked, Some(1));
    assert_eq!(snap.stats.symlinks, Some(1));
    assert!(last.issues.iter().any(|i| i.path == "locked.pst" && i.kind == IssueKind::Locked));
    let rules = snap.roots[0].left_out.as_ref().unwrap();
    assert!(rules.iter().any(|r| r.id.as_deref() == Some("cloud-only")));

    let entries = repo.load_tree(&snap.roots[0].tree).unwrap();
    let names: Vec<_> = entries.iter().map(|e| e.display_name()).collect();
    assert!(!names.contains(&"locked.pst".to_owned()), "a locked file is not stored");
    let link = entries.iter().find(|e| e.display_name() == "Docs link").unwrap();
    match &link.kind {
        EntryKind::Symlink { target, link } => {
            assert_eq!(link.as_deref(), Some("junction"));
            assert!(String::from_utf8_lossy(target).ends_with(r"\Documents"));
        }
        other => panic!("junction stored as {other:?}"),
    }
    let ini = entries.iter().find(|e| e.display_name() == "desktop.ini").unwrap();
    assert_eq!(ini.meta.win_attrs.as_deref(), Some(&["archive".to_owned(), "hidden".into(), "system".into()][..]));

    let report = restore(&repo, &entries, &f.out, &RestoreOptions::default(), &mut |_| {}).unwrap();
    assert!(report.renamed.is_empty());
    assert_eq!(report.symlinks, 1);

    assert_eq!(std::fs::read(f.out.join("Documents/big.bin")).unwrap(), noise(5_500, 1));
    assert_eq!(std::fs::read(f.out.join("Documents/empty.txt")).unwrap(), b"");
    assert!(f.out.join("Documents/empty").is_dir());
    assert!(!f.out.join("AppData/Local/Temp/scratch.tmp").exists());
    assert!(!f.out.join("locked.pst").exists());
    for p in ["Documents/big.bin", "Documents/empty"] {
        let (a, b) = (std::fs::metadata(f.home.join(p)).unwrap(), std::fs::metadata(f.out.join(p)).unwrap());
        assert_eq!(a.last_write_time(), b.last_write_time(), "{p}: modified");
        assert_eq!(a.creation_time(), b.creation_time(), "{p}: created");
    }
    assert_ne!(attributes(&f.out.join("readonly.txt")) & READONLY, 0);
    assert_eq!(attributes(&f.out.join("desktop.ini")) & (HIDDEN | SYSTEM), HIDDEN | SYSTEM);
    assert_ne!(attributes(&f.out.join("Docs link")) & REPARSE_POINT, 0);

    // Clean up the read-only flag so the temporary folder can be removed.
    attrib(&["-r"], &f.out.join("readonly.txt"));
    attrib(&["-r"], &f.home.join("readonly.txt"));
}

#[test]
fn an_unchanged_folder_reads_nothing_again() {
    let f = fixture();
    let held = build_home(&f.home);
    drop(held);
    let mut repo = new_repo();
    let first = backup(&mut repo, &f.home, options("2026-11-20T10:00:00Z", None), &mut |_| {}).unwrap();
    let mut last = Progress::default();
    let second =
        backup(&mut repo, &f.home, options("2026-11-20T11:00:00Z", Some(&first)), &mut |p| last = p.clone()).unwrap();
    assert_eq!(last.files_read, 0);
    assert_eq!(first.roots[0].tree, second.roots[0].tree);
    attrib(&["-r"], &f.home.join("readonly.txt"));
}

#[test]
fn names_from_linux_are_made_safe_and_listed() {
    let f = fixture();
    let mut repo = new_repo();
    let file = |repo: &mut Repository<MemoryDestination>, name: &str| {
        let content = vec![repo.save_blob(BlobType::Data, name.as_bytes()).unwrap()];
        Entry {
            name: name.as_bytes().to_vec(),
            kind: EntryKind::File { size: name.len() as u64, content },
            meta: Meta::default(),
        }
    };
    let entries: Vec<Entry> =
        ["CON", "a:b.txt", "Read.me", "read.ME", "ends."].iter().map(|n| file(&mut repo, n)).collect();
    repo.flush().unwrap();
    let options = RestoreOptions { conflict: Conflict::KeepBoth, cancel: None };
    let report = restore(&repo, &entries, &f.out, &options, &mut |_| {}).unwrap();
    let renamed: Vec<(&str, &str)> = report.renamed.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    assert_eq!(renamed, [("CON", "CON_"), ("a:b.txt", "a_b.txt"), ("read.ME", "read (2).ME"), ("ends.", "ends_")]);
    assert_eq!(std::fs::read(f.out.join("CON_")).unwrap(), b"CON");
    assert_eq!(std::fs::read(f.out.join("read (2).ME")).unwrap(), b"read.ME");
    assert_eq!(std::fs::read(f.out.join("Read.me")).unwrap(), b"Read.me");
}

/// Against the real user folder of a Windows test machine, read only: an
/// online-only OneDrive file is counted and never downloaded, and app
/// execution aliases are counted as special (FORMAT-v2-windows.md 9). Needs
/// `OneDrive/XkyHold-wd probe/cloud.bin` made online-only beforehand.
#[test]
#[ignore = "needs a real OneDrive folder with an online-only test file"]
fn real_online_only_files_and_app_aliases() {
    const RECALL_ON_DATA_ACCESS: u32 = 0x40_0000;
    let home = PathBuf::from(std::env::var("USERPROFILE").unwrap());
    let cloud = home.join("OneDrive/XkyHold-wd probe/cloud.bin");
    assert_ne!(attributes(&cloud) & RECALL_ON_DATA_ACCESS, 0, "make cloud.bin online-only first");
    let mut repo = new_repo();
    let mut o = options("2026-11-20T12:00:00Z", None);
    o.selection = Some(vec![b"OneDrive/XkyHold-wd probe".to_vec(), b"AppData/Local/Microsoft/WindowsApps".to_vec()]);
    let mut last = Progress::default();
    let snap = backup(&mut repo, &home, o, &mut |p| last = p.clone()).unwrap();
    assert_eq!(snap.stats.cloud_only, Some(1));
    assert!(snap.stats.special.unwrap() >= 1, "app execution aliases");
    assert!(last.issues.iter().any(|i| i.kind == IssueKind::CloudOnly && i.path.ends_with("cloud.bin")));
    assert_ne!(attributes(&cloud) & RECALL_ON_DATA_ACCESS, 0, "still online-only: nothing was downloaded");
}

#[test]
fn paths_longer_than_260_characters_round_trip() {
    let f = fixture();
    let deep: PathBuf = (0..8).map(|i| format!("folder-with-a-long-name-number-{i:02}-xxxxxxxxxx")).collect();
    let dir = f.home.join(&deep);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("deep file.txt"), b"far down").unwrap();
    assert!(dir.join("deep file.txt").as_os_str().len() > 300);
    let mut repo = new_repo();
    let snap = backup(&mut repo, &f.home, options("2026-11-20T12:00:00Z", None), &mut |_| {}).unwrap();
    assert_eq!(snap.stats.skipped, 0);
    let entries = repo.load_tree(&snap.roots[0].tree).unwrap();
    restore(&repo, &entries, &f.out, &RestoreOptions::default(), &mut |_| {}).unwrap();
    assert_eq!(std::fs::read(f.out.join(&deep).join("deep file.txt")).unwrap(), b"far down");
}
