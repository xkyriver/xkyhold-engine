//! `golden-v2-windows-repo.json` (FORMAT-v2-windows.md 9): a small
//! repository written once on Windows by XkyHold-wd and frozen. Every
//! implementation reads it; Windows and Linux restore it.
//!
//! The generator runs once, by hand, on a Windows test machine, with the
//! user folder at a neutral path and a neutral user name:
//!
//! ```text
//! set XKYHOLD_GOLDEN_HOME=C:\Golden\ana
//! set USERNAME=ana
//! <test binary> --ignored generate
//! ```

use std::collections::BTreeMap;

use serde_json::Value;
use xkyhold_core::bytes::from_base64;
use xkyhold_core::crypto::Credential;
use xkyhold_core::destination::{Destination, Dir, MemoryDestination};
use xkyhold_core::repo::{Options, Repository};
use xkyhold_core::tree::EntryKind;
use zeroize::Zeroizing;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/golden-v2-windows-repo.json");

fn load() -> Value {
    serde_json::from_str(&std::fs::read_to_string(FIXTURE).expect("golden-v2-windows-repo.json")).unwrap()
}

fn open(golden: &Value, credential: Credential) -> Repository<MemoryDestination> {
    let dest = MemoryDestination::default();
    for (key, value) in golden["objects"].as_object().unwrap() {
        let (dir, name) = key.split_once('/').unwrap();
        dest.put(Dir::parse(dir).unwrap(), name, &from_base64(value.as_str().unwrap()).unwrap()).unwrap();
    }
    Repository::open(dest, &credential, Options::default()).unwrap()
}

fn expected(golden: &Value) -> BTreeMap<String, Value> {
    golden["expected"].as_array().unwrap().iter().map(|v| (v["path"].as_str().unwrap().to_owned(), v.clone())).collect()
}

/// Readable on every system: the snapshot, the Windows fields of the
/// entries and the counts, with the password and the recovery key.
#[test]
fn reads_golden_v2_windows() {
    let golden = load();
    for credential in [
        Credential::Password(Zeroizing::new(golden["password"].as_str().unwrap().into())),
        Credential::RecoveryKey(Zeroizing::new(golden["recoveryKey"].as_str().unwrap().into())),
    ] {
        let repo = open(&golden, credential);
        let snaps = repo.list_snapshots().unwrap();
        assert_eq!(snaps.len(), 1);
        let snap = &snaps[0];
        assert_eq!((snap.id.as_str(), snap.version()), (golden["snapshotId"].as_str().unwrap(), 2));
        assert!(snap.home.is_none());
        let origin = snap.origin.as_ref().unwrap();
        assert_eq!(
            (origin.os.as_str(), origin.path.as_str(), origin.user.as_str()),
            ("windows", r"C:\Golden\ana", "ana")
        );
        assert_eq!((snap.stats.locked, snap.stats.bad_names, snap.stats.symlinks), (Some(1), Some(1), Some(4)));
        let ids: Vec<_> = snap.roots[0].left_out.as_ref().unwrap().iter().filter_map(|r| r.id.clone()).collect();
        for id in ["temp", "registry-hives", "app-state", "cachedir-tag", "cloud-only", "node-modules"] {
            assert!(ids.iter().any(|i| i == id), "{id}");
        }

        let entries = repo.load_tree(&snap.roots[0].tree).unwrap();
        let get = |name: &str| entries.iter().find(|e| e.display_name() == name).unwrap_or_else(|| panic!("{name}"));
        assert_eq!(get("readonly.txt").meta.win_attrs.as_deref(), Some(&["archive".to_owned(), "readonly".into()][..]));
        assert_eq!(
            get("desktop.ini").meta.win_attrs.as_deref(),
            Some(&["archive".to_owned(), "hidden".into(), "system".into()][..])
        );
        assert!(get("Folder").meta.btime.is_some());
        assert_ne!(get("Folder").meta.btime, get("Folder").meta.mtime);
        for (name, kind) in
            [("file-link", "file"), ("dir-link", "dir"), ("Docs junction", "junction"), ("dangling", "file")]
        {
            match &get(name).kind {
                EntryKind::Symlink { link, .. } => assert_eq!(link.as_deref(), Some(kind), "{name}"),
                other => panic!("{name}: {other:?}"),
            }
        }
        for gone in ["locked.pst", "Private"] {
            assert!(entries.iter().all(|e| e.display_name() != gone), "{gone}");
        }
    }
}

/// On Linux: content and modification times come back; Windows links are
/// written with their target as stored.
#[cfg(unix)]
#[test]
fn restores_golden_v2_windows_on_linux() {
    use std::os::unix::fs::MetadataExt;
    use xkyhold_core::bytes::sha256_hex;
    use xkyhold_core::restore::{RestoreOptions, restore};

    let golden = load();
    let repo = open(&golden, Credential::Password(Zeroizing::new(golden["password"].as_str().unwrap().into())));
    let snap = &repo.list_snapshots().unwrap()[0];
    let entries = repo.load_tree(&snap.roots[0].tree).unwrap();
    let out = tempfile::tempdir().unwrap();
    let report = restore(&repo, &entries, out.path(), &RestoreOptions::default(), &mut |_| {}).unwrap();
    assert_eq!(report.symlinks, 4);
    for (path, want) in expected(&golden) {
        let at = out.path().join(&path);
        match want["type"].as_str().unwrap() {
            "file" => {
                assert_eq!(sha256_hex(&std::fs::read(&at).unwrap()), want["sha256"].as_str().unwrap(), "{path}");
                let md = std::fs::symlink_metadata(&at).unwrap();
                let ns = i128::from(md.mtime()) * 1_000_000_000 + i128::from(md.mtime_nsec());
                let ticks = want["mtime"].as_i64().unwrap();
                assert_eq!(ns, (i128::from(ticks) - 116_444_736_000_000_000) * 100, "{path}: modified");
            }
            "symlink" => {
                let target = std::fs::read_link(&at).unwrap();
                assert_eq!(target.to_string_lossy(), want["target"].as_str().unwrap(), "{path}");
            }
            _ => assert!(at.is_dir(), "{path}"),
        }
    }
}

/// On Windows: everything as it was in the source, attributes and
/// creation times included.
#[cfg(windows)]
#[test]
fn restores_golden_v2_windows_on_windows() {
    use xkyhold_core::restore::{RestoreOptions, restore};

    let golden = load();
    let repo = open(&golden, Credential::Password(Zeroizing::new(golden["password"].as_str().unwrap().into())));
    let snap = &repo.list_snapshots().unwrap()[0];
    let entries = repo.load_tree(&snap.roots[0].tree).unwrap();
    let out = tempfile::tempdir().unwrap();
    let report = restore(&repo, &entries, out.path(), &RestoreOptions::default(), &mut |_| {}).unwrap();
    assert_eq!(report.symlinks as usize + report.links_refused.len(), 4);
    let got = windows::describe(out.path());
    let want = expected(&golden);
    assert_eq!(got.keys().collect::<Vec<_>>(), want.keys().collect::<Vec<_>>());
    for (path, want) in want {
        let mut have = got[&path].clone();
        for field in ["mtime", "btime"] {
            if want[field].is_null() {
                have[field] = Value::Null;
            }
        }
        // A junction's target is written absolute: compare its last part.
        if want["link"] == "junction" {
            let tail = |v: &Value| v["target"].as_str().unwrap().rsplit('\\').next().unwrap().to_owned();
            assert_eq!(tail(&have), tail(&want), "{path}");
            have["target"] = want["target"].clone();
        }
        if report.links_refused.iter().any(|(p, _)| *p == path) {
            continue;
        }
        assert_eq!(have, want, "{path}");
    }
    windows::clear_readonly(out.path());
}

#[cfg(windows)]
mod windows {
    use std::collections::BTreeMap;
    use std::os::windows::fs::MetadataExt;
    use std::path::Path;

    use serde_json::{Value, json};
    use xkyhold_core::bytes::sha256_hex;

    const READONLY: u32 = 0x1;
    const HIDDEN: u32 = 0x2;
    const SYSTEM: u32 = 0x4;
    const DIRECTORY: u32 = 0x10;
    const REPARSE: u32 = 0x400;

    /// What a restore must reproduce: content, times in 100 ns ticks since
    /// 1601, the attributes the format keeps, link kinds and targets.
    pub fn describe(root: &Path) -> BTreeMap<String, Value> {
        fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Value>) {
            let mut items: Vec<_> = std::fs::read_dir(dir).unwrap().map(|i| i.unwrap().path()).collect();
            items.sort();
            for path in items {
                let rel = path.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                let md = std::fs::symlink_metadata(&path).unwrap();
                let attrs = md.file_attributes();
                let mut kept = Vec::new();
                for (bit, name) in [(HIDDEN, "hidden"), (READONLY, "readonly"), (SYSTEM, "system")] {
                    if attrs & bit != 0 {
                        kept.push(name);
                    }
                }
                let mut v = json!({
                    "path": rel,
                    "mtime": md.last_write_time() as i64,
                    "btime": md.creation_time() as i64,
                    "attrs": kept,
                });
                if attrs & REPARSE != 0 {
                    v["type"] = json!("symlink");
                    let target = std::fs::read_link(&path).unwrap().to_string_lossy().into_owned();
                    let target = target.strip_prefix(r"\\?\").unwrap_or(&target).to_owned();
                    let junction = std::process::Command::new("fsutil")
                        .args(["reparsepoint", "query"])
                        .arg(&path)
                        .output()
                        .map(|o| String::from_utf8_lossy(&o.stdout).contains("0xa0000003"))
                        .unwrap_or(false);
                    v["link"] = json!(if junction {
                        "junction"
                    } else if attrs & DIRECTORY != 0 {
                        "dir"
                    } else {
                        "file"
                    });
                    v["target"] = json!(target);
                } else if md.is_dir() {
                    walk(root, &path, out);
                    v["type"] = json!("dir");
                } else {
                    let data = std::fs::read(&path).unwrap();
                    v["type"] = json!("file");
                    v["size"] = json!(data.len());
                    v["sha256"] = json!(sha256_hex(&data));
                }
                out.insert(rel, v);
            }
        }
        let mut out = BTreeMap::new();
        walk(root, root, &mut out);
        out
    }

    /// Read-only items would stop the temporary folder from being removed.
    pub fn clear_readonly(root: &Path) {
        let _ = std::process::Command::new("attrib").arg("-r").arg(root.join("*")).args(["/s", "/d"]).status();
    }
}

/// Writes the frozen fixture. Never run again once it exists.
#[cfg(windows)]
#[test]
#[ignore = "writes the frozen fixture; run once by hand on Windows"]
fn generate() {
    use std::ffi::OsString;
    use std::fs::{FileTimes, OpenOptions};
    use std::os::windows::ffi::OsStringExt;
    use std::os::windows::fs::{FileTimesExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use serde_json::json;
    use xkyhold_core::backup::{BackupOptions, backup};
    use xkyhold_core::bytes::to_base64;
    use xkyhold_core::crypto::Argon2Params;
    use xkyhold_core::rules::Exclusions;

    const PASSWORD: &str = "correct horse battery staple";
    const CHUNK: usize = 1024;

    assert!(!Path::new(FIXTURE).exists(), "golden-v2-windows-repo.json exists and must never be regenerated");
    let home = PathBuf::from(std::env::var("XKYHOLD_GOLDEN_HOME").expect("XKYHOLD_GOLDEN_HOME"));
    assert_eq!(home.to_str(), Some(r"C:\Golden\ana"), "neutral path, as the fixture records it");
    assert_eq!(std::env::var("USERNAME").as_deref(), Ok("ana"), "neutral user name");
    assert!(!home.exists(), "start from nothing");

    let noise = |len: usize, seed: u32| -> Vec<u8> {
        let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                (x & 255) as u8
            })
            .collect()
    };
    let mk = |p: &str| std::fs::create_dir_all(home.join(p)).unwrap();
    let w = |p: &str, data: &[u8]| std::fs::write(home.join(p), data).unwrap();
    let at = |secs: i64, hundreds: u64| -> SystemTime {
        let base = if secs >= 0 {
            UNIX_EPOCH + Duration::from_secs(secs as u64)
        } else {
            UNIX_EPOCH - Duration::from_secs(secs.unsigned_abs())
        };
        base + Duration::from_nanos(hundreds * 100)
    };
    let set = |p: &str, modified: SystemTime, created: SystemTime| {
        let f = OpenOptions::new().write(true).custom_flags(0x0200_0000 | 0x0020_0000).open(home.join(p)).unwrap();
        f.set_times(FileTimes::new().set_modified(modified).set_accessed(modified).set_created(created)).unwrap();
    };
    let run =
        |cmd: &str, args: &[&str]| assert!(Command::new(cmd).args(args).status().unwrap().success(), "{cmd} {args:?}");

    for d in ["Documents", "Empty", "Folder", "Private", "Downloads", "code/node_modules/x", "AppData/Local/Temp"] {
        mk(d);
    }
    w("plain.txt", b"hello world");
    w("empty.txt", b"");
    w("readonly.txt", b"do not change me");
    w("desktop.ini", b"[.ShellClassInfo]\r\n");
    w("Documents/big.bin", &noise(3000, 3));
    w("Documents/old.txt", b"from the sixties");
    w("Relat\u{f3}rio de a\u{e7}\u{e3}o.txt", b"non-ASCII name");
    w("locked.pst", b"held by another program");
    w("Private/diary.txt", b"left out by path");
    w("Downloads/arch.iso", b"left out by pattern");
    w("code/node_modules/x/index.js", b"left out by preset");
    w("AppData/Local/Temp/t.tmp", b"left out by default");
    // A name that is not valid UTF-16: 'x' and a lone high surrogate.
    std::fs::write(home.join(OsString::from_wide(&[0x78, 0xD800])), b"bad name").unwrap();
    std::os::windows::fs::symlink_file("plain.txt", home.join("file-link")).unwrap();
    std::os::windows::fs::symlink_dir("Documents", home.join("dir-link")).unwrap();
    std::os::windows::fs::symlink_file(r"does\not\exist", home.join("dangling")).unwrap();
    run(
        "cmd",
        &[
            "/c",
            "mklink",
            "/J",
            &home.join("Docs junction").to_string_lossy(),
            &home.join("Documents").to_string_lossy(),
        ],
    );

    for (i, p) in [
        "plain.txt",
        "empty.txt",
        "readonly.txt",
        "desktop.ini",
        "Documents/big.bin",
        "Relat\u{f3}rio de a\u{e7}\u{e3}o.txt",
        "file-link",
        "dir-link",
        "dangling",
        "Docs junction",
    ]
    .iter()
    .enumerate()
    {
        let i = i as i64;
        set(p, at(1_794_400_000 + i * 60, 1_234_567 + i as u64 * 11), at(1_790_000_000 + i * 60, 7_654_321));
    }
    set("Documents/old.txt", at(-86_400 * 365, 9_999_999), at(-86_400 * 366, 1));
    for p in ["Documents", "Empty", "Folder"] {
        set(p, at(1_794_000_000, 5), at(1_700_000_000, 3));
    }
    run("attrib", &["+r", &home.join("readonly.txt").to_string_lossy()]);
    run("attrib", &["+h", "+s", &home.join("desktop.ini").to_string_lossy()]);
    let held = OpenOptions::new().read(true).write(true).share_mode(0).open(home.join("locked.pst")).unwrap();

    let dest = MemoryDestination::default();
    let fast = Argon2Params { memory_kib: 1024, iterations: 2, parallelism: 1 };
    let options = Options { pack_size: 4096, index_every: 2, ..Options::default() };
    let (mut repo, recovery) =
        Repository::create(dest, PASSWORD, fast, "2026-11-20T12:00:00.000Z".into(), options).unwrap();
    let mut o = BackupOptions::new("golden".into(), "2026-11-20T12:00:00.000Z".into());
    o.chunk_size = CHUNK;
    o.exclusions = Exclusions {
        presets: vec!["node-modules".into()],
        paths: vec![b"Private".to_vec()],
        patterns: vec!["**/*.iso".into()],
        cross_mounts: vec![],
        repository: None,
    };
    let snap = backup(&mut repo, &home, o, &mut |_| {}).unwrap();
    drop(held);
    assert_eq!((snap.stats.locked, snap.stats.bad_names), (Some(1), Some(1)));

    let mut expected = windows::describe(&home);
    for gone in [
        "locked.pst",
        "Private",
        "Private/diary.txt",
        "Downloads/arch.iso",
        "code/node_modules",
        "code/node_modules/x",
        "code/node_modules/x/index.js",
        "AppData/Local/Temp",
        "AppData/Local/Temp/t.tmp",
    ] {
        expected.remove(gone).unwrap_or_else(|| panic!("{gone}"));
    }
    expected.retain(|k, _| !k.contains('\u{FFFD}'));
    // Folders whose contents were left out changed in the source when those
    // contents were made; their stored times are what is restored.
    for p in ["code", "Downloads", "AppData", "AppData/Local"] {
        let v = expected.get_mut(p).unwrap();
        v["mtime"] = Value::Null;
        v["btime"] = Value::Null;
    }

    let objects: BTreeMap<String, String> = repo
        .dest
        .objects
        .lock()
        .unwrap()
        .iter()
        .map(|((dir, name), data)| (format!("{}/{name}", dir.as_str()), to_base64(data)))
        .collect();
    let fixture = json!({
        "note": "Format v2 Windows fixture (FORMAT-v2-windows.md section 9). Written once by XkyHold-wd on 2026-11-20; never regenerate. Times are Windows ticks (100 ns since 1601); an expected time of null means 'not compared' (a folder whose left-out contents changed it in the source). attrs lists the hidden, readonly and system attributes. The chunk size used is in chunkSize.",
        "password": PASSWORD,
        "recoveryKey": *recovery,
        "chunkSize": CHUNK,
        "snapshotId": snap.id,
        "expected": expected.values().collect::<Vec<_>>(),
        "objects": objects,
    });
    std::fs::write(FIXTURE, serde_json::to_string_pretty(&fixture).unwrap() + "\n").unwrap();
    let _ = Command::new("attrib").arg("-r").arg(home.join("readonly.txt")).status();
}
