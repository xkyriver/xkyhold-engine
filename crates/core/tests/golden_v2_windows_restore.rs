//! The frozen Linux fixture `golden-v2-repo.json`, restored on Windows
//! (FORMAT-v2-windows.md 5): every file comes back with its content and
//! modification time, names Windows cannot take are renamed and listed,
//! and every Linux link is either created or listed as refused.

#![cfg(windows)]

use std::collections::BTreeMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde_json::Value;
use xkyhold_core::bytes::{from_base64, sha256_hex};
use xkyhold_core::crypto::Credential;
use xkyhold_core::destination::{Destination, Dir, MemoryDestination};
use xkyhold_core::repo::{Options, Repository};
use xkyhold_core::restore::{RestoreOptions, restore};
use zeroize::Zeroizing;

const FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/golden-v2-repo.json");

fn open(golden: &Value) -> Repository<MemoryDestination> {
    let dest = MemoryDestination::default();
    for (key, value) in golden["objects"].as_object().unwrap() {
        let (dir, name) = key.split_once('/').unwrap();
        dest.put(Dir::parse(dir).unwrap(), name, &from_base64(value.as_str().unwrap()).unwrap()).unwrap();
    }
    let password = Credential::Password(Zeroizing::new(golden["password"].as_str().unwrap().into()));
    Repository::open(dest, &password, Options::default()).unwrap()
}

/// Every regular file below `root`: path with `/` → (sha256, mtime in ns).
fn files(root: &Path) -> BTreeMap<String, (String, i128)> {
    fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, (String, i128)>) {
        for item in std::fs::read_dir(dir).unwrap() {
            let item = item.unwrap();
            let meta = std::fs::symlink_metadata(item.path()).unwrap();
            let rel = item.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
            if meta.is_dir() && !meta.file_type().is_symlink() {
                walk(root, &item.path(), out);
            } else if meta.is_file() {
                let modified = meta.modified().unwrap();
                let ns = match modified.duration_since(UNIX_EPOCH) {
                    Ok(d) => d.as_nanos() as i128,
                    Err(e) => -(e.duration().as_nanos() as i128),
                };
                out.insert(rel, (sha256_hex(&std::fs::read(item.path()).unwrap()), ns));
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

#[test]
fn the_linux_fixture_restores_on_windows() {
    let golden: Value = serde_json::from_str(&std::fs::read_to_string(FIXTURE).unwrap()).unwrap();
    let repo = open(&golden);
    let snap = &repo.list_snapshots().unwrap()[0];
    let entries = repo.load_tree(&snap.roots[0].tree).unwrap();
    let out = tempfile::tempdir().unwrap();
    let report = restore(&repo, &entries, out.path(), &RestoreOptions::default(), &mut |_| {}).unwrap();

    let expected = golden["expected"].as_array().unwrap();
    let want_files: Vec<&Value> = expected.iter().filter(|e| e["type"] == "file").collect();
    let want_links = expected.iter().filter(|e| e["type"] == "symlink").count();
    let got = files(out.path());

    assert_eq!(got.len(), want_files.len(), "{:?}", got.keys().collect::<Vec<_>>());
    // Every file's content comes back, whatever name it got.
    let mut want_shas: Vec<&str> = want_files.iter().map(|w| w["sha256"].as_str().unwrap()).collect();
    let mut got_shas: Vec<&str> = got.values().map(|(sha, _)| sha.as_str()).collect();
    want_shas.sort_unstable();
    got_shas.sort_unstable();
    assert_eq!(got_shas, want_shas);
    // Names that are valid UTF-8 keep their path, unless the restore
    // listed them as renamed, and keep their modification time.
    for want in want_files {
        let path = from_base64(want["path"].as_str().unwrap()).unwrap();
        let Ok(shown) = String::from_utf8(path) else { continue };
        let restored_as =
            report.renamed.iter().find(|(from, _)| *from == shown).map_or(shown.clone(), |(_, to)| to.clone());
        let (have_sha, have_ns) = got.get(&restored_as).unwrap_or_else(|| panic!("missing {restored_as}"));
        assert_eq!(have_sha, want["sha256"].as_str().unwrap(), "{shown}");
        if let Some([sec, nsec]) = want["mtime"].as_array().map(|a| [a[0].as_i64().unwrap(), a[1].as_i64().unwrap()]) {
            let ns = i128::from(sec) * 1_000_000_000 + i128::from(nsec);
            // Windows keeps 100 ns units; before 1970 the standard library rounds
            // towards 1970 rather than down, so allow one unit either way.
            assert!((*have_ns - ns).abs() < 100, "{shown}: modified {have_ns} vs {ns}");
        }
    }
    assert!(report.renamed.iter().any(|(from, _)| from.contains('\u{FFFD}')), "{:?}", report.renamed);
    assert_eq!(report.symlinks as usize + report.links_refused.len(), want_links);
}
