# XkyHold engine

The backup engine shared by the XkyHold desktop apps: XkyHold-lx (Linux)
and XkyHold-wd (Windows). No user interface and no app logic: encryption,
packs, index, trees, snapshots, backup, restore, prune, locks, check, the
local-folder and Google Drive destinations, and the system keyring.

It implements the XkyHold repository format, specified in the XkyHold
repository: `docs/FORMAT.md` (version 1), `docs/FORMAT-v2.md` (version 2)
and `docs/FORMAT-v2-windows.md` (how Windows writes version 2).

## Crates

| Crate | What |
|---|---|
| `crates/core` | `xkyhold-core`: the engine |
| `crates/dest-local` | `xkyhold-dest-local`: repository in a local folder |
| `crates/dest-drive` | `xkyhold-dest-drive`: repository in Google Drive |
| `crates/secrets` | `xkyhold-secrets`: repository keys and the Google refresh token in the system keyring |

The apps depend on these crates by git revision.

## Origin

Extracted from the XkyHold-lx repository with its history (version 1.0.2).

## License

AGPL-3.0-only.
