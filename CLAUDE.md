# XkyHold engine

Backup engine shared by XkyHold-lx (Linux) and XkyHold-wd (Windows); the
apps depend on these crates by git revision. The repository format lives
in the XkyHold repository (`docs/FORMAT.md`, `docs/FORMAT-v2.md`,
`docs/FORMAT-v2-windows.md`); change the spec first, then the code. Plans
and state logs live in the apps' `docs/PLAN.md` (Portuguese).

## Hard rules

- Never regenerate `golden` fixtures (`crates/core/tests/fixtures/`). A
  failing golden test means the change is wrong.
- What is backed up is the user's home folder only (`$HOME`,
  `%USERPROFILE%`): never follow links, junctions or mount points while
  backing up; never need root or elevation.
- Encryption happens on the user's computer; destinations only see
  ciphertext. "Delete" in Drive is always "move to trash"; in a local
  folder it moves into the repository's `trash/`.
- Tests use temporary folders or the in-memory destination, never a real
  home folder or the real Drive.
- Platform code is behind `cfg(unix)` / `cfg(windows)`; everything else is
  shared. Tests stay green on Linux and on Windows.

## Development

`cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace`. Toolchain pinned in `rust-toolchain.toml` and
`mise.toml`. `scripts/cross-ts.sh <path to the xkyhold repo>` runs the
round trip with the TypeScript engine.

## Conventions

- Code, comments, commit messages, docs: English.
- Commits: a title and bullet points. No local machine paths, personal
  email addresses or employer names in versioned files.
- Keep dependencies few and small.
