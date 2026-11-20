#!/usr/bin/env bash
# The TypeScript engine of XkyHold reads golden-v2-windows-repo.json.
# Usage: scripts/cross-ts-windows.sh <path to an XkyHold checkout with node_modules>
# The XkyHold checkout is not touched: a throwaway worktree is used.
set -euo pipefail
xkyhold=$(cd "${1:?path to an XkyHold checkout}" && pwd)
here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'git -C "$xkyhold" worktree remove --force "$work/xkyhold" >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
export GOLDEN_WINDOWS="$here/crates/core/tests/fixtures/golden-v2-windows-repo.json"

git -C "$xkyhold" worktree add --detach -q "$work/xkyhold" HEAD
ln -s "$xkyhold/node_modules" "$work/xkyhold/node_modules"
cp "$here/scripts/cross-ts/golden-windows.test.ts" "$work/xkyhold/src/engine/"
(cd "$work/xkyhold" && npx vitest run src/engine/golden-windows.test.ts)
echo "The TypeScript engine reads the Windows fixture: OK"
