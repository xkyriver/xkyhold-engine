// The TypeScript engine of XkyHold reads golden-v2-windows-repo.json
// (FORMAT-v2-windows.md 9): a repository written on Windows by XkyHold-wd.
// Copied into a throwaway worktree of the XkyHold repository by
// scripts/cross-ts-windows.sh; never committed there.

import { readFileSync } from 'node:fs'
import { expect, it } from 'vitest'
import { MemoryDestination } from '../storage/memory'
import { fromBase64, sha256Hex } from './bytes'
import type { Bytes } from './bytes'
import { Repository } from './repo'
import type { TreeEntry, TreeFile } from './repo'
import { readFile } from './restore'

const golden = JSON.parse(readFileSync(process.env.GOLDEN_WINDOWS as string, 'utf8'))

async function contents(repo: Repository, file: TreeFile): Promise<Bytes> {
  const parts: Bytes[] = []
  for await (const chunk of readFile(repo, file)) parts.push(chunk)
  const all = new Uint8Array(parts.reduce((n, p) => n + p.length, 0))
  let at = 0
  for (const p of parts) {
    all.set(p, at)
    at += p.length
  }
  return all
}

it.each([
  ['password', { password: golden.password }],
  ['recovery key', { recoveryKey: golden.recoveryKey }],
])('opens a Windows backup with the %s and reads every entry', async (_name, credential) => {
  const dest = new MemoryDestination()
  for (const [k, v] of Object.entries(golden.objects)) dest.objects.set(k, fromBase64(v as string))
  const repo = await Repository.open(dest, credential)
  expect(repo.format).toBe(2)
  const [snapshot] = await repo.listSnapshots()
  expect(snapshot.id).toBe(golden.snapshotId)
  expect(snapshot.home).toBeUndefined()
  expect((snapshot as unknown as { origin: { os: string } }).origin.os).toBe('windows')

  const found = new Map<string, { type: string; sha256?: string; target?: string }>()
  const walk = async (prefix: string, tree: string) => {
    for (const entry of (await repo.loadTree(tree)) as TreeEntry[]) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name
      if (entry.type === 'dir') {
        found.set(path, { type: 'dir' })
        await walk(path, entry.subtree)
      } else if (entry.type === 'symlink') {
        found.set(path, { type: 'symlink', target: entry.target })
      } else {
        found.set(path, { type: 'file', sha256: await sha256Hex(await contents(repo, entry)) })
      }
    }
  }
  await walk('', snapshot.roots[0].tree)
  for (const want of golden.expected as { path: string; type: string; sha256?: string; target?: string }[]) {
    const have = found.get(want.path)
    expect(have, want.path).toBeDefined()
    expect(have?.type).toBe(want.type)
    if (want.type === 'file') expect(have?.sha256, want.path).toBe(want.sha256)
    if (want.type === 'symlink') expect(have?.target, want.path).toBe(want.target)
  }
  expect(found.size).toBe(golden.expected.length)
})
