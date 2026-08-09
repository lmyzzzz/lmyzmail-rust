# WSL native workspace migration evidence

The authoritative development checkout moved from
`D:\MiscProjects\lmyzmail-rust` to `/home/lmyzzz/lmyzmail-rust` on 2026-08-09.
The Windows checkout remained unchanged and is retained as the source snapshot
until the completed project is synchronized back for final acceptance.

## Git continuity

- Windows source HEAD: `d542581b03fd9ae586abab824d003ffc9bbacded`
- Native pre-resume HEAD: `3ff0d3b96fa4a549891ab227587a7216fc3c7158`
- `d542581b` is a strict ancestor of `3ff0d3b9`.
- Native commit `b34e636c` contains the report-generation source and immutable
  golden work present in the Windows dirty tree; `3ff0d3b9` adds the subsequent
  pinned HTTPS report delivery milestone.
- `git fsck --no-dangling` completed without errors in both repositories.

## Exact source-state archive

The recoverable migration snapshot is stored outside the repository at
`/home/lmyzzz/lmyzmail-migration-snapshots/windows-20260809T221000+0800`.
It contains the complete referenced Git history, the binary tracked-file diff,
all 31 non-ignored untracked files, both repository status/log captures, file
hash manifests, and verification output. Ignored build/runtime caches remain
recoverable from the unchanged Windows checkout and are not source evidence.

- `repository.bundle`: `7b3650db14afc01dbefa3e1e7402d5bccffbf7a0702b9c7ed22296ab4691e46d`
- `windows-dirty.patch`: `fb133c124c9c60e2db47ebec9f742ce2f174ac3c4ac235b1c9207271797fc513`
- `windows-untracked.tar.gz`: `b9e5a793e9ad981c7d30762070d7be9ed05a435db38f482b6353aa345a851bae`
- Binary dirty patch size: 95,325 bytes
- `git bundle verify`: successful

No Cargo, rustc, C compiler, Java oracle, PostgreSQL, or Redis process held the
workspace during migration verification. All subsequent compilation and tests
run only from the native Linux checkout; the two frozen source repositories
remain read-only.
