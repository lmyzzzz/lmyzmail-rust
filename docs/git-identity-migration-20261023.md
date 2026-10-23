# Git identity migration, 2026-10-23

The user authorized rewriting every historical Author and Committer to
`lmyzzzz <harryluo1355@gmail.com>` and publishing with `force-with-lease`.
GitHub's authenticated `/user` endpoint confirmed login `lmyzzzz`. The existing
credential could not read `/user/emails` (404); the user explicitly confirmed
the verified email above. Local repository identity now uses the same values.

## Preserved history and content

All 374 commits reachable from local branches, remote-tracking refs and the
two detached release-worktree heads were rewritten. Every rewritten commit
was read back and compared byte for byte with its original after replacing
only Author/Committer identities and parent IDs through the mapping. Author
and Committer timestamps/timezones, messages, other headers, parent order and
topology were preserved. None of these commits contained signatures requiring
removal. Each original/rewritten commit has the exact same Git tree ID, which
also preserves every blob, path, mode, symlink, original acceptance record and
golden. This identity migration does not claim a new product test run.

The prior published tip `5ad583436392a75395835a73b054ba514b9baaf9` maps to
`ad1e529daf8050769c15c19ab42e3c33301a9e52`. A separate subsequent audit commit
adds only this document and `evidence/history/identity-20261023/`; that new
commit has no original counterpart. No historical evidence was edited to
replace an old SHA. Resolve those references using the complete
[SHA mapping](../evidence/history/identity-20261023/commit-map.tsv).

The per-commit [tree records](../evidence/history/identity-20261023/tree-verification.json)
and [verification result](../evidence/history/identity-20261023/verification.json)
record the checks. `git fsck --full --no-reflogs` passed. The working index,
staged/unstaged patches, porcelain status and all 143,474 protected file/directory
records were independently compared with their pre-rewrite snapshots. The
two detached release worktrees moved to mapped commits with identical trees.
No Java or Skibidi frozen-source repository was modified.

## Recovery material

Before changing refs, a complete `.git` archive and self-contained Git bundle
were created. The archive retains every original object, reflog, ref, index,
configuration and linked-worktree metadata, including otherwise unreachable
objects. The bundle passed `git bundle verify`; an independently extracted
original `.git` passed `git fsck` and retained the exact original HEAD.

Modified, untracked and ignored work was protected in a separate archive:
143,474 paths, with 28,932,026,390 logical bytes. Each archive regular file's
SHA-256/size, file type/mode and symlink target was verified independently
against the source inventory. Regenerable build, virtual-environment,
browser-dependency and bytecode caches were excluded from that archive and
left untouched in the active workspace. The inventory and exact exclusions
remain in the private backup. Historical acceptance data, raw profiler
captures, diagnostic database files and existing local release artifacts
were included.

Private backup locations:

```text
/home/lmyzzz/lmyzmail-rust/.blackbox/history-rewrite/20261023T065418Z/
D:\MiscProjects\lmyzmail-rust\releases\history-rewrite-20261023T065418Z\
```

The Windows copy was independently checked with PowerShell `Get-FileHash`
against all eight [backup checksums](../evidence/history/identity-20261023/backup-checksums.json).
Raw backups and uncommitted data are local recovery material and are not
published to GitHub. The exact local migration tool and recovery notes are
retained alongside both backup copies.

## Remote update

The intended remote is `https://github.com/lmyzzzz/lmyzmail-rust.git`, branch
`main`. Its pre-migration value was recorded as
`5ad583436392a75395835a73b054ba514b9baaf9`. The update uses the explicit lease
`--force-with-lease=refs/heads/main:5ad583436392a75395835a73b054ba514b9baaf9`;
an intervening remote change must reject the push. Only `main` is published;
original refs/objects are retained locally and in backups for recovery.
The remote branch ID and all reachable identities are checked after pushing.

This metadata-only migration does not change product acceptance status. The
remaining formal SMTP and native AVX-512 requirements remain open.
