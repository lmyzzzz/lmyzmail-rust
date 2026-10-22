# Maildir takeover and rollback status

The 2026-10-22 compatibility repair restores the frozen Java directory layout
for unambiguous ASCII mailbox names, including `qa@example.test` and
`qa+tag@example.test`. The runtime still reads earlier Rust v2 and v1 paths.
Recovery searches for the actual message, rather than stopping at the first
existing directory, and preserves device/inode/size/hash ownership checks.
An already published inbound v2 intent binds its original inode instead of
publishing a second copy after an upgrade.

Indexed legacy messages can be deleted through the same ownership-checked
lookup used to read them. Deletion retains its tombstone, database transaction,
rollback, and configured fsync behavior. Legacy access still requires proof
that no other registered mailbox shares the Java alias; unindexed files remain
inaccessible. Directory traversal and symlinks are rejected.

This does not yet qualify universal rollback. Mailboxes containing underscores,
Unicode, consecutive dots, or reserved `v1-` prefixes still use the injective v2
layout for new writes. Java's lossy sanitizer maps, for example,
`foo/bar@example.test` and `foo_bar@example.test` to the same directory. Copying
that ambiguity into new storage would permit cross-mailbox aliases. An explicit,
evidenced security exception and a complete migration/rollback procedure for
these addresses are still required before production acceptance. Do not move
or merge such directories by hand, and do not treat the ordinary-address fix
as evidence that every existing installation can already roll back losslessly.

The original Java goldens remain unchanged. The current campaign re-attests
the frozen oracle independently and compares its observations with those
historical goldens. Negative runs are retained alongside successful reruns.

Relevant regressions are in `mailbox.rs`, `smtp_inbound_delivery.rs`,
`outbound_message.rs`, and `tests/outbound_delivery_postgres.rs`. The complete
workspace run passed 957 tests with all targets and features; strict Clippy
also passed. External deletion, attachment, multipart, and mail-state evidence
is recorded separately under `evidence/compatibility/maildir-layout-20261022-*`.

## 2026-10-23 legacy-name evidence and security exceptions

`tools/test_ambiguous_takeover.py` now performs real Java -> Rust -> Java ->
Rust transitions over one PostgreSQL/Redis/Maildir data set. The successful
`ambiguous-takeover-20261023-v5.json` records byte-exact Rust reads of Java
publications for underscore, consecutive-dot, literal `v1-` prefix and Unicode
mailboxes. It also checks both lossy Java directory aliases and the early Rust
v1 namespace against cross-owner reads, including after restart. This qualifies
legacy read takeover for those cases; it does not qualify rollback of new v2
publications or pending outbound tasks.

The following are narrowly evidenced compatibility exceptions. They do not
permit changes to unrelated routes, indexed ownership, new-write layout,
message bytes, path checks, or transaction semantics.

| Exception | Frozen behavior and evidence | Required Rust behavior |
| --- | --- | --- |
| `legacy-smtp-reader-directory-mismatch` | Frozen `MailFileStore.java:1212` preserves interior `..`, but `MailReadService.java:870` replaces it with `__`. Java receives and indexes `user..dots@example.test` but its raw HTTP read returns 404. The actual delivered file and its SHA-256 are captured in `ambiguous-takeover-20261023-v5.json`. | Recover the indexed file through either frozen mapping after proving exclusive registered ownership of the chosen alias. This repairs loss of access to existing mail. |
| `legacy-lossy-directory-cross-owner-disclosure` | Two registered addresses `under_score@example.test` and `under/score@example.test`, with corresponding index rows, resolve to one Java directory. The frozen Java raw endpoint returns the same owner bytes to both sessions; the test reproduces this after a real restart into Java. | Refuse the shared legacy alias with 404 for both owners. Continue reading unrelated unique aliases and new injective v2 publications. |

The v1 regression is a candidate repair rather than a Java exception. An early
Rust v1 directory for `qa@example.test` can also be the literal Java directory
for `v1-qa@example.test`. The negative `ambiguous-takeover-20261023-v4` run proved
that an index row alone allowed the first mailbox to read the latter's bytes.
The corrected bridge proves the requested registered owner exists and that no
other registered mailbox has a Java reader/writer alias at that v1 component.
Literal `v1-` Java mailbox reads remain available through their own exclusive
legacy mapping. Unit regressions cover both frozen sanitizers and this boundary.

All 961 workspace Rust tests and strict Clippy passed for the repair. Original
negative logs and intermediate positive results are retained. These results
do not erase the separate ambiguous-name export/rollback requirement above.
