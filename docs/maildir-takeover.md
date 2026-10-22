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
