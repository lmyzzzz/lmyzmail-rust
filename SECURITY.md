# Security invariants

The rewrite preserves or strengthens the frozen oracle's externally reachable
security boundaries. A difference is accepted only when a regression test and
an evidence-backed allowlist entry show that matching the oracle would retain a
vulnerability, race, or undefined behavior.

Core invariants:

- Untrusted protocol input is parsed incrementally with bounded buffers.
- Deadlines and cancellation span DNS, connection, TLS, writes, reads, and
  blocking or CPU work.
- Queues, executors, caches, sessions, and per-peer state have hard limits.
- Validated network destinations remain pinned through connection setup while
  preserving hostname verification and SNI.
- Maildir publication is atomic; database and Redis compatibility includes
  transaction behavior, key formats, and TTL behavior.
- Unsafe Rust is limited to reviewed FFI and SIMD modules with documented
  ownership, alignment, CPU-feature, and lifetime invariants.
- Secrets, private keys, production credentials, models, and built artifacts do
  not enter Git history.

