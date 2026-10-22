# Local acceptance follow-up, 2026-10-23

No AVX-512 host is available. The user explicitly requested that all locally
verifiable work continue; native AVX-512 execution and performance remain open.
No old source repository has been edited. Performance optimization is paused.

The oracle fixture repair is described in
[oracle-fixture-isolation-20261023.md](oracle-fixture-isolation-20261023.md).
Its focused Java/Rust replay passed without changing any historical golden or
business assertion. A full current-definition Java replay is recorded
separately and must finish before it can be called a clean complete matrix.

The mailbox repair and its evidenced exception whitelist are described in
[maildir-takeover.md](maildir-takeover.md). The development release ELF SHA-256
is `78ac1919e25812181202455ba28a12e33276f7ffb8b88c1b4e4ef08c05e3861e`.
It passed four-class legacy takeover, the v1 namespace boundary, lossy alias
rejection, and Java/Rust restart checks. This is development-artifact evidence;
any independently rebuilt package must be checked separately.

The full Rust run in `legacy-writer-path-20261023-rust-tests-v3.log` passed
961 tests with zero failures or ignored tests. Strict Clippy passed in
`legacy-writer-path-20261023-clippy-v2.log`. Earlier logs remain unchanged,
including an unrelated benchmark-proxy shutdown regression failure.

## Benchmark proxy accept-backlog regression

The unchanged proxy test failed intermittently in parallel-suite repetitions.
The diagnostic run captured no listening socket, one active connection, and a
second client in ESTABLISHED with no matching server-side connection. This is
the Linux final-handshake/listener-close race: client `connect()` can return
before the server consumes its final ACK. Such a connection is not yet the
established accept-backlog child the test intended to verify.

The test now first requires a matching server-side ESTABLISHED connection in
`/proc/net/tcp`, under its own two-second deadline. It then executes the original
shutdown request and unchanged two-second reset/EOF assertion. No SMTP data is
added, no proxy implementation changes, no timeout extension, no retry or
skipped case is involved. The exact full workspace proxy binary then passed
100 consecutive complete 13-test suites, 1,300 checks, while the Java matrix
continued running. Evidence is
`proxy-backlog-workspace-20261023-fixed-repeat.log`; earlier repeat failures and
diagnostic socket/telemetry captures are retained alongside it.

The first combined takeover invocation accidentally inherited the generic
30-second pytest timeout for the ordinary four-runtime takeover tool. Its Java
readiness was interrupted; that test has a 90-second runtime startup allowance.
The failed `maildir-takeover-20261023-v5` log is retained. The separate ordinary
takeover rerun uses the existing bounded 240-second tool invocation.
It passed in 23.31 seconds (`ordinary-takeover-20261023-v6.log/.xml`),
with byte-exact inbound and multipart Sent reads after Java/Rust/Java/Rust
restarts. Its JSON identifies the same development ELF listed above; this
result does not erase the combined invocation's retained timeout failure.

The existing Windows `bf6c0d53` RC is retained. None of this closes formal
250,000-message SMTP stability, same-process 100,000-message recovery,
disk-budgeted 10 MiB stress, full ambiguous-name rollback, or native AVX-512
acceptance. The overall goal remains active.
