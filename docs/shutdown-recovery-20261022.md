# Stress shutdown recovery validation

SIGTERM during stress delivery previously left a correctly recoverable PENDING
outbound task, but retained its Sent copy. The unchanged process regression also
requires complete stress-mailbox cleanup. Waiting for terminal delivery after
stopping the outbound worker cannot satisfy that requirement.

The shutdown-only cleanup now waits for successful termination of SMTP storage
writers and the outbound worker, and HTTP joins its publication reconciler before
starting final stress cleanup. SMTP success requires its maintenance and all three
inbound committers to drain, and its bounded file workers to relinquish their
permits. A panic, timeout or failed join does not release the cleanup barrier.

Before deleting stress Maildir copies, and again afterward, each active queue
entry must match PostgreSQL/Redis identity and retain verified content authority.
Disk-backed messages require the existing device/inode/size/SHA-256 publication
proof; inline messages require canonical base64, bounded size and the matching
content SHA-256. Content validation runs in the bounded blocking pool. Unproven
state fails closed. Normal live cleanup still waits for task terminal state;
shutdown does not acknowledge or delete recoverable queue tasks.

The tested optimized ELF SHA-256 is
`210510cec73f5da0416799ce834a66d7b2844ac3d00070ffef9e8cb36cd8bb7d`.
Evidence under `evidence/compatibility/shutdown-recovery-20261022-*` records:

- `rust-verified.log`: all 959 workspace/all-target/all-feature Rust tests passed,
  with zero failures or ignored tests. The earlier `rust.log` is retained: every
  test group passed, but its shell wrapper failed when forwarding the exit code.
  The verified run uses the original Cargo exit code and exited zero.
- `clippy.log`: strict workspace/all-target/all-feature Clippy exited zero.
- `build.log`: the frozen-lock release build exited zero.
- `process.xml` and `process.log`: all four unchanged SIGTERM/SIGKILL generation,
  enqueue, delivery and restart-recovery regressions passed. ELF hashes before
  and after the run match.
- `model-takeover.xml`, `model-takeover.log` and `takeover.json`: both compact
  model Scalar/Auto SMTP/DB tests and the same-state ordinary-address
  Java/Rust/Java/Rust takeover passed against that exact ELF.

The compact weights are the final model from user-specified thread
`01a16323-de1d-7a11-976d-8e2ff3322839`, SHA-256
`4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428`.
This milestone does not close formal large-mail SMTP stability, ambiguous-mailbox
rollback, full differential replay or native AVX-512 acceptance.
