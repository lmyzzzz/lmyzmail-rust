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
- `candidate.xml` and `candidate.log`: all 88 candidate-marked scenarios passed
  in 691.56 seconds, including the unchanged MTA-STS discovery and stress
  termination regressions.
- `unmarked.xml` and `unmarked.log`: all 178 non-oracle, non-candidate-marked
  checks passed. Together these two disjoint selections cover all 266 non-oracle
  checks in `blackbox/tests`; no test assertion or golden was changed.

Both replay audits confirmed that all 6,897 historical golden files were
unchanged, all 346 campaign observations/artifacts matched their historical
counterparts, and the executable hash was unchanged. The previously observed
intermittent A/AAAA query-order failure is still retained: one successful full
replay does not establish that this ordering race can no longer occur. The
frozen-Java replay's earlier DMARC query-count and multi-domain stress failures
also remain unresolved evidence.

The actual independently reproduced release ELF has a different hash from the
development checkout build. Its complete 310-check replay, separate RBL check,
model/takeover checks and packaged installation subsequently passed. See
[the exact release validation](release-bf6c0d53-validation.md); do not substitute
the development ELF hash above for the published executable's hash.

The compact weights are the final model from user-specified thread
`01a16323-de1d-7a11-976d-8e2ff3322839`, SHA-256
`4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428`.
This milestone does not close formal large-mail SMTP stability, ambiguous-mailbox
rollback, a clean repeatable frozen-Java differential matrix or native AVX-512
acceptance.
