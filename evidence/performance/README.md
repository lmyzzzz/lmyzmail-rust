# Java/Rust Baseline

`perf-baseline-v1.py` starts one isolated runtime at a time through the
managed black-box harness. Each row measures startup to readiness, twenty
seconds of bounded `GET /api/health` probes, one SMTP greeting/`QUIT` probe,
RSS, and file-descriptor counts. The Java oracle closes some `QUIT` exchanges
without a final `221`; the probe accepts that EOF after a valid `220` greeting
while preserving the wire behavior in the differential SMTP tests.

The run is a warm service/resource baseline, not a throughput claim. The
candidate is the locked Linux x86_64 release binary identified by the SHA-256
in the JSON evidence. The script installs a signal handler, uses bounded
socket reads, checks process-group cleanup, and fails if any runtime process
leader remains after teardown.

This evidence does not mark the full lmyzmail rewrite complete; it records the
same-host Java/Rust baseline required before later optimization and soak campaigns.

## Original stress-endpoint throughput

`run-smtp-endpoint-throughput-v1.sh` is the root-only launcher for the extreme
self-SMTP throughput and queue-scheduling benchmark. It creates a temporary
cgroup v2 hierarchy, places the Python verifier and SMTP proxy in the housekeeping
CPU harness group, and moves the managed application to a workload group constrained
to one logical CPU while PostgreSQL and Redis use the services group. All children
inherit the exact memory, PID, and dual-device I/O limits. The root ext4 device is
capped at exactly 500,000,000 bytes per second for both reads and writes.

Run a short contract smoke before any formal evidence run:

```bash
sudo evidence/performance/run-smtp-endpoint-throughput-v1.sh \
  --smoke \
  --output evidence/performance/smtp-endpoint-throughput-smoke-v1.json
```

The default matrix runs 1KB and 10KB as Java, Rust, Rust, Java ABBA pairs.
The 10MB tier is always Rust-only with two fresh-state arms. The launcher never
runs the frozen Java oracle at 10MB because that endpoint can stall in an SMTP
session; `--target java --tier 10mb` is rejected before resources are created.

Before any new Rust pressure run, capture the dedicated Java-small baseline:

```bash
sudo evidence/performance/run-smtp-endpoint-throughput-v1.sh \
  --profile java-small \
  --target java \
  --output evidence/performance/smtp-endpoint-java-small-baseline-v1.json
```

Every non-smoke run containing Rust binds exactly one filesystem durability
mode. Use separate create-only outputs; the launcher rejects a missing,
duplicate, invalid, or Java-only mode before it creates benchmark resources.
The Java-comparison run uses close-only filesystem behavior:

```bash
sudo evidence/performance/run-smtp-endpoint-throughput-v1.sh \
  --profile abba \
  --target both \
  --rust-filesystem-fsync off \
  --output evidence/performance/smtp-endpoint-throughput-fsync-off-v1.json
```

Run the durable arm independently; do not merge it with the off-mode evidence:

```bash
sudo evidence/performance/run-smtp-endpoint-throughput-v1.sh \
  --profile abba \
  --target both \
  --rust-filesystem-fsync on \
  --output evidence/performance/smtp-endpoint-throughput-fsync-on-v1.json
```

`off` changes only lmyzmail-owned filesystem barriers. PostgreSQL WAL and
`synchronous_commit`, Redis persistence, atomic publication, ownership checks,
queue bounds, and evidence-file fsync remain unchanged. `on` remains the
production default and is the required mode for long-running durability and
leak/stability qualification.

The external syscall qualification for that boundary is reproducible with:

```bash
.blackbox-venv-wsl/bin/python \
  evidence/performance/fsync-mode-syscall-evidence-v1.py \
  --output evidence/performance/smtp-rust-fsync-mode-syscall-v1.json
```

It traces the complete isolated process tree for three real inbound deliveries
(`DATA`, `PIPELINING`, and `BDAT`) in each mode. The published v1 evidence found
zero lmyzmail-owned workspace `fsync`/`fdatasync` calls in `off`, versus 27
successful calls in `on`; both modes retained three successful Maildir atomic
publications. PostgreSQL remained at `fsync=on`, `synchronous_commit=on`, and
`full_page_writes=on`, with 31/30 observed `pg_wal` syncs. The probe explicitly
enables Redis AOF with `appendfsync=always`; both modes observed 13 AOF syncs,
zero pending AOF fsync work, and identical final AOF size. The JSON and its two
raw traces are create-only and SHA-256 bound. `strace` is invasive, so this is a
scope/isolation qualification and never a throughput measurement.

### Fsync-off outbound batch qualification

The close-only stress path now coalesces outbound admission only when all three
conditions hold: lmyzmail-owned filesystem fsync is disabled, the caller is the
quota-bypassing stress endpoint, and the message is not a DSN. Production keeps
fsync enabled by default, and ordinary outbound plus DSN admission retain the
existing per-message path. The stress-only worker has a bounded 256-request
channel, a maximum batch of 64 rows, and a two-millisecond collection window.
One PostgreSQL transaction writes the queue, spool ownership, content authority,
and Sent index rows; Redis publication remains after the commit and uses the
existing reconciliation contract. Shutdown closes the channel and joins the
worker explicitly.

The reproducible external qualification is:

```bash
.blackbox-venv-wsl/bin/python -m pytest -q \
  evidence/performance/test_fsync_off_batch_persistence_v1.py
```

The 2026-08-17 run passed both tests in 24.85 seconds. The 256-message case
observed every task exactly once in all four PostgreSQL authorities and in the
Redis pending set. The opt-in `LMYZMAIL_STRESS_ENQUEUE_OBSERVER=1` snapshot used
schema `lmyzmail.outbound-batch-observation.v1`; it reported all 256 rows, a
`max_rows` greater than one and no greater than 64, fewer batches than rows, and
zero uncertain commits. This proves real coalescing without using harness-side
batching.

The second case holds the outbound advisory lock before starting a 64-message
request and sends SIGTERM only after non-control materialization appears. It
then proves there are no stress bodies, outbound data files, queue/Sent rows, or
Redis pending IDs. `.lmyzmail-staging.lease` deliberately remains as a regular,
zero-byte, mode-0600, single-link control inode with the expected owner; the
test obtains `LOCK_EX | LOCK_NB` after shutdown to prove release. Unlinking that
inode would permit two live inodes and split the flock lock domain, so its
presence is not classified as leaked mail.

This qualification does not re-attest the frozen black-box golden. The current
black-box definition tree hashes to
`0c1a5f9c7c747d9c7658935842b10ec78682f5dba375ad80afc3c29b63ac7b8c`,
while the frozen suite requires
`b0ce09dd6c4bf3fc0baa8f817d2bfe1ce9b8c35034dd5c099d2fc811f764f703`.
Three selected default-fsync replay tests failed closed at `suite.json`
attestation before candidate execution. No golden was changed or re-recorded;
full differential re-attestation remains an explicit completion gate.

The post-batch worker sweep uses the same 4,096-message, 10 KiB, fsync-off
diagnostic, with one original stress-endpoint invocation and no harness
batching. The unconstrained runs measured 316.53, 480.46, 661.56, and 748.58
messages/second at worker bounds 8, 16, 32, and 64. Their batch counts were 865,
508, 279, and 218, with maximum batch rows 8, 16, 28, and 52. Although 64 had
the highest enqueue-only rate, it substantially increased materialization and
persistence tail costs, and its CPU-23 attempt failed during candidate startup
before measurement. It is therefore negative diagnostic evidence rather than a
retained bound.

The bounded CPU-23 comparison then measured 389.51 messages/second at 16
workers and 491.30 at 32 workers, a 26.14% advantage for 32. Both runs verified
all 4,096 queue, spool, content, and Sent PostgreSQL authorities plus all 4,096
Redis pending IDs, reached zero active enqueue work, removed their temporary
workspaces, and recorded zero uncertain batches. The retained fsync-off
small-message worker bound is consequently 32. The two CPU-constrained JSON
SHA-256 values are
`a48af3d4b45f8a90a6be37fa6af062a42f5c0c6e4c7de5a38ba240ada1542d6b`
for 16 and
`c42493b490a49afdeaaf7eb49be913881453b3bc678436959c2372c4ae9e4922`
for 32. These remain enqueue-only diagnostics with `qualified=false`; they do
not replace the Java/Rust endpoint comparison or formal 500,000-message gates.

### High-cardinality cleanup observation

Automatic endpoint cleanup no longer reads every Redis value on every
250-millisecond poll. Its readiness phase reads only `DBSIZE`, fixed PostgreSQL
aggregate state, and Maildir file counts. A Redis key count no greater than the
pre-round baseline plus the three bounded authentication DNS caches can only
trigger, never replace, the original full validation. Qualification still
requires three identical semantic snapshots containing every Redis key's type,
TTL, cardinality, complete value-stream SHA-256, and byte count. Those full
snapshots now use non-transactional pipelines bounded to 512 keys, so the
evidence semantics remain unchanged without one network round trip per field.

`redis-full-value-snapshot-profiler-v1.json` is the focused live check against
the frozen black-box Redis binary. It read and hashed 32,768 string keys and
4,194,304 value bytes in 0.855595 seconds, reported a stable complete scan, and
removed its temporary workspace. The create-only JSON SHA-256 is
`6b82c6bf14156ddf24bf4545176ea2cf939cf342e4fc94f602e21cdf59878442`.
It has `qualified=false`: this is a harness diagnostic, not SMTP throughput
evidence.

The Maildir observer profile is now
`lmyzmail-maildir-inotify-publication-v7`. Any inotify overflow before all
expected receiver/inbox and sender/Sent publications remains a hard failure.
After all publications are present, an overflow during endpoint cleanup is
recovered by read-only directory-name reconciliation of already observed
paths; it never opens, stats, reads, writes, or hashes a message file. Evidence
records overflow events, reconciliation scans, and removals recovered through
that path. Exact publication/removal counts and the final empty Maildir trees
remain mandatory, so overflow handling does not convert missing evidence into
success.

This profile is intentionally not qualification evidence. It fixes the plan to
1KB and then 10KB, exactly 200,000 messages per tier, one original
`/api/stress/start` invocation per tier, no warmup, no repetition loop, and no
harness batching. Each tier uses a fresh Java runtime, database, Redis state,
workspace, and capture proxy. The launcher rejects Rust, `both`, smoke, tier
selection, altered disk budgets, and therefore any Java 10MB run before it
creates per-run resources. The selected frozen oracle is
`oracle/artifacts/lmyzmail-java-oracle.jar`, SHA-256
`FE2D8FCEFAD9A4127398EEB5D911805EA10A8DCE75EC70912FD3BE909C8FBDFC`.
The machine is recorded as a Core Ultra 9 275HX in user-reported OEM power-save
mode; Windows `powercfg` reported `High performance`. The launcher does not
change either setting.

The frozen Java endpoint could not reasonably finish either 200,000-message
request. Under the revised baseline rule, both launchers were terminated after
failure-free stable windows and watchdog cleanup. The extracted passive-proxy
windows are recorded in
`smtp-endpoint-java-stable-window-baseline-v1.json`: 1KB sustained
44.674072 messages/second over 6,548 messages and 146.572714350 seconds; 10KB
sustained 47.223536 messages/second over 2,978 messages and 63.061775065 seconds.
This is the same-host Java reference floor only. It is explicitly not a completed
Java-small run, persistence qualification, ABBA median, or Java 10MB claim.

The current Rust CPU profile is
`smtp-rust-queue-tuned-profiler-v2.json`, backed by the 60-second DWARF
call-graph capture
`smtp-rust-queue-tuned-symbolized-cpu-clock-60s-v1.data`. Its unqualified
10KB window delivered 1,479 messages without SMTP failures, retries, or
observer failures at 12.466483 messages/second. The profile attributes 25.80%
children to `process_next_inner`, 23.41% to `process_claimed`, 20.03% to
message materialization, 10.64% to DKIM finish, and material PostgreSQL work
to connection/query paths. A benchmark-only pool expansion produced no
reportable improvement and was reverted. This window is profiler evidence,
not a completed 500,000-message or ABBA throughput result. The companion
`smtp-self-stress-v2-temp-cleanup-v4.json` smoke passes 1KB, 10KB, and 10MB;
all final PostgreSQL, Redis, Maildir, spool, and stress-temporary state is zero.

A follow-up connection-local prepared-statement experiment is recorded in
`smtp-rust-prepared-statements-profiler-v3.json` and the 60-second capture
`smtp-rust-prepared-statements-cpu-clock-60s-v1.data`. It removed the prior
reportable `ToStatementType::into_statement` hotspot and reduced the primary
`query_opt` children share, but the measured 10KB window fell to 12.274000
messages/second, 1.54% below the preceding 12.466483 window. The experiment was
therefore reverted and is retained only as negative profiler evidence. The next
performance work must target serialized durable PostgreSQL round trips rather
than statement-cache CPU cost, without weakening fencing or crash semantics.

The next two-window diagnostic is recorded in
`smtp-rust-coordinator-publish-verify-profiler-v4.json`, with raw captures
`smtp-rust-coordinator-verify-cpu-clock-60s-v1.data` and
`smtp-rust-coordinator-verify-cpu-clock-60s-v2.data`. Moving the post-index
commit inbound check from repeated directory fsyncs to an identity, digest,
link-count, size, and staging-residue verification reduced that observer stage
from about 13.81 ms/message to 0.118-0.133 ms/message in two windows. The second
window nevertheless delivered only 10.749 messages/second, below the prior
12.466483-message/second diagnostic. This is retained correctness-preserving
local-stage evidence only: it is explicitly not an end-to-end improvement,
formal qualification, or reason to weaken the SMTP throughput gates. The same
observer identified `queue_ack_spool_cleanup` at about 45.85 ms/message as the
next falsifiable durability-path hypothesis.

The follow-up spool cleanup diagnostic is recorded in
`smtp-rust-spool-parent-fsync-profiler-v5.json`, with raw capture
`smtp-rust-spool-parent-fsync-cpu-clock-60s-v1.data`. Removing the redundant
setup-time spool parent-directory fsync reduced `queue_ack_spool_setup` from
about 17.46 ms/message to 0.0247 ms/message and the complete spool cleanup from
about 86.76 ms/message to 42.39 ms/message at the comparable 1,280-task
snapshot. Final quarantine/spool durability barriers, publication-proof cleanup,
the database checkpoint, and rename-cutpoint recovery remain in place. The
interrupted arm delivered only a derived 7.106 messages/second and also logged
1,524 stress strict-pool soft deadlines, so it is retained strictly as local
stage evidence with `qualification=false`; it does not establish an end-to-end
gain. The next producer-side hypothesis is the four-worker stress
body/materialization pool under 1,000 active 10KB enqueue jobs, while the
delivery-side observer still points to durability, proof cleanup, and checkpoint
latency.

The next Linux durability-coalescing experiment is recorded in
`smtp-rust-durability-group-commit-profiler-v10.json`, with syscall capture
`smtp-rust-durability-group-commit-syscall-trace-v10.txt`. It observed no SMTP
or observer failures in its bounded window, but fsync/rename/unlink ratios were
unchanged from v9 and fsync tail latency worsened; the coordinator experiment
was rejected and reverted. Its assembled record explicitly notes that the
temporary raw observer log was not preserved.

The post-revert CPU/database baseline is recorded in
`smtp-rust-smtp-commit-db-baseline-v11.json`, backed by
`smtp-rust-smtp-commit-db-baseline-v11-rust-candidate.log` and
`smtp-rust-smtp-commit-db-cpu-clock-v11.data`. The 60-second capture had 8,044
CPU-clock samples with no lost samples; flat CPU attribution was led by RSA
`ring_core...bn_sqrx8x_internal` (8.32%), `malloc` (3.06%),
`mulx4x_internal` (2.61%), and PostgreSQL connection polling (1.65%). The
window is not qualified because maintenance logged 11 spool-cleanup checkpoint
failures and 2 queue-unavailable diagnostics. Those failures must be explained
before any optimization is retained.

The checkpoint/reconciler race investigation is recorded in three create-only
diagnostic records. `smtp-rust-spool-checkpoint-classification-v13.json`
reproduces 3 invalid-transition checkpoint failures and 2 queue-unavailable
diagnostics in a 1,792-task window. The first ownership-aware checkpoint fix in
`smtp-rust-spool-checkpoint-race-fix-v14.json` removes every invalid transition,
but its 2,560-task window still exposes 3 spool-cleanup and 5 per-task background
reconciler races. `smtp-rust-reconciler-race-fix-v15.json` adds atomic live-
admission exclusion and strict post-delete identity reconciliation; its preserved
3,584-task candidate log contains zero diagnostics in all four categories. The
v15 code passes 22 focused outbound unit tests, 16 PostgreSQL/Redis coordinator
integration tests, all-target clippy with warnings denied, and the format check.
All three records remain `qualification=false`: they are correctness evidence
from interrupted windows, not completed endpoint runs or throughput gains. The
next performance decision requires a fresh clean profiler capture.

The clean post-race CPU capture is preserved as
`smtp-rust-post-race-clean-cpu-clock-v16.data`, with flat and children reports
beside it. Its 7,800 samples over 60.0275 seconds had no lost samples and showed
that the candidate was not CPU-saturated; coordinator wall waits dominate. The
observer-only SMTP split in `smtp-rust-smtp-stage-breakdown-v17.json` then located
about 42.92 ms/message in EHLO, 44.27 ms/message in the envelope exchange, and
74.19 ms/message waiting for the final SMTP reply. The first two delays were
consistent with Nagle/delayed-ACK interaction on the production inbound accepted
socket.

`smtp-rust-tcp-nodelay-stage-breakdown-v18.json` records the falsification arm.
Enabling `TCP_NODELAY` before inbound SMTP protocol I/O reduced observed EHLO
from 42.92 to 0.224 ms/message, envelope exchange from 44.27 to 0.791 ms/message,
and complete SMTP preparation from 89.01 to 2.55 ms/message. The 3,072-task
window contains no transition, reconciler, queue, stress-deadline, or delivery
diagnostics, and the socket behavior has a direct loopback regression test. The
remaining 86.48 ms final-reply mean is not a network delay: the seven inbound
Maildir, PostgreSQL, and Redis stages account for 85.63 ms, with file prepare and
file publish the two largest components. Both v17 and v18 are interrupted
`qualification=false` diagnostics and make no endpoint-throughput claim. The next
profile targets the synchronous Maildir prepare/publish operations.

The 30-second syscall trace is preserved in
`smtp-rust-maildir-syscall-trace-v19.txt` and assembled in
`smtp-rust-maildir-syscall-profiler-v19.json`. Across the inbound path it found
521 staging-file fsyncs at a 9.49 ms mean, 1,039 staging-directory fsyncs at an
8.08 ms mean, and 518 final-Maildir directory fsyncs at a 7.72 ms mean. Inbound
rename, staging write, and cached final-file reads were only 0.157, 0.168, and
0.100 ms mean respectively. The trace was invasive and coincided with one
outbound spool ownership or cleanup failure, so v19 is diagnostic only. Its
pre-attach sequence-2 window is retained solely as a same-kernel local baseline.
The four Maildir barriers remain required until crash-cutpoint evidence proves a
different ordering equally durable.

`smtp-rust-staging-barrier-v20.json` records the resulting falsification arm. A
generation-based userspace barrier retained file and final-directory fsyncs but
made the same-kernel sequence-2 prepare, publish, and final-reply means 15.14%,
1.81%, and 2.57% worse. The clean 2,048-task window had no transition,
reconciler, queue, deadline, or delivery diagnostics, and all focused tests and
lint gates passed, but ext4 was already coalescing concurrent flushes while the
extra coordinator introduced head-of-line blocking. The experiment was rejected
and fully reverted. The next profile moves above the filesystem layer to the
durable intent, index, completion, and projection state transitions; it must not
weaken Maildir atomicity or restart recovery.

`smtp-rust-intent-roundtrip-v21.json` records the next falsification arm. Three
`MATERIALIZED` CTEs fused advisory-lock acquisition with intent insertion,
locked index selection, and completion deletion. In the clean sequence-2 repeat,
intent insertion and completion improved by 11.00% and 15.73%, and final SMTP
reply latency improved by 4.51%, but index commit regressed by 3.43%. The clean
log had zero transition, reconciler, queue, deadline, or delivery diagnostics;
all focused tests, differential gates, and lint gates passed. Because every
targeted stage had to improve materially and repeatably, the experiment was
rejected and fully reverted. The restored profiling ELF is byte-identical to the
pre-experiment binary. The next diagnostic must measure PostgreSQL WAL and commit
waits directly before changing any remaining durable transaction boundary.

`smtp-rust-postgres-wal-profiler-v22.json` and its syscall trace measure that
boundary directly. During 19.954 seconds, the isolated PostgreSQL instance made
3,105 successful `fdatasync` calls on `pg_wal` at a 3.862 ms mean and 5.686 ms
p95, versus 3,114 WAL `pwrite64` calls at a 0.141 ms mean. Aggregate WAL sync
time was 27.41 times aggregate WAL write time. The corresponding observer delta
contained 1,024 completed tasks, or approximately 3.032 WAL syncs and 11.712 ms
of aggregate WAL sync wait per task. The trace was invasive and is not throughput
evidence, but it localizes the next safe hypothesis: test bounded PostgreSQL
group-commit delay while retaining `fsync`, `synchronous_commit`,
`full_page_writes`, transaction ordering, and recovery guarantees.

`smtp-rust-postgres-commit-delay-profiler-v23.json` records that falsification.
A session-local `commit_delay=500` microseconds retained every durability
setting and used the default `commit_siblings=5`, but two fresh-state sequence-2
windows regressed final SMTP reply latency by 19.30% and 17.44%. Intent insert,
index commit, intent completion, and projection flush all regressed in both
repetitions as well. Both copied logs contain zero transition, reconciler,
queue, deadline, or delivery diagnostics, and both exact-launcher interrupts
produced clean isolation receipts. The experiment was rejected and fully
reverted; the restored profiling ELF is byte-identical to the pre-experiment
baseline. No invasive WAL trace was justified after the latency gate failed.

The isolated self-SMTP transport keeps the oracle connection limiter enabled but
raises its per-IP concurrent connection ceiling to 2,048 and its new-connection
rate ceiling to 1,000,000 per minute. Only the private benchmark namespace can
reach that sink; this prevents the production anti-abuse threshold from becoming
the queue-throughput result. The exact override is recorded in the run
attestation. The global inbound byte limiter also remains enabled, with an 8 GiB
one-hour bucket for the isolated benchmark instance; the frozen endpoint only
bypasses its sender-count bucket, while the production 100 MiB default would
otherwise asynchronously discard a 200,000-message tier. Production defaults and
security coverage remain unchanged in the differential suite.

The retained projection-coalescing change is recorded in
`smtp-rust-projection-coalescing-profiler-v24.json`.  It removes the synchronous
post-250 Redis projection flush while keeping the durable projection upsert in
the PostgreSQL index transaction; the bounded one-second maintenance loop still
flushes with `SET KEEPTTL` and generation fencing.  Two clean windows reduced
final-reply latency by 7.85% and 14.00%, and reduced index-commit latency by
9.53% and 17.53%.  Both windows had zero projection flushes on the SMTP path,
exact accepted counts, converged PostgreSQL/Redis state, and no transition,
reconciler, queue, deadline, or delivery diagnostics.  This is retained
correctness-preserving evidence, not a completed endpoint qualification.

The associated WAL syscall capture is recorded in
`smtp-rust-projection-coalescing-wal-profiler-v25.json`, with raw trace
`smtp-rust-projection-coalescing-wal-syscall-trace-v25.txt`.  It observed 1,285
successful `fdatasync` calls for 1,024 completed tasks (1.254883 per message),
down from approximately 3.032227 per message in v22, a 58.615% reduction;
`pwrite64` had 1,287 successful calls and no errors.  The syscall trace is
intrusive and its aggregate sync wait is not a throughput claim.  It is retained
as durability-rate evidence for the coalescing decision; crash recovery,
Maildir ordering, and projection convergence remain gated by the existing
tests and reconciliation path.

The single-statement completion experiment is recorded in
`smtp-rust-intent-completion-single-delete-profiler-v26.json`.  It replaced the
explicit completion transaction, advisory lock, identity read, delete, and
commit with one `INDEXED` delete constrained by all sixteen durable identity
fields, while preserving ambiguous-outcome reconciliation.  Completion latency
improved by 19.13% and 11.92% in the two fresh-state windows.  The second window,
however, regressed final reply by 1.08% and index commit by 19.69% relative to
its v24 counterpart.  The end-to-end retention gate failed, so the experiment
was rejected and restored byte-for-byte.  Its logs and clean isolation receipts
are retained as negative profiler evidence, not a throughput claim.

The qualified full profile uses one `/api/stress/start` invocation per arm,
with no harness batching, warmup calls, or repetition loop. The 1KB and 10KB
tiers run Java, Rust, Rust, Java in ABBA order using fresh isolated state per
arm and request 500,000 messages per arm. The 10MB tier runs two Rust-only arms
and is reduced only by the fixed 20 GiB disk budget, up to 1,000 messages per
arm. It is a candidate durability/stability tier, not a Java comparison.

```bash
sudo evidence/performance/run-smtp-endpoint-throughput-v1.sh \
  --output evidence/performance/smtp-endpoint-throughput-formal-v1.json
```

PostgreSQL runs with `fsync`, `synchronous_commit`, and `full_page_writes`
enabled for both targets. The measured window starts immediately before the
single endpoint request and ends at the final self-SMTP `250`; post-final
PostgreSQL/Redis queries never change its duration or message rate. A pre-opened
PostgreSQL observer is signalled as the first final-`250` action while the main
thread freezes the passive Maildir event counter. Measurement arms forward that
`250` transparently instead of delaying the frozen endpoint for an external
persistence query. The Maildir observer independently requires `N` publications
and removals for both `receiver/inbox` and `sender/sent`, for `2N` total visible
paths. Java direct creates are counted once and a later `CLOSE_WRITE` only
upgrades their mechanism. Rust inbox rename publication is recorded as
`atomic_rename`; its hard-link sent-copy publication is visible as `IN_CREATE`
and therefore recorded as `visible_create`. Bounded directory reconciliation
may recover a missed inotify edge but cannot invent content or cardinality.

Formal lifecycle qualification also binds a stable `email_index` relation OID
and `stats_reset`, then requires exactly `2N` `n_tup_ins`, `2N` `n_tup_del`, zero
`n_tup_upd`, and zero database transaction rollbacks. This proves both transient
rows existed and endpoint cleanup removed them even when the immediate
post-final snapshot arrives after Java has already cleaned them. The endpoint's
unique `[RESULT] Received: N`, both Maildir scopes, and the PostgreSQL lifecycle
counters must agree; none can substitute alone. The observer's normal read
transaction commits, so the audit itself does not manufacture a rollback.

Both first post-final observations must equal the accepted count within their
fixed lag bound. Later publication or audit growth is diagnostic only and cannot
repair an early `250`. Candidate before-`250` durable ordering must be established
by separate ordinal receipt/crash-cutpoint evidence before formal qualification;
it is not inferred from a late maintenance query. Endpoint cleanup is excluded
from throughput and must remove queue, database, and Maildir state for three
stable polls before the next run.
The runner records bounded latency histograms,
order-independent message digests, cgroup CPU/I/O/memory/PID metrics, FD and
queue peaks, disk growth, cleanup state, immutable output, and a chained JSONL
checkpoint. Failed and interrupted evidence paths are never overwritten.
Launcher intent, runner receipt, checkpoint events, promotion validation, and
cleanup qualification all bind the single Rust fsync mode. New journals always
end with a newline; the bounded reader still accepts historical final records
that predate that fix and lack only the trailing newline.

Before a formal run, the launcher automatically executes `headroom-attest` in
the same harness cgroup and publishes a root-owned content-addressed report. No
attestation file can be injected through an environment variable. The producer
binds boot ID, time window, executable/source/runner hashes, cpuset, parent and
process cgroups, both `io.max` lines, memory/swap/PID limits, and exact soft/hard
`RLIMIT_NOFILE=8192`. The required FD bound is `4 * 1500 + 512 = 6512`; 8192
leaves the recorded reserve while covering both sides of every proxied
connection plus the in-process clients and backend. The launcher and runner
parse `io.max` structurally: both devices must retain exact 500,000,000-byte/s
read and write limits, while IOPS may only be omitted or explicitly reported by
the kernel as `riops=max wiops=max`; finite IOPS, unknown fields, and duplicate
devices fail closed. The launcher and runner
independently recompute all raw schema-4 ABBA tier gates and reject stale,
cross-host, cross-cgroup, low-limit, or modified evidence. Each raw control arm
uses the same bounded `ProxyServer` data plane, TCP-hop topology, listener
backlog, admission and memory permits, connection lifecycle, reply buffer, and
64 KiB directional pumps as the observing proxy, with observation permanently
disabled before connection creation. The unchanged 0.90 ratio therefore
measures observer overhead rather
than comparing a two-endpoint direct socket with a four-endpoint proxy path.
The 10MB raw arm uses 2,000 messages per round so scheduler transients cannot
dominate the large-message sample. The 1KB schema-2 synthetic persistence gate
uses 24,000 messages at concurrency 1,500; this keeps its unchanged 1% gate-hold
fraction meaningful on the high-throughput tier. The 10MB synthetic gate uses
100 messages at concurrency 20, while the real candidate on/off gate uses 100
messages at the tier's concurrency 80; the latter therefore enforces the
existing duration-fraction check instead of taking the sub-50-message
exemption. Each tier carries an independent schema-2 persistence-gate
calibration whose hash is combined with, but never substituted for, the raw
calibration hash. Gate qualification is based directly on the measured
mechanism: maximum gate hold is at most 1% of its round,
release-to-forwarding is at most 5 ms, and forwarding itself is at most 1 ms.
The ABBA throughput spreads and on/off ratios remain recorded as diagnostics;
they are not an indirect qualification proxy for those three timing bounds.
Both launcher and runner recompute the gate binding, fixed synthetic snapshot,
four paired ratios, per-round observer/memory evidence, and the two-level hash
bundle before accepting the root-owned attestation.

`smtp-proxy-schema4-10kb-diagnostic-v2.json` is the focused post-fix 10KB
calibration on the current WSL host. The release proxy SHA-256 was
`c45f3dc44debf57512857d87d6013de43b7d31b014a8a283fcf1f7ea5b017095`;
the raw JSON SHA-256 is
`735c2f816334afb9881124c65800b3259abd8f11e55951d3a3d7458045795f67`.
It verified 1,000,000 observed messages with no missing, duplicate, failed, or
active connection: both control and observed accepted and completed 4,000
connections and reached a peak of 1,000. Control spread was 10.5601%, observed
spread was 4.9971%, and the observed/control median ratio was 1.037107, passing
the unchanged 20% spread and 0.90 ratio gates. This focused result supports the
same-data-plane plus per-round-idle change, but it is diagnostic evidence, not a
root-owned formal headroom attestation or an application throughput result.
The report retains the observed proxy's absolute sustained rate, and formal
qualification separately requires that rate to be at least twice the fastest
actual application arm; equal-topology control does not replace that gate.

The 10MB profiler sequence is preserved in
`smtp-proxy-schema4-10mb-profiler-v1.json`,
`smtp-proxy-schema4-10mb-streaming-post-v1.{data,json,txt}`, and
`smtp-proxy-schema4-10mb-reuse-post-v1.{data,json,txt}`. The first profile
localized observer copies and hashing; the streaming observer removed full
chunk retention, and the reuse profile then removed per-message 10 MiB client
allocation/zero-fill plus the synthetic backend's byte-at-a-time marker scan.
Across those stages, the observed/control ratio improved from 0.896589 through
0.947752 to 1.045575, while the estimated observer CPU increment fell from
64.447 through 27.493 to 14.897 ms/message. The final 33,208-sample capture lost
no samples, verified all 4,000 observed messages, drained both connection pools
to zero, and kept direct/observed spreads at 17.099%/7.905%. These are focused
profiler results, not substitutes for the strict production-release headroom
gate or root-owned formal endpoint evidence.

The production-release strict 10MB diagnostics are retained as
`smtp-proxy-schema4-10mb-diagnostic-v1.json` and `-v2.json`. The v1 diagnostic
ran concurrently with the Python contract suite and correctly failed closed:
its ratio was 0.986041 and observed spread was 11.610%, but direct spread was
20.160%, 0.160 percentage points beyond the fixed 20% ceiling. Its SHA-256 is
`d75b0288e556c30afdbf75d82f8e3dd181f0b1abeb4b59cc4932dc1d9df4ee9a`.
The independent idle-host v2 run used the same release proxy SHA-256
`58842ba9211c61f39edee4856edfe0a7422ea67e5698d6bfa599609f6d51412d`
and unchanged command/gates. It passed with ratio 0.984165, direct/observed
spreads 9.478%/4.314%, exact 4,000-message observer cardinality, no observer
failure, and both 320-connection pools fully drained. Its JSON SHA-256 is
`8ae1a3706d2c65ecef535fa6e5c8c61af13d45acbb4a38f84e7b0be29c4c13d8`.
The failed diagnostic remains evidence; it was not overwritten or promoted.

The first formal fsync-off attempt, launcher run
`9c9d976d-495d-4e7a-9593-008a938d42c2`, was stopped before any candidate arm by
the root-owned headroom gate. Its 10MB raw ratio was 0.898736 with 14.007%
direct and 24.531% observed spread. The 1KB synthetic persistence gate also
recorded one 16.605 ms hold in a 1.389 s round, exceeding the fixed 1% fraction.
The 10KB tier passed with ratio 1.038200 and 16.943%/16.006% spreads. Cleanup
completed with `request=ABORT`, `cleanup=passed`, no lazy unmount, and no
provisional output or checkpoint. The failed run motivated only stronger sample
sizes: 10MB raw rose from 1,000 to 2,000 messages per round and the 1KB
synthetic gate from 12,000 to 24,000. All ratio, spread, 1%, 5 ms, and 1 ms
thresholds remain unchanged.

The strengthened headroom then passed in launcher run
`a9c1ad03-66d2-4881-a54b-218b0f81b1b5`, publishing the content-addressed proxy
attestation, but the runner stopped before its first real calibration: the
composed external prerequisite was root-owned mode 0400 while the runner is
deliberately non-root, so its descriptor-relative `openat` returned EACCES.
Cleanup again completed with `request=ABORT`, `cleanup=passed`, and no promoted
output/checkpoint. The producer now uses root-owned mode 0444. This preserves
the existing one-link, no-write-bits, content-hash, metadata, and `O_NOFOLLOW`
checks while making the non-secret attestation readable by the sandboxed
runner; the launcher contract test pins that mode.

Launcher run `07da6e63-5a78-4b23-97ca-4faf5819d862` proved the 0444 handoff:
the non-root runner opened and hashed the external prerequisite. It then stopped
before real calibration because the generic metric scanner treated the `ratio`
substring inside the legitimate boolean key `root_only_cgroup_migration` as a
numeric ratio. The scanner now tokenizes snake-case keys and only applies its
finite-number rule to complete `headroom`, `ratio`, or `throughput` words.
Dedicated structure validators still enforce every boolean and numeric field,
and regressions cover legal migration booleans plus boolean/NaN/Inf metric
rejection. The abort cleanup passed without a promoted output or checkpoint.

`smtp-proxy-schema4-10mb-diagnostic-v3.json` is the independent strict check of
the strengthened 2,000-message raw shape. With release proxy SHA-256
`58206b678abb8e99d9327e1c8739499696b73ea71a98e91d7e8e9c55002280dd`,
it passed the unchanged 0.90 ratio and 20% spread limits at ratio 0.953014 and
9.759%/2.711% direct/observed spreads. The observer verified all 8,000 messages
with no missing, duplicate, parser failure, or residual connection; both
320-connection pools drained exactly. The create-only JSON SHA-256 is
`ee91d2a53e7b4a6c60dc5fa101fc8103848b27504c20e5d512b82a6611454198`.

The strengthened full producer subsequently showed order-sensitive 10MB
variance: two published passing runs on the same proxy/source recorded ratios
0.994516 and 0.923503 with spreads below 11%, while launcher v4 recorded ratio
0.885334 and 11.451%/21.044% spreads after the million-message 1KB and 10KB
tiers. The fresh-process strict v3 remained at ratio 0.953014. Because the
profiler still attributes 12.00% flat CPU to page clearing, formal headroom now
uses the fixed largest-first execution order `10MB, 1KB, 10KB`. No tier, round,
message, or failed result is omitted; the same BTreeMap evidence and all fixed
qualification limits remain intact. The large-buffer tier runs in fresh process
state, followed by both maximum-connection small-message tiers.

The Java median measured first on the same hardware is the small-message gate;
the remembered 1,500 messages/second 10KB result is context only. Formal 1KB
and 10KB Rust medians must be at least 1.20 times Java. The 10MB tier has no
Java throughput ratio: both Rust arms must instead pass the unchanged exact
persistence, cleanup, resource, and cross-arm stability gates. Passing this
benchmark is necessary but is not sufficient to mark the rewrite complete.

Launcher smoke v16, run `0e368546-b5c1-4444-b6dd-888ff55388e6`, is the first
published end-to-end check of the mixed-v2 topology after the Redis readiness,
Java-10MB exclusion, cgroup-zombie reconciliation, and launcher-validation
fixes. It invoked the original endpoint exactly ten times: Java/Rust/Rust/Java
for 1KB, the same ABBA order for 10KB, then two Rust-only 10MB arms. Java 10MB
was absent. Every requested message was passively observed exactly once; every
arm retained at least three complete Redis type/TTL/value snapshots and three
identical stable semantic polls, with passing PostgreSQL deltas, Maildir state,
resource accounting, cgroup membership, quota placement, and artifact hashes.

In fsync-off mode, the conservative `min(Rust)/max(Java)` ratios were 6.166831
for 1KB and 6.139721 for 10KB. Rust medians were 11.435340 and 11.455396
messages/second, versus Java medians 1.795413 and 1.810526. The two Rust 10MB
arms measured 0.957655 and 0.928752 messages/second and passed the 20% cross-arm
stability gate. The root cleanup receipt records `request=DONE`,
`cleanup=passed`, no lazy unmount, and no recovered state; independent
post-exit checks found no run process, mount, loop, cgroup, provisional output,
or temporary workspace. The create-only JSON SHA-256 is
`ebe6e455fed65a38159a5a33a4672039e0c4741818b60bc3b655eca8ec60ab15`.
This is smoke evidence with `qualified=false`; it does not replace either the
500,000-message fsync-off comparison or the fsync-on durability/soak campaign.

Formal launcher v5, run `7a1aa007-8e7c-4371-97ae-9ae433654406`, advanced into
the first real fsync-off 10KB Rust measurement but failed before completing the
single 500,000-message endpoint invocation. At the fixed measurement deadline,
PostgreSQL contained 32,151 exact sender/receiver pairs and 32,151 terminal
outbound rows while the passive SMTP proxy had verified 32,149 messages.
Application cleanup then timed out with 32,234 Redis keys and 3,168 outbound
spool files in its last unstable snapshot, and the Python Maildir inotify
observer reported a queue overflow during the deletion burst. The launcher
published no final JSON or checkpoint. Its protected journal records
`request=ABORT`, `cleanup=passed`, no lazy unmount, and no recovered run; the
ext4 image, mount, cgroup, and root artifacts were absent after exit. The
bounded failure record is
`smtp-endpoint-throughput-fsync-off-formal-v5-failure.txt`. It has
`qualification=false` and cannot support any throughput claim. The failure
requires separate fixes for the candidate's foreground per-message persistence
bottleneck and for the harness's high-cardinality cleanup/observer paths; no
threshold or requested count is reduced.

Before the batch path existed, the bounded 8-versus-32-worker follow-up was
recorded in
`smtp-rust-stress-persist-lock-profiler-v1-failure.txt`. The profiler-only
enqueue observer reached both worker limits, but increasing the 10KB stress
worker bound from 8 to 32 changed the initial diagnostic rate from about 66.2
to 64.3 messages/second. At 9,472 observed completions the 32-worker run had
accumulated 4,546.9 seconds in persistence and 130,549.3 seconds waiting for
admission, versus 62.7 seconds materializing and 5.9 seconds publishing. Every
admission transaction holds the same PostgreSQL advisory transaction lock
through its per-message commit. The 32-worker hypothesis was therefore rejected
for that per-message implementation and the bound was restored to 8. The
post-batch sweep above supersedes that bound because one transaction now
coalesces multiple authorities instead of holding the lock through every
message independently. The 8-worker
`perf` capture lost 19 chunks and itself caused an approximately 30-second I/O
stall. Its 1.2 GiB raw file was hashed, documented, and removed, and neither
diagnostic is eligible for a throughput claim.

### Receipt-capacity and startup diagnostics

The v43 receipt-capacity diagnostic is retained as four component logs named
`smtp-rust-receipt-capacity-profiler-v43-*.log`. The candidate queue observer
advanced to 17,408 completed Redis publications with zero classified publish
failure, while the stress observer reached the same 17,408 completed publish
stages. This is direct evidence that the former 4,096-entry cleanup-receipt
ceiling no longer stalls publication. It remains an interrupted profiler run,
not a completed 500,000-message benchmark or persistence qualification. The
candidate, proxy, PostgreSQL, and Redis log SHA-256 values are respectively
`261a2c2385456bdee145bd645551ca26891cab3f3ab2115d04bf90a3920b72fc`,
`2e531cc479ed24acbf355b9b51e9633660b641a42115c8ac4dcd719d6f0e24da`,
`8901447f5f40f9390985280bfd659fbc27522dc233cde06da8511b8b351acb09`,
and
`e0618fad3eb2e6097538dd652e80e5e6b241645556e219527b233bab54df2315`.

The post-capacity v45 CPU capture is
`smtp-rust-post-receipt-capacity-cpu-clock-v45.data`, with separately saved
flat and children reports. The 473,160-byte capture reports zero lost samples.
Its largest flat entries were RSA/DKIM squaring at 10.44%, kernel socket wakeup
work at 8.65%, CRC32C at 3.67%, and another RSA multiply kernel at 2.98%.
No single new CPU hotspot explains the remaining endpoint latency; the stage
observers continue to place the dominant wall time in SMTP final replies and
PostgreSQL commits. The data, flat-report, and children-report SHA-256 values
are
`d6861aa83bcd099ddaac845db7144c6886f4f8bf0de6f0cf2bba182894faae10`,
`30f2e98c177d65220bf2cc6c3a75465bb993c02cec4efacc67eed5d326808ff2`,
and
`48c7884dd782a289b55de1b541d59148d0b33e7d1b2ca63850d58850977066b2`.
The accompanying v45 candidate, proxy, PostgreSQL, and Redis logs hash to
`9d6891a175b765ba99377294beb4e1989cfb9da37bbb858bfa443106fb635c8f`,
`0522733284bdbad506468d1b0e40f67b6c2e4992bd525fd2aa9319c51a41483a`,
`9fdf608a703a79e6817a4075cbf50ba8830f3496bf5778fbb1f9c90b70a2cc67`,
and
`1904c88270c282730f92a9647d52f944b4ff47e0fda0b65689bd4bb8df6bfbc5`.

The historical v44 startup failure predates the added Redis acquisition,
command, result-bound, and HTTP-startup diagnostics; its only candidate line
was `lmyzmail HTTP service failed: outbound queue unavailable`, so it cannot
be classified further. Manual isolated startup attempts v46 through v53 all
reached readiness and did not emit any of those new classifications. Their
run-specific abort/recovery cleanup found no residual process, loop device,
mount, or child cgroup. Those attempts did not publish create-only artifacts,
so they are reproducibility context only and do not prove that the startup race
is fixed. A newly classified reproduction or a bounded repeated-start
qualification remains required before any retry policy is added.

## Renderer SIMD kernels

`run-renderer-simd-v1.sh` builds the feature-gated `renderer-simd-bench`
binary and launches scalar, AVX2+FMA, and AVX-512F as three independent
processes. Each process decodes frame zero of the frozen 1920x1080 MP4 before
timing, then measures the production resize, contrast, block-palette RGB, and
map-palette stages at square edges 64, 128, 256, and 512. The 64x64 case times
block-state conversion at the production `MAX_BLOCK_PIXELS=4096` boundary;
larger block-state rows are reported as not applicable, and the harness never
invents chunked work.

The binary rejects a requested backend unless the production dispatcher
resolves to exactly that backend. `--unsupported record` emits an untimed
capability record, while `--unsupported fail` exits without an output report.
Every report includes `fallback_used`: it is false for timed results and true
only for unsupported requested/resolved mismatches.
Warmup and hashing occur outside measured intervals. Each stage records all 30
fixed-iteration samples plus the median and nearest-rank p95 in nanoseconds.

Run a short contract smoke first:

```bash
evidence/performance/run-renderer-simd-v1.sh \
  --smoke \
  --output evidence/performance/renderer-simd-smoke-v1.json
```

The formal profile uses five warmups and 30 measured iterations per stage:

```bash
evidence/performance/run-renderer-simd-v1.sh \
  --output evidence/performance/renderer-simd-formal-v1.json
```

The launcher fails before publishing evidence if any supported SIMD output
hash differs from scalar. The aggregate JSON records CPU flags, toolchain,
target, release profile, `RUSTFLAGS`, backend capability decisions, the binary,
`Cargo.lock`, relevant source, MP4 asset, decoded frame hashes, and both Git
dirty-status and tracked-diff digests. Evidence paths are create-only.

## Inbound index substage profiler

`smtp-rust-inbound-index-substages-profiler-v54.json` is a focused diagnostic
run after the receipt-capacity work. It used the original 10KB stress endpoint
with the Rust profiler candidate and `filesystem_fsync=off` to match the Java
throughput mode; PostgreSQL itself remained `fsync=on`. The run was interrupted
after 8,704 coordinator tasks, and the candidate log retained 8,660 completed
inbound index commits. Redis publication completed 18,621 times with zero
classified failures.

The substage timers directly identify the bottleneck: the shared
`lmyzmail_inbound_mail_count_state` `ON CONFLICT` increment consumed
5,521,072,392,593 ns of 5,812,138,226,298 ns in the enclosing inbound index
commit, 94.99210407%. Its mean was 637.390 ms and its maximum was 8.003 s.
The transaction commit substage averaged 9.131 ms, so WAL/fsync commit latency
is not the dominant wall-time cause in this sample. All self-SMTP messages use
one mailbox/folder, which makes this row-lock serialization visible.

The run is diagnostic only: `formal_benchmark=false`, `qualification=false`,
and it carries no throughput claim. The launcher received `SIGINT` before its
own trap could finish; its normal recovery path then produced a create-only
receipt with `request=RECOVERY`, `cleanup=passed`, `lazy_unmount=0`, and no
remaining process, mount, loop device, cgroup, image, or provisional artifact.
The four service logs, launcher log, receipt, source hashes, and binary hash
are recorded in the JSON. No SQL or default durability behavior changed.

The follow-up batch-committer profiler attempt is recorded as
`smtp-rust-inbound-index-batch-profiler-v55-failure.json`. It intentionally has
no measurement or throughput claim: an external timeout terminated the root
launcher before its runner completed. The launcher recovery protocol then
reported `cleanup=passed`, `recovered=1`, and no residual process, mount, loop,
or workload cgroup. This is negative harness evidence only; the next short
benchmark must stop through the runner's own bounded completion path rather
than an outer signal.

The next two bounded 8,192-message attempts remain negative evidence.
`smtp-rust-inbound-index-batch-profiler-v56-failure.json` used a profiling
binary whose timestamp preceded the batch source, so its 73.68 messages/second
window is invalid for comparing the implementation. It also overflowed the
Maildir inotify queue and ended with 14 PostgreSQL rollbacks. No throughput
claim is made from that run.

`smtp-rust-inbound-index-batch-profiler-v57-failure.json` used the rebuilt
profiling binary and completed all 8,192 messages without failure or loss in
74.257 seconds, a diagnostic load-window rate of 110.32 messages/second. The
batch path reduced the shared mailbox/folder count work from thousands of
seconds to 9.845 seconds across 2,228 updates; 1,114 index transactions averaged
7.35 messages each. All queue rows reached `SENT`, recipients reached
`DELIVERED`, attempts reached `PROJECTED`, and email-index, Maildir, and spool
transient state returned to zero. The strict 30-minute cleanup gate nevertheless
rejected the run because `database_xact_rollback` was 57. Since no qualifying
artifact existed, the root receipt was not published; a post-exit audit found
no run process, mount, cgroup, or runtime directory. The recorded load rate is
diagnostic only and is not a benchmark result.

The rollback source was the no-write stale-claim branch of
`PostgresDeliveryState::release`, which explicitly rolled back after fencing.
It now commits that read-only transaction to release locks without manufacturing
a rollback statistic. The real-PostgreSQL regression first proves that an
explicit control rollback increments `pg_stat_database.xact_rollback`, then
proves a stale `release` returns false without another increment. The complete
`outbound_delivery_postgres` integration target passes with this change.

`smtp-rust-inbound-index-batch-profiler-v58-failure.json` is a third negative
artifact. The rebuilt candidate completed all 8,192 messages with zero failure
or loss in 74.834 seconds, a diagnostic load-window rate of 109.47
messages/second. It used 1,098 index transactions, averaging 7.46 messages per
batch, and spent 9.429 seconds in the mailbox/folder count update. Business
state converged, but `database_xact_rollback` reached 59, so the strict gate
made qualification impossible and the run was stopped through the launcher
trap. Stale-journal recovery emitted a create-only receipt with
`request=RECOVERY`, `cleanup=passed`, `lazy_unmount=0`, and `recovered=1`; no
run process, mount, loop device, cgroup, or run directory remained. No formal
throughput claim is made from this run.

The remaining rollbacks came from two inbound read-only advisory-lock
transactions: intent reconciliation and the tracked branch of staging cleanup.
Both now commit their read-only transactions to release the locks. A real
PostgreSQL regression first proves a control rollback is observable and then
proves both paths add no rollback. The throughput runner also fails closed as
soon as the monotonic rollback delta becomes nonzero instead of waiting for the
full cleanup timeout; the required delta remains exactly zero.

`smtp-rust-inbound-index-batch-profiler-v59-failure.json` records the first run
with those inbound changes in the profiling binary. It completed 8,192/8,192
messages with zero failure or loss in 76.022 seconds, but the immediate gate
still observed `database_xact_rollback delta=59` and rejected the run. The
ABORT receipt reports successful cleanup with no residual resource. Its
107.76 messages/second load-window rate remains diagnostic only.

The follow-up PostgreSQL statement trace is summarized by
`smtp-rust-rollback-trace-profiler-v61-failure.json`; the create-only raw log is
`smtp-rust-rollback-trace-profiler-v61-postgres.log`. The 512-message diagnostic
observed five rollback statements. All five immediately followed the same
`mark_outbound_spool_removed` `SELECT ... FOR UPDATE` with no matching sidecar
row, for task IDs 412, 413, 417, 420, and 431. A concurrent terminal cleanup
had already deleted each row, and the missing-row error dropped the open
transaction. The exact path now commits and returns idempotent `false`, matching
the existing reconciliation and exact-delete semantics. A real PostgreSQL
regression proves the path does not increment `xact_rollback`; the complete
`outbound_delivery_postgres` target passes 12/12, and the formerly failing
Redis-ack sidecar retention integration test also passes.

`smtp-rust-inbound-index-batch-profiler-v62-invalid.json` records the next
8,192-message diagnostic. The candidate accepted every message with zero
failure or loss in 75.236 seconds, or 108.88 messages/second during the load
window. Its 1,114 inbound index transactions averaged 7.354 messages per
batch. The run is observer-contaminated and makes no throughput claim: an
out-of-band autocommit query used a nonexistent recipient `status` column and
created the only PostgreSQL rollback. This was not a candidate rollback. The
runner correctly rejected the zero-rollback gate and root cleanup left no run
resource behind. The invalid evidence JSON hashes to
`0af976660dc92303cdeadac1a9144101bfe2c9f94566ed69753752ff6720d897`.

`smtp-rust-inbound-index-batch-profiler-v63-failure.json` reran the same binary
without connecting an observer to the isolated PostgreSQL or Redis services.
All 8,192 queue rows reached `SENT`, recipients reached `DELIVERED`, attempts
reached `PROJECTED`, the 16,384 email-index insertions were matched by 16,384
deletions, PostgreSQL rollback remained zero, and Maildir, spool, DSN, and
email-index residuals were zero. The run nevertheless exceeded the strict
1,800-second automatic-cleanup window. Stable empty migration tokens reused an
`EMPTY` receipt every second, and the legacy-list claim script refreshed both
its TTL and done-index zset score on each suppress-mode poll. Exact Redis value
hashes therefore never produced three identical semantic snapshots. The
failure JSON hashes to
`f3fc747ca79701d9e53871be6af1caa92bf38645bb2fcc6a102315a633e09c6c`;
its root cleanup receipt hashes to
`aa4fcc6e55e5ba8a7101039efe7ad568f870039f3181db05618a619147fb9274`
and proves no residual process, mount, loop device, cgroup, or run directory.
The failed launcher did not publish provisional load metrics, so none are
inferred from truncated console output.

Suppress-mode empty legacy migration polling now returns an existing `EMPTY`
receipt without refreshing its TTL or done-index score. Public create-mode
claims retain the existing refresh behavior, and a newly nonempty legacy list
still retires the empty receipt before recovery. Redis integration coverage
shortens both receipt TTLs, waits across a one-second boundary, and proves the
TTL and zset score remain unchanged after another migrator poll while external
receipt purge and archive recovery continue to work.

## Outbound connection pool and inbound batch-window diagnostics

The connection-pool smoke runs v69 through v71 are diagnostic only. V69 sent
64/64 messages without loss, but was too short to retain coordinator records
and failed the queue-scheduler and throughput-stability gates. V70 sent
512/512 without loss but still opened 239 SMTP connections. After the pool
lifetime and stale-socket fixes, v71 sent 512/512 with zero failure, retry, or
loss and opened only 54 connections; no new connection was opened during the
second 256 messages. V71 still failed the unchanged short-run stability gate.
The v69, v70, and v71 console SHA-256 values are respectively
`d718c573a37be113031e3dbd9ee2751a9ae8e0098e7a3e35356c99ed38eb0341`,
`b005c9dead77fdb1be91b3ee5a84890d71ecafc70c74e912a3b633c87063d695`,
and
`63697fbd69b1bce082b13e2e587c99ee4d84c579cb6f922ee5d573c7f738d1c8`.

V72 extended the same fsync-off 10KB diagnostic to 8,192 messages. Every
message was queued and received with zero failure, retry, or loss. Only 58
connect, greeting, and EHLO operations were observed, 99.29% fewer than the
8,192 operations in the pre-pool v67 diagnostic. Queueing took 36.745 seconds,
delivery took 38.352 seconds, and total time was 75.097 seconds, only 2.41%
below v67. The four quartile rates were 84.32, 105.06, 140.22, and 131.74
messages/second, so the 47.21% relative range failed the unchanged 30% gate.
This proves that pooling works but is not the dominant bottleneck; it is not a
formal throughput result. The v72 console SHA-256 is
`24ca3a2e6f8ce93f679313ebba5c43a3eb3a6d11f20c0fc57b1613936f0cf4ef`.

V73 attempted two 30-second PID-attached `cpu-clock` captures. Tokio's thread
count caused one software event per candidate thread, and WSL retained only 13
and 12 samples. Those captures are explicitly unusable for optimization
claims. Their SHA-256 values are
`778db3c84e47b5f593e6e3ad41de57d8c9fad0394de7c472e7593aa8da73f336`
and
`62c267e2b4858518b02504e7d54b16a1d38ee3a62713490502ae3a08bd70d11d`;
the console SHA-256 is
`90634d6f877f45a26d872b2ac8b8e8599587700475bb84dac7957d43c851c79e`.

V74 instead sampled CPU 23 directly at 99 Hz for 30 seconds while the unchanged
2 ms candidate processed 4,096 10KB messages. The capture retained 2,970
samples with zero loss. By command, 59.97% of samples were candidate Tokio
workers, 13.84% were the stress thread, and 26.19% were idle `swapper` or
`kworker/dying`. No candidate user-space self hotspot exceeded 1.01%; the next
largest were mutex contention at 0.81% and the PostgreSQL connection poll at
0.71%. This rules out a single compute hotspot at the resolution of this run
and supports the wall-stage evidence that latency is dominated by serialized
database work. The profiler-contaminated run delivered 4,096/4,096 with zero
failure, retry, or loss, but failed the stability gate and makes no throughput
claim. Its 524 inbound index transactions averaged 7.82 messages each.

The v74 data, flat report, children report, comm report, and console hashes
are respectively
`b2b127b4a56ab90d51bfb48a752f5996227690eb804e6d2eb94f85a9224cc806`,
`a0e187b23c3479bf31ed3a571f64dccf588b78c3919b4969e765aeaf36205563`,
`91910f90ea47a6a9c1f46aa59a22a7791af09c93ba7ce3f369bc23308ccd43dd`,
`db25429769d7cd5b20f9c7f97d0305987d7b0b01f55abeb68ac4bdd838abb939`,
and
`3b3f5c613c490e6047d6f887b554944cfe8ca5aa8f8ac7c8febe698cea20d4d8`.
Run `0207a5f3-bd1f-4c85-aa3e-aef41b7aa6b1` ended with
`request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`; the copied receipt
hashes to
`a0aa2e51b875bfc69c06425a13c2a6d6c8877a23712fde3b2752cf30135fc6ec`.

V75 tested only one follow-up variable: increasing the inbound index collection
window from 2 ms to 5 ms. It delivered 512/512 with zero failure, retry, or
loss. The 63 transactions averaged 8.13 messages each, versus 70 transactions
and 7.31 messages each in the comparable 2 ms v71 run, but total time was
6.077 seconds versus 6.073 seconds and final-reply latency did not improve.
The unchanged stability gate also rejected both short runs. The window was
therefore restored to 2 ms: the small batching gain did not improve the target
metric. The v75 console SHA-256 is
`8b1685475e31b9d573e355bd145a3be5981028d654660095767b539a70ec4ec7`.
Run `44ec886d-55ae-4e84-9ef0-a57e0f7f0241` ended with
`request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`; the copied receipt
hashes to
`dc191395cb1701e4a335430068ac996870d7be91ab6ef5146241648da67aa46e`.

V76 tested one further PostgreSQL round-trip hypothesis: combine the per-group
advisory lock and count-state update in one CTE while preserving the existing
transaction and replay semantics. It delivered 512/512 with zero failure,
retry, or loss. Count-state instrumentation was reduced to one stage completion
per transaction, but delivery took 4.029 seconds and total time was 6.825
seconds, versus 4.023 and 6.073 seconds in the comparable v71 run. The
unchanged stability gate rejected the run. Because neither the delivery nor
end-to-end target improved, the combined statement was removed and the
production SQL restored. The retained multi-folder legacy count-state
regression test passes against the restored path. The v76 console SHA-256 is
`8788b6904762edc8aa7a913c5080acbf08c039bbd8896987f66907c9b1c4fdcc`.
Run `5915b6aa-aa12-48d0-b987-ab3ef8e27663` ended with
`request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`; the copied receipt
hashes to
`555af993063321ac08191e3c9f25725442e1bc9d59ee068484c96333bbf605bd`.

After the v76 rollback, the current 2 ms/original-SQL profiling ELF was rebuilt
as v77. The fixed profiling artifact and Cargo output are the same hard-linked
inode and hash to
`1fd60862ed53345122fc39ab0353b65e1c6b003c4631c3b066c52c6c4bf39efb`;
the ELF Build ID is `31686ab8afdcc0de0e25a7fb12788ab540cd5d00`.

V78 recorded every PostgreSQL statement duration during an otherwise unchanged
4,096-message fsync-off diagnostic. It delivered 4,096/4,096 with zero failure,
retry, or loss in 41.220 seconds, or 99.37 messages/second, but failed the
unchanged ramp-up stability gate. The transaction-aware analyzer reconstructed
133 complete inbound batch transactions. Their mean wall time was 53.015 ms,
while PostgreSQL logged only 14.713 ms of statement execution; the unexplained
client round-trip and scheduling gap was about 38.3 ms, or 72% of transaction
wall time. The existing-index lookup averaged 5.155 ms of server execution and
COMMIT averaged 5.718 ms. This is direct evidence that sequential database
exchanges, rather than one server-side query or CPU hotspot, dominated the
inbound index path.

The final v78 summary, console, raw PostgreSQL log, and cleanup-receipt hashes
are respectively
`9ab6afd01f097c45d7660a977a10011f9c71cc9ee8504421cee3ec077f153760`,
`a5f9d1c715f8b688183069e64210e4b1bb9f1f9c9f7bc9cedf3202a3e6ec9992`,
`c7f1fefd75a35297305f95c9141c948f1feea5b60385c9e10c15eb8621d88c15`,
and
`227b6eca0a0a79cb709cb22ef8424c1217e09ad449dc3ddc60e831f305485e7c`.
Run `1d5aab79-4798-42f3-8577-0b78799f88fa` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`.

V79 captured CPU 23 scheduler events without callchains while the same
4,096-message workload delivered every message with zero failure, retry, or
loss. The profiler-contaminated run took 44.892 seconds and failed only the
unchanged stability gate. During the 30.003-second trace, CPU 23 was idle for
5.168 seconds (17.22%). The main candidate Tokio worker had 115,712 sched-ins,
13.243 seconds of runtime, a 0.114 ms average run slice, and approximately
0.081 ms average scheduler delay. The capture retained 372,822 events without
a lost-event warning. This rules out candidate CPU saturation or scheduler
starvation as the source of the multi-millisecond PostgreSQL exchange gaps.

The v79 console, scheduler data, timehist summary, latency report, and cleanup
receipt hashes are respectively
`0a24a7733056a8e3ad147f1c5f6413a7f3ad331798a569aed253b115d217c2de`,
`cff03d24a89c2979740122d5ea9b3dc9632a09b59f00d9240e7513a0aedc2233`,
`1bf0ac20095defcf6def6f9c6ee6bad17d25f4a420a316a81ef8e702358201af`,
`56f3dd97d79850f45c412fd1395dcf124486563ffa8769c11b746bb0cdd2d221`,
and
`b8ced1387a514045d998b8bf4c32a4377af046a6aa237d399e2aa1785210cf47`.
Run `7034dcb8-bd31-49a1-ba28-e03cbcb9ebf6` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`.

The retained follow-up combines the batch intent identity read, mailbox
key-share read, and exact existing-index read into one PostgreSQL statement.
It preserves the existing order of advisory intent locks, durable intent row
locks, and mailbox key-share locks by using materialized, data-dependent CTEs.
It also preserves request-specific errors, exact replay validation, count
locks, count-state repair, projection updates, intent advancement, and commit
reconciliation. All 15 inbound-delivery module tests pass, including first
commit, replay, legacy count-state initialization across folders, batch versus
single-recovery concurrency, request-failure isolation, and rollback
accounting.

V80 and v81 repeated the same 4,096-message, 10KB, fsync-off, single-CPU,
500 MB/s diagnostic with only that validation-read fusion changed. Both
delivered 4,096/4,096 with zero failure, retry, or loss. V80 took 36.809 seconds
at 111.28 messages/second; v81 took 36.741 seconds at 111.48
messages/second. Their delivery phases were 19.124 and 19.147 seconds, and
their final two quartile rates were 148.22/145.49 and 148.39/148.10
messages/second. The two-run mean was 111.38 messages/second, 12.09% above the
v78 diagnostic, while mean delivery time fell 13.75%. Both runs still failed
the unchanged ramp-up stability gate, so these are repeatable retention
evidence for the optimization, not a formal throughput result.

The v80 console and cleanup-receipt hashes are
`70570c69a7a087cc607e3cd6fb6cc4b91b0e7e028d04f0b2e914524248d13453`
and
`574ca6c6cd7816b0be21c7f41ebbe8a8530f5f98bac21d6ea4fba50c74ab663e`.
Run `0bb4a1dd-a994-49ec-9991-250f3a3344c0` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. The v81 console and cleanup-receipt
hashes are
`dc675ab0532aca1815176bf9e497bc5413c74d661c163185a073a3746678a6aa`
and
`1d4d72314ec06e2f4ac575c4438ff9d3c8d178292b3042d2cb6a5c72f80ca95a`.
Run `1f97018f-79a2-4fd0-a168-c262bfb5d153` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`.

The retained v80/v81 profiling ELF and Cargo output are the same hard-linked
inode and hash to
`9963ce0abf28cbfb0aab76983c3a4e611d4dc96a8f8d9a39d4593643bef2aed1`;
the ELF Build ID is `4a894dda8a94adb60e3c5b49018b6a545fae1940`.

V82 traced every PostgreSQL statement after validation-read fusion and before
write mutation fusion. It delivered 4,096/4,096 messages with zero failure,
retry, or loss in 38.244 seconds at 107.10 messages/second; delivery took
20.165 seconds. The trace reconstructed 614 complete inbound index
transactions. Their mean wall time was 48.623779 ms, PostgreSQL logged a mean
10.410941 ms of execution, and the remaining client/round-trip gap was
38.212838 ms. Each transaction had 23 duration records. The 63 rejected
duration lines were startup or log-header records without a parseable
timestamp, not candidate or database failures.

The v82 console, PostgreSQL log, summary, and cleanup-receipt hashes are
respectively
`5a315c316249d447020c7031ca7ff7b5f02b3fc50065ba5e022c3b67e787d477`,
`1e5a91b7bcee8dbd4b69d382c2a6c3a5a2b60af7337ec03177f451da269e0f05`,
`da328b12001e40a7ff1396ff8d70f791df49d59e98922c4c3daf97a58acdf86c`,
and
`9b4515fa6d6202d4fa5d7ae4e274c5d1abd72030fe2c542b1fd5c8a544b1bdea`.
Run `6affa273-2d21-458e-9e60-a0275ae8cec5` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`.

The retained mutation fusion replaces four ordered write exchanges with one
data-modifying CTE after the existing count advisory lock. The statement
inserts missing `email_index` rows, rebuilds exact count state, advances the
count projection, and advances every durable inbound intent. It returns the
actual index, count-state, projection, and intent row counts; Rust rejects the
transaction unless all four match the request. Advisory lock order, durable
intent and mailbox validation, replay checking, transaction commit
reconciliation, and the separate count-lock exchange remain unchanged.

V83 and v84 repeated the same 4,096-message, 10KB, fsync-off, single-CPU,
500 MB/s diagnostic with only mutation fusion changed. Both delivered every
message with zero failure, retry, or loss. V83 took 36.195 seconds at 113.16
messages/second and v84 took 36.194 seconds at 113.17 messages/second; delivery
took 19.153 and 19.108 seconds. Their two-run throughput mean was 113.165
messages/second, 1.60% above v80/v81. Both used 735 inbound index
transactions, or 5.573 messages per transaction. Mean lock-following write
work (count lock, mutation, and commit) fell from approximately 24.87 ms before
fusion to 13.79 ms after fusion, a 44.5% reduction. Both runs failed only the
unchanged ramp-up stability gate, so the figures retain the optimization but
do not qualify as formal throughput evidence.

The v83 console and cleanup-receipt hashes are
`de43795af65cacc33062c8c844b490aa48cc054113a6feab424b1fb51f35b061`
and
`e7683811060224ea957f30c7745e2b1cdc352b5f79659ee8688884b4feb08988`.
Run `c00d4dfd-8e55-423c-a376-edb2a2909ae3` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. The v84 console and cleanup-receipt
hashes are
`1625f9784c201c521a2e690057f7f2e6edce8e8db4474f783da293d7585efce6`
and
`473ce3dc9f92b4e76c08a6d154df2a8589722253a876520598304e8e9083f28d`.
Run `71530183-145d-4000-b266-b10c263dd567` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. Their profiling ELF hashes to
`b96aab073158f011b97e57a0e4f379af58ac128e80a9100d59a748568f52b0cc`;
its Build ID is `9a53eccd3d81e6a80644e25f354e4e714e958e61`.

V85 traced the retained mutation-fused form. It delivered 4,096/4,096 in
38.170 seconds at 107.31 messages/second with zero failure, retry, or loss;
delivery took 20.189 seconds. The trace reconstructed 761 complete inbound
transactions. Mean transaction wall time was 36.084100 ms, mean logged
execution was 10.857945 ms, and the client/round-trip gap was 25.226155 ms.
The duration-record count fell from 23 in v82 to 14, exactly matching the three
eliminated extended-protocol write exchanges. The remaining serialized
exchanges are transaction begin, intent advisory lock, fused validation,
count advisory lock, fused mutation, and commit. The 67 rejected duration
lines were the same startup/log-header parse noise as v82.

The v85 console, PostgreSQL log, summary, and cleanup-receipt hashes are
respectively
`ae93f393a56f0c3fbde8cea61c69c382a7d91eb2f135d220c8384615f30b83a7`,
`a855e33755cc922138acec57eccda13266857e4356b08b2bd0483b1a272725dc`,
`6f773f476aa55d3779bbc431920e22741e049fda90d13a53f0a11022efdea6d8`,
and
`bd25ecb15b5f80929ea631670de0135992959b36e460374b546da6212088a122`.
Run `a6aeccbe-2366-4de2-a846-4591c8ccb93e` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`.

V86 and v87 tested one further round-trip hypothesis: acquire the sorted
intent advisory locks inside the validation CTE while retaining explicit data
dependencies from advisory locks to durable intent row locks and then mailbox
key-share locks. Both delivered 4,096/4,096 with zero failure, retry, or loss.
V86 took 36.804 seconds at 111.29 messages/second and v87 took 36.557 seconds
at 112.04 messages/second; delivery took 19.150 and 19.137 seconds. The fused
lock-plus-validation stage averaged 9.069 ms, 33.17% below the 13.570 ms mean
for the two separate stages in v83/v84. However, faster transactions reduced
self-batching: transaction count rose from 735 in both retained runs to 813
and 818, reducing mean batch size from 5.573 to 5.023. Their throughput mean
was 111.665 messages/second, 1.33% below v83/v84. The hypothesis was therefore
rejected and the separate intent-lock exchange restored.

The rejected v86/v87 profiling ELF hashes to
`c4ae8f055ec17ec6c93457d214506c26c121770d48c9c5cf844be253bbb92ccc`;
its Build ID is `aa11abbb1f71989a93734472a0fc7f8ebffb4b20`. The v86 console and
cleanup-receipt hashes are
`e95c4c7c41b6a239dfe5400de990ef6b0e7b654952f37de8bd6f24ec46ec694f`
and
`20c43a4c92edf2ead8017ec7be961fc207797f508766eafd43ff7f25a62cdf66`.
Run `3134d869-e350-41e8-8cbf-7be5aa2e2b2c` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. The v87 console and cleanup-receipt
hashes are
`c0f1f71b544e49fb9bdff6b9699ff84a24436acc63a060ca9ec4290522ed3d55`
and
`57767ad323e8e9062557f5de6e406d3cbdb07eb4106019f5ef0b6919588353b7`.
Run `d42af4af-fb9a-4cfa-85bb-c2c552ab4661` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`.

V88 and v89 tested whether a five-millisecond inbound collection window could
recover the lost batching while the rejected intent-lock fusion remained in
place. Transaction counts fell to 757 and 750, or a 5.436-message mean batch.
V88 took 36.431 seconds at 112.43 messages/second and v89 took 36.411 seconds
at 112.49 messages/second; delivery remained 19.147 and 19.161 seconds. Their
112.46 messages/second mean recovered 0.71% over v86/v87 but remained 0.62%
below retained v83/v84. The extra three milliseconds of per-batch collection
latency offset the transactions it eliminated. The five-millisecond window
was rejected and restored to two milliseconds together with the separate
intent-lock exchange.

The rejected v88/v89 profiling ELF hashes to
`2b02c1f992d0ee8b489519c3dfbc4d6d6e55e46ab730f36f6b45c4b6b5dcb0be`;
its Build ID is `11d7a8e7cc977ccc7ac42b62131f01479b7fd125`. The v88 console and
cleanup-receipt hashes are
`a579054d68a8d47be27732fce995bb09267d49c76e60c353bb457126b21e18bb`
and
`76b744c0c6355bd600bd018a2a4e7dba1452c1e1b7197b7a865e77328493861b`.
Run `8e0ba025-88a2-42e8-acd5-835c9c47d7eb` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. The v89 console and cleanup-receipt
hashes are
`8ff2e3036f63215af66270a046f113a758f65929f3f76cc1d330be741ca07d9e`
and
`fcc7252675795851e141a2df693a601bd6adb7ef7d6e4c338c2e80408ff296e9`.
Run `a71c2b66-81a6-4835-9b16-f4ee006fa926` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. All four rejected runs failed only the
unchanged ramp-up stability gate and retained no qualified throughput
artifact. After restoring the retained v83/v84 shape, all 15 inbound-delivery
module tests pass, including batch replay, legacy count-state initialization,
batch/single recovery concurrency, request-failure isolation, and rollback
accounting.

V90b reran the restored mutation-fused shape from commit `816f7da4` after the
recovery audit. Two clean rebuilds from that commit produced the same profiling
ELF SHA-256,
`0a20582506be4eeda1257176b82488c55aeaf1fd1493c26e006a0999cb5b9de5`,
and Build ID `c435828cacdd1c15f2be21abeccc19d0a9aa3e0c`. The run delivered
4,096/4,096 messages with zero failure, exception, retry, or loss in 36.345
seconds at 112.70 messages/second; delivery took 19.135 seconds. It used 743
inbound index transactions, or 5.513 messages per transaction, which restores
the v83/v84 transaction shape and throughput. Its quartile rates were 89.71,
112.94, 145.15, and 147.01 messages/second, so it failed only the unchanged
30% ramp-up stability gate and is diagnostic rather than formal throughput
evidence.

The v90b console and cleanup-receipt hashes are
`558654a1df75adf4ab7107aaa6ebf8b0dbf8d07f5ac7b328898daa44c36dc86d`
and
`08bb7ec6486722cf3fa34b79d993d4a2100c1560c8aa47ecff3801fc302be601`.
Run `b991fdca-9cd1-454b-826d-d91afbd9d131` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. The watchdog refused to signal the
already-exited runner after the failed stability assertion, so no qualified
artifact or runner-success receipt exists. A root audit confirmed that its
cgroup, mount, image, loop device, artifacts, candidate, PostgreSQL, and Redis
processes were absent before this unqualified receipt was retained.

V91 repeated v90b with the same ELF and isolation settings. It delivered
4,096/4,096 messages with zero failure, exception, retry, or loss in 35.912
seconds at 114.06 messages/second; delivery took 19.154 seconds. Its 737
inbound index transactions averaged 5.558 messages each. V90b and v91 have a
113.38 messages/second mean and a 1.20% relative range, confirming that the
restored source reproduces the retained mutation-fused baseline. V91's
quartile rates were 93.52, 110.78, 142.75, and 147.27 messages/second, so it
also failed only the unchanged 30% ramp-up stability gate and remains
diagnostic rather than formal throughput evidence.

The v91 console and cleanup-receipt hashes are
`23db3d1a80a30a826633018bd592d79600f03ed7f35841a0477f3826c88d9dd4`
and
`d665f3483dffb4afb0b61f991e47600a537eff30f04616b7c32164d89da8f817`.
Run `845430ec-b405-41fc-902f-12f052c6f9eb` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`; a root audit again found no residual
run resource or service process.

V92 tested a rejected full-transaction fusion. It reduced the retained six
PostgreSQL exchanges (begin, intent lock, fused validation, count lock, fused
mutation, and commit) to begin, one materialized statement, and commit while
preserving the existing lock order and validation-before-mutation dependency.
The database failure-atomicity gate covered a missing intent, durable identity
drift, a missing mailbox, mismatched replay content, and duplicate replay under
a NULL shard; a separate database oracle found identical index, intent,
count-state, and projection snapshots for the fused and retained paths.

The run delivered 4,096/4,096 messages with zero failure, exception, retry, or
loss in 36.470 seconds at 112.31 messages/second; delivery took 19.147 seconds.
It used 981 inbound index transactions, or 4.175 messages per transaction,
versus 737 and 743 transactions in v90b/v91. Its quartile rates were 90.58,
110.41, 144.62, and 143.42 messages/second, so it again failed only the
unchanged 30% ramp-up stability gate. Although the fused statement reduced
per-transaction PostgreSQL time, its smaller self-batches left throughput
0.94% below the 113.38 messages/second v90b/v91 mean. The experiment therefore
failed the retention gate and the production path was restored.

The rejected profiling ELF hashes to
`10591053dc6a9ebd8044628782cfe81f7a685f00febac18b34d588811839dea6`;
its Build ID is `1276c9f1fab5c48153376bf9df6b4c0f2d36830c`. The v92 console
and cleanup-receipt hashes are
`5e3ba90480480bf76a961dccd68f56206f10a5d77ca9644d27bc5b3aaa172725`
and
`9d8eec9d91614d3788314a9e27f2e702c67dd31d9d9cd4e7a636bfa3c8113405`.
Run `e196896f-f789-4ac2-8ee0-c029e3b99b73` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. A root audit confirmed its cgroup,
mount, image, loop device, artifacts, candidate, PostgreSQL, and Redis
processes were absent before the independent unqualified receipt was retained.

The restored current-HEAD `release-with-debug` profiler build was reproduced
twice with `CARGO_TARGET_DIR=target/profiling` and the locked toolchain. The
main binary and its deps hard link are one inode and byte-identical on both
runs. Their SHA-256 is
`0a20582506be4eeda1257176b82488c55aeaf1fd1493c26e006a0999cb5b9de5`, Build ID
`c435828cacdd1c15f2be21abeccc19d0a9aa3e0c`, and size 218,842,472 bytes.

V93 is a profiler-only Rust 10KB fsync-off diagnostic at the current HEAD.
It completed 8,192/8,192 messages with zero failure, retry, exception, OOM, or
loss at 114.20 messages/second; queueing took 35.395 seconds and delivery
took 36.338 seconds. The unchanged ramp-up gate failed because its four
segments were 90.436, 106.504, 141.724, and 143.281 messages/second, a
42.5771% range versus the 30% limit. The runner therefore published no
qualified JSON or checkpoint. The derived diagnostic is
`smtp-rust-next-profiler-v93-diagnostic.json` (SHA-256
`e84043e54dafc1db5361110257e21771311fd22a107319de3cb3eba99a307476`) and is
explicitly not throughput qualification evidence.

The completed stage trace points at `smtp_commit` (120.856 ms average),
`smtp_final_reply` (117.077 ms), `inbound_index_commit` (66.894 ms), and
`queue_acknowledge` (60.648 ms), followed by the three checkpoint/projection
stages at 40.008-41.426 ms. The run's root cleanup receipt has SHA-256
`034839d3f14f62de33ebfc8454025a6f8487b054e679487d83ef42f68d0cd16f` and
records `request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`; no run
process, mount, cgroup, or temporary artifact remained.

V94 repeated the same profiler arm at 2,048 messages so the complete
coordinator stage vector could be retained from the raw failure output. It
delivered 2,048/2,048 with zero failure, retry, exception, OOM, or loss; the
last quartile reached 149.485 messages/second, but the unchanged stability
gate failed at a 46.1975% range (88.669, 116.674, 146.613, and 149.485
messages/second). The derived diagnostic is
`smtp-rust-next-profiler-v94-diagnostic.json` (SHA-256
`9dc0493923e74e6484d68ee4b3537e68c03c6d2b4faf6e8dea6d04f24ba7c12e`) and is
not qualification evidence.

The substage values show that the final inbound index SQL work remained about
2.292 ms begin, 3.426 ms intent lock, 6.733 ms validation, 4.431 ms count
state, 6.598 ms mutation, and 6.641 ms transaction commit. The complete
`inbound_index_commit` stage averaged 47.497 ms, so queue/admission wait is
the dominant part of that stage rather than PostgreSQL execution. The root
cleanup receipt SHA-256 is
`8470cc1c481389f1c90172707e001720458a5971dde5e4476683ab829199d1cb` and
records `request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`.

V95 tested a bounded mailbox-sharded inbound `IndexCommitter` at experiment
commit `b2501fcd`. Up to eight workers were selected from the PostgreSQL pool;
the fixed total channel budget remained 256 and a stable mailbox hash kept
same-mailbox ordering and count-lock semantics on one shard. The complete
inbound-delivery unit module passed 18/18 tests, including an advisory-lock
test proving that a blocked mailbox did not block a different shard. Clippy
passed with warnings denied. The SMTP DATA candidate differential passed; the
MIME and command candidate suites were independently blocked before candidate
startup by pre-existing suite-manifest drift and their goldens were not
changed.

The profiler delivered 2,048/2,048 with zero failure, retry, exception, OOM,
or loss at 110.44 messages/second. Its four segments were 87.387, 116.195,
145.712, and 149.436 messages/second, so it failed the unchanged 30% stability
gate at a 47.383% range. More importantly, its final segment was 0.0325% below
v94's 149.485 messages/second while average `inbound_index_commit` increased
17.66% from 47.497 ms to 55.887 ms. The hypothesis therefore produced no
repeatable end-to-end benefit and was reverted by `17a7be7c`.

The rejected ELF was reproduced twice at SHA-256
`290608beee4257877e894223745a03c45e53cda8065fd8ab4c9d741c69a2cc1e` and
Build ID `2b40e8ef03fdfecfbfbebd83e2bdda950899a677`. The derived diagnostic is
`smtp-rust-mailbox-sharded-profiler-v95-diagnostic.json` with SHA-256
`6cc0b9ccf5c29a7d80b847f31cab8d89e8071f497d44c68c9489e116105743af`;
the raw console is
`smtp-rust-mailbox-sharded-profiler-v95-console.log` with SHA-256
`3ab09fdaee669d2cb64d39c1bfc0fd1cd354a5ac42733aa5d7b3919d9347a437`.
Run `c226f54b-82bd-4131-abd9-1ca4e8e79c00` has a root-owned 0400 cleanup
receipt at SHA-256
`51e91dd4a7beb092c5a49d4a4f124ba6a5c2fbe424c4b552807e25075cf070d4`
with `request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`; the independent
audit found no remaining process, cgroup, loop image, mount, runner artifact,
or provisional output.

V96 retained the queue-acknowledgement stage vector without changing the
delivery path. It delivered 2,048/2,048 messages with zero failure, retry,
exception, OOM, or loss at 109.91 messages/second. Its final segment reached
148.865 messages/second, but the four-segment range was 47.1234%, so the
unchanged 30% ramp-up gate rejected the run. In that final segment,
`queue_acknowledge` averaged 58.443 ms: terminal spool cleanup was 26.008 ms,
Redis acknowledgement plus reconciliation was 7.420 ms, and the acknowledged
sidecar cleanup was 25.124 ms. This excluded the Redis mutation itself as the
dominant cost and justified narrower sidecar instrumentation.

The v96 diagnostic JSON, console, and cleanup receipt hash to
`2c4d17a9e63a8c3b4228afe9733b31f88c75fa4e49b208196aa7119853a671c8`,
`9b179f81a8d681483a13e1657fbe592ae2844c107102f9382f24965cd529c07f`, and
`34f55850420aa18b589af8c293c50c384be770f27a693dea9c3c6e8405cfe10c`.
Run `44395fb4-6785-4659-9df0-4381a5d45930` ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. Two intervening setup attempts were
discarded because the selected-stage list and rebuilt profiling ELF did not
match; they produced no retained diagnostic or qualified artifact.

V99 used a profiling ELF that was verified to contain three new substages for
the acknowledged sidecar path. It delivered 2,048/2,048 messages with zero
failure, retry, exception, OOM, or loss. Its final segment measured 25.308 ms
for sidecar cleanup: 4.161 ms for the snapshot, 0.372 ms for proof cleanup, and
20.509 ms for `delete_removed_outbound_spool`. The database deletion therefore
accounted for 81.0% of the sidecar path. V99 remained unqualified because its
four rates of 86.857, 115.028, 140.185, and 140.003 messages/second had a
41.8213% range.

The retained optimization replaces that deletion's five PostgreSQL exchanges
(`BEGIN`, server timeout, locked validation, `DELETE`, and `COMMIT`) with one
atomic data-modifying CTE. The CTE still sets a transaction-local server
statement timeout, locks both spool and queue rows, validates path, removal
state, and terminal delivery state before mutation, and maps a timeout or
database error to the existing unknown-outcome reconciliation path. A real
PostgreSQL integration test covers absence, successful and repeated deletion,
path conflict, pre-removal rejection, and nonterminal rejection. The 19
outbound-coordinator tests, two observer tests, 39 launcher tests, and library
clippy with warnings denied also pass.

V100 and v101 each delivered 2,048/2,048 with zero failure, retry, exception,
OOM, or loss. Their final segments reached 144.432 and 147.004
messages/second. The mean final sidecar deletion fell 51.14%, from 20.509 ms
to 10.021 ms; sidecar cleanup fell 43.12%, from 25.308 ms to 14.395 ms; and
`queue_acknowledge` fell 15.20%, from 59.427 ms to 50.393 ms. Their mean final
throughput was 145.718 messages/second, 4.08% above v99. Both still failed only
the unchanged ramp-up stability gate, so this proves the targeted optimization
and its repeatability but is not formal endpoint throughput qualification.

The v99 diagnostic JSON and console hash to
`14845f900e6d655dc0ac0d4a9c8c3b1101e96ae3df9f234abeedfa75bdc7671a` and
`3272838190160b6eb78977fc9cfcfffc62c9167aa1095dbc7fa7f856c6844781`.
Its profiling ELF SHA-256 is
`a115ff629838bb48db8bd9f20c83433dc7aa870d2526225463a56146f3b1519a`
with Build ID `3e5169ae8a15e3424895b43129fbe6b4ef31c6ce`. The combined v100/v101
summary hashes to
`edf74b10c5446eda5b2253124b6e7423c74f2537de63d3750a33447d625a50a7`;
their console hashes are
`3a249cf3b643529bf7545243594dc3e76495335a4eb216375f8206adb1a5ab68`
and
`36d354cf21ad023447beae0751b0007e28c2f64a358aee504ca113160ebc952c`.
The optimized ELF SHA-256 is
`c3d0565d303b2ee14f0ad9f97a5cb6216cb0ffab8b462a4ebdbf08dc66c47812`
with Build ID `74ed3d149e3efa545d85114a68b5da4bdc20ce4f`; its main path and deps
hard link are one root-owned mode-0555 inode.

Runs `77534734-2550-41e4-920e-90774fb0c64e`,
`968dce7d-51da-40ba-9760-421baea14446`, and
`c32cf369-fa68-4da6-bdb0-e944972e6434` each ended with `request=ABORT`,
`cleanup=passed`, and `lazy_unmount=0`. Their cleanup receipts hash to
`be39f4ef5a4b05c51e17d755f919c0545a68867d20fb7e6b75310f81d2b572e6`,
`b633fbedb083ceaf1896d4663c632b7d17c6373a6d763b201926e265243f3a50`,
and
`9cceef792fbdc2bbdf7f786e69233b496f774dd27b20d15bb928ba5577274942`.
The root audit found no remaining candidate or service process, per-run cgroup,
loop image, mount, provisional output, or runner artifact after any run.

V102 changed only the retained profiler stage selection and ran the optimized
ELF at 2,048 messages in the same Rust 10KB fsync-off isolation profile. It
delivered 2,048/2,048 messages with zero failure, retry, exception, OOM, or
loss. Its final segment reached 145.158 messages/second, but the four rates of
88.005, 114.974, 145.003, and 145.158 messages/second had a 43.9671% range, so
the unchanged 30% ramp-up gate rejected the run.

The new substages falsified filesystem I/O as the remaining terminal-spool
bottleneck. In the final segment, `queue_ack_spool_cleanup` averaged 27.568 ms:
the PostgreSQL removed-state checkpoint used 21.199 ms (76.90%), the sidecar
snapshot used 5.778 ms (20.96%), and all measured setup, proof validation,
Sent comparison, mutation, disabled durability, proof cleanup, and permit work
used 0.196 ms (0.71%) together. In particular, the fsync-off durability stage
averaged 122 ns. The next profiler-driven hypothesis is therefore the database
checkpoint path, not file hashing, comparison, rename, unlink, or fsync.

The launcher cleaned the run but failed closed at its post-cleanup runner PID
qualification check, so it published no formal output or cleanup receipt. The
root journal for run `adeb2eb2-0c63-4900-88f1-ca6b875740a2` independently
records `request=ABORT`, `cleanup=passed`, and `lazy_unmount=0`; its exact
content was retained as the explicitly unqualified cleanup receipt. An
independent audit found no candidate, service, per-run cgroup, loop image,
mount, provisional output, output artifact, or checkpoint artifact. The
derived diagnostic, console, and receipt SHA-256 values are
`5a6045bffc79727fb080983ee9764c578a0f37aad884329b14b4d57527cb6aa7`,
`48cb6d6267bd522be055e14c62341f4552bf4f6530ed79ea133706472cabac3c`,
and `24e2b0883dfff768501f3d429c2ff0426e8dab13cfcc0877d0a86bfc696e3eba`.
