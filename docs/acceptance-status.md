# Acceptance Status

This record is intentionally a status report, not a completion claim. The overall rewrite goal remains incomplete until every required protocol, rendering, model, security, stress, differential, release, and rollback gate has evidence.

Release candidate `22dae7d0` and its complete source/history are available in
`D:\MiscProjects\lmyzmail-rust\releases\20261023-rc.22dae7d0`.
See [its validation supplement](release-22dae7d0-validation.md) for the exact
reproduced ELF, source/package inventory, installation and current validation
results. The earlier `bf6c0d53` package and
[its validation supplement](release-bf6c0d53-validation.md), `39379c04` package and
[its negative and corrected evidence](release-39379c04-validation.md) are retained.
Packaging does not close the remaining gates.

The [2026-10-23 local follow-up](local-validation-20261023.md) fixes isolation
of the two retained oracle fixtures and adds evidenced four-class legacy-name
takeover and alias security regressions. The repaired source passed all 961
Rust tests and strict Clippy. The new reproduced `22dae7d0` ELF is packaged
separately; every older package and its checksums remain unchanged.

The current milestone also adds a copy-only, fsynced offline exporter for
new v2 mail and real PENDING memory/file-mode queue handoff in both runtime
directions. The exporter passed five consecutive same-state Java/Rust checks;
the queue check passed and observed a full scheduling cycle after a final
Rust restart. These close the tested rollback/handoff cases without claiming
all in-flight crash boundaries or allowing unsafe colliding Java aliases.

## Passed in the current milestone

- The full fresh frozen-Java campaign passed 107 oracle tests in 2,129.89
  seconds; the separately isolated RBL Java/candidate checks also passed.
  All 6,897 historical golden files remained unchanged and all 346 fresh
  campaign observations/artifacts matched them without semantic differences.
  The complete retained `22dae7d0` candidate replay then passed all 126
  selected checks in 899.16 seconds, matching the same observations with
  unchanged ELF hashes. With 188 disjoint unmarked checks and independent
  candidate RBL, all 315 non-oracle checks passed.
- The retained `22dae7d0` runtime/source/history package passed complete source
  stream and 17,240-path inventory checks, full Git-bundle verification and
  checksums after copying to Windows. Two independent-target frozen builds
  produced identical ELF bytes. The full installation regression and actual
  unpacked package installation/reinstallation/uninstallation passed.
- The first `22dae7d0` half-hour soak is retained as a failure: zero protocol
  errors across 254,064 operations and stable RSS/FD/tasks do not override its
  filesystem-wide disk peak of 2,767,642,624 bytes against the 1 GiB gate.
  Its own workspace grew by 5,787,648 bytes while oracle/package work ran
  concurrently. The isolated v2 then passed that same unchanged policy in
  1,800.152 seconds with 16 workers, 269,344 operations and zero failures.
  Peak RSS was 412,112 KiB, steady RSS growth 192 KiB, peak sampled tasks 62,
  steady FD/task growth zero and filesystem/workspace growth 5,787,648 bytes.
  All immutable-input, ELF and cleanup checks passed with no residual managed
  process and the workspace removed. This closes the current half-hour gate;
  it does not substitute for high-volume SMTP publication/recovery evidence.
- The 2026-10-22 shutdown recovery repair passed all 959 Rust tests, strict
  Clippy, all four unchanged stress SIGTERM/SIGKILL regressions, compact-model
  Scalar/Auto SMTP/DB checks, and ordinary-address bidirectional Java/Rust
  takeover. The current candidate-marked replay passed 88 scenarios and the
  disjoint unmarked non-oracle suite passed 178 checks. Both audits retained all
  6,897 historical golden files unchanged and matched all 346 campaign
  observations/artifacts. See [the evidence record](shutdown-recovery-20261022.md).
  The reproduced `bf6c0d53` ELF then passed all 310 non-oracle checks across both
  test directories and the separately required RBL runner, plus model/takeover
  and packaged installation checks. Source inventory, full-history bundle and
  all Windows package checksums passed. Earlier Java-oracle failures and the
  intermittent DNS order failure remain recorded.
- Commit `f3b10966` passed the fresh formal multi-module soak recorded in [`candidate-soak-f3b10966-20261022.json`](../evidence/compatibility/candidate-soak-f3b10966-20261022.json).
- The run lasted `1800.046` seconds with `16` workers and completed `252608` HTTP, SMTP, HTCPCP, and Minecraft operations.
- It recorded `0` failures, a peak RSS of `413072 KiB`, a constant FD count of `27`, a peak task count of `61`, and a queue range of `0..0`. After initialization, RSS grew by `768 KiB`, FD/tasks by zero, and the workspace by `5787648` bytes (PostgreSQL data). These observations pass the existing resource gates for this workload; they do not substitute for the separate mail-publication stress test.
- The runner verified protocol activity, unchanged immutable inputs, release-binary stability, cleanup of candidate/PostgreSQL/Redis, workspace removal, and no residual PIDs or ports.
- The SMTP endpoint harness now has a dedicated `candidate-stability` profile. It preserves one original endpoint invocation per tier, has no harness batching, and lets each Rust tier qualify independently after the separate Java baseline is frozen.
- The profile's fsync-off and fsync-on 1 KiB end-to-end smokes both passed with one arm, `8/8` passively observed messages, zero failures/retries, and successful root cleanup receipts. As smokes they are intentionally not formal 500,000-message evidence.
- The first formal 1 KiB fsync-off attempt reached `224232/500000` passively verified messages with no proxy retry, duplicate, or observer error, then failed the candidate's fixed 30-minute queue deadline. It is retained as negative evidence only; root cleanup passed and no throughput result was published. The deadline now scales to `10000` seconds for 500,000 messages under a three-hour hard ceiling. Two later formal launch attempts failed closed before candidate startup, first on the unchanged proxy spread gate and then on a build-feature-dependent producer/verifier JSON hash mismatch; both causes have regression coverage.
- The next formal run reached `390475/500000` with zero duplicate or proxy failure observations before fail-closing on an out-of-order proxy completion timestamp and the independent 8 GiB `memory.max` gate. Both are retained as negative evidence. Proxy progress now uses the maximum accepted completion timestamp, and the unchanged 8 GiB hard limit has a verified 7 GiB `memory.high` watermark for earlier reclaim. A root-isolated post-fix smoke passed `8/8`, persistence, resource, attestation, and cleanup checks with zero memory max/OOM events. The formal 500,000-message tier must still be rerun before this gate can pass.
- The latest uncontaminated formal 1 KiB fsync-off run independently proved `500000/500000` successful SMTP replies, exact sender/receiver Maildir publication, exact outbound audit/index mutation, zero rollback, and zero missing/duplicate/retry/observer failures. Qualification still failed because the inherited Java stress endpoint started its 20-minute delivery timer before the 5,207-second enqueue phase, then sampled its inbox counter at 490,186 and timed out immediately after enqueue. Rust now starts that bounded delivery wait at queue completion; the rebuilt release passed an `8/8` root-isolated regression smoke and cleanup audit, but a formal rerun is still required.
- The post-fix formal rerun again completed `500000/500000` messages with zero endpoint, SMTP proxy, retry, duplicate, missing, observer, OOM, or database-cleanup failures. Its provisional endpoint result was `97.19 msg/s`, about `2.06x` the same-host Java 10 KiB stable-window reference, but it is not qualified evidence: passive throughput fell across the four quartiles from `128.12` to `77.62 msg/s`, for a `0.514375` relative range against the unchanged `0.30` limit. The cgroup recorded 18,255 `memory.high` reclaim events, zero `memory.max` events, and zero OOM/OOM-kill events. Root cleanup eventually passed, but the watchdog did not publish formal JSON or a qualified cleanup receipt. The next work is stability diagnosis under complete coordinator, queue, PostgreSQL/Redis, Maildir, and cgroup observations rather than another local micro-optimization.

The 30-second smoke companion is retained as [`candidate-soak-v6-smoke-0eb2-v1.json`](../evidence/compatibility/candidate-soak-v6-smoke-0eb2-v1.json), but it does not qualify the half-hour gate.

## Still required

- V9 completed all eight actual 10 MiB calibration rounds in the same process:
  800/800 messages, all endpoint outcomes and persistence barriers passed.
  Snapshot field equality now passes. Aggregate off/on spread was 15.00%/4.61%
  against the unchanged 1% calibration bound; formal measurement never began.
  A separate endpoint-identity record defect is repaired with a real-builder
  regression (221 Python checks passed), without promoting that failed run.
  Full rounds, evaluation and successful unqualified cleanup are retained in
  [the calibration record](proxy-runtime-isolation-20261023.md).

- The uncontaminated v8 actual gate-on round verified 100/100 10 MiB messages,
  zero observer failures and passing causal timing, then exposed a missing Sent
  count in the Rust benchmark control snapshot. It now preserves and validates
  that field while retaining exact snapshot equality. All 85 proxy Rust tests,
  strict Clippy and 220 Python checks passed. V8 remains negative evidence; a
  new actual calibration and formal workload must pass before any tier closes.
  See [the snapshot protocol repair](proxy-runtime-isolation-20261023.md).

- The v5 actual-product calibration reached two 100-message 10 MiB endpoint
  rounds, but an agent diagnostic used root for a UID-1000 control socket and
  contaminated observer evidence. The gate-on round failed causal qualification;
  root cleanup passed and the protected checkpoint is retained. It is neither a
  qualified SMTP tier nor an uncontaminated product stability failure. Gate
  exceptions and calibration checkpoints now retain the details needed to
  diagnose the next run; all 220 tooling checks pass. See
  [the v5 evidence record](proxy-runtime-isolation-20261023.md).

- The role-isolated calibration now passed the actual root/cgroup producer and
  independent verifier for every tier, without changing the 0.90 ratio or 0.20
  spread gates. The next 10 MiB fsync-off workload observed 500/500 messages and
  passed its comparison, but remained unqualified. A reproduced visible-mount
  detection bug incorrectly read the covered writable cgroup mount; the fixed
  probe now follows the actual read-only bind. Failed raw artifacts will also be
  retained instead of deleted. See [the runtime-isolation evidence](proxy-runtime-isolation-20261023.md).
  That run is still negative evidence; a new formal run must exercise real-product
  gate calibration and retain complete publication, resource, recovery and cleanup
  proofs before any SMTP tier can qualify.

- The earlier `22dae7d0` formal SMTP attempts failed before candidate startup on
  the proxy preflight. A controlled diagnosis found that WSL host loopback
  traffic traverses Windows, while the workload uses private Linux loopback.
  Matching that isolation removed the large round-to-round variation, but
  exposed a separate shared-runtime observer ratio below the unchanged `0.90` gate.
  Benchmark tooling repairs and all negative evidence are documented in
  [the calibration record](proxy-calibration-20261023.md). No current formal
  SMTP tier can be counted as passing from these diagnostic observations.
  The first new smoke also exposed the harness's obsolete encoded Maildir
  watch paths; a real-inotify negative regression reproduced the zero count.
  Correcting the fixed stress addresses to their oracle-compatible raw paths
  retained every count/publication/cleanup assertion. Both fsync modes then
  passed independent 8-message integrations, each with 16 exact Maildir
  publications/removals and successful root cleanup. These remain smokes.

- The earlier release-candidate `292cf3b3` is available with full source/history and
  reproducible binary hash `958a7d7b448491e726e7c25461188bcc5e0b3300c32b8a0050206eb76afad570`.
  The 2026-10-22 current-harness HTTP run passed 35 checks and exposed two real
  Maildir regressions: legacy deletion returns `not_found`, and multipart Sent
  publication uses an encoded path absent from the frozen layout. Both now have
  product fixes: 957 Rust tests, strict Clippy, and 17 external mail/attachment/
  multipart checks passed. All 6897 historical golden files remained unchanged;
  346 fresh Java observations/artifacts match their historical counterparts.
  The fresh full Java replay had 105 passes and two failures (DMARC DNS query
  count and multi-domain stress publication); both failed again in isolation.
  The full candidate replay had 120 passes and six failures. Replacing permanent
  staging lease files with Linux directory locks fixed the exact Maildir file
  counts: queue layout, reports, cron scheduler and enqueue-time SIGTERM checks
  passed unchanged. The 4xx retry and DSN tests also passed after separating DSN
  publication backoff from ordinary queue maintenance. Delivery-time SIGTERM
  cleanup failed in that earlier replay: a PENDING task was preserved safely,
  but its Sent copy prevented complete stress-mailbox cleanup. The new
  shutdown-only recovery proof passed the original regression, including exact
  cleanup and queue recoverability. Diagnostic state and every earlier failing
  log are retained. The historical replay is still not a clean full replay.
  The later `bf6c0d53` package and complete non-oracle replay passed, but a clean
  repeatable Java differential matrix remains required. See
  [Maildir takeover status](maildir-takeover.md) for the later ownership repair,
  four-class offline rollback, pending-queue handoff and remaining limitations.
  Package availability is not production acceptance.
- The packaged compact 2026-10-22 InferX model has independent frozen-Java
  Scalar/AVX2 output goldens, 24 Rust inference tests, and two real SMTP/DB tests
  (Scalar and Auto) with model mmap and no JVM/kernel runtime dependency.
- The real same-state Java -> Rust -> Java -> Rust takeover passed for ordinary
  ASCII addresses, including byte-exact reads of existing mail, newly received
  SMTP mail and multipart Sent attachments. Evidence:
  `takeover-directory-lease-20261022-v2.json`. This does not cover ambiguous
  mailbox names or all pending-outbound transitions.
- Privileged XDP attach, IPv4/IPv6 ban/drop, restart persistence, unban/pass and
  isolated cleanup passed in `xdp-privileged-20261022.json`.
- Run the revised single-invocation `candidate-stability` SMTP profile formally: 250,000 messages at 1 KiB and 10 KiB, then 100,000 more in the same process with at least 90% of the first 100,000-message rate, plus a disk-budgeted 10 MiB run. Record fsync-off throughput for the independent Java comparison and fsync-on durability, restart recovery, no-loss, leak, and cleanup evidence. Formal v9 and v10 are recorded product stability failures; the shared delivery-state fix in `af56b587` still needs a qualifying rerun. The user permits moving to other incomplete gates after ten unsuccessful stability rounds; that does not turn a failed round into passing evidence.
- Repeat reproducible release and installation verification after further product
  changes. The `bf6c0d53` independent-target-directory builds, install, upgrade,
  configuration preservation and uninstall passed. Complete data rollback is
  still a separate requirement.
- The fresh `22dae7d0` full Java/candidate matrix now passes, including the
  isolated DMARC and corrected multi-domain scheduling fixture. Preserve this
  evidence and rerun after product or harness changes. The earlier intermittent
  DNS query-order failure remains retained; one successful complete run does
  not establish that its underlying ordering race has been eliminated.
- Verify actual AVX2+FMA and AVX-512 runtime-dispatch execution evidence for the implemented mail rendering and Minecraft palette/resize/color conversion paths; Scalar-only evidence is insufficient. The current 275HX WSL host exposes AVX2/FMA but no AVX-512F, so compilation and safe fallback alone cannot prove AVX-512 execution or native performance.
  Local Scalar/AVX2 Minecraft video and mail-view wire/pixel goldens passed with
  verified runtime-dispatch events (`renderer-local-f3b10966/`). The six-round
  local benchmark (`renderer-local-20261022-v2/summary.json`) kept every output
  hash identical. Median AVX2 speedups across sizes/dithers were 1.50x for block
  palette RGB, 1.47x for block states, 1.64x for map palette, 6.40x for contrast,
  and 1.09x for resize; the slowest resize case was 0.84x. These measurements
  share the host with other acceptance processes and are partial comparative
  evidence, not full three-backend performance qualification.
  The user confirmed that no AVX-512 test host is available and requested that
  all locally verifiable work continue. This leaves the native AVX-512 gate open.

## Performance interpretation

The current diagnostic 10 KiB Rust result is about `117.09 msg/s` versus a stable Java window of `47.2235 msg/s` on the same host, or about `2.48x`. The completed but unqualified 1 KiB formal rerun observed `97.19 msg/s`, about `2.06x` that same Java reference, before failing its within-arm stability gate. These results are sufficient to stop low-yield local profiler optimizations and prioritize stability, but neither is the final acceptance benchmark: the Java run did not complete 200,000 messages, the Rust diagnostic arms failed stability, and the 500,000-message result was not formally published.
