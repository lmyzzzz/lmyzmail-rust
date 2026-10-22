# Acceptance Status

This record is intentionally a status report, not a completion claim. The overall rewrite goal remains incomplete until every required protocol, rendering, model, security, stress, differential, release, and rollback gate has evidence.

## Passed in the current milestone

- The current candidate passed the formal multi-module soak recorded in [`candidate-soak-v6-0eb2-v1.json`](../evidence/compatibility/candidate-soak-v6-0eb2-v1.json).
- The run lasted `1800.184` seconds with `16` workers and exercised HTTP, SMTP, HTCPCP, and Minecraft continuously.
- It recorded `0` failures, a peak RSS of `412040 KiB`, a peak FD count of `28`, a peak task count of `61`, and a queue range of `0..0`.
- The runner verified protocol activity, unchanged immutable inputs, release-binary stability, cleanup of candidate/PostgreSQL/Redis, workspace removal, and no residual PIDs or ports.
- The SMTP endpoint harness now has a dedicated `candidate-stability` profile. It preserves one original endpoint invocation per tier, has no harness batching, and lets each Rust tier qualify independently after the separate Java baseline is frozen.
- The profile's fsync-off and fsync-on 1 KiB end-to-end smokes both passed with one arm, `8/8` passively observed messages, zero failures/retries, and successful root cleanup receipts. As smokes they are intentionally not formal 500,000-message evidence.
- The first formal 1 KiB fsync-off attempt reached `224232/500000` passively verified messages with no proxy retry, duplicate, or observer error, then failed the candidate's fixed 30-minute queue deadline. It is retained as negative evidence only; root cleanup passed and no throughput result was published. The deadline now scales to `10000` seconds for 500,000 messages under a three-hour hard ceiling. Two later formal launch attempts failed closed before candidate startup, first on the unchanged proxy spread gate and then on a build-feature-dependent producer/verifier JSON hash mismatch; both causes have regression coverage.
- The next formal run reached `390475/500000` with zero duplicate or proxy failure observations before fail-closing on an out-of-order proxy completion timestamp and the independent 8 GiB `memory.max` gate. Both are retained as negative evidence. Proxy progress now uses the maximum accepted completion timestamp, and the unchanged 8 GiB hard limit has a verified 7 GiB `memory.high` watermark for earlier reclaim. A root-isolated post-fix smoke passed `8/8`, persistence, resource, attestation, and cleanup checks with zero memory max/OOM events. The formal 500,000-message tier must still be rerun before this gate can pass.
- The latest uncontaminated formal 1 KiB fsync-off run independently proved `500000/500000` successful SMTP replies, exact sender/receiver Maildir publication, exact outbound audit/index mutation, zero rollback, and zero missing/duplicate/retry/observer failures. Qualification still failed because the inherited Java stress endpoint started its 20-minute delivery timer before the 5,207-second enqueue phase, then sampled its inbox counter at 490,186 and timed out immediately after enqueue. Rust now starts that bounded delivery wait at queue completion; the rebuilt release passed an `8/8` root-isolated regression smoke and cleanup audit, but a formal rerun is still required.
- The post-fix formal rerun again completed `500000/500000` messages with zero endpoint, SMTP proxy, retry, duplicate, missing, observer, OOM, or database-cleanup failures. Its provisional endpoint result was `97.19 msg/s`, about `2.06x` the same-host Java 10 KiB stable-window reference, but it is not qualified evidence: passive throughput fell across the four quartiles from `128.12` to `77.62 msg/s`, for a `0.514375` relative range against the unchanged `0.30` limit. The cgroup recorded 18,255 `memory.high` reclaim events, zero `memory.max` events, and zero OOM/OOM-kill events. Root cleanup eventually passed, but the watchdog did not publish formal JSON or a qualified cleanup receipt. The next work is stability diagnosis under complete coordinator, queue, PostgreSQL/Redis, Maildir, and cgroup observations rather than another local micro-optimization.

The 30-second smoke companion is retained as [`candidate-soak-v6-smoke-0eb2-v1.json`](../evidence/compatibility/candidate-soak-v6-smoke-0eb2-v1.json), but it does not qualify the half-hour gate.

## Still required

- The earlier release-candidate `292cf3b3` is available with full source/history and
  reproducible binary hash `958a7d7b448491e726e7c25461188bcc5e0b3300c32b8a0050206eb76afad570`.
  The 2026-10-22 current-harness HTTP run passed 35 checks and exposed two real
  Maildir regressions: legacy deletion returns `not_found`, and multipart Sent
  publication uses an encoded path absent from the frozen layout. Both now have
  product fixes: 957 Rust tests, strict Clippy, and 17 external mail/attachment/
  multipart checks passed. All 6897 historical golden files remained unchanged;
  343 fresh Java observations/artifacts match their historical counterparts.
  The full Java recording run had 103 passes and four failures; all four passed
  in an isolated rerun without assertion changes. This is not a clean full replay.
  A new package and fresh full replay are still required. See
  [Maildir takeover status](maildir-takeover.md) for the remaining ambiguous-name
  layout and rollback gap. Package availability is not production acceptance.
- The packaged compact 2026-10-22 InferX model has independent frozen-Java
  Scalar/AVX2 output goldens, 24 Rust inference tests, and two real SMTP/DB tests
  (Scalar and Auto) with model mmap and no JVM/kernel runtime dependency.
- Privileged XDP attach, IPv4/IPv6 ban/drop, restart persistence, unban/pass and
  isolated cleanup passed in `xdp-privileged-20261022.json`.
- Run the revised single-invocation `candidate-stability` SMTP profile formally: 250,000 messages at 1 KiB and 10 KiB, then 100,000 more in the same process with at least 90% of the first 100,000-message rate, plus a disk-budgeted 10 MiB run. Record fsync-off throughput for the independent Java comparison and fsync-on durability, restart recovery, no-loss, leak, and cleanup evidence. Formal v9 and v10 are recorded product stability failures; the shared delivery-state fix in `af56b587` still needs a qualifying rerun. The user permits moving to other incomplete gates after ten unsuccessful stability rounds; that does not turn a failed round into passing evidence.
- Re-run current-HEAD reproducible release and installation/rollback verification.
- Complete the full Java/Rust differential matrix, including all HTTP/UI/auth/API/attachment/error/security cases, SMTP client/server paths, storage/restart behavior, HTCPCP, Minecraft, honeypots, rendering, InferX, and XDP privileged gates.
- Verify actual AVX2+FMA and AVX-512 runtime-dispatch execution evidence for the implemented mail rendering and Minecraft palette/resize/color conversion paths; Scalar-only evidence is insufficient. The current 275HX WSL host exposes AVX2/FMA but no AVX-512F, so compilation and safe fallback alone cannot prove AVX-512 execution or native performance.
  The user confirmed that no AVX-512 test host is available and requested that
  all locally verifiable work continue. This leaves the native AVX-512 gate open.

## Performance interpretation

The current diagnostic 10 KiB Rust result is about `117.09 msg/s` versus a stable Java window of `47.2235 msg/s` on the same host, or about `2.48x`. The completed but unqualified 1 KiB formal rerun observed `97.19 msg/s`, about `2.06x` that same Java reference, before failing its within-arm stability gate. These results are sufficient to stop low-yield local profiler optimizations and prioritize stability, but neither is the final acceptance benchmark: the Java run did not complete 200,000 messages, the Rust diagnostic arms failed stability, and the 500,000-message result was not formally published.
