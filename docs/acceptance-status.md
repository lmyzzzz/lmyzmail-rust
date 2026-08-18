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

The 30-second smoke companion is retained as [`candidate-soak-v6-smoke-0eb2-v1.json`](../evidence/compatibility/candidate-soak-v6-smoke-0eb2-v1.json), but it does not qualify the half-hour gate.

## Still required

- Run the single-invocation `candidate-stability` SMTP profile formally: 500,000 messages at 1 KiB and 10 KiB, plus a disk-budgeted 10 MiB run. Record fsync-off throughput for the independent Java comparison and fsync-on durability, restart recovery, no-loss, leak, and cleanup evidence.
- Re-run current-HEAD reproducible release and installation/rollback verification.
- Complete the full Java/Rust differential matrix, including all HTTP/UI/auth/API/attachment/error/security cases, SMTP client/server paths, storage/restart behavior, HTCPCP, Minecraft, honeypots, rendering, InferX, and XDP privileged gates.
- Add and verify actual AVX2+FMA and AVX-512 runtime-dispatch execution evidence for mail rendering and Minecraft palette/resize/color conversion paths; Scalar-only evidence is insufficient.

## Performance interpretation

The current diagnostic 10 KiB Rust result is about `117.09 msg/s` versus a stable Java window of `47.2235 msg/s` on the same host, or about `2.48x`. This is useful evidence that small profiler gains are not the current priority, but it is not the final acceptance benchmark because the Java run did not complete 200,000 messages and the Rust profiler stability gate was not met.
