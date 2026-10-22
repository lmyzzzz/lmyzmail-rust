# SMTP benchmark preflight diagnosis, 2026-10-23

This work changes benchmark tooling only. The delivered service ELF remains
`78a4c31145010e479ec64a9e0a2f3ac767b2860e32180100cad699a155c37790`
from runtime source `22dae7d0`. It does not qualify the outstanding formal SMTP
tiers or the unavailable native AVX-512 path.

## Retained formal failure

`release-22dae7d0-formal-off-10mb.console.log` records run
`54e88e94-c4e8-4c2d-978e-570a1e33a627`. The producer failed its proxy preflight
before starting the candidate, PostgreSQL or Maildir workload. All three raw
tiers exceeded the unchanged `0.20` round-spread limit. Observer message checks
passed and proxy connection failures were zero. This is a preflight failure,
not a completed SMTP stress test or a candidate failure.

The copied authoritative cleanup record is
`release-22dae7d0-formal-off-10mb.preflight-root-cleanup.txt`. It records `ABORT`,
`cleanup=passed`, no lazy unmount, missing provisional/checkpoint artifacts and
`qualified_cleanup=0`. Successful resource cleanup does not qualify the run.
The root journal original was not modified.

## Controlled evidence

The host namespace routes TCP `127.0.0.1` through `loopback0`, via
`169.254.73.152`, with MTU 1500. The actual workload already creates a private
Linux network namespace. Its route is `local 127.0.0.1 dev lo`, MTU 65536.
Previously the calibration producer did not enter that private topology.

`tools/diagnose_proxy_calibration.py` records the exact binary hash and command,
per-thread scheduled CPU/runqueue wait, TCP socket witnesses, kernel network
counters, exit status and timeout. Its outputs are diagnostic only; they cannot
publish formal qualification. Global host MIB deltas may include unrelated
traffic. Socket witnesses are restricted to the measured PID.

With the original proxy binary, a 25,000-message, 1,000-connection, 10 KiB
control round took 7.544 seconds with 4.678 seconds of process CPU, while
another took 1.716 seconds with 5.387 seconds of CPU. The second host repeat
also retained small unsent replies, delayed ACKs and retransmission timers.
The evidence is in `proxy-calibration-20261023-nagle-before-v1/` and `-v2/`.
Those directory names record the initial hypothesis, not a claim that Nagle
alone caused every delay.

The same binary and unchanged full raw settings in a private network namespace
used 250,000 messages per arm, 1,000 connections and four balanced rounds per
arm. Direct spread fell to `0.011916`, observing-proxy spread to `0.015717`.
All 1,000,000 observed messages passed. The proxy/control throughput ratio was
`0.698835`, so the independent `0.90` overhead gate still failed. Evidence:
`proxy-calibration-20261023-isolated-full-v1/`.

A symbolized, independently identified proxy build was CPU sampled over the
same full raw workload. The recording has 26,156 samples and zero lost samples;
74.58% fell in the kernel, including networking and synchronization paths,
19.12% in the proxy and 5.49% in libc. The retained symbol report is
`proxy-calibration-20261023-cpu-symbols.txt`; the underlying perf recordings
remain local. This is synthetic calibration evidence, not a service profile.

## Final tooling changes and validation

- The launcher now creates a private network namespace and raises only its
  loopback interface before headroom calibration. It changes no host route,
  interface or global networking setting.
- Failed headroom output now retains every raw round's elapsed time, scheduled
  CPU and rate, alongside the existing failure summary.
- Completed-message header parsing, Message-ID hashing and sample formatting
  run before taking the shared round lock. Epoch, state, uniqueness, counts,
  ordered record digest, persistence and publication checks remain under their
  existing synchronization. The original header parser is retained.
- Both control and observing proxy connections use TCP_NODELAY in both
  directions, avoiding extra small-write buffering by the observer's sockets.
- The final proxy has 82 passing unit/integration tests, including malformed
  input, first-duplicate/folded-header semantics, exact forwarding, DATA/BDAT,
  persistence gating, backpressure and shutdown. The throughput/launcher
  Python suites have 216 passing checks. Their logs are under `evidence/build`.

Moving independent work outside the shared lock improved the measured raw
ratio into approximately `0.80..0.84`; it did not pass `0.90`. Single-worker and
four-worker experiments also failed that gate and did not change the default
runtime policy. An additional parser-allocation experiment and completion-lock
combination did not demonstrate a useful improvement and are absent from the
final implementation. Their negative diagnostic results remain retained.

The byte hashes, duplicate detection, counts, persistence checks, maximum
spread and minimum ratios have not been weakened. These measurements do not
replace 250,000 plus same-process 100,000 SMTP publication/recovery tests, either
fsync mode, the budgeted 10 MiB tier or the independent half-hour soak.
