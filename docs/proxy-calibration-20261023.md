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
  Python suites have 217 passing checks after the Maildir correction below.
  Their logs are under `evidence/build`.

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

## Maildir observer correction

The first integrated smoke, run `71b9de3d-5f95-4ac2-9a22-4746f14eb7b0`,
failed closed with zero observed publications against the exact expected 16.
The endpoint reported 8 sent/received messages and completed its cleanup, but
those endpoint counters did not override the external failure. Root cleanup
passed; the retained receipt remains unqualified.

The benchmark runtime still selected the early-candidate `lmyzmail-v2` path
layout. The current release writes these fixed ordinary stress addresses in
their oracle-compatible raw directories. An independent real-inotify fixture
reproduced the failure (`0 != 2`) before the correction. The runtime now selects
the existing raw-layout observer for exactly `stress-receiver@lmyz.net/inbox`
and `stress-sender@lmyz.net/sent`. The expected counts, atomic publication,
cleanup requirements and unrelated-tree exclusions are unchanged. The fixture
and all 217 Python harness checks pass; actual service integration is verified
separately and the original failed run is retained.

The corrected original-endpoint 10 KiB integrations then passed separately for
fsync off (`5114a495-d2eb-44ab-a30a-82defeb77b20`) and fsync on
(`f01e863a-1398-4b68-b090-a62ab31f83a9`). Each made one endpoint call for 8
messages, with zero harness batches, 8/8 passive SMTP verification, exactly
8 Inbox and 8 Sent publications and their 16 removals, no observer writes and
successful operational/cleanup checks. Root receipts record `DONE`, cleanup
passed, no lazy unmount and no recovery. Both JSON reports explicitly retain
`qualified=false`: these smokes do not run the formal preflight, large counts
or same-process continuation, and are not formal acceptance evidence.

## Formal preflight after the correction

One fresh formal launch, `c0756010-e43b-4848-805d-ef88587fa840`, exercised the
actual root launcher, private network namespace and unchanged cgroup/resource
policy. It retained every raw CPU/elapsed/rate measurement. All round spreads
now passed `0.20`, but the independent proxy/control ratio failed `0.90`:

| Tier | Ratio | Direct spread | Proxy spread | Verified | Failed connections |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 KiB | 0.895412 | 0.009568 | 0.039233 | 1,000,000 | 0 |
| 10 KiB | 0.847545 | 0.037767 | 0.050758 | 1,000,000 | 0 |
| 10 MiB | 0.720337 | 0.089213 | 0.102491 | 8,000 | 0 |

The producer correctly refused qualification before candidate startup. The
authoritative root receipt records `ABORT`, cleanup passed, no lazy unmount,
no recovery, and `qualified_cleanup=0`. The retained files are
`release-22dae7d0-formal-off-10mb-v2.console.log` and its `.root-cleanup.txt`.
No formal candidate tier or high-volume continuation ran. This confirms the
remaining calibration-overhead gate; passing protocol and cleanup observations
do not substitute for it. No retry was used to select a favorable round.
