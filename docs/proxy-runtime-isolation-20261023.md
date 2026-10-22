# SMTP calibration runtime isolation, 2026-10-23

This is a benchmark-tooling change. The service source, model and delivered
`22dae7d0` ELF are unchanged. It does not close native AVX-512 validation or
qualify a formal SMTP workload by itself.

## Evidence and scope

The earlier calibration put the synthetic SMTP clients, synthetic backend,
control proxy and observing proxy on the same Tokio worker pool. Its formal
root/cgroup run produced raw observing/control ratios of 0.895412 (1 KiB),
0.847545 (10 KiB) and 0.720337 (10 MiB). All spreads passed, but those ratios
failed the unchanged 0.90 gate. The actual benchmark instead runs its service
with a one-CPU limit and its external observer on housekeeping CPUs.

The existing CPU profile, retained in `proxy-calibration-20261023-cpu-symbols.txt`,
had 26,156 samples, zero lost samples and 74.58% kernel samples. There was no
single dominant application function whose removal could explain the complete
gap. This motivated a scheduler-topology experiment, not a product optimization
or removal of observer checks.

Both experiments below used a private Linux network namespace, the same eight
CPU affinity set, four balanced rounds per arm, 250,000 messages per round,
10,240-byte messages, 1,000 connections, 0.90 minimum ratio and 0.20 maximum
spread. Both verified all 1,000,000 observed messages. All results are retained;
neither is formal service acceptance evidence.

| Experiment | Synthetic workers | Workers per proxy | Control msg/s | Observed msg/s | Ratio | Control/observed spread |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Dedicated single-worker proxy | 8 | 1 | 54,352.01 | 38,903.17 | 0.715763 | 0.040813 / 0.152288 |
| Separate role runtimes | 1 | 8 | 49,147.67 | 47,651.86 | 0.969565 | 0.027805 / 0.027251 |

The first experiment failed. Merely separating the proxy did not suffice.
The second kept each proxy's scheduler independent of the synthetic source and
backend, with a bounded single-worker source/backend runtime and the proxy's
ordinary multicore scheduler. The experiment directories are
`evidence/performance/proxy-calibration-20261023-dedicated-runtime-v1/` and
`evidence/performance/proxy-calibration-20261023-role-runtime-v1/`. Each retains
the executable hash, arguments, CPU/network/socket samples, raw rounds and exit
status. The experimental executable hashes are respectively `ec5b2f00d96e795923e1e6c75d14ef239143366906001b8e4aadddc99557ae02`
and `10df59515ef244d8cf9821ab492136a1746e03e872c1cc48c82789847e3ac770`.

This changes the synthetic saturation point: the second experiment's control
rate is lower than the old shared eight-worker calibration's approximately
134,000 msg/s. That reduction is explicit, not a product speedup claim. The
separate required capacity check still uses the slowest observing round and
requires at least twice the maximum observed product-arm rate. Both proxy arms
have identical worker counts, TCP hops, forwarding and memory policies.

## Implementation and checks

Raw calibration schema 5 and persistence-gate schema 3 record
`runtime_topology`: one synthetic worker, at most eight proxy workers bounded
by available CPUs, and a separate proxy runtime. Both raw arms and gate on/off
arms use this structure. The public calibration functions enforce it without
depending on `TOKIO_WORKER_THREADS` or their caller's runtime. The service and
its standalone external proxy keep their existing configuration.

The launcher and Python verifier independently recompute the expected topology
from the attested CPU set and reject old schemas, missing topology, shared
runtimes, incorrect worker counts and boolean-as-integer substitutions. Negative
tests rehash all report levels, ensuring an integrity mismatch cannot hide a
missing topology assertion. No ratio, spread, hash, count, persistence, cleanup,
disk, resource or actual-product headroom threshold was reduced.

The new runtime owner cancels tasks on caller cancellation and shuts down
without blocking inside another async runtime. A cancellation regression proves
the operation's pending task is dropped. Real DATA and BDAT proxy tests, gate
on/off final-reply checks and the existing malformed-input/backpressure suite
remain enabled.

The first expanded Rust suite recorded 65 passes and one `ENOENT` from the new
gate integration. It remains in
`evidence/build/proxy-runtime-isolation-rust-20261023.log`. The control connection
error now includes its path and command for diagnosis. The next full suite
passed 84 tests and strict Clippy, and 30 consecutive targeted gate integrations
passed; these do not establish the cause of that first failure. Logs are
`proxy-runtime-isolation-rust-20261023-v2.log` and
`proxy-runtime-gate-repetition-20261023.log`. The Python throughput/launcher suite
passed all 217 checks in `proxy-runtime-isolation-python-20261023.log`.

The fresh root/cgroup launch `694dd432-31d6-47bd-a5e1-dffebabd6b83` passed
the actual producer and independent verifier preflight. It did not select a
diagnostic round or reuse the experimental executable. The fixed producer ELF
hash is `6e3e7ee896f1c716bd8c29aaf0b80f0d5e97d46cced498087cea66d246955b05`.

| Tier | Ratio | Control spread | Observed spread | Slowest observed msg/s | Gate checks |
| --- | ---: | ---: | ---: | ---: | --- |
| 1 KiB | 0.918360 | 0.075342 | 0.125487 | 47,985.03 | passed |
| 10 KiB | 1.017978 | 0.117272 | 0.045819 | 44,092.85 | passed |
| 10 MiB | 1.013410 | 0.014801 | 0.008614 | 385.90 | passed |

The root-owned immutable external attestation was copied, without modifying
its original, to
`evidence/performance/release-22dae7d0-formal-off-10mb-v3.preflight.json`.
Its SHA-256 is `e6acae3f9a32e6adb0efb306ecce043ab90567473f00f4da55d7050002a977df`.
The definition hash is `cae8cb6e30f0928f2e3165ec88853f414678d4e3c148f863a8478e762a656117`.
The candidate then started one original-endpoint invocation for 500 messages
of 10 MiB each, fsync off, with the existing one-CPU, 500,000,000 B/s I/O,
20 GiB disk, 7 GiB memory.high and 8 GiB memory.max policy. Its terminal result
is separate from preflight qualification and is retained with the console
`release-22dae7d0-formal-off-10mb-v3.console.log`.

## First workload outcome and visible-mount regression

The workload ended with one measurement endpoint invocation, 500/500 observed
messages and a passing comparison at 2.941438 msg/s. Its endpoint log also
records 500 queued, 500 received, zero lost/failed/exceptions/OOM/rate-limited
messages and completed endpoint cleanup. The candidate log contains deferred
publication-intent and queue-unavailable messages; the retained active snapshots
are not a complete final audit log. None of this promotes the run: the runner
reported `qualified=false`, and root recorded `ABORT`, cleanup passed, no lazy
unmount/recovery and `qualified_cleanup=0`.

The old unqualified-artifact cleanup removed the raw output/checkpoint files.
The console, preflight, sampled logs and copied root receipt remain. Complete
publication/resource/recovery evidence cannot be reconstructed from that console
and must be obtained in a new run. In particular, no formal 10 MiB pass is claimed.

A controlled root mount-namespace probe then reproduced a concrete false
rejection in `_cgroup_mount_is_read_only`: mountinfo lists the original writable
cgroup mount before the read-only bind that covers it. The old helper returned
the first row's `False` while the kernel's visible mount had `ST_RDONLY=True`.
The runner could consequently bypass real-product gate calibration as an
unqualified run, execute the measurement anyway and only fail final promotion.

The helper now reads the kernel's visible-mount flag with `statvfs`. The actual
namespace probe proved `False` before the bind and `True` after it, with both
mountinfo rows still present. Evidence is
`evidence/build/proxy-visible-cgroup-mount-20261023.log`. A regression includes
both covered read-only and visible-writable cases; a writable mount remains
rejected. Non-smoke Rust runs also fail before workload startup if any initial
qualification prerequisite fails, emitting their isolation/resource details.

Failed or partial root output/checkpoint artifacts are now retained and sealed
to mode 0400 in their original root-private artifact directory, after the same
owner, path, inode, link-count and mode checks. They cannot gain a qualified
producer/cleanup receipt. Repeat cleanup accepts sealed files, and a regression
proves byte preservation and hardlink rejection. This retains negative evidence
without retaining the disposable service data or quota image. Future readable
copies must not change the protected originals. All 219 Python checks and Bash
syntax validation passed; no qualification threshold was loosened.
