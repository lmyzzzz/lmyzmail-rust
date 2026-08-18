# lmyzmail benchmark proxy

`lmyzmail-benchmark-proxy` is a transparent TCP forwarder with a bounded,
read-only SMTP observer. It is intended for formal throughput evidence where
the load generator must talk to the real candidate without changing SMTP
PIPELINING, DATA, or BDAT flow control.

The forwarding path uses two independent Tokio pumps, fixed 64 KiB buffers,
socket backpressure, and exact byte forwarding. Observation never rejects a
connection. A parse error or observer limit violation disables observation for
that connection and disqualifies the round while forwarding continues.

## Proxy mode

```text
lmyzmail-benchmark-proxy proxy \
  --listen 127.0.0.1:11025 \
  --backend 127.0.0.1:1025 \
  --control /absolute/path/observer.sock \
  --max-connections 224 \
  --memory-budget-mib 384
```

The 384 MiB default covers the checked 224-connection requirement with reserve
headroom. Startup fails closed when the configured budget is one byte below the
permit-rounded sum of connection, observer-round, and control reserves. Control
snapshots publish the configured connection count, usable and required bytes,
and the remaining headroom so the formal runner can recompute the same bound.

The control socket is created with mode `0600`, and accepted peers must match
the socket owner's UID through Linux peer credentials. Requests and responses
are one JSON object per line and are limited to 64 KiB including the final LF.
Supported requests are:

```json
{"command":"begin","run_id":"10kb-candidate","expected_messages":500000,"message_bytes":10240}
{"command":"summary"}
{"command":"wait","timeout_millis":3600000}
{"command":"finish"}
{"command":"shutdown"}
```

`begin` may also provide `expected_sender` and `expected_receiver`, and is
accepted only once in a process. Connections accepted before that begin are
epoch-isolated and cannot contribute to the round. `wait`
returns when every unique expected stress index has received its backend final
`250`, and that reply has been completely written to the SMTP client, or when
its timeout expires. Backend replies are parsed into pending observation state,
forwarded with `write_all`, and only then acknowledged into the round. A slow or
failed client write therefore cannot shorten measured completion latency.
`finish` first closes the listener (dropping
its kernel backlog), then joins or aborts every connection within the fixed
grace, and only then freezes the round and exits the process. `shutdown` uses
the same stop-and-join lifecycle. A connection can therefore never survive
into another round.

The global memory budget is enforced by a weighted semaphore. Startup rejects
any `max_connections` whose accounted worst case does not fit. Accounting
includes both fixed pump buffers, both bounded parser buffers, retained header
prefix, pending reply ring, fixed per-connection overhead, and a conservative
reserve for the maximum round index/Message-ID state. It also reserves the
request, decoded JSON, response, socket, and task ceilings of all 16 control
clients. STARTTLS `220`
switches that connection to byte-transparent opaque forwarding and explicitly
disqualifies observer evidence; encrypted bytes are never parsed.

Client write-half-close is legal while only backend replies remain. Once both
directions end, the observer audits all pending replies, parser/capture state,
DATA/BDAT bodies, and transaction state; any residual disqualifies the round.

Round evidence includes missing and duplicate indexes, duplicate Message-ID
detection, bounded first/last samples, order-independent SHA-256 XOR and
modular sums, an observed-order record digest, the exact last unique
final-`250` boundary, fixed-bucket transaction latency percentiles, connection
counts, byte counts, memory accounting, and fixed-bucket forwarding-stall
telemetry. Forwarding stall includes peer/socket backpressure and is not a
measurement of proxy-only overhead.

## Calibration mode

```text
lmyzmail-benchmark-proxy calibrate \
  --output /absolute/new/report.json \
  --messages 100000 \
  --message-bytes 10240 \
  --concurrency 100 \
  --mode data \
  --minimum-ratio 0.90 \
  --rounds 4 \
  --maximum-spread 0.20
```

Calibration runs balanced ABBA direct/proxied measurements with at least three
rounds per arm, reports per-round values and medians, and fails when either
arm exceeds the configured relative spread. It also records process scheduled
CPU and an incremental proxy CPU estimate; capacity ratio plus that CPU value,
not forwarding stall, is the proxy headroom evidence. The report is written as
a new, fsynced JSON file. `--mode` accepts `data` or `bdat`. Calibration remains
an observer-isolation check, not the oracle-versus-candidate product throughput
benchmark.

The formal launcher uses the `headroom-attest` command rather than accepting a
preselected report. It runs the producer inside the formal harness cgroup and
fixes three four-round ABBA tiers: 250,000 messages at 1 KiB and 10 KiB, plus
200 messages at 10 MiB. The content-addressed report includes every raw schema-2
calibration, per-tier and bundle hashes, host boot/time identity, executable,
runner and source hashes, cpuset/cgroup identity, both `io.max` records, and the
memory, swap, PID and open-file limits. The 1 KiB tier uses 1,500 concurrent
connections. Its open-file proof is `4 * 1500 + 512 = 6512`, and the formal
soft/hard limit is exactly 8192; a lower limit fails before calibration.

Formal throughput evidence pins both the exact release proxy binary SHA-256 and
a canonical SHA-256 of this crate's source tree. The external calibration must
carry those same identities. The launcher and runner independently recompute
the raw ABBA medians, spreads, observer counts, connection failures, minimum
proxied round, and calibration hashes instead of trusting top-level `passed`.
Its sustained per-tier message rate is divided by
the maximum observed Java or Rust product arm rate; a reported/precomputed
ratio is informational and qualification requires at least 2x recomputed
headroom.

## Evidence boundary

This crate observes SMTP wire acceptance. It does not replace candidate queue,
database, Maildir, disk-budget, process-metric, or restart-recovery evidence.
The formal harness must combine its output with those independently collected
artifacts and must reject any observer failure or missing message.
