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
