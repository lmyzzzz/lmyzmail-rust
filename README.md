# lmyzmail

`lmyzmail` is a Linux x86_64 Rust rewrite of the frozen Java oracle. It is a
single-process modular monolith: one production binary, one lifecycle, bounded
internal execution pools, and no Java runtime dependency.

The current repository milestone contains the immutable source baselines and
the implementation-independent black-box compatibility harness. Product code
is admitted only after the harness can recreate isolated PostgreSQL, Redis,
Maildir, certificate, and port state and can produce a repeatable Java golden.

## Compatibility rules

- Existing PostgreSQL data, Redis keys and TTLs, Maildir content, certificates,
  and model files are adopted in place.
- `lmyzmail.*` configuration keys take precedence over legacy `botmail.*`
  aliases when both are present.
- Branding and configuration aliases are the only intentional default
  differences. Other observable behavior is measured against the frozen Java
  oracle.
- Protocol parsers, queues, caches, and blocking or CPU work all have explicit
  limits, deadlines, cancellation, and backpressure.

## Repository layout

- `blackbox/`: external pytest, raw-socket, and Playwright differential tests.
- `evidence/freeze/`: immutable baseline manifests, patches, and test evidence.
- `native/lmyzmail-skibidi/`: source pinned to the frozen 1.8.0 commit.
- `oracle/artifacts/`: ignored local Java oracle artifact, verified by manifest.
- `docs/`: architecture, compatibility, security, and acceptance records.

