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
- `docs/outbound-queue-contract.md`: frozen Redis/queue lifecycle and required
  crash-recovery invariants for outbound delivery takeover.
- `docs/outbound-route-contract.md`: MX, MTA-STS, Redis cache, DNS pinning,
  deadline, and cancellation rules for outbound routing.
- `config/lmyzmail.properties.example`: non-secret installation configuration
  using the new key namespace.
- `deploy/lmyzmail.service`: bounded single-process systemd unit template.

## Current Runtime Milestone

The Rust candidate now provides the bounded Tokio lifecycle and configuration
alias contract together with incremental HTTP, authentication and session
handling, trusted-proxy enforcement, mailbox reads and mutations, attachment
downloads, and inbound SMTP persistence. Each admitted surface is exercised by
the external Java/Rust differential harness.

Outbound HTTP currently covers durable PostgreSQL admission, sender-scoped and
API status lookup, and quota reporting. A `202` response is emitted only after a
complete `PENDING` row commits; PostgreSQL advisory locks make queue-depth and
per-sender quota decisions atomic, and password verification runs behind a
bounded blocking-work permit. The outbound stack now includes fenced legacy
  Redis claims with reverse-token recovery, a PostgreSQL per-recipient commit
  ledger, a streaming SMTP adapter with a durable pre-terminator barrier, and
  bounded MX/MTA-STS routing with pinned addresses. An internal coordinator
  joins those pieces with one attempt token, renewable Redis/PostgreSQL
  keepalives, response-loss reconciliation, and PostgreSQL-before-Redis final
  ordering. Isolated PostgreSQL, Redis, and raw-SMTP tests cover successful,
  retryable, permanent, ambiguous, cancelled, stale-owner, and dropped-response
  paths. The coordinator is deliberately not started by `main` yet: MIME/DKIM
  and Sent Maildir publication plus the production worker lifecycle remain the
  next vertical boundary. This milestone is not yet a complete production
  replacement.
