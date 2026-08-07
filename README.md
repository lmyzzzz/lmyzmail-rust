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

## Database upgrade and rollback

On startup, `lmyzmail` acquires a PostgreSQL advisory transaction lock and
installs `001_outbound_delivery_ledger.sql` and
`002_outbound_spool_ownership.sql` and `003_outbound_dsn.sql`. These migrations are additive and
idempotent: they create only `lmyzmail_*` tables and indexes and do not alter
the frozen `outbound_mail_queue` columns or existing data. Startup does not
open protocol listeners until schema initialization succeeds.

For rollback, stop `lmyzmail` and let its bounded shutdown finish before
starting the frozen Java service. Keep the additive tables in place; Java
ignores them and a later lmyzmail restart needs them for delivery and spool
reconciliation. The Rust runtime preserves legacy Redis names and the
seven-day domain hashes, advances the legacy PostgreSQL identity sequence for
adopted IDs, and never deletes the Sent Maildir copy during spool cleanup.
Do not run Java and lmyzmail outbound workers concurrently against the same
queue.

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
  paths. MIME/DKIM construction, atomic Sent Maildir publication, and the
  coordinator are now connected to the production process through one bounded
  worker lifecycle. Startup first migrates the frozen Java archive and status
  lists through recoverable Redis inflight records; malformed or conflicting
  records are retained in lmyzmail quarantine lists. A single queue probe fills
  at most the configured concurrency and batch limits, while retry movement,
  stale-claim recovery, cancellation, and graceful shutdown remain bounded.
  Permanent failures are staged in the PostgreSQL DSN outbox. Admission uses a
  lease-fenced task ID, a durable RFC 3464/RFC 6533 report, and a temporary
  prepared-byte recovery image. The image is cleared atomically with `ADMITTED`
  queue commit while its SHA-256 remains durable. On restart, committed but
  unpublished DSNs are reconstructed from Sent Maildir/spool and idempotently
  replayed to the legacy Redis keys; active `PROCESSING` rows remain fenced.
  This milestone closes outbound delivery takeover, but the repository is not
  yet a complete production replacement for every frozen Java surface.
