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
`002_outbound_spool_ownership.sql`, `003_outbound_dsn.sql`, and
`004_outbound_spool_cleanup.sql`. These migrations are additive and idempotent:
they create or extend only `lmyzmail_*` tables and indexes and do not alter the
frozen `outbound_mail_queue` columns or existing data. Startup does not open
protocol listeners until schema initialization succeeds.

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
downloads, inbound SMTP persistence, and the complete HTCPCP coffee/tea state
machine. Each admitted surface is exercised by the external Java/Rust
differential harness.

HTCPCP runs as a bounded Tokio listener only when enabled. It preserves the
frozen eight-pot configuration, BREW/POST/GET/HEAD/OPTIONS/PROPFIND/WHEN wire
behavior, coffee URI variants, additions and tea rules, chunked and
100-continue framing, keep-alive pipelining, timers, and process-local restart
semantics. The candidate v8 differential passed every frozen scenario; unit,
property, structured-fuzz, concurrency, and release tests cover the parser and
state machine. Three resource-safety differences are allowlisted: declared
connection close is honored immediately, incomplete framing has an absolute
60-second deadline, and ambiguous Content-Length/Transfer-Encoding combinations
are rejected before dispatch or 100 Continue.

The authenticated management API now includes `POST /api/mailboxes` and
`GET /api/mailboxes/{address}/exists`, with Java-compatible permission, JSON,
normalization, password-length, response-order, and PostgreSQL behavior. Public
registration can be disabled without disabling API management. Domain receipt
uses `lmyzmail.domains.main.receive-enabled`, falls back to the frozen
`botmail.domains.main.receiveEnabled` alias, and gives the new key precedence.
Mailbox creation is serialized and rate-limited with hard bounds. Every auth
database operation uses one absolute deadline, request cancellation,
transaction-local PostgreSQL timeouts, bounded `CancelRequest` draining, and
connection detachment when reuse or commit outcome cannot be proven. Bcrypt
work runs on a dedicated four-worker, four-slot pool and is joined even after
its soft deadline. Mailbox creation and session mutations hold deterministic
transaction-level advisory locks. If a COMMIT response is lost, the old
connection is permanently detached and a fresh connection uses the same lock
plus the exact durable identity or intended final state to distinguish a
committed result from a safe retry; conflicts and failed reconciliation remain
outcome-unknown.

The read API now also includes `POST /api/mail/poll`, `/api/mail/raw`, and
`/api/mail/rawDecoded`. It preserves mailbox-password authentication and ban
responses, the legacy 32 KiB raw-read ceiling, decoded plain/HTML selection,
missing-file errors, nonpositive-limit fallback, and the complete signed
64-bit `sinceEpochMillis` input range. Polling is a bounded indexed PostgreSQL
query, and raw mail is streamed to the socket without copying the whole message
into an HTTP response buffer.

Minecraft now has an admitted 1.8.9 status slice, enabled only through
`lmyzmail.minecraft.enabled` or its frozen `botmail.minecraft.enabled` alias.
Fragmented handshake, status, ping/pong, malformed framing, exact UTF-8 MOTD
bytes, and close behavior match the Java golden. The listener has a fixed
64-connection admission bound, a 2 MiB frame ceiling, one absolute configured
connection deadline, and joined cancellation. Login, authentication, play,
GUI, mail, world, and video remain outside this milestone and are not claimed
as implemented.

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
  Cancellation and storage soft deadlines signal cooperative blocking work and
  join it before worker shutdown, leaving no detached Maildir mutation.
  Redis publication response loss is checked against the complete legacy task,
  domain, sent-file, and queue references before one bounded idempotent retry.
  Every Rust spool has a PostgreSQL ownership row; inline spools carry a durable
  post-publication cleanup flag and restart recovery advances them to `REMOVED`
  only after Redis publication is proven. HTTP request deadlines propagate
  cancellation through admission and join cooperative work before returning.
  This milestone closes outbound delivery takeover, but the repository is not
  yet a complete production replacement for every frozen Java surface.
