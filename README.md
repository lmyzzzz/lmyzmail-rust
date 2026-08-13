# lmyzmail

`lmyzmail` is a Linux x86_64 Rust rewrite of the frozen Java oracle. It is a
single-process modular monolith: one production binary, one lifecycle, bounded
internal execution pools, and no Java runtime dependency.

The current repository milestone contains the immutable source baselines and
the implementation-independent black-box compatibility harness. Product code
is admitted only after the harness can recreate isolated PostgreSQL, Redis,
Maildir, certificate, and port state and can produce a repeatable Java golden.
The report API harness records a separate `managed-reports` golden from raw
HTTP sockets and an attested legacy PostgreSQL fixture, then replays it against
a second independently initialized Java oracle before admitting that golden.
The XDP harness separately freezes the disabled control plane before any
privileged attach testing, so ordinary HTTP compatibility cannot be confused
with kernel-map or program-ownership evidence.

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

## Reproducible release verification

Run the locked release verifier only from a clean commit:

```bash
tools/verify-release-reproducibility.sh evidence/build/release-reproducibility-v1.json
```

The verifier performs two complete `cargo --frozen` release builds in separate
temporary target directories, with the commit timestamp, UTC, and the C locale
fixed. It requires byte-identical stripped ELF files and Build IDs, rejects
unresolved libraries and Java/JVM dependencies or dynamic symbols, and writes
the machine-readable result atomically. It never cleans or reuses the normal
workspace `target/` directory.

## Installation and rollback

Stage an installation without changing the host:

```bash
tools/install-lmyzmail.sh --destdir /absolute/staging/root
tools/test-installation.sh
```

For a live installation, run the installer as root. It creates the locked
`lmyzmail` system account, installs the release binary, systemd unit, default
configuration, InferX model, tokenizer, and video asset, then leaves the unit
stopped unless `--enable` is specified. Existing
`/etc/lmyzmail/application.properties` is never overwritten. Re-running the
installer atomically upgrades packaged files while preserving configuration,
Maildir, spool, and state. `--enable` is accepted only for a fresh install;
after an upgrade, inspect the preserved configuration and start the unit
explicitly.

`ProtectHome=true` remains enabled. To adopt existing storage outside the
default directories during a live install, pass each canonical path explicitly,
for example `--legacy-rw /srv/legacy-mail/data/mail` for Maildir or
`--legacy-ro /srv/legacy-mail/certs` for certificates and model assets. Every
ancestor must be root-owned and not group/other writable so the bind source
cannot be replaced between validation and service start. The installer does not
change ownership of adopted paths and rejects paths the `lmyzmail` user cannot
access. It generates only exact-path systemd bind allowances; broad filesystem
roots and symlinks are rejected. Adoption flags are intentionally unavailable
with `--destdir`, because host staging paths cannot encode relocatable binds.

```bash
sudo tools/uninstall-lmyzmail.sh
```

The conservative uninstall requires a successful, verified systemd shutdown,
then disables lmyzmail and removes the binary, unit, packaged example, and
generated legacy-path grant. It fails without removing those files when the
service manager is unavailable,
the process does not stop, or the unit records an unsuccessful result. This is
important because an unsuccessful shutdown may also mean that conditional XDP
detach failed. It deliberately retains PostgreSQL, Redis, configuration,
Maildir, spool, logs, model/video assets, the service account, and BPF pins so
the frozen Java service or a later lmyzmail install can adopt the same state.
Never run the Java and Rust outbound workers concurrently.

The base unit grants only `CAP_NET_BIND_SERVICE` for SMTP port 25. It grants no
XDP capability and the default configuration keeps XDP disabled. Privileged
XDP deployment remains gated on a dedicated active/legacy bpffs ownership
model and a verified conditional-detach maintenance command; do not add
`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_DAC_OVERRIDE`, or run the monolith as root to
bypass that gate.

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

Inbound SMTP now includes the frozen Spamhaus DNSBL/DBL early-check path. The
candidate accepts every legacy `botmail.smtp-security.spamhaus-*` setting with
field-by-field `lmyzmail.*` precedence, performs bounded asynchronous A lookups,
preserves Java return-code descriptions and Latin-1 rejection bytes, caches the
combined client/domain result, and persists exact `SPAMHAUS_LISTED` Cringe
activity. Three create-once profiles cover DBL decisions, fail-open DNS errors,
cache expiry, reject-disabled behavior, and the fully disabled no-query path.
Malformed explicit-DNS replies fail open after strict transaction, question,
response-type, truncation, and 4 KiB checks.

The active default content-filter composition is frozen under
`managed-smtp-content-filter-default-v4`. With reputation rules isolated, the
default body produces ordered `SPAM_KEYWORDS=8.0, SUSPICIOUS_URL=1.5`; omitting
From and Date prepends `MISSING_HEADERS=3.5` for a total of 13.0. Both messages
route exactly once to spam with matching Maildir bytes, PostgreSQL index state,
and Redis no-TTL counters. Five Java placeholder rule classes are disabled
no-ops and are not presented as implemented product behavior.

The reporting slice now discovers Java-compatible DMARC and TLSRPT RUA
destinations, reads the legacy PostgreSQL aggregates, renders byte-exact gzip
attachments on a bounded blocking pool, and publishes single-domain or full
manual-trigger deliveries through the durable PostgreSQL/Redis/Sent-Maildir
outbound queue. The seeded v19 differential covers DNS order and positive TTL
cache reuse, HTTP summary counts, MIME, decompressed XML/JSON, queue fields and
TTLs, Maildir shards, and unchanged source rows.
TLSRPT HTTPS RUA delivery now performs the frozen POST through one validated,
pinned DNS answer set with public-address enforcement, hostname-verified TLS,
no proxy or redirects, exact request framing, bounded response headers, no
response-body consumption, and one absolute deadline/cancellation path. The
User-Agent uses the authorized `lmyzmail` product identifier. When reporting
and automatic sending are enabled, a cancellation-aware root task runs the same
bounded generation path at 01:00 UTC. The frozen Java retention queries are not
invoked by its scheduler, so the candidate likewise performs no implicit
report-row deletion.

The authenticated `/api/stress/*` slice now preserves the frozen warmup and
production round state, dynamic 1500/1000/400/200/120/80 concurrency
thresholds, exact generated bodies, mailbox creation, outbound quota bypass,
Redis task/TTL state, status/reset responses, and automatic or manual cleanup.
It is disabled by default and accepts every legacy `botmail.stress-test-*`
setting with field-by-field `lmyzmail.*` precedence. One active run, four
dedicated body workers, a four-job blocking queue, a shared 64 MiB generated
body budget, file-backed streaming for bodies above 20 KiB, serialized manual
cleanup, and bounded non-symlink-following cleanup prevent the frozen
controller's overlapping-run, cleanup-race, and resource-growth defects.

The XDP foundation embeds the frozen C/eBPF source behind a serialized Rust FFI
worker. Its build verifies every frozen source hash, requires Clang 18.1.3, and
compiles x86_64 C ABI layout assertions. Configuration accepts the complete
legacy `botmail.xdp.*` namespace with `lmyzmail.xdp.*` precedence and fixed
limits. Cringe reconciliation reads every existing IPv4/IPv6 ban in a
repeatable PostgreSQL snapshot and keyset-pages new candidates, rather than
reusing the 10,000-row management export. Initialization cancellation closes a
late native attach, management failures fail closed, and cache capacity matches
the two 100,000-entry native maps. Disabled HTTP behavior is frozen separately;
enabled takeover is admitted only by the privileged veth/netns, pinned-map,
restart, ownership, and rollback tests.

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
connection deadline, and joined cancellation. Offline login, world bootstrap,
scheduled play maintenance, bounded position rebound, and the email/password
authentication prompt plus the basic authenticated `/help`, `/stuck`,
`/skibidi`, `/video` usage, empty `/draft`, and `/clear` commands now match
frozen Java wire goldens. Auth attempts use the bounded
`lmyzmail.minecraft.auth.*` settings with the legacy `botmail.minecraft.auth.*`
aliases accepted at lower precedence. The authenticated six-row main menu now
opens with its exact frozen slot/NBT layout, rejects and refreshes a filler
click, and restores the Book & Quill and Nether Star when the client closes the
window. Help, Close Menu, and Switch Account clicks now preserve the Java packet
order and Switch Account returns the connection to the email/password flow.
Logout now has its complete confirmation, cancel, and disconnect flow. The Rust
runtime flushes the final Disconnect Play frame before EOF instead of preserving
the frozen Java write/close race. Render Settings now preserves the complete
menu and `/mail rendersize|rs` sign-editor flows, direct command updates,
per-session dimensions and font state, validation boundaries, scoreboard
refresh, and updated menu NBT. Data-backed Inbox/Sent/Trash/Spam folder lists
now use the legacy PostgreSQL index, preserve attachment glow and Java UTF-16
truncation at the NBT boundary, and refresh pagination in place while discarding
cancelled or late database results. Clicking a message now loads the bounded
legacy Maildir detail and renders plain text, HTML, CID images, safe external
images, and attachment cards into Minecraft 1.8 map colors. Rust owns resource
decoding, pagination, dithering, and tile storage; an ABI-versioned native
boundary uses source-pinned litehtml with Cairo only for HTML layout and drawing.
Rendering runs on a two-worker, two-slot blocking pool with a 60-second deadline,
hard input/output/image budgets, cancellation, SSRF-resistant image fetching,
and joined shutdown. The map wall preserves configurable orientation and IDs,
restores covered blocks and hotbar state, and overwrites absent rows with the
frozen blank palette color on short final pages. The complete v4 raw-socket
candidate trace and all seven rendered page hashes match the frozen Java golden.
Map and block video playback now use the source-pinned FFmpeg 7.1 decoder behind
a narrow C/Rust boundary, stream one bounded frame at a time, and run palette or
block conversion on a two-worker, two-entry CPU pool. The frozen MP4 hash, video
menu and command validation, map IDs and item frames, full and dirty-rectangle
pixels, block chunks, pause/resume/stop flow, teardown, hotbar, scoreboard, and
completion messages match the v3 Java golden. A shared fixed-capacity permit
remains held through every admitted map or block playback lifecycle; this
intentionally fixes the oracle's premature map-video permit release without
changing admitted-session protocol behavior.

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
