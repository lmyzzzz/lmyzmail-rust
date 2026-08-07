# Architecture

`lmyzmail` is one Tokio process with explicit module ownership. The planned
runtime graph is deliberately internal, not a collection of services:

1. A configuration and lifecycle layer owns startup, cancellation, reload, and
   graceful shutdown.
2. Protocol frontends own HTTP, SMTP, HTCPCP, Minecraft, honeypot, and XDP
   ingress state machines.
3. Mail, identity, policy, reports, scheduling, and abuse modules own domain
   transactions.
4. PostgreSQL, Redis, Maildir, DNS, TLS, and outbound HTTP/SMTP adapters own
   external side effects.
5. Bounded native, inference, rendering, and media pools isolate CPU and
   blocking work from protocol reactors.

Every cross-module request carries a deadline and cancellation token. Capacity
is reserved before accepting work; admission failure is observable at the same
protocol boundary where overload occurs.

The process creates one PostgreSQL pool at startup and clones its handle into
HTTP authentication, mailbox, outbound, and SMTP modules. Consequently,
`lmyzmail.postgres.pool.max-size` (or the legacy Hikari alias) is a process-wide
connection ceiling rather than a per-module multiplier.

The same ownership rule applies to Redis. One bounded authenticated/TLS-aware
pool is shared by SMTP counters and the outbound queue. The outbound producer
uses a four-slot blocking pool for MIME, DKIM, and Maildir work; it does not
hold a PostgreSQL transaction while generating message bytes. PostgreSQL is
the durable outbox, while the legacy Redis task/domain/list/hash surface is the
delivery index consumed by queue workers. A Rust-only additive PostgreSQL
recipient ledger records the SMTP pre-commit barrier and exact per-recipient
outcome without changing legacy columns. One caller-generated opaque attempt
token fences the Redis lease, legacy PostgreSQL row, and sidecar generation;
unknown mutation responses are reconciled before either store is advanced.
An admission `COMMIT` response loss is read back on that same ordered
connection and classified from the exact queue, `email_index`, and spool
identities. Anything other than a complete match or complete absence remains
unknown and preserves all materialized files.
Caller-token claim results remain for the matching lease lifetime, while final
settlement and migration receipts remain for 300 seconds. Every receipt family
has a 4096-entry expiry index maintained from Redis server time; admission
prunes expired entries and rejects before changing queue state when the bound
is full. Empty claim probes leave no tombstone. Final reconciliation validates
the receipt and the complete pending, retry, or acknowledgement postcondition.
All Lua mutations validate every static and dynamic key type, identity, size,
and receipt bound before their first write. Claim previews and validates the
list head before `LPOP`, so a malformed task or existing lease cannot be
partially claimed.
The internal outbound coordinator validates the exact PostgreSQL, Redis task,
and per-domain recipient rosters before reading message bytes. It prepares an
SMTP transaction without its DATA terminator, commits `COMMIT_ARMED`, then
sends the terminator and durably records the final or ambiguous result. Only a
projected PostgreSQL result permits the fenced Redis claim to be acknowledged
or scheduled for retry. A bounded keepalive renews both stores during delivery,
stops database heartbeats after projection, and is fully quiesced before the
final Redis mutation.

Large-message temporary-file ownership is recorded in the additive
`lmyzmail_outbound_spool` table in the same PostgreSQL database. Queue
maintenance scans only a bounded terminal subset of that table, independently
of whether the Redis task still exists. Cleanup accepts only the configured
spool root and the task-bound `message-<id>.eml` or `signed-<id>.eml` name;
legacy Java files additionally have to match the retained Sent Maildir copy
byte for byte. Linux cleanup holds root directory descriptors and uses
`openat2`/`unlinkat` with beneath, no-symlink, and inode checks. Unlink is
followed by directory fsync and a monotonic `REMOVED` checkpoint, so a crash at
either boundary is idempotently recoverable and a timed-out blocking unlink is
never allowed to continue after the queue claim has been released.
The `REMOVED` sidecar remains until Redis atomically proves that task, pending,
processing, processing-time, retry, lease, and sent-file references are all
absent. PostgreSQL then deletes only the exact sidecar identity; maintenance
uses a wrapping bounded cursor so one active low-ID row cannot starve later
cleanup.

Outbound routing is another internal adapter, not a service. One bounded
resolver owns MX and MTA-STS singleflight caches while sharing the process Redis
pool. It preserves the frozen `dns:mx:*` and `mta-sts:*` values and TTLs, pins
validated public addresses for policy HTTPS and SMTP, and carries one monotonic
deadline and per-caller cancellation through Redis, DNS, HTTPS, and host
selection. The internal coordinator consumes its ordered endpoints. `main`
constructs and initializes the outbound worker before opening the long-running
service graph, retrying PostgreSQL schema initialization with cancellation-aware
exponential backoff and jitter, then supervises it together with HTTP and SMTP
under the same cancellation token. The worker migrates recoverable legacy
archive/status records in an independent bounded background loop, uses one
claim probe to fill bounded concurrency without an idle Redis stampede, and
periodically moves due retries and recovers only claims whose lease and
processing deadline have both expired.
Delivery-wide infrastructure failures open a circuit with capped equal-jitter
backoff. Expiry admits one half-open probe only; its success restores normal
concurrency and its failure returns to backoff.
SIGTERM cancels all three services and gives outbound delivery 30 seconds to
release or quarantine owned commit state before the process deadline is
enforced.
