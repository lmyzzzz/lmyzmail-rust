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
Caller-token claim results and final settlement receipts remain in bounded
seven-day Redis keys, so a delayed request cannot reuse a token or turn missing
lease state into false success. Final reconciliation validates the receipt and
the complete pending, retry, or acknowledgement postcondition.
The internal outbound coordinator validates the exact PostgreSQL, Redis task,
and per-domain recipient rosters before reading message bytes. It prepares an
SMTP transaction without its DATA terminator, commits `COMMIT_ARMED`, then
sends the terminator and durably records the final or ambiguous result. Only a
projected PostgreSQL result permits the fenced Redis claim to be acknowledged
or scheduled for retry. A bounded keepalive renews both stores during delivery,
stops database heartbeats after projection, and is fully quiesced before the
final Redis mutation.

Outbound routing is another internal adapter, not a service. One bounded
resolver owns MX and MTA-STS singleflight caches while sharing the process Redis
pool. It preserves the frozen `dns:mx:*` and `mta-sts:*` values and TTLs, pins
validated public addresses for policy HTTPS and SMTP, and carries one monotonic
deadline and per-caller cancellation through Redis, DNS, HTTPS, and host
selection. The internal coordinator consumes its ordered endpoints, but neither
component spawns a production worker merely by being constructed. `main` will
only start that worker after the remaining MIME/DKIM and Sent Maildir publication
boundary is integrated.
