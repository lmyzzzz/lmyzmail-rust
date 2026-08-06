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
delivery index consumed by queue workers.
