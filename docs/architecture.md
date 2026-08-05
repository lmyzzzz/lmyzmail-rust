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

