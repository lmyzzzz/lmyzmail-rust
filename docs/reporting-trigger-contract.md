# Report trigger compatibility contract

`POST /api/reports/trigger` preserves the frozen Java scheduler's process-local
single-run admission, DMARC-before-TLS execution order, per-delivery summary
counts, no-RUA zero-count behavior, durable outbound publication, and
`Already running` result. Cancellation exits the active request and releases
the admission guard.

The Rust implementation selects at most 10,000 reportable domains for each
protocol, processes them sequentially, and inherits every per-report database,
DNS, render, HTTP, outbound queue, and Maildir deadline or bound. Successful TXT
answers are cached for their received TTL in a 1,024-response cache. NXDOMAIN
answers are not cached, preserving the oracle's explicit retry behavior.

When both reporting and automatic sending are enabled, the HTTP route and the
01:00 UTC scheduler share the same generation guard, resolver, and outbound
service. The scheduler recalculates wall-clock distance at least once per minute
so clock corrections cannot create an unbounded sleep, runs the prior UTC date,
and observes root cancellation during both waiting and generation. Like the
frozen scheduler, it does not catch up a missed run after restart and does not
invoke the otherwise unused retention queries.

The scheduling contract is traced to frozen Java commit
`5dac2ab2922c30c726c4a83d7626c95ad4e231c8`, source
`ReportGenerationScheduler.java`, SHA-256
`7fff9bf0d8bdd157e1afcad4fa163a6de51ee828e426a1fd14a43b48d567e3cb`.

The active `managed-reports-v19` profile exercises a full seeded trigger after
single-domain delivery has warmed the resolver. It compares the HTTP result,
zero additional DNS traffic, Redis tasks and TTLs, Sent Maildir MIME and gzip
payloads, unchanged source rows, and exact fixture restoration across fresh
Java and Rust workspaces.
