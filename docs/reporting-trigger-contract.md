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

The active `managed-reports-v15` profile exercises a full seeded trigger after
single-domain delivery has warmed the resolver. It compares the HTTP result,
zero additional DNS traffic, Redis tasks and TTLs, Sent Maildir MIME and gzip
payloads, unchanged source rows, and exact fixture restoration across fresh
Java and Rust workspaces.
