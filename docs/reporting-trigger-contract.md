# Report trigger compatibility contract

`POST /api/reports/trigger` preserves the frozen Java scheduler's process-local
single-run admission, DMARC-before-TLS execution order, per-delivery summary
counts, no-RUA zero-count behavior, durable outbound publication, and
`Already running` result. Candidate-side deadline, root shutdown, and peer
disconnect cancellation exit the active request, join its work, and release
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

The active `managed-reports-v23` profile exercises a full seeded trigger after
single-domain delivery has warmed the resolver. It compares the HTTP result,
zero additional DNS traffic, Redis tasks and TTLs, Sent Maildir MIME and gzip
payloads, unchanged source rows, and exact fixture restoration across fresh
Java and Rust workspaces. All eight report scenarios now run from the normal
`blackbox/tests` collection for both targets; the earlier tools-only candidate
entry point has been removed. v1 through v22 remain immutable historical
profiles.

The v23 profile preserves the independently replayed v22 observations under
the final scheduler-restart definition tree. Rust separately starts and stops
with automatic sending enabled. The dedicated
`managed-reports-scheduler-v2` profile crosses a real 01:00 UTC cron boundary
under an application-only wall-clock shim and proves prior-date selection, one
publication at the boundary, exact DNS order, Redis/Maildir/MIME/gzip side
effects, unchanged source rows, and bounded shutdown.

The independent `managed-reports-scheduler-restart-v1` profile stops the
application at 00:59:20 UTC and restarts it at 01:00:20 UTC while PostgreSQL
and Redis remain running. A fresh Java process performs no missed-run catch-up,
and the Rust candidate matches its zero DNS, Redis, Maildir, and source-row
side effects. Storage fault injection and scheduler high-concurrency or
long-running soak remain separate matrices.

The supplemental `report-trigger-concurrency-v1` profile holds an admitted
trigger at the real DMARC domain-discovery query with a PostgreSQL table lock.
After `pg_locks` confirms the waiting `AccessShareLock`, a concurrent raw HTTP
trigger receives status 200 with zero counts and `error=Already running`; it
adds no DNS query, Redis task, or Maildir file. Releasing the lock lets only
the admitted request publish one DMARC and one TLSRPT report. Java recording,
fresh Java replay, and Rust replay match under the unchanged active definition
tree. Disconnect cancellation, storage faults, higher fan-in, and soak remain
unclaimed by that concurrency profile.

The supplemental `report-trigger-disconnect-v1` profile isolates peer-lifetime
cancellation. It sends a complete authenticated request, blocks the real DMARC
domain query with a PostgreSQL table lock, confirms the waiting lock through
`pg_locks`, and closes the client with TCP RST. Java retains the blocked query
and guard, and a later request receives `Already running`. Rust observes the
closed peer, cancels the PostgreSQL wait, releases the guard, and admits a retry
before the table lock is released. Neither path may perform DNS, Redis,
Maildir, or source-table mutations.

The Java behavior is frozen in
`evidence/compatibility/report-trigger-disconnect-v1/java-golden/observation.json`
with SHA-256
`0b8ceeb22e472d852233029692906de1972f183b4993367b4e71aa145b5b1255`.
The Rust expectation is frozen in `candidate-observation.json` with SHA-256
`ab628fa4b165a58470c582bbe5aa92445bc4a711630ea4c8b08831b70970168a`.
The external test's SHA-256 is recorded in the supplemental manifest,
the candidate HTTP source has SHA-256
`6c63f11ac277433682f5c550f7b4431f7394aeaab3b7b6fb2389ea7051c9795f`,
and the tested Linux x86_64 release has SHA-256
`618dfa5140196fee54f908d2e71f63eb67d4a454324f9b263dd32135f3e47e53`.
The immutable supplemental manifest has SHA-256
`e2719d43d55cdda8558b12297ba429eea537db7ba20edd653d1bbd69b772842a`.
The exact difference is approved as the supplemental
`http-report-trigger-client-disconnect-cancellation` entry; connected requests
and all surrounding report semantics remain frozen compatibility requirements.
