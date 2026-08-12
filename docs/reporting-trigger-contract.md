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
RST or socket error, cancels the PostgreSQL wait, releases the guard, and admits a retry
before the table lock is released. Neither path may perform DNS, Redis,
Maildir, or source-table mutations.

Clean FIN, unread data followed by FIN, and request write half-close are not
abort signals. They must not cancel a valid request or suppress its response.

The Java behavior is frozen in
`evidence/compatibility/report-trigger-disconnect-v1/java-golden/observation.json`
with SHA-256
`0b8ceeb22e472d852233029692906de1972f183b4993367b4e71aa145b5b1255`.
The Rust expectation is frozen in `candidate-observation.json` with SHA-256
`ab628fa4b165a58470c582bbe5aa92445bc4a711630ea4c8b08831b70970168a`.
The external test's SHA-256 is recorded in the supplemental manifest,
the candidate HTTP source has SHA-256
`f73a78567787e397224430da1fe840ce20ecd408cd3e5f846282bc6d7d4a9a3d`,
and the tested Linux x86_64 release has SHA-256
`e8663099260085f649c47ed8dac377323e716a8a79e805ab15daa6b67ddcb7dc`.
The immutable supplemental manifest has SHA-256
`de8fbdaa30e982e095a651ff4f87a228a5990a26c534d81cbc9ad1d591b7a6f2`.
The exact difference is approved as the supplemental
`http-report-trigger-client-disconnect-cancellation` entry; connected requests
and all surrounding report semantics remain frozen compatibility requirements.

The supplemental `report-trigger-postgres-outage-v1` profile applies an
`ACCESS EXCLUSIVE` lock, confirms one waiting report query with `pg_locks`,
and stops the isolated PostgreSQL process group without dropping existing
connections. Frozen Java remains blocked for the full twelve-second paused
observation and returns its normal zero-count `error=none` response only after
recovery. Rust reserves cancellation/drain time inside the eight-second
reporting database deadline and returns an exact HTTP 200 zero-count
`error=reporting database deadline exceeded` response while PostgreSQL is
still stopped. It then releases the guard and returns `error=none` on retry.
Both paths preserve the overlap `Already running` response and make no DNS,
Redis, Maildir, or source-row change. Empty EOF is not an accepted outcome.

This bounded safety difference is recorded only in the supplemental evidence
as `report-trigger-postgres-total-deadline`; the main definition tree and its
SHA-256 `f4747bee86575a8f59725e02829a459ceb88961dadfbf858113b63a517b99d4c`
remain unchanged.

The supplemental `report-trigger-postgres-crash-recovery-v1` profile runs
both databases with `fsync=on`, `synchronous_commit=on`, and
`full_page_writes=on`, blocks the real domain query, then sends `SIGKILL` only
to PostgreSQL. PostgreSQL restarts with a new PID from the same data directory
and port while the application PID remains unchanged. Both implementations
return HTTP 200 with zero counts during the failure, recover their connection
pools without an application restart, return `error=none` on retry, and leave
DNS, Redis, Maildir, and source rows unchanged.

Frozen Java's outage `error` includes its Hibernate SELECT, generated alias,
and JDBC/backend I/O exception. Rust returns the stable
`reporting database unavailable` value. The only approved supplemental
difference is `report-trigger-postgres-error-redaction`; SQL/driver disclosure
is intentionally removed, while every surrounding wire, lifecycle, recovery,
and storage assertion remains strict.
