# Outbound Queue Contract

This document records the outbound queue boundary that the Rust runtime must
adopt before it takes over an existing installation. The observations below
are from the frozen Java oracle at commit
`5dac2ab2922c30c726c4a83d7626c95ad4e231c8`. The source checkout is read-only;
the hashes bind this document to that commit rather than to a drifting working
tree.

## Legacy Redis Surface

The deployed Redis names are part of the takeover contract. They remain
readable and writable by the Rust runtime, even when the new configuration uses
`lmyzmail.*` names:

| Purpose | Legacy key | Type | Lifetime |
| --- | --- | --- | --- |
| pending task IDs | `botmail:mail:queue:pending` | list | no key TTL |
| active claims | `botmail:mail:queue:processing` | set | no key TTL |
| delayed retry IDs | `botmail:mail:queue:retry` | sorted set | no key TTL |
| claim start times | `botmail:mail:queue:processing_time` | hash | no key TTL |
| task metadata | `botmail:mail:queue:task:<id>` | string JSON | 7 days (604800 s) |
| per-domain status | `botmail:mail:queue:domains:<id>` | hash | 7 days, refreshed on update |
| sent-file lookup | `botmail:mail:queue:sentfile_index` | hash | no key TTL |
| status updates | `botmail:mail:queue:status_updates` | list | no key TTL |
| archive records | `botmail:mail:queue:archive` | list | no key TTL |

The Java claim script atomically performs `LPOP pending`, `SADD
processing`, and `HSET processing_time`. Retry scheduling atomically removes
the processing claim and timestamp and inserts the ID into the retry sorted
set. Expired retry IDs are moved back to pending by a Lua script. Task-detail
JSON is written with a seven-day TTL independently of the queue references.

The task-detail TTL and the non-expiring pending/retry references are therefore
not a safe durability design: a task can remain referenced after its metadata
has silently expired. This is an observed legacy behavior, not a Rust design
requirement.

The frozen source has producers for `status_updates`, but its
`popStatusUpdates` method has no production caller. Failures routed only to
that list can therefore accumulate without a consumer or key TTL. The Rust
takeover must inventory and reconcile existing entries before enforcing its
configured queue bound.

## Frozen Lifecycle

The relevant frozen source hashes are:

| Source | SHA-256 |
| --- | --- |
| `MailQueueScheduler.java` | `06b64256a19e0f8589ca12599181ee5a2b2b2176005c13c213d32e5e19b2ee02` |
| `MailQueueRedisService.java` | `f9abffe3fbc98e314db34fcf38d894fd200d93ad74ff933f2c0f57e2717f1bf4` |
| `MailQueuePersister.java` | `f5ba8596cf36f2fdb8af7bbde2133f9f352e9db2c073eacbf5bb8277e87b6360` |
| `AsyncMailSender.java` | `c7f10f2416ae308335e9f6f77ffe00140b64904b0b2e8dc7eb04ed74394c603e` |
| `OutboundMailService.java` | `4364488928d307a31e5bdabaa7355db3f0d146607cace085f8900faa364b99ba` |

The observed sequence is:

1. Queue creation writes a sent Maildir copy, initializes domain status,
   writes task metadata, saves the sent-file index, and pushes the task ID to
   pending. These operations are separate Redis/filesystem/database effects.
2. A scheduler claims IDs with the Lua script and submits work to a bounded
   Java worker pool. A semaphore wait refreshes the claim timestamp once before
   sending.
3. A successful or permanently failed send pushes an archive record, removes
   the processing claim, and deletes file-mode temporary content. Archive
   persistence happens later in another worker.
4. The archive worker removes records with `LPOP` before its PostgreSQL
   transaction. A database failure therefore loses the Redis archive record;
   the Java loop retries the remaining records but cannot reinsert the popped
   item.
5. Archive persistence uses an idempotent PostgreSQL upsert and deletes task
   details only after the database batch succeeds. File cleanup is attempted
   after the database write, but a task that was already marked complete can
   have no Redis body left when archive persistence later runs.

## Rust Producer And Outbox

The Rust producer now applies the following bounded order:

1. Validate sender, recipients, subject, attachment count/bytes, canonical
   Base64, filename, MIME type, and Content-ID before allocating a task ID.
2. Raise the legacy Redis sequence above the current PostgreSQL maximum using
   decimal-string comparison, then increment it without converting the 64-bit
   value through a Lua floating-point number.
3. Build and optionally DKIM-sign MIME in a four-slot blocking pool with a
   60-second deadline and cancellation checks. Small messages use Redis Base64;
   large messages retain a file below the configured lmyzmail spool directory.
4. Publish the Sent copy with a same-filesystem temporary file, file `fsync`,
   atomic no-clobber hard link, temporary unlink, and directory `fsync`.
5. Under PostgreSQL advisory admission locks, atomically insert the complete
   `outbound_mail_queue` row and Sent `email_index` row. The identity sequence
   is advanced to the explicit legacy task ID so a rollback to Java/default
   inserts cannot collide. Timestamps are fixed to PostgreSQL microsecond
   precision before the first Redis serialization.
6. Atomically create the exact legacy task JSON, domain-status hash, sent-file
   index, and pending reference in Redis. Repeated publication succeeds only
   when the task and every domain JSON value are identical.
7. Delete a small-message spool only after Redis publication succeeds. A Redis
   failure leaves PostgreSQL, Sent Maildir, and message bytes intact for replay.

The in-process outbox reconciler starts immediately and scans at most 128
pending rows every five seconds using an ID cursor. Complete Redis tasks have
their task/domain TTL renewed without reading message bytes. Missing state is
rebuilt from the Sent copy: small messages are Base64-encoded with a bounded
read, while a missing large-message spool is atomically reconstructed at the
same stable path. The same path runs after process restart and does not depend
on Java or an in-memory request object.

## Rust Claim And Lease Primitive

Rust claims preserve the three legacy observations (`LPOP pending`, membership
in `processing`, and the millisecond value in `processing_time`) while adding a
per-task fencing key named `lmyzmail:mail:queue:lease:<id>`. The value is an
opaque, bounded owner token and the key always has a millisecond TTL. A claim
sets that key with `NX PX` in the same Lua execution that updates the legacy
structures. A duplicate pending reference cannot create a second owner.

Renewal, release, retry scheduling, and acknowledgement compare the opaque
token inside their Lua script. A stale owner therefore cannot extend, requeue,
or acknowledge a task after its lease has been replaced. Renewal also refreshes
the legacy processing timestamp and the seven-day task/domain TTLs. Retry
scheduling atomically replaces the Java-compatible task JSON, removes the
processing claim, and inserts the ID into the legacy retry sorted set. A
bounded script moves due retry IDs back to pending without duplicating an
already pending or processing ID.

Expired-claim discovery uses bounded `SSCAN` pages and only reports processing
members whose Rust lease key is absent. Recovery checks absence again inside
the mutation script, so a concurrent renewal wins. The future delivery worker
must additionally fence the corresponding PostgreSQL row with `processor_id`;
it may call Redis acknowledgement only after the PostgreSQL terminal-state
transaction commits. These primitives deliberately are not wired to a sender
until that durable database transition and real SMTP delivery exist together.

## Rust SMTP Delivery Adapter

The standalone Tokio adapter accepts a pinned `SocketAddr`, never a hostname
that it could resolve again during connect. Direct-MX callers must construct an
endpoint through `SmtpEndpoint::public_mx`, which rejects loopback, private,
link-local, documentation, benchmark, multicast, reserved, Teredo, and unsafe
6to4 targets. Only an administrator-controlled relay may use the explicit
`trusted_relay` constructor. DNS resolution, full-answer-set validation, and
MX ordering remain outside the adapter so that the eventual resolver can pin
the exact reviewed address without a DNS-rebinding window.

The client performs bounded multiline reply parsing, EHLO-to-HELO fallback,
STARTTLS followed by a fresh EHLO, SMTPUTF8 negotiation with IDN-only
downgrade, bounded MAIL/RCPT PIPELINING, and per-recipient 2xx/4xx/5xx
classification. It opens and validates file sources before issuing DATA,
waits for exactly `354`, streams in 16 KiB chunks, normalizes CR/LF/CRLF to
CRLF, and dot-stuffs across chunk boundaries. Reply lines, aggregate replies,
recipient count, command-pipeline bytes, remote summaries, message input, and
all temporary buffers have explicit limits.

One absolute session deadline is shared by the TLS attempt and any permitted
plaintext retry. Each connect, command, TLS handshake, file operation, and
message chunk also has an operation deadline and cancellation branch. A
failure before the DATA terminator is retryable or cancelled; a timeout,
cancellation, malformed reply, or disconnect after the terminator may have
followed remote acceptance and is therefore returned as `Ambiguous` with the
known recipient outcomes. The worker must durably record that distinction and
must not turn it into an ordinary automatic retry. Errors carry a structured
SMTP stage and optional reply code; worker policy never parses display text.
Missing or invalid local content is permanent, while deadlines and unknown
resource/filesystem errors remain retryable.

The default trust roots come from the Linux native certificate store, with the
compiled WebPKI set only as a fallback for an empty store. TLS server-name
verification is always enabled. The frozen Java client enables endpoint-name
verification only for MTA-STS enforce mode; this identity-validation defect is
recorded as `outbound-starttls-hostname-verification` in the approved behavior
difference manifest. Opportunistic TLS still follows the oracle by retrying a
fresh plaintext connection after a TLS negotiation failure, while required
TLS never downgrades.

## Required Rust Invariants

The candidate must preserve the legacy key names and successful status/body
semantics while closing the reliability gaps above:

- Claim, lease renewal, timeout recovery, and acknowledgement must be bounded
  and crash-safe. A task is not removed from a durable work list until its
  PostgreSQL archive transaction commits.
- An active send needs a renewable lease or fencing token. Recovery must not
  start a second sender while the first still owns the task. A remote SMTP
  acceptance followed by a local crash remains an inherently ambiguous
  two-system outcome; retries use stable task/message IDs and the ambiguity is
  surfaced rather than pretending to provide exactly-once SMTP delivery.
- Archive and status-update consumers need a recoverable in-flight state and
  idempotent database writes. The Rust process must be able to restart with
  Redis and PostgreSQL unavailable, then resume without silently dropping IDs.
- Queue depth, task-detail size, attachment/body bytes, worker count, lease
  count, and archive batch size all have hard limits with cancellation and
  deadlines. Backpressure must reach the HTTP/API producer. The legacy
  `status_updates` list is drained through an idempotent migration consumer;
  it is never allowed to remain an unbounded write-only queue.
- The seven-day task-detail TTL cannot be allowed to expire while a pending,
  processing, retry, or archive reference remains. Migration must preserve
  existing TTLs and extend or repair only records that are actively owned by
  the Rust runtime.
- Message bytes and the sent Maildir copy are retained until the durable send
  result is archived. Publication uses a same-filesystem temporary file,
  flush, atomic no-clobber link, temporary unlink, and directory fsync.
- Permanent SMTP failures must keep the frozen queue status fields and also
  feed the candidate's standards-compliant DSN/bounce path. Absence of a Java
  DSN is not permission to omit the required Rust feature.

## Fault-Injection Matrix

The black-box harness should run each case against an isolated PostgreSQL,
Redis, Maildir, and fake remote SMTP server. Only time, generated IDs, and
ports are normalized.

| Injection point | Oracle observation to freeze | Rust assertion |
| --- | --- | --- |
| after sent-file write, before task detail | orphan sent file or no queue ID is possible | no unbounded orphan growth; startup reconciliation is bounded and observable |
| after task detail, before pending push | metadata exists without work | repair/replay must be explicit and idempotent |
| after `LPOP pending`, before SMTP connect | processing claim remains until timeout | lease recovery requeues exactly once |
| during a slow SMTP transaction | no heartbeat during most of the send | lease renewal prevents concurrent recovery; deadlines cancel the send |
| remote `250` then process kill | local completion may be absent although remote accepted | stable Message-ID, durable ambiguous outcome, bounded retry policy |
| after archive `LPOP`, before PostgreSQL commit | popped archive item is lost on Java | Rust keeps recoverable in-flight archive state |
| PostgreSQL outage during archive | archive worker retries other items | no item loss and no duplicate row effect |
| task-detail TTL expiry with pending ID | metadata is missing after seven days | active queue references cannot expire silently |
| repeated missing-content/permanent failures | `status_updates` grows without a production consumer | bounded idempotent migration and archival drain |
| permanent `5xx` from remote | Java records FAILED without DSN | Rust preserves status and emits a tested DSN |

The remote SMTP fixture must also cover EHLO/STARTTLS policy, per-recipient
4xx/5xx responses, connection drops before and after message acceptance,
PIPELINING, DATA backpressure, and reconnect/retry timing. A soak run must
assert bounded Redis list/set/hash sizes, temporary-file count, PostgreSQL row
cardinality, and active-task leases while repeatedly injecting those failures.
