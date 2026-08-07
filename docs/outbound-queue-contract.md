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
   60-second deadline and cancellation checks. The frozen mode boundary uses
   Java's estimate of 2048 header bytes plus UTF-8 text/HTML bytes plus each
   attachment's estimated Base64 bytes and 200-byte MIME overhead. Estimates
   strictly below 10 KiB use Redis Base64; the 10 KiB boundary and larger retain
   a file below the configured lmyzmail spool directory. The attested v21 oracle
   golden proves 8191 body bytes are memory mode and 8192 are file mode even
   though the final signed MIME sizes differ from that estimate.
4. Publish the Sent copy with a same-filesystem temporary file, file `fsync`,
   atomic no-clobber hard link, temporary unlink, and directory `fsync`.
5. Under PostgreSQL advisory admission locks, atomically insert the complete
   `outbound_mail_queue` row and Sent `email_index` row. The identity sequence
   is advanced to the explicit legacy task ID so a rollback to Java/default
   inserts cannot collide. Timestamps are fixed to PostgreSQL microsecond
   precision before the first Redis serialization.
   If the `COMMIT` response is lost, the producer sends an ordered read on the
   same PostgreSQL connection and compares the complete queue identity, exact
   `email_index` identity, and exact spool sidecar identity. Only absence of all
   three proves `NotCommitted` and permits materialized files to be removed;
   an exact triple proves committed, while partial state, conflicting identity,
   or another read failure is `OutcomeUnknown` and preserves Sent/spool files.
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
structures. The same script creates the reverse key
`lmyzmail:mail:queue:attempt:<token>` with the claimed task ID and identical
TTL. A non-empty claim also writes
`lmyzmail:mail:queue:claim-result:<token>` with that task ID and the same lease
TTL. Empty probes leave no tombstone and a lost empty response reconciles as
`NotFound`, so the scheduler simply probes again with a new token. A 4096-entry
sorted-set index uses Redis server epoch milliseconds, removes expired members
before admission, and rejects before `LPOP` when full. A duplicate pending
reference, delayed live claim request, or reused live attempt token cannot
create a second owner or consume a later task. A valid task-ID tombstone with
no live attempt reconciles as `NotFound`; malformed type, value, or TTL is
inconsistent.

Every claim, renewal, release, retry, acknowledgement, expired recovery, and
response-loss reconciliation Lua script validates all static key types before
its first write. Claim additionally previews the pending head, validates its
positive decimal task ID and bounded task/domain values, and checks the dynamic
lease key before `LPOP`. A wrong type, malformed ID, oversized task, full
receipt index, or lease collision therefore leaves every Redis key byte and TTL
unchanged; a collision cannot consume and then restore a pending reference.

Because a Redis connection can fail after a claim script commits but before
the reply arrives, the caller retains the generated token and invokes bounded
attempt reconciliation. Reconciliation follows only the reverse token key,
then validates the task ID, lease token, processing membership and timestamp,
bounded task JSON, and matching positive TTLs. It never scans the pending or
processing collections to guess which task was claimed.

Renewal, release, retry scheduling, and acknowledgement compare the opaque
token inside their Lua script. A stale owner therefore cannot extend, requeue,
or acknowledge a task after its lease has been replaced. Renewal also refreshes
the legacy processing timestamp and the seven-day task/domain TTLs. Retry
scheduling atomically replaces the Java-compatible task JSON, removes the
processing claim, and inserts the ID into the legacy retry sorted set. A
bounded script moves due retry IDs back to pending without duplicating an
already pending or processing ID.

Release, retry, and acknowledgement write a bounded 300-second
`lmyzmail:mail:queue:settlement:<token>` receipt in the same Lua mutation. A
4096-entry expiry index is pruned using Redis server epoch seconds before the
script checks capacity; a full index rejects before any queue mutation.
Response-loss reconciliation requires the exact expected receipt, no processing
membership or processing timestamp, and no lease or reverse attempt. It also
requires exact action-specific state: release has the requested pending/drop
placement, retry has the exact ZSET score and task JSON, and acknowledgement has
no pending/retry reference or task JSON. A missing lease/attempt without a
matching receipt is `NotFound`, never proof of success. A delayed mutation that
arrives after lease expiry is rejected and remains recoverable only through the
expired-claim path.

Expired-claim discovery uses bounded `SSCAN` pages and only reports processing
members whose Rust lease key is absent. Recovery checks absence again inside
the mutation script, so a concurrent renewal wins.

Every Lua mutation is submitted through the mutation-specific query path.
After a connection has been acquired, a timeout, disconnect, or Redis error is
therefore `OutcomeUnknown`, including publish, TTL refresh, domain updates,
retry movement, acknowledgement, release, and expired recovery. The caller
must reconcile before issuing a compensating mutation.

Per-domain status reads and writes use the same lease token and also require
the task ID to remain in the legacy `processing` set. The scripts reject a
missing, non-hash, oversized, malformed, or internally inconsistent domain
map before returning data or applying any update. The caller supplies the
bounded domain set derived from the durable recipient list. Lua first requires
`HLEN` to match that set, then checks `HEXISTS` and `HSTRLEN` for every expected
field and the aggregate byte budget before executing any `HGET`; it never uses
`HGETALL`, `HKEYS`, or `HSCAN`. Batch updates validate the complete existing
hash and the complete resulting byte and recipient budgets, then apply all
fields and refresh the legacy seven-day TTL in one Lua execution. A stale
worker therefore cannot overwrite a replacement worker's domain outcome or
extend its status lifetime, and an oversized corrupt value is rejected before
Redis copies it into the script.

## Rust PostgreSQL Delivery Fence

The database-side delivery state now uses the existing `processor_id` column
as a second fencing token. A `DeliveryAttemptId` binds one task ID to the
bounded worker ID and a fresh 128-bit random nonce; reusing a worker ID can
never make a stale claim valid again. The coordinator generates that ID before
the Redis claim, binds the returned task ID to it, and passes the same
opaque token to PostgreSQL. A claim is one conditional `PENDING` to `PROCESSING` update and
succeeds only when `next_retry_at` is due and no database owner is present.
Heartbeat, release, retry, and terminal updates all compare the same opaque
token. A recovered or replaced owner therefore cannot mutate a new owner's row
even if it still has an old in-memory claim.

A claim whose response is lost is reconciled by a bounded row read using the
caller-retained `DeliveryAttemptId`. It returns a usable `DatabaseClaim` only
when the row is still `PROCESSING`, its retry counters are valid, and its
`processor_id` exactly equals the attempt token.

A frozen Java producer can leave a valid pending task only in Redis because
its PostgreSQL archive is write-behind. When the fenced Redis claim has no
PostgreSQL row, Rust does not acknowledge it. It validates the exact task ID,
recipient/domain rosters, and the sender's referenced Sent Maildir copy; binds
the Redis task source to that stable copy under the lease; then takes a
task-scoped PostgreSQL advisory transaction lock and atomically inserts the
explicit-ID `outbound_mail_queue` row and any missing `email_index` row. The
identity sequence is advanced past the explicit task ID. The
claim is released back to pending so the next pass enters the ordinary
PostgreSQL claim path. Missing/corrupt detail, an unavailable Sent copy, an ID
conflict, cancellation, or an unknown database outcome is fenced-released and
requeued, never acknowledged.

The frozen schema has no range check on `retry_count` or `max_retries`. The
claim statement therefore validates `0 <= retry_count <= max_retries` while it
holds the row lock. An invalid due row is atomically quarantined as `FAILED`
with no owner and a fixed diagnostic instead of entering a claim/recovery loop.

Retry increments, next retry time, bounded error summary, owner release, and
status change commit in one statement. Terminal writes atomically store the
canonical sent/failed domain outcome, clear processing ownership, and set
`sent_at` only for `SENT` or `PARTIAL_SUCCESS`. Recovery only resets a
`PROCESSING` row whose heartbeat predates the caller's cutoff. A null heartbeat
is expired, but a stale row without the Rust recipient sidecar is not blindly
requeued: its legacy flat or structured recipient JSON is validated and
projected into an all-`AMBIGUOUS` sidecar, while the legacy row becomes
`FAILED` with no owner. This takeover rule prevents a pre-upgrade Java send
whose remote commit cannot be reconstructed from being duplicated or receiving
a false DSN. Malformed legacy recipient data fails closed and remains owned for
operator repair. The conditional recovery races safely with a concurrent
monotonic heartbeat.

The additive `lmyzmail_outbound_delivery_attempt` and
`lmyzmail_outbound_delivery_recipient` tables are installed under a PostgreSQL
advisory transaction lock; no legacy column changes. A stable ordinal/address
roster is protected by both its count and SHA-256 fingerprint. Each attempt is
fenced by opaque owner token and monotonically increasing generation. Accepted
RCPT outcomes become `COMMIT_ARMED` in the same transaction that arms the
attempt, before SMTP DATA commit. Final replies move those exact recipients to
`DELIVERED`, `RETRYABLE`, or `PERMANENT`; an unknown result moves them to
`AMBIGUOUS`. Release or expired recovery of an armed attempt also creates an
ambiguous terminal projection. The attempt phase and presence of armed
recipients must agree on every mutation and snapshot; a cross-table mismatch
is rejected transactionally and cannot reopen delivery.

The additive `lmyzmail_outbound_spool` table records ownership of large-message
temporary files without changing the frozen queue table. A bounded maintenance
query selects only `OWNED` rows whose legacy queue row is terminal, even when
the Redis task detail has already disappeared. Rust spools are removable only
from the configured spool root with the exact `message-<task-id>.eml` name.
Adopted Java `signed-<task-id>.eml` files require the same root and a bounded
byte-for-byte match with their indexed Sent Maildir copy. Missing files are
treated as an already-completed unlink; successful unlink is directory-fsynced
before the sidecar advances monotonically to `REMOVED`. On Linux, validation
holds directory file descriptors, opens both files with `openat2` beneath
their configured roots while rejecting symlinks, rechecks the target inode,
and removes it with `unlinkat`. Once that irreversible unlink operation has
started, a soft I/O deadline is reported but the coordinator joins the bounded
blocking task before it may release or requeue the Redis claim.
The sidecar foreign key restricts deletion of its legacy queue row, including
after an upgrade from the earlier cascading definition. Retention must first
observe `REMOVED` and delete that sidecar row explicitly; an `OWNED` row can
therefore never disappear ahead of its file-cleanup evidence. Sidecar deletion
also requires one atomic Redis proof that the exact task has no task value,
lease, pending/list reference, processing membership, processing timestamp,
retry score, or sent-file index. PostgreSQL then deletes only the exact
`(task_id, spool_path)` row in `REMOVED` state whose legacy queue row is
terminal. A bounded wrapping task-ID cursor prevents an old active sidecar from
starving later removable rows, and a lost delete response is reconciled by the
same exact sidecar identity.

Every operation shares one bounded deadline across pool admission and the
database request; production uses eight seconds and tests may select a shorter
validated duration. Every mutation runs in an explicit transaction whose local
PostgreSQL `statement_timeout` is half the remaining client deadline. If the
outer deadline still expires, Rust drops the transaction future so no later
statement or `COMMIT` can be polled, and sends a separately bounded
`CancelRequest` through the connection's `CancelToken`. A cancellation
transport failure or a database error remains `OutcomeUnknown`, never an
ordinary availability failure: a completed `COMMIT` whose response was lost
must still be reconciled. A bounded read-only snapshot exposes status,
retry state, timestamps, owner presence, and whether a supplied claim still
owns the row, without returning the token. Callers must reconcile an unknown
outcome through that snapshot before touching the Redis lease. The read-only
attempt snapshot accepts the caller-retained attempt ID even when an unknown
claim response means no `DatabaseClaim` was returned. Local permanent
failures may preserve the Java-compatible `FAILED` row with null domain JSON,
but require a bounded non-empty error summary. Externally visible `last_error`
uses the oracle's 1000 UTF-16-code-unit limit and appends `...` when truncated;
Rust stops before a supplementary-plane character that would be split into an
invalid unpaired surrogate.

The Linux integration test starts an isolated PostgreSQL process, loads the
frozen legacy DDL with the required `LONGTEXT` to `TEXT` translation, and
exercises concurrent claims through separate pooled connections, random-token
stale-owner fencing, retry exhaustion, partial and local terminal states, and
timeout recovery including a null legacy heartbeat. Row-lock fault injection
forces claim, heartbeat, retry, terminal, and ledger mutation timeouts; while
the lock is still held, `pg_stat_activity` must show no waiting mutation, and
the row must remain unchanged after release. A transparent proxy also refuses
the fallback CancelRequest transport while withholding the server response;
server timeout still prevents a late claim or commit. It also covers reverse-token claim binding,
sidecarless takeover quarantine, recipient roster integrity, monotonic terminal
states, generation fencing, armed crash/cancellation recovery, and fail-closed
cross-table corruption. Poisoned negative, inverted, and negative maximum
retry counters are also exercised. The internal coordinator calls Redis
acknowledgement or retry scheduling only after PostgreSQL projection commits.
Producer publication, MIME/DKIM, Sent Maildir storage, coordinator delivery,
and queue maintenance now run inside the production lifecycle in `main`.

Before the first delivery probe, the worker drains the frozen Java `archive`
and `status_updates` lists. A Lua claim moves at most one bounded record per
list into an lmyzmail inflight list and payload hash. PostgreSQL uses an
advisory-locked, statement-timeout-bounded transaction with monotonic terminal
state and identity checks. Only a committed or idempotently reconciled database
result permits terminal Redis references and then the inflight record to be
removed. A crash or dropped Redis response leaves the record replayable.
Malformed, oversized, conflicting, and orphan status records are moved intact
to source-specific lmyzmail quarantine lists with length and digest metadata;
they are never discarded or allowed to block later records.

The production dispatcher preserves the Java defaults of 100 concurrent sends,
a 50-item poll batch, and a 1000 ms poll interval, while allowing bounded new
keys to override the legacy aliases. Only one outstanding claim probe is used
while the queue is idle. Retry promotion and expired-claim scanning are bounded
per tick. Recovery requires both a missing lmyzmail lease and a processing
timestamp older than the configured processing timeout, preventing a second
sender from starting during an active lease.
An operational failure opens a delivery circuit and starts capped equal-jitter
backoff. When the deadline expires, the circuit admits exactly one claim while
no other delivery is active. Only that half-open probe's successful completion
closes the circuit and restores the configured batch/concurrency budget; a
failed probe returns directly to backoff, preventing an outage from releasing a
full concurrent burst.

Redis publication applies the same `lmyzmail.outbound.max-pending-tasks`
configuration used by PostgreSQL admission, with
`botmail.outbound.max-pending-tasks` as the lower-priority legacy alias. The
default is 10,000 and the validated absolute maximum is 1,000,000. One Lua
admission counts pending, processing, and retry references before writing any
task/domain/index state; an already-published identical task remains
idempotent at capacity. A durable PostgreSQL backlog above a newly lowered
limit remains intact and is replayed by the bounded reconciler as capacity
becomes available.

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
CRLF, and dot-stuffs across chunk boundaries. `prepare` stops after the
normalized body-ending CRLF and retains the live SMTP session without sending
the `.<CRLF>` terminator. After the coordinator durably records
`COMMIT_ARMED`, consuming `commit` sends the terminator and reads the final
reply. Reply lines, aggregate replies,
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

## Rust Outbound Coordinator

The coordinator is an internal Tokio component, not a service. Configuration
uses `lmyzmail.queue.*` first and the matching `botmail.queue.*` alias second
for worker ID, lease and renewal durations, processing deadline, and retry
backoff. Defaults are a 90-second lease, 10-second renewal, 10-minute task
deadline, and Java-compatible exponential retry delays of 30, 60, and 120
seconds capped at 3600 seconds. Leases shorter than 65 seconds are rejected;
that floor covers three worst-case Redis mutation and reconciliation rounds.
Worker IDs are ASCII and at most 64 bytes so the generated nonce-bearing token
is accepted by every Redis and PostgreSQL fence.

One run claims Redis with a caller-retained token, reconciles a dropped claim
response through the reverse token key, claims the matching PostgreSQL row,
and compares the exact ordered PostgreSQL, task JSON, and per-domain rosters.
It accepts canonical bounded Base64 or one absolute bounded spool path. For
each retryable domain it resolves pinned routes, prepares SMTP, durably records
the recipient checkpoint and `COMMIT_ARMED`, then consumes the prepared session
to send the DATA terminator. A final reply is recorded without repeating SMTP;
an unknown post-terminator outcome becomes `AMBIGUOUS` and disables retry and
DSN for those recipients.

Redis lease renewal and PostgreSQL heartbeat run in one owned keepalive task.
After every recipient is durable, the coordinator projects the sidecar into the
legacy row, stops database heartbeat, explicitly renews Redis, waits for the
keepalive task to exit, and only then executes the final fenced ack or retry
Lua script. A dropped final Redis response is reconciled as complete only when
the matching settlement receipt and every action-specific postcondition agree;
missing fence keys alone never prove completion. Cancellation before the commit
barrier releases both owners without incrementing retry state; cancellation or
ownership loss after the barrier is quarantined as ambiguous. The integration
fixture uses isolated PostgreSQL and Redis plus raw SMTP and verifies that
PostgreSQL already contains `COMMIT_ARMED` when the peer receives `.<CRLF>`.
It also covers PostgreSQL outage immediately after Redis claim, cancellation at
that boundary, delayed Redis delivery after lease expiry, mixed multi-domain
results, commit-armed cancellation/lease loss, and a lost PostgreSQL checkpoint
response after the SMTP peer accepted the message without repeating SMTP.

Domain projection is also a settlement precondition. A failed domain update
leaves the Redis claim recoverable; expired-claim maintenance requeues it, and
the next owner rebuilds the domain projection from the already projected
PostgreSQL ledger before ACK or retry scheduling. Regular ACK and migrated
terminal cleanup preserve `domains:<id>` to its existing seven-day TTL and
remove only the exact known `sentFileName` index. Settlement receipts bind that
filename by SHA-256; no Redis hash scan or alias deletion is permitted.
Migration done/quarantine receipts use a separate 4096-entry index per archive
or status namespace, and terminal cleanup uses one 4096-entry global index.
All three receipt classes expire after 300 seconds and reject atomically before
source, inflight, payload, task, or sent-file-index mutation when their index is
full.

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
surfaced rather than pretending to provide exactly-once SMTP delivery. Once
the durable commit barrier is armed, cancellation, timeout, disconnect, or a
crash is never converted back to an ordinary retry, even if the process cannot
prove whether the terminator reached the peer.
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
