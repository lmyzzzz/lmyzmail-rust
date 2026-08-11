# Compatibility contract

The frozen Java oracle is the behavioral authority except for the new product
name, configuration aliases, and the native Skibidi banner generator described
below. The differential harness compares bytes, status, headers, bodies, state
transitions, persistence, and recovery behavior.

Configuration resolution is deterministic:

1. Read `lmyzmail.*`.
2. If absent, read the exact frozen alias. Most aliases are `botmail.*`; the
   frozen MX cache settings are bare `dns.cache.mx.*` keys.
3. If both are absent, apply the frozen oracle default.
4. Never merge scalar values or silently accept conflicting structured values.

Legacy Spring profiles are also supported when a file is loaded from disk. A
`spring.profiles.include=keywords` entry loads
`application-keywords.properties` beside the main file; when that sibling is
absent, lmyzmail uses the byte-pinned copy at
`crates/lmyzmail/resources/java-oracle/application-keywords.properties`. The
copy is frozen from Java commit `5dac2ab2922c30c726c4a83d7626c95ad4e231c8`
and has SHA-256
`cee5be2e215eaab7f1808850506164aa2aad4c7ba0dccbf0a9b0900657de8363`.
Profile names, included bytes, and every list are bounded; the frozen profile
contains 1,585 spam phrases, 758 phishing phrases, 69 shortener domains, and
124 suspicious TLDs. Explicit `lmyzmail.*` keys still win over profile and
legacy `botmail.*` values per field.

Generated product identifiers use the new `lmyzmail` brand. The intentional
wire-level exception is the TLSRPT HTTPS User-Agent, which is
`lmyzmail-TLSRPT/1.0`; all delivery status, request framing, TLS, DNS, and
error semantics remain subject to the frozen oracle contract.

Only genuine nondeterminism such as wall-clock time, random identifiers, and
ephemeral ports may be normalized. Each normalizer is field-scoped and tested;
there is no whole-response masking or assertion weakening.

## Native Skibidi banner

SMTP banner generation always calls the frozen Skibidi 1.8.0 C library. Its
grammar, probability thresholds, seed behavior, batch behavior, ABI, and memory
ownership are authoritative; lmyzmail does not reproduce the Java 26.85% outer
fast path or maintain a second probability implementation.

The frozen source commit is `4bc484c15b780d578ee8e53cab968f2819958215`.
`skibidi_avx.c` has SHA-256
`7e8e7f3ee5bea0ac8d0857bd5bc8d806b44e5142c17ec8b5b6583db7c62fc613`
and `skibidi_avx.h` has SHA-256
`bde8e9d19d6668c644aba1cdd81fb9f56c2236ff827ddd16fb366369bc68bbea`.
The build rejects either source if its digest changes.

Legacy `JAVA` mode is retained only as a configuration alias for the scalar C
backend; it never starts a JVM. `SCALAR` is the explicit spelling. `AVX2` and
`AVX512` require OS-aware runtime support, while `AUTO`, `AUTO_SAFE`, and
`NATIVE` choose the best permitted C backend. The AVX-512 object is called only
when both AVX2 and AVX-512F extended state are available to the process.

The managed Java oracle runs in `JAVA` mode in WSL because its historical
bundled native library can execute an unsupported instruction. It therefore
remains the banner wire-grammar oracle, while frozen C tests and external Rust
candidate sampling are the probability authorities.

## Java parity edge cases

These are required Java parity behaviors, not approved security differences.

- An isolated `BDAT 0 LAST` is acknowledged with `250 2.0.0 0 bytes received`
  and does not deliver a message.
- A nonzero non-`LAST` BDAT is acknowledged; a following `BDAT 0 LAST` is also
  acknowledged, resets the transaction, and discards the complete message
  without delivery.
- MIME indexing scans only the first body part. Consequently, a multipart body
  before its attachment is indexed with `has_attachments=false`.
- A missing session token on `POST /web/mail/send/multipart` returns `401` with
  an empty body, `Content-Length: 0`, and `Connection: close`.

## SMTP body content filter

`SPAM_KEYWORDS` and `SUSPICIOUS_URL` run in BODY order 10 and 20. Text and
HTML-like MIME parts are scanned with bounded UTF-16 line buffers; keywords are
counted at most once per configured phrase per line, URLs are exactly
deduplicated, and each URL category is capped before the rule weight is
applied. Text leaves are scanned as raw transfer-encoded bytes, matching the
frozen Mime4j configuration. Only encoded `message/rfc822` containers are
decoded before recursively parsing their child message; `message/global` is
not traversed, and `multipart/digest` children default to `message/rfc822`.

The parser permits at most 4,096 MIME entities, 64 active boundaries, a
200-byte boundary, 64 KiB and 256 fields per entity header, 8 KiB per relevant
field, 64 embedded messages, and 64 MiB of aggregate decoded work. Keyword and
URL lines are bounded to 8,192 and 16,384 UTF-16 code units respectively, and
URL deduplication retains at most 500 unique values. Exceeding a structural or
work budget is a controlled delivery error instead of the oracle's partial
fail-open result. The post-freeze supplemental allowlist is recorded as
`smtp-mime-bounded-work` in
`evidence/compatibility/smtp-content-filter-body-v1.json`. Header-only
attachment indexing preserves the oracle's 256 KiB input window and stops at
the first actual body callback, including through encoded embedded messages.

The four base golden observations are recorded under
`managed-smtp-content-filter-body-v1`. Six additional raw-CTE, charset,
malformed, deep embedded-message, and UTF-8 parser-chunk observations are
recorded under `managed-smtp-content-filter-body-edge-v1`.

## SMTP sender-domain rejection

`MAIL FROM` validates the extracted sender domain before local-domain SPF or
other DNS work. The Rust validator preserves the frozen Java check order and
exact `550 5.1.8 Sender address rejected: <reason>` text for reserved names and
TLDs, missing dots, IPv4/IPv6 and address literals, dot and hyphen placement,
ASCII label syntax, label/domain length, numeric and frozen-invalid TLDs,
Punycode shape, and the frozen Unicode control/private-use/surrogate rules.

An invalid domain does not become the accepted sender. A following `RCPT`
therefore receives the frozen `503 5.5.1 Bad sequence of commands`. The server
persists one `ILLEGAL_SENDER_DOMAIN` activity with score 4 and exact metadata,
then the RCPT state probe persists one `PROTOCOL_VIOLATION` with score 1. The
aggregate is `(total_score=5, current_score=5, activity_count=2,
illegal_domain_count=1, other_count=1)`. Activity admission uses the existing
256-entry bounded SMTP Cringe queue and shutdown deadlines.

The create-once oracle matrix is `managed-smtp-sender-domain-v1`. It freezes
20 rejection cases plus accepted ASCII, A-label, and U-label boundaries using
raw sockets and independent PostgreSQL state; a second fresh Java runtime
replayed it unchanged, and the Linux x86_64 Rust release matched it.

## Approved security differences

The authoritative allowlist is
`blackbox/manifests/behavior-differences.json`. Every entry binds the frozen
commit and source hash, describes the exact scope, and states a stricter
candidate requirement. An allowlisted difference never relaxes surrounding
wire, state, storage, or recovery assertions.

After a profile's complete blackbox definition tree is frozen, later
profile-specific additions live under `evidence/compatibility` so the earlier
golden attestation remains immutable. Such a supplemental manifest must bind
the frozen definition-tree hash, oracle commit, source hashes, and its external
candidate test; it has the same review requirements as the primary allowlist.

- Maildir publication must use a flushed same-filesystem temporary file,
  atomic rename, and directory fsync instead of exposing a partially written
  final file.
- Malformed SMTP command bytes must receive a fixed non-reflective syntax
  response. The frozen oracle can reflect tabs, NUL, bare CR/LF, and replaced
  invalid UTF-8 into its reply; its isolated evidence golden is not a candidate
  expectation.
- Generated self-spoof rejection text must replace control scalars with spaces
  and fit within the 506-byte reply-text budget, preserving the SMTP 512-byte
  line ceiling after `550 ` and CRLF. The frozen Java InferX path can pass an
  embedded model-generated delimiter directly into response framing.
- SMTP Cringe persistence admits at most 256 queued activities and applies
  nonblocking overflow backpressure, while the Java batch writer's default
  queue is 10,000 entries. Accepted activities, transaction fields, normal
  shutdown drain, and SMTP replies remain differential requirements; only
  post-cap admission is allowlisted as `smtp-cringe-queue-overflow-bound`.
- One fragmented overlong SMTP command must produce and charge exactly one
  error regardless of packetization. The frozen oracle can reply twice and
  consume two error-budget entries when CRLF arrives after the length error;
  its isolated evidence golden is not a candidate expectation.
- STARTTLS must close without executing plaintext command bytes buffered after
  the STARTTLS line. The frozen Java oracle executes such a command across the
  TLS boundary; its isolated evidence golden is not a candidate expectation.
- DATA framing must return bytes after the terminator to the bounded command
  parser. The frozen oracle can silently drop a coalesced pipelined command;
  the isolated evidence profile records that packetization-dependent desync.
- Coalesced `MAIL`/`RCPT`/`BDAT LAST` must apply prerequisite state in wire
  order, reply and deliver within fixed deadlines, and use a hard-bounded
  pending queue. The frozen oracle can wedge the connection after the first
  two replies; that liveness evidence is not a candidate expectation.
- SMTP Skibidi video rejects non-finite FPS, contrast, brightness, gamma, and
  aspect before native work, and enforces checked transform and output budgets.
  The frozen handler lets `NaN` bypass ordered range checks and forwards other
  non-finite values into native dimension and pixel conversion.
- SMTP Skibidi video acquires its one-viewer permit atomically and holds it
  across decoder open, playback, writes, cancellation, disconnect, and bounded
  shutdown. The frozen handler has a check-then-act `isPlaying`/CAS race that
  sends concurrent losers through exceptional dispatcher handling instead of
  the defined overload reply.
- RFC null MX is an explicit permanent no-service route and cannot become an
  empty hostname or coexist with ordinary MX records.
- MX, address, MTA-STS TXT, policy-pattern, and policy-body processing have the
  exact hard ceilings recorded in the allowlist rather than the oracle's
  unbounded DNS fanout.
- Report-address discovery has one absolute deadline, process-wide DNS
  admission, per-query TXT record and byte ceilings, and bounded ASCII domain
  normalization. The frozen RUA limit of 10 and every in-budget query, TXT,
  authorization, ordering, and HTTP behavior remain exact compatibility
  requirements.
- Aggregate report rendering accepts at most 10,000 database groups, 4 MiB of
  aggregate input, 4 KiB per text field, and 4 MiB each of compressed and
  uncompressed output. Counts must fit the signed 32-bit wire fields, and a
  dedicated two-worker/eight-waiter pool applies one ten-second deadline with
  cancellation and bounded drain. In-budget DMARC XML and TLSRPT JSON remain
  byte-exact with the frozen Java golden.
- XDP full reconciliation must not reuse the 10,000-row Cringe export API.
  Existing IPv4 and IPv6 bans are enumerated up to their independent native
  100,000-entry capacities, their scores are resolved in 500-address chunks,
  and new threshold candidates use deterministic keyset pagination inside one
  read-only repeatable-read snapshot. Capacity or snapshot failure aborts
  before native reconciliation, and a ban added after the initial enumeration
  is retained rather than inferred stale.
- XDP PPS monitoring retains at most the configured `max-ips-per-poll` IP
  states and `ring-buffer-size` global samples. Snapshot, consecutive-count,
  and per-event cooldown state are evicted together. Global, IPv4, and IPv6
  read failures are isolated, and one failed automatic ban does not discard
  later detected events. Thresholds, fixed configured-interval rates,
  PPS-before-SYN ordering, strict two-second cooldown, metadata bytes, scores,
  healthy database mutations, and ban decisions remain compatible with the
  frozen monitor.
- PPS database writes use one deadline-bounded atomic activity/aggregate
  transaction and reconcile a lost COMMIT response by preallocated activity
  identity. Reviewed exceptions repair nullable legacy PPS/SYN counters,
  preserve monotonic `last_seen_at` under concurrent writes, and saturate
  consecutive counters instead of reproducing Java signed overflow. The exact
  scopes and PostgreSQL evidence are recorded in
  `blackbox/manifests/behavior-differences.json`.
- XDP clear/status native failures are fail-closed. The frozen Java controller
  reports clear success with count zero after native exceptions; the candidate
  returns a fixed 5xx and records the reviewed difference in
  `blackbox/manifests/behavior-differences.json`.
- TLSRPT HTTPS delivery accepts only HTTPS endpoints with a hostname and no
  userinfo, fragment, or non-443 port. The complete DNS answer set must pass
  the frozen Java public-address policy before the candidate pins at most 16
  addresses for TCP/TLS. Hostname verification and SNI use the original
  hostname, redirects and proxies are disabled, the request body is the
  already-bounded TLSRPT gzip stream, and only the final HTTP status is read.
  DNS, connection, TLS, write, response-header, and admission work share the
  configured absolute deadline and cancellation token.
- A live legacy MTA-STS NONE value is reusable only for its remaining Redis TTL,
  capped at five minutes. This repairs the oracle's restart-only negative-cache
  expiry bug without changing bytes, keys, or post-expiry discovery.
- Outbound HTTP status reads have a bounded Redis deadline. The frozen oracle
  leaves known-ID and sent-file requests unanswered beyond the ten-second
  blackbox observation window after Redis disappears; lmyzmail returns a fixed
  `500 {"error":"internal_error"}` for a known status and still resolves an
  unknown sent file to `404` through PostgreSQL within the same request budget.
- Malformed userdata writes are rejected before PostgreSQL mutation. The frozen
  controller can return 500 for malformed JSON and can commit a nameless contact
  before response serialization fails; the evidence-only golden records both.
- Concurrent contact creation is serialized per normalized mailbox/email pair,
  so equal addresses create exactly one row while unrelated addresses remain
  concurrent. Contact list materialization is capped at 10,000 rows and 16 MiB
  of UTF-8 field data; an over-budget mailbox receives the fixed bounded
  response recorded in the allowlist.
- Authentication and mailbox-management PostgreSQL work has one absolute
  deadline and observes HTTP cancellation. Interrupted pre-commit queries send
  PostgreSQL `CancelRequest` and drain before reuse; cancellation failure,
  drain timeout, or an unresolved COMMIT detaches the connection from the pool.
  Mailbox creation, login, logout, expired-session deletion, and last-used
  updates hold deterministic transaction advisory locks. A lost COMMIT response
  is reconciled only through a fresh connection, the same lock, and an exact
  durable identity or idempotently equivalent final state under an independent
  eight-second deadline; conflicts or failed reconciliation remain unknown.
  This replaces the oracle's unbounded JDBC lock waits without changing any
  healthy-path authentication, session, mailbox, API permission, or wire
  behavior.
- A non-keep-alive HTCPCP response actively closes its socket after the full
  Content-Length-framed response is written. The oracle advertises close but
  retains the connection until its independent 60-second idle timer.
- HTCPCP request framing has a 60-second absolute deadline in addition to the
  oracle-compatible read-idle timeout. This prevents an incomplete request from
  retaining a connection indefinitely by sending one byte before each idle
  boundary; complete and ordinarily fragmented requests remain exact-wire
  compatibility requirements.
- A Minecraft connection has one absolute configured deadline from acceptance
  through pong and close. The oracle resets a read-idle timer for every byte,
  allowing a deliberately fragmented packet to retain state indefinitely.
- Minecraft status admission is fixed at 64 concurrent connections, with
  overload closed before task creation and all admitted tasks joined during
  bounded shutdown. The oracle has no application-level connection bound.
- Confirmed Minecraft logout flushes the exact Disconnect Play reason before
  closing. The oracle calls `writeAndFlush` and immediately closes the channel,
  producing a nondeterministic proper prefix without the final disconnect in
  isolated runs; only that terminal race is normalized and allowlisted.
- Minecraft render dimensions are connection-local and default to 10 by 20
  maps with a 20px font. The sign editor accepts widths 2-24, heights 2-20, and
  fonts 8-48 using the oracle's 384-UTF-16-unit field bound. Valid width and
  height commit before font validation, so an invalid font preserves the prior
  font while applying the new dimensions; malformed or oversized sign packets
  close the connection without a business response.
- `/mail rendersize` and `/mail rs` use the same connection-local state. With
  width and height arguments they update dimensions directly, ignore an absent,
  malformed, or out-of-range optional font, then refresh the scoreboard before
  the confirmation chat. With fewer than two value arguments they open the
  render-settings sign editor.
- Minecraft folder lists use the legacy `email_index` ordering (`received_at`
  descending), 36 items per page, and the Java slot map 46/49/52 for previous,
  back, and next. Opening a folder emits the loading/close/hotbar sequence
  before a new six-row chest; pagination refreshes only `WindowItems` under the
  same window ID. Database loads have an eight-second bound and are dropped on
  connection close, GUI replacement, or service cancellation. NBT display
  strings retain Java UTF-16 substring semantics, including CESU-8 for an
  isolated surrogate produced by a split supplementary character.

## Cringe decay contract

The candidate accepts `lmyzmail.cringe.decay.*` and the frozen
`botmail.cringe.decay.*` keys, with the new namespace taking precedence per
field. Spring simple durations and non-negative ISO-8601 durations are accepted;
the effective check interval retains the oracle's interval/4 calculation and
1-minute to 1-hour clamp. The config endpoint preserves Jackson's numeric
seconds with nine fractional digits.

Decay updates positive scores whose nullable `last_decay_at` is older than the
configured interval, clamps at zero, and changes `last_decay_at` in the same
PostgreSQL transaction. Calls are serialized with a transaction advisory lock.
Pool acquisition, every query, the lock, update, and COMMIT share one absolute
eight-second transaction deadline. Cancellation before COMMIT sends a
PostgreSQL CancelRequest and drains for at most two additional seconds. A lost
COMMIT response is not retried: an independent reconciliation phase has its own
eight-second deadline plus the same bounded cancellation drain, waits on the
same lock, and accepts the outcome only when the exact timestamp marker count
whose PostgreSQL `xmin` matches the decay transaction equals the pre-COMMIT
affected count. A concurrent writer using the same microsecond marker cannot
confirm the wrong transaction. Reconciliation observes caller cancellation and
returns an unknown outcome rather than guessing whether the commit applied.

The manual decay route follows the frozen method annotation and therefore
requires write permission; a write-only API key is valid. Every decay check also
retries XDP cleanup so an earlier native failure cannot strand a zero-score ban.
XDP work is bounded to the at-most 200,000 already-banned addresses now below
the unban threshold and cannot add a ban. One dedicated native operation uses
an eight-second budget, checks cancellation between entries in 500-address
chunks, avoids repeated full-map scans, and continues after individual native
unban failures while emitting one aggregate diagnostic. Lock waiting, database
selection, and native work are additionally covered by one 20-second whole-sync
budget. Timeout cancels the operation and permits at most two seconds for its
bounded drain. Shared full-sync and decay-sync workers own their cancellation
tokens, so one disconnected HTTP caller stops only its own wait; service
shutdown is the only external cancellation of shared work. Every native
dispatch has the same two-second cancellation drain. A native call that does
not return by then marks XDP unavailable, and bounded pool shutdown detaches an
unfinished native thread handle rather than blocking process teardown.

The scheduler uses the oracle's initial delay and fixed-delay cadence, is joined
during process shutdown, and independently deletes expired activity rows at
03:00 local time. Decay and cleanup use separate cancellation-aware loops so a
cleanup run cannot postpone a due decay check. Nonexistent local times advance
to the next date whose 03:00 exists; ambiguous times expose both occurrences in
absolute-time order, matching the frozen Spring cron expression.
`amount=0` is an intentional safety difference: decay is a
no-op and an above-threshold estimate returns the controlled
`{"error":"decay_disabled"}` response instead of reproducing the oracle's
integer division by zero. This difference is limited to the invalid/disabled
configuration boundary; positive amounts remain governed by
`managed-cringe-decay-v2`.

## Minecraft mail-view contract

Opening a folder item resolves the same indexed Maildir message as the frozen
oracle, applies the same HTML/plain-text selection and attachment-card
composition, and preserves case-sensitive first-resource CID ownership. The
renderer accepts bounded raster formats and SVG CID resources, rejects SVG
external resources, disables redirects and ambient proxies, pins every external
image request to a bounded public DNS result, and carries one cancellation-aware
deadline through DNS, admission, HTTP, decode, layout, dithering, and packet
production. Native litehtml context calls are single-threaded and all Rust-owned
HTML, CID, and RGBA storage remains live and immutable through context destroy.

Pages use row-major map tiles and the configured wall orientation, base map ID,
and base entity ID. Every page transition sends all wall map IDs; a short final
page fills missing lower tiles with palette index 34 so pixels from the previous
page cannot remain visible. Closing or replacing a GUI while a mail wall is
active restores slots 36, 44, 39, 40, and 41 in that order and then selects held
slot 4. The v4 fixture freezes seven Java pages, including the 128-pixel final
page, full-wall padding, packet sequence, and rendered palette hashes. Login
prefix reads have a separate bounded 60-second allowance so cold Java world
bootstrap cannot consume the renderer's unchanged 90-second phase budget or
5-second per-read budget.

## Minecraft video contract

The frozen 15,048,248-byte MP4 is accepted only at its attested SHA-256 and is
decoded one frame at a time through the source-pinned FFmpeg 7.1 boundary. Map
and block playback share a configurable admission semaphore capped at 64; the
permit is owned until success, error, disconnect, cancellation, rejection, or
shutdown reaches its terminal teardown path. Frame conversion uses a dedicated
two-worker, two-entry pool, rejects oversized frames and block regions, and
inherits the connection's absolute deadline and cancellation token.

The v3 raw-socket golden freezes video menu NBT, command errors and limits,
map-wall setup, row-major map IDs, the first full frame, resumed dirty
rectangles, pause silence, stop restoration, block chunk-section updates,
Java HashMap/HashSet teardown ordering, duplicate completion scoreboard refresh,
and final messages. The only allowlisted behavior difference is permit lifetime:
the Java map player returns its permit before submitting decode work, while the
candidate holds the permit for the complete admitted lifecycle.

## SMTP SKIBIDITOILET contract

The frozen extension is available before HELO and advertises from EHLO when
enabled. HELP, invalid subcommands, all three quiz levels, answer validation,
forfeit, completion, feedback, scoring, and connection-local state are exact
wire contracts. HELO and RSET preserve an active quiz. The copied 474-question
bank is bound to SHA-256
`7bcbeacd0d36a58931efa49234143946cb981b4c978c74432313fcad843ba8d1`;
random selection is normalized only after every selected question is proven to
match the full frozen record, remain unique in that quiz, and satisfy the
level's difficulty budget.

`WATCHSKIBIDITOILET` uses the frozen 15,048,248-byte MP4 through the pinned
FFmpeg 7.1 decoder, streams SMTP `250-` continuation lines, and permits one
viewer process-wide. Width, FPS, contrast, brightness, gamma, aspect and invert
retain the frozen parsing and defaults. Frame conversion is a Rust-owned,
bounded RGB24 box-resize and ASCII pipeline; the old self-authored
`libasciiart` is not a runtime dependency. Disconnect, cancellation, error, EOF
and shutdown must all release admission and join or boundedly drain decode
work. The v1 oracle golden freezes the exact width-10, three-row first-frame
prefix at SHA-256
`97cb629ab6ffd992439c2dc82664b4d61f11d4b99ea554db11b589421f877df1`.
The candidate-only v2 security contract rejects non-finite transform values,
proves one winner under 32 simultaneous requests, and requires permit recovery
within five seconds after the admitted socket disconnects. These two reviewed
differences are bound in
`evidence/compatibility/smtp-skibidi-security-v2.json`; they do not alter the v1
golden.

## SMTP STARTTLS contract

The Rust candidate matches the v35 STARTTLS profile for TLS 1.2 and TLS 1.3
negotiation, TLS 1.1 rejection, certificate chain and `smtp.example.test`
hostname verification, post-upgrade EHLO state reset, repeated-upgrade
rejection, ESMTPS DATA storage, and recovery after a malformed handshake. The
ephemeral PKCS#12 password is passed only through
`LMYZMAIL_SSL_KEYSTORE_PASSWORD`; runtime configuration and goldens contain no
password or private key. The companion evidence profile remains Java-only for
the approved buffered-plaintext command-smuggling fix.

## SMTP DATA and BDAT contract

The Rust candidate matches the v31 DATA/BDAT profile across incremental DATA
terminator parsing and dot transparency, fragmented binary BDAT with exact
octet counts, coalesced multi-chunk delivery, zero-length and 15,728,640-byte
state boundaries, and partial DATA/BDAT disconnect recovery. Each accepted
message is checked through the normalized Maildir bytes, PostgreSQL
`email_index`, and Redis mail-count state; failed partial transactions leave no
temporary or durable delivery state, and a fresh session can deliver normally.
The companion v31 evidence profile remains Java-only for the oracle's
terminator-tail command loss and coalesced prerequisite-state stall.

## SMTP MIME contract

The Rust candidate matches the v31 MIME profile for multipart DATA and BDAT
delivery, base64 attachment decoding, `From`/`To` index materialization, exact
Maildir publication, and Redis mail-count updates. It intentionally preserves
the frozen first-body-part indexing rule: when a multipart message puts a text
body before its attachment, `email_index.has_attachments` remains `false` even
though the stored message contains the attachment.

The v33 profile additionally freezes the active `NEW_DOMAIN` envelope rule.
MAIL FROM takes precedence over the first `From` header, one trailing dot is
removed, and the final two labels are queried without PSL or IDNA rewriting.
The shared Hickory resolver has an 8,192-entry cache and at most 32 active SOA
queries. Admission and lookup share one five-second deadline; ordinary DNS
failure is scored as the oracle's missing-SOA result instead of silently making
the message clean. Eight- and ten-digit SOA serials retain the frozen UTC age
bands and rule weight. `NEW_DOMAIN` is appended before header and attachment
hits, preserving the exact `X-Spam-Rules` order.

The v1 RBL profile freezes the preceding `RBL_CHECK` rule over a dynamically
selected WSL global IPv6 peer. IPv4 octets and every IPv6 nibble are reversed
exactly as in Java. Blank, loopback, RFC 1918 site-local, link-local,
unspecified, IPv6 `fec0::/10`, and IPv4-mapped private peers do not query RBLs.
Configured servers are queried concurrently through a shared Hickory resolver;
each lookup and its bounded admission share the configured deadline, and either
an A or AAAA answer is a listing. At most 32 servers are accepted, at most 64
queries run concurrently, and the resolver cache is limited to 8,192 entries.
The golden proves two listings, score-per-hit multiplication, max-score capping,
rule weighting, loopback skip, and the exact Maildir/PostgreSQL/Redis effects.
New `lmyzmail.contentfilter.rbl.*` and `rules.RBL_CHECK.*` keys take precedence
per field over their `botmail.*` aliases.

This is an incremental content-filter milestone, not a claim that the whole
scanner is complete. The default-enabled `SPAM_KEYWORDS` and `SUSPICIOUS_URL`
rules remain separate required migration slices. Evidence for the completed
reputation rules is recorded in
`evidence/compatibility/smtp-content-filter-new-domain-v1.json` and
`evidence/compatibility/smtp-content-filter-rbl-v1.json`.

## SMTP command contract

The Rust candidate matches the v32 command profile byte for byte across utility
commands, HELO/EHLO and transaction resets, MAIL/RCPT syntax and state, the
15,728,640-byte declared-size boundary, CRLF and 1,000-byte command limits,
partial-disconnect recovery, and the ten-error per-connection budget. The v32
Java observations are unchanged from v31; the new generation re-attests them to
definition tree `5f708ae5d17d99b39938c1726f0e4a3068debe0e1975cf36d771d4d3b4adc761`
and adds candidate verification. The companion evidence profile remains
Java-only for the two approved malformed-input fixes above.

## SMTP AUTH oracle behavior

The frozen SMTP dispatcher registers `AUTH` as a probe sink, not as a login
implementation. EHLO never advertises an AUTH mechanism. In the valid HELO state,
`AUTH` with any argument, including PLAIN/LOGIN-shaped, malformed Base64, or an
initial response, returns the exact `502 5.5.1 AUTH command not implemented` wire
reply and does not enter a challenge or authenticated state. A following Base64
line is parsed as a new command. AUTH outside the HELO state is a `503` sequence
error; after STARTTLS a fresh EHLO is required before the same probe-sink behavior
returns. The isolated managed profile also freezes the default 20-probe SMTP error
budget, the subsequent `MAIL FROM` `550` block, and the loopback exclusion that
keeps `AUTH_PROBE` rows out of the temporary PostgreSQL fixture.

The Rust candidate matches the v34 plaintext and STARTTLS profiles, including
the exact wire replies, command-state transitions, failure threshold, partial
disconnect recovery, post-TLS EHLO reset, certificate hostname verification,
and the bounded PostgreSQL no-side-effect observation window. The managed TLS
candidate receives its ephemeral PKCS#12 password only through
`LMYZMAIL_SSL_KEYSTORE_PASSWORD`; neither runtime configuration nor goldens
contain the password or private key.
