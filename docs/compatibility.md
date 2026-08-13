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

## HTTP multipart outbound admission

`POST /web/mail/send/multipart` reads at most 64 KiB of headers, applies the
declared request limit before authentication, validates the session before
consuming the body, and then parses multipart fields incrementally under the
request cancellation token. The normal HTTP body limit remains 10 MiB. The
multipart limit defaults to 200 MiB and resolves
`lmyzmail.http.max-multipart-bytes` before the legacy
`botmail.netty.http.max-multipart-size` alias.

The `data` JSON field is capped at 64 KiB and the last Java-compatible data
field wins. At most 256 attachment parts are admitted; the configured per-file,
aggregate attachment, complete multipart, and final message limits all apply.
Attachment bytes stream to random create-new files in the mode-0700
`<maildir>/.lmyzmail-upload` directory unless
`lmyzmail.http.upload-temp-dir` or its legacy `botmail.http.upload-temp-dir`
alias selects another directory. MIME materialization reads those files in
bounded chunks and does not load or Base64-copy a complete attachment in
memory.

Every request-owned upload is removed after success, validation failure,
malformed input, disconnect, deadline, cancellation, PostgreSQL failure, or
Redis failure. The two intentional oracle differences are recorded as
`http-multipart-error-detail-redaction` and
`http-multipart-request-owned-upload-cleanup` in
`blackbox/manifests/behavior-differences.json`; all successful response,
Redis, TTL, Maildir, MIME, limit, and error bytes remain differential
requirements.

The final common recording is `managed-web-multipart-v8`: `suite.json` has
SHA-256 `1c0c2091193b862e6e967c8ad15aa5b9a3c01cb99a0c179698012f2b0354fb4a`
and its observation has SHA-256
`59217ebd361ea6c0979b623b5d7ac829d99763c6825ab2ea1b71a74602c04db6`.
The independent defect evidence is
`managed-web-multipart-oracle-evidence-v5`: `suite.json` has SHA-256
`135a1ed3c35d311d7ae6303ede9338f31b55da65147ea8fc968cdd74849a5643`
and its observation has SHA-256
`ef10d8de210743489d3d008c337faf6a4c905b5427b563b54fc14058ca84edc5`.
Historical common v1-v7 and defect-evidence v1-v4 recordings remain
immutable evidence.

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

The active `managed-smtp-content-filter-default-v4` profile composes the real
defaults while disabling only the separately frozen `RBL_CHECK` and
`NEW_DOMAIN` DNS rules. A complete From/Date message scores 9.5 in exact BODY
order: `SPAM_KEYWORDS=8.0, SUSPICIOUS_URL=1.5`. Omitting both headers prepends
the HEADER hit `MISSING_HEADERS=3.5`, yields 13.0, and indexes a SQL NULL
`from_address`. Both messages carry exactly one ordered
`X-Spam-Status`/`X-Spam-Score`/`X-Spam-Rules` block, route to the spam Maildir,
insert one PostgreSQL row, and increment the corresponding no-TTL Redis counter
exactly once. One isolated Java runtime created v2, a fresh JVM replayed it,
and the locked Rust release matched both observations.

`FROM_REPLYTO_MISMATCH`, `SUSPICIOUS_DATE`, `HTML_TEXT_RATIO`,
`PHISHING_PATTERN`, and `INVISIBLE_TEXT` are not missing candidate features.
Their frozen Java classes unconditionally return `false` from `isEnabled()` and
return null/no-op evaluators. The candidate therefore does not invent behavior
for those placeholders.

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

## SMTP external-sender SPF

For every accepted non-null `MAIL FROM`, SMTP evaluates SPF once before
accepting the sender. The check uses the canonical envelope address, peer IP,
current HELO name, and configured local domain. Its result is retained in the
bounded transaction state and reused by local-domain self-spoof rejection and
DATA or BDAT delivery; EHLO, RSET, STARTTLS, and completed delivery clear it.
Null reverse paths retain the frozen `spf=none (No MAIL FROM address)` behavior
without a DNS query.

The implementation uses `mail-auth` for SPF evaluation. The initial positive
TXT record is parsed once and injected into a transaction-local FQDN cache, so
the evaluator does not repeat the top-level query. That cache holds at most 16
TXT entries, and lookup plus evaluation share a ten-second deadline and the
connection cancellation token.

`Authentication-Results` carries the frozen result and reason. SPF `fail` adds
3.0 to `X-Spam-Score` and sets `X-Spam-Status: Yes`; `softfail` adds 1.0 but
does not set the status by itself. Other SPF results add zero. A clean SPF pass
is stored in `inbox`; every other unsigned result is stored in `spam`. Content
filter scores and quarantine decisions remain additive.

The create-once `managed-smtp-spf-v1` matrix freezes pass, fail, softfail,
neutral, and no-record behavior over raw SMTP, scripted DNS, Maildir,
`email_index`, and the legacy Redis count keys. A fresh Java runtime replayed
the golden unchanged, and the Linux x86_64 Rust release matched it byte for
byte after the documented nondeterminism normalizers.

## SMTP external-sender DKIM

DKIM verification runs once when an accepted DATA or final BDAT transaction is
delivered. It uses `mail-auth` with the configured SMTP security resolver. The
initial selector TXT record is parsed once and injected into a
transaction-local cache so a valid zero-TTL key produces one wire query per
transaction. Verification and DNS share the connection cancellation token and
a ten-second deadline; at most 16 verifications run concurrently and each
transaction retains at most 16 TXT cache entries.

`Authentication-Results` preserves the frozen Java result and reason. A valid
signature reports `dkim=pass` and can route a clean message to `inbox` even
when the null reverse path yields SPF none. A body-hash or signature failure
reports `dkim=fail`, adds 3.0 to `X-Spam-Score`, sets
`X-Spam-Status: Yes`, and routes to `spam`. A missing selector key reports
`dkim=permerror`, adds no protocol score, leaves `X-Spam-Status: No` when no
other rule fires, and routes an otherwise unauthenticated message to `spam`.
Unsigned messages retain `dkim=none (No DKIM signature present)`. Content
filter and SPF scores and quarantine decisions remain additive.

The create-once `managed-smtp-dkim-v5` matrix uses three fixed RSA public keys
and nine fixed pre-signed messages to freeze pass, body-hash failure,
signature failure, missing-key permerror, multiple-signature ordering, and
valid AUID forms. When the first signature is valid and the second selector is
missing, the result is pass and the second selector is never queried. Reversing
those headers produces the first signature's permerror and the valid second
selector is never queried. Exact-domain and permitted subdomain `i=` values
pass; a public key carrying `t=s` passes an exact-domain AUID.

The separate create-once
`managed-smtp-dkim-identity-oracle-evidence-v1` set proves that Java also
accepts an unrelated AUID domain, a subdomain forbidden by `t=s`, a signing
domain followed by an attacker suffix, and an `i=` value with no `@`. Rust
rejects exactly those four cases as `dkim=fail` under the approved
`smtp-dkim-auid-domain-validation` security difference. The normal matrix
covers raw SMTP DATA, zero-TTL/NXDOMAIN scripted DNS,
`Authentication-Results`, spam headers, Maildir, `email_index`, and legacy
Redis count keys. A fresh Java runtime replayed both golden sets unchanged;
the locked Linux x86_64 Rust release matched v5 byte for byte after the
documented field-scoped normalizers and passed the stricter identity checks.

The create-once `managed-smtp-spf-dkim-v1` matrix exhaustively crosses SPF
pass, fail, softfail, neutral, and no-record with DKIM pass, body-hash fail,
missing-key permerror, and unsigned. Either mechanism passing routes to
`inbox`, including SPF-pass/DKIM-fail and SPF-fail/DKIM-pass. An explicit fail
still sets `X-Spam-Status: Yes`, so those inbox cases retain a 3.0 protocol
score and spam-status header. SPF softfail adds 1.0 without setting the status;
neutral, none, and DKIM permerror add zero. The both-fail case adds 6.0 and
routes to `spam`.

All 20 cases use unique envelope domains and Message-IDs, assert positive and
bounded missing-record DNS traffic, and freeze the exact
`Authentication-Results`, spam headers, folder, Maildir, `email_index`, and
legacy Redis counter behavior. The committed fixture contains only its RSA
public key and fixed signatures. A fresh Java runtime replayed the golden, all
ten signatures passed independent verification, and the locked Rust release
matched the matrix without a Java runtime dependency.

## SMTP DMARC alignment and disposition

For each accepted non-null reverse path, lmyzmail performs the frozen early
DMARC lookup for the envelope domain after SPF and retains a positive record in
the bounded transaction state. At DATA or final BDAT delivery it parses exactly
one non-group RFC5322.From mailbox, reuses that record only when the normalized
From and envelope domains are equal, and otherwise looks up the author domain.
IDNA normalization and the pinned Mozilla Public Suffix List from `psl
2.1.223` provide strict or relaxed SPF/DKIM alignment without a JVM.

DMARC lookup and its 16-permit admission share a ten-second deadline and the
SMTP connection cancellation token. Each response considers at most 32 TXT
records and 4 KiB per joined record. An author-domain miss falls back once to
the registrable domain and applies `sp`; lookup, parse, or normalization failure
fails open as the frozen oracle's `dmarc=none` result.

An aligned SPF or DKIM pass emits `dmarc=pass` and permits inbox routing. A
`p=quarantine` alignment failure overrides an otherwise passing mechanism,
routes to spam, and sets `X-Spam-Status: Yes`. Every DMARC fail adds 2.0 to
`X-Spam-Score`; SPF and DKIM scores remain additive. A `p=reject` failure keeps
the frozen SMTP behavior of returning a normal `250` acceptance ID while
publishing no Maildir file, PostgreSQL index row, or Redis counter change.

The active create-once `managed-smtp-dmarc-v3` profile retains the original five
DATA cases and adds eight edge transactions. Multiple From fields and group
syntax produce `dmarc=none` without querying either invalid author domain while
the frozen index keeps the final raw From value. Organizational-domain fallback
uses `sp` for a distinct author subdomain. A malformed record is skipped in
favor of the following valid record, while two valid records preserve the
oracle's first-record selection. Both multiple-DKIM orders prove that only the
first signature contributes to DMARC, including zero queries for the ignored
selector. The final case runs aligned SPF through BDAT LAST and proves the same
wire, Maildir, PostgreSQL, and Redis outcome as DATA.

One isolated Java runtime created v3, a fresh JVM replayed it unchanged, and the
locked Linux x86_64 Rust release matched all thirteen transactions byte for
byte. `managed-smtp-dmarc-v2` remains immutable exploration history from the
early envelope-domain lookup path; it is not the active candidate expectation.

## SMTP Spamhaus DNSBL and DBL

Spamhaus is disabled by default, with the frozen `zen.spamhaus.org` IP zone,
`dbl.spamhaus.org` domain zone, 3,000 ms total check deadline, 300-second cache
TTL, reject-on-listed enabled, and DBL disabled. Every
`botmail.smtp-security.spamhaus-*` property remains accepted; the corresponding
`lmyzmail.*` value wins independently when both exist. Semantic JSON exposes
the same fields without changing the property precedence contract.

After sender-domain syntax validation, an enabled check concurrently evaluates
the reversed public IPv4 address against the configured DNSBL zones and the
lowercase IDNA sender domain against DBL. Private, loopback, link-local, and
unspecified client addresses skip the IP path. The first non-ignored IPv4 A
answer in configured zone order uses the frozen Java return-code description.
NXDOMAIN receives the oracle-compatible second lookup; NODATA, SERVFAIL,
malformed replies, timeout, cancellation, and transport failures fail open.
The explicit fixture resolver uses connected UDP, admits at most 64 active DNS
requests, accepts at most 4,096 response bytes, and validates transaction ID,
response type, opcode, truncation state, and the exact question before using an
A record. The combined `(client IP, ASCII sender domain)` cache contains at
most 10,000 entries and uses the configured wall-clock TTL rather than DNS TTL.

Listed senders receive the frozen Latin-1 `550 5.7.1 Service unavailable`
reply. A rejected listing persists `SPAMHAUS_LISTED` with score 3 and increments
only `spamhaus_count`; a following RCPT state probe adds the frozen score-1
`PROTOCOL_VIOLATION`. The seven-case DBL matrix and cache scenario are frozen
under `managed-smtp-spamhaus-v1`; one-case profiles separately freeze
reject-disabled acceptance and disabled no-query behavior. A fresh Java replay
and the Linux x86_64 Rust release matched all three profile definitions without
changing their golden bytes.

Invalid or operationally unsafe configuration is the reviewed
`smtp-spamhaus-config-bounds` difference. The candidate accepts at most 32
zones and 256 ignored IPv4 codes, requires bounded DNS-name syntax, restricts
the timeout to 1 through 60,000 ms, and caps cache TTL at seven days. Cache TTL
zero remains valid and disables caching. These checks affect only invalid or
out-of-budget configuration; every in-budget lookup, wire, cache, and
persistence behavior remains differential. The post-freeze supplemental
allowlist is bound in `evidence/compatibility/smtp-spamhaus-v1.json`; the frozen
golden definition tree and global manifest are unchanged.

## Outbound SMTP success and permanent-failure paths

The immutable `managed-outbound-queue-v34.json` generation was the first
external outbound delivery observation replayed by both runtimes. Active
generation `managed-outbound-queue-v36.json` re-attests the same observation
byte-for-byte under definition tree
`f5fadc4f3851ee9ba0b84d29234270f12cacd8d53922ae2c9459d82532432657`.
It starts isolated PostgreSQL, Redis, Maildir, remote SMTP peer, and network
namespace fixtures, then submits four asynchronous API messages whose text
bodies are 19, 8,191, 8,192, and 12,288 bytes. The frozen 10 KiB estimate keeps
8,191 bytes inline in Redis and switches 8,192 bytes to an owned spool file.

The Rust candidate matches the Java oracle's `202` admission bodies, legacy
Redis task JSON/type/seven-day TTL, pending order, sent-file index, memory/file
boundary, Sent Maildir byte totals and shard numbers, PostgreSQL `SENT` rows,
SMTP envelope, message and wire byte lengths, ordered SMTP event sequence, and
all four normalized message SHA-256 values. The message normalizer replaces
only Date, Message-ID, and an optional DKIM-Signature. Java's streaming
quoted-printable rule folds before byte 76, so the Rust writer deliberately
emits at most 75 encoded bytes before a soft break without buffering the body.

The candidate's resolver consumes a zero-TTL A answer from a bounded scripted
DNS server inside the probe namespace and connects to the already reviewed
numeric address; the recipient-domain MX value remains the exact legacy Redis
cache entry. Snapshot assertions are scoped to the four task IDs created by
this scenario.

The active `managed-outbound-5xx-v4.json` generation uses the same definition
tree and adds a ten-case raw-wire matrix: RCPT and final DATA replies for codes
500, 501, 549, 550, and 554. The candidate matches the initial `202` queue
response; exact EHLO, MAIL, RCPT, DATA, and reply order; absence of message data
for RCPT failures; message data for DATA failures; no QUIT after a rejected
final DATA reply; legacy Redis task acknowledgement, per-domain state, and
aggregate status; and PostgreSQL `FAILED` rows with zero retries. The frozen
aggregate remains `PROCESSING` for 500, 501, and 549 and becomes `FAILED` for
550 and 554. Exact errors retain Java's `RCPT TO failed: CODE ...`, `Message
not accepted: CODE ...`, and `All domains failed: {domain=error}` forms. Only
the generated queue ID is normalized. v1 through v3 remain immutable history; a
fresh Java recording, independent Java replay, and Rust candidate replay all
passed v4.

The active `managed-outbound-4xx-v3.json` generation freezes RCPT and final
DATA replies for 400, 421, 450, 451, 452, and 499. The Java oracle retries only
421, 450, 451, and 452; despite their reply class, 400 and 499 fail after one
attempt with `retry_count=0`. Each retryable matrix case observes the real
30-second deadline before advancing only that isolated task to retry count 5
and proving the second failure is terminal. A separate DATA 451 case proves
the complete 30, 60, 120, 240, and 480 second sequence followed by terminal
failure on attempt six. Every Redis task deadline must agree with its retry
ZSET score within one second and lie within a five-second observation window.
No wall clock or runtime retry configuration is modified.

The frozen Java queue has no `outbound_mail_queue` row while a retry is
pending; Redis is authoritative until terminal archive. The candidate keeps a
PostgreSQL `PENDING` checkpoint with the same retry count, error, and deadline
before publishing Redis state. The approved
`outbound-retry-postgres-checkpoint` difference asserts both sides exactly and
then requires the rest of the complete observation to equal the Java golden.
It is a crash-recovery improvement, not a deadline normalizer.

The candidate reads `lmyzmail.outbound.helo-hostname` with
`botmail.outbound.helo-hostname` fallback and new-key precedence. Empty,
non-ASCII, whitespace/control-bearing, or over-253-byte values are rejected at
startup. The differential fixtures use `blackbox.example` through the legacy
key for Java and the new key for Rust.

The active `managed-outbound-dsn-oracle-evidence-v3.json` recording freezes a
real RCPT 550 followed by an eight-second bounded Java observation. The oracle
archives the original local-sender task as `FAILED`, leaves its original Sent
Maildir copy and domain projection intact, and emits no DSN. Rust preserves all
of those effects and exercises the approved
`outbound-permanent-failure-dsn` difference: exactly one durable generated
queue row, one `ADMITTED` PostgreSQL DSN outbox row, one accepted remote SMTP
transaction with null reverse-path, and one bounded RFC 3464
`multipart/report`. The report includes `message/delivery-status` plus only
the original headers, never the original body. Both implementations must leave
their pre-existing Redis worklist baseline unchanged. v1 and v2 remain
immutable pre-final-definition history and are not active.

The active `managed-outbound-tls-v5.json` profile covers opportunistic
STARTTLS success with a post-TLS EHLO, trust-chain failure and command
rejection followed by a fresh plaintext connection, MTA-STS enforce success,
and enforce rejection without downgrade when STARTTLS is absent. It also
freezes the approved `outbound-starttls-hostname-verification` difference:
Java accepts a trusted but hostname-mismatched certificate outside enforce
mode, while Rust verifies the name and then follows the same fresh-connection
opportunistic fallback. Enforce policy, certificate, and STARTTLS-rejection
failures are permanent terminal queue failures with zero retries. TLS handshake
timeouts and connection-class transport failures remain retryable on Java's
30-second schedule, without a plaintext downgrade.

The independent active `managed-outbound-tls-negotiation-v1.json` profile
freezes TLS 1.3 with `TLS_AES_256_GCM_SHA384`, TLS 1.2 with
`ECDHE-RSA-AES128-GCM-SHA256`, TLS 1.1 rejection, an RSA-certificate/no-shared-
cipher rejection, and the exact protocol-version and handshake-failure queue
errors. Opportunistic failures must create a new plaintext connection;
MTA-STS enforce failures must not downgrade and must terminate with zero
retries. The only approved difference is
`outbound-starttls-static-rsa-cbc-rejection`: Java accepts TLS 1.2
`TLS_RSA_WITH_AES_128_CBC_SHA` (`AES128-SHA`), while Rust retains rustls ring's
modern AEAD/ECDHE policy. Rust therefore uses the ordinary fresh-connection
fallback in opportunistic mode and permanently fails without downgrade in
enforce mode. No other version, cipher, certificate, alert, SMTP byte, or
queue-state difference is allowed.

The active `managed-mta-sts-discovery-v3.json` profile freezes 21 external
policy-discovery cases: absent, malformed, and multiple TXT records; policy
host address failure; untrusted HTTPS certificates; 404, 500, and redirect
responses; missing or wrong content type; invalid UTF-8; malformed, oversized,
and stalled policies; testing, none, enforce, and `max_age=0` modes; positive
same-process caching; and positive and negative cache behavior across restart.
Negative results retain the frozen six-field NONE value and five-minute Redis
TTL and are reused by the same process through L1. After restart, Java rejects
that invalid Redis policy and performs fresh TXT discovery, while valid
positive policies remain reusable. Rust matches those semantics exactly. v2
remains immutable pre-final-definition history.

Disconnect ambiguity, DSN restart recovery across injected process or storage
loss, DSN suppression, backpressure, high concurrency, and soak remain
separate external differential matrices. v36,
5xx v4, 4xx v3, DSN v3, outbound TLS v5, negotiation v1, and MTA-STS discovery
v3 do not claim those paths. TLS v1 through v4 remain immutable history; v5
retains the header-only normalization and API-returned queue identity
established by v3 under the current harness definition tree.

The active `managed-tlsrpt-https-v11.json` profile separately freezes external
TLS report HTTPS delivery through the real report API. It covers a successful
204 POST, a 302 that is reported without following, an untrusted collector
certificate, a private-address SSRF rejection before connect, and a stalled
response under the shared two-second deadline. Java and Rust match on policy
TXT discovery, exact target and Host bytes, SNI, TLS 1.3 cipher, complete gzip
JSON body after only the UUIDv4 report id is normalized, API result, and
unchanged source report row. Hickory's exact AAAA-before-A trace is asserted
for Rust; Java collector resolution uses its isolated JDK hosts file. v1
through v10 remain immutable pre-final-definition history. The only wire
difference is the explicitly authorized `Botmail-TLSRPT/1.0` to
`lmyzmail-TLSRPT/1.0` branding change.

The active `managed-reports-v23` profile is collected by the normal black-box
test suite for both frozen Java and Rust. Its eight scenarios cover report
status, domain/address discovery, date errors, empty generation, seeded DMARC
and TLSRPT delivery, and the combined trigger across PostgreSQL, DNS, Redis,
Maildir, MIME, and gzip artifacts. A separate Rust test enables automatic
sending and verifies bounded startup and shutdown. Scheduler fault injection
and soak remain separate matrices.

The active `managed-reports-scheduler-v2` profile separately freezes an
externally clock-driven 01:00 UTC boundary in isolated Java and Rust
processes. It compares the prior-date report publication, exact DNS order,
Redis task and Maildir side effects, unchanged source rows, single-run
admission at the boundary, and bounded shutdown. The fixture advances only
`CLOCK_REALTIME`; monotonic deadlines and database/Redis clocks remain real.

The independent `managed-reports-scheduler-restart-v1` profile freezes a
process stopped at 00:59:20 UTC and restarted at 01:00:20 UTC. Java performs
no catch-up publication, DNS work, Redis mutation, Maildir write, or source-row
mutation; Rust matches that behavior. Concurrent trigger admission, storage
fault injection, scheduler high-concurrency, and long-running soak remain
unclaimed by that restart profile.

The supplemental `report-trigger-concurrency-v1` profile freezes the shared
process-local trigger guard without changing the active golden definition
tree. A PostgreSQL `ACCESS EXCLUSIVE` fixture blocks the admitted request at
its real DMARC domain query, and `pg_locks` proves its `AccessShareLock` is
waiting before a second raw HTTP request is sent. Java and Rust return the
exact zero-count `Already running` summary for that overlap, perform no early
DNS, Redis, or Maildir work, then publish exactly one DMARC/TLSRPT pair after
the lock is released. Source rows and threshold fixtures remain unchanged.
Storage fault injection, higher fan-in, and soak remain separate evidence.

The supplemental `report-trigger-fanin-v1` profile extends that shared guard
contract to a synchronized 32-request overlap. The admitted request is held at
the same real PostgreSQL domain query while every overlap must finish within a
five-second budget before the table lock is released. Java and Rust return the
same byte-exact zero-count `Already running` response for all 32 requests,
without queuing another generation or changing DNS, Redis, Maildir, or source
rows. Releasing the lock completes the sole admitted no-data request with
`error=none`. Fan-in beyond 32 and long-running soak remain separate evidence.

The supplemental `report-trigger-disconnect-v1` profile sends a complete
authenticated trigger, proves its real PostgreSQL domain query is blocked, and
then closes the client with TCP RST. The frozen Java process retains the query
and guard, so an overlap returns `Already running`. Rust cancels the blocked
query, joins the request task, releases the guard, and admits a retry, with no
DNS, Redis, Maildir, or source-table mutation on either path. This bounded
lifecycle correction is approved by the immutable supplemental difference
manifest as
`http-report-trigger-client-disconnect-cancellation`. The Java observation has
SHA-256 `0b8ceeb22e472d852233029692906de1972f183b4993367b4e71aa145b5b1255`,
the candidate observation has SHA-256
`ab628fa4b165a58470c582bbe5aa92445bc4a711630ea4c8b08831b70970168a`,
and the verified Linux x86_64 release has SHA-256
`e8663099260085f649c47ed8dac377323e716a8a79e805ab15daa6b67ddcb7dc`.
The supplemental manifest has SHA-256
`de8fbdaa30e982e095a651ff4f87a228a5990a26c534d81cbc9ad1d591b7a6f2`.
Clean FIN, unread data followed by FIN,
and request write half-close are not treated as aborts; valid responses must
still complete.

The supplemental `report-trigger-postgres-outage-v1` profile stops the
isolated PostgreSQL process group only after `pg_locks` proves that the real
DMARC domain query is waiting. Frozen Java remains blocked throughout a
twelve-second observation and returns `error=none` only after PostgreSQL is
resumed. Rust includes query cancellation and drain in one eight-second
database budget, returns HTTP 200 with the exact
`error=reporting database deadline exceeded` JSON while PostgreSQL is still
stopped, discards the unconfirmed connection, releases the guard, and accepts
a successful retry after recovery. Both paths preserve the exact overlap
`Already running` response and perform no DNS, Redis, Maildir, or source-row
mutation. This evidence-bound safety difference is
`report-trigger-postgres-total-deadline`; it is supplemental and does not
change the frozen main black-box definition tree.

The supplemental `report-trigger-postgres-crash-recovery-v1` profile kills
only the isolated PostgreSQL process group after a real report query is
blocked, then restarts PostgreSQL from the same durable data directory on the
same port while the application PID remains unchanged. Both Java and Rust
return HTTP 200 with zero counts, recover their existing connection pools,
return `error=none` on retry, and preserve DNS, Redis, Maildir, and source-row
state. Frozen Java exposes its Hibernate SQL, generated alias, and JDBC driver
I/O exception in the public `error` field. Rust instead returns the fixed
`reporting database unavailable` value. This narrowly approved supplemental
difference is `report-trigger-postgres-error-redaction`; it does not relax any
status, recovery, byte, or side-effect assertion.

The supplemental `report-trigger-redis-outage-v1` profile stops the isolated
Redis process group after the report request has completed its exact DMARC DNS
discovery. Frozen Java does not respond during a twelve-second observation and
continues the original request after Redis resumes. Rust applies its bounded
queue deadline, returns HTTP 200 with the exact failed delivery result
`error=outbound queue unavailable`, and leaves PostgreSQL, Redis, and Maildir
unchanged before accepting an explicit retry. Both recover without an
application or Redis restart and then publish one Redis/Maildir DMARC message
that matches the active seeded-delivery golden byte for byte. The bounded wait
is the supplemental `report-trigger-redis-outage-deadline` difference. Rust's
additional PostgreSQL `PENDING` checkpoint after successful recovery remains
within the existing `outbound-retry-postgres-checkpoint` difference.

The supplemental `report-trigger-maildir-failure-v1` profile replaces the empty
`qa@example.test/sent` directory with a regular marker file during one DMARC
report admission. Java advances its Redis task sequence and publishes a task,
domain state, and pending reference despite the missing Sent file; the task has
null Sent metadata while the HTTP result reports success. Rust intentionally
fails closed with the exact `outbound queue unavailable` per-delivery result and
advances only bounded task-ID allocators. No queue projection, PostgreSQL row,
email index, Maildir file, spool, or temporary file is allowed. Restoring the
directory and retrying produces one DMARC publication matching the active v23
golden, with unchanged application PID and no extra DNS query in this fixture.
This evidence-bound safety difference is `report-trigger-maildir-write-failure`;
it does not relax successful Maildir byte, Redis TTL, PostgreSQL, or report
response requirements.

The supplemental `report-trigger-redis-crash-recovery-v1` profile enables Redis
AOF and an explicit SAVE, SIGKILLs only Redis after DMARC DNS discovery, and
restarts the same data directory. Java resumes the original request after the
Redis PID changes. Rust returns its bounded `outbound queue unavailable` result
while Redis is down, keeps the application PID unchanged, preserves the
pre-existing pending prefix, and succeeds on one explicit retry. Both produce
one DMARC Redis/Maildir publication matching the active v23 golden with no
additional recovery DNS query or source-row mutation. This evidence-bound
crash-recovery difference does not claim Redis data-loss, post-commit crash,
Maildir-failure, dual-report failure, or repeated-soak behavior.

The active `managed-outbound-tls-validity-v3.json` profile separately freezes
trusted-chain certificates that are expired or not yet valid. Opportunistic
mode closes the failed TLS connection and delivers over a fresh plaintext
connection. MTA-STS enforce mode never downgrades and archives both failures as
`FAILED` with zero retries. Validity v1 and v2 remain immutable
pre-final-definition history.

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
- Outbound STARTTLS always verifies the TLS server name. The frozen Java client
  omits endpoint identification outside MTA-STS enforce mode; the candidate
  rejects that certificate, closes the TLS attempt, and uses a fresh plaintext
  connection only because the delivery is opportunistic. Trust-chain checks,
  enforce-mode name verification, no-downgrade behavior, SMTP bytes, and queue
  state remain exact requirements.
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

## Stress-test contract

`POST /api/stress/status` requires API read permission. `start`, `reset`, and
`cleanup` require write permission. All four routes fail closed while
`lmyzmail.stress-test-enabled=false`; the legacy
`botmail.stress-test-enabled` alias remains accepted, and a new key wins when
both are present. Every other frozen `botmail.stress-test-*` property has the
same field-by-field `lmyzmail.*` precedence. The disabled start message names
only the new product key.

An admitted run preserves Java's warmup counter transition, exact response
fields including the `KB` acronym, 20 KiB mode threshold, dynamic
1500/1000/400/200/120/80 concurrency thresholds, generated subject and body,
test mailbox creation, sender quota bypass, durable outbound admission, Redis
task and seven-day TTL, delivery polling, and cleanup of both test mailbox
indexes and trees. Reset remains process-local and manual cleanup retains the
frozen best-effort response contract while no run is active. Bodies above 20
KiB are generated into private mode-0600 files and quoted-printable encoded
incrementally into the durable spool. The frozen PostgreSQL `body_text` value
still requires one bounded UTF-8 materialization at the database parameter
boundary; no second full body copy is retained by the stress service.

The active stress goldens attest only the managed singleton domain
`example.test`. In a multi-domain Java configuration, the sender uses the
first send-enabled domain and the receiver independently uses the first
receive-enabled domain in Java `HashMap` iteration order, so the two domains
can differ. The current Rust runtime still exposes one scalar domain to stress
and other subsystems. Full multi-domain configuration and selection parity is
therefore unresolved goal scope, not an approved behavior difference.

The candidate clamps the same warmup and email-size inputs as Java. It also
enforces the approved `stress-resource-and-input-bounds` difference: production
counts from 1 through 1,000,000, at most 1,000,000 warmup messages and 10,000
warmup rounds, safe nonempty 64-byte ASCII mailbox prefixes, a control-free
4,096-byte password of at least eight UTF-16 code units while enabled, four
body workers plus a four-job queue, a shared 64 MiB generated-body admission
budget, a 30-minute queue deadline, and 1,100,000 cleanup entries. Cancellation
propagates through body generation, database calls, delivery polling, cleanup,
and shutdown joins. HTTP requests, stress shutdown, its blocking pool, and the
outbound reconciler share one absolute 20-second HTTP-service shutdown budget.

Java accepts overlapping starts against the same sender and receiver and lets
each run recursively delete those shared trees. Rust returns the exact bounded
503 response recorded by the `stress-bounded-run-admission` allowlist entry
without incrementing the round or starting work. Normal single-run behavior is
governed by `managed-stress-disabled-v5`, `managed-stress-enabled-v5`, and the
32 KiB `managed-stress-streaming-v3`; the frozen defect is isolated in
`managed-stress-oracle-evidence-v4`.

Java also accepts manual cleanup while an active run is concurrently queueing
or waiting for delivery against the same Maildir and index namespace. Rust
returns the same bounded 503 busy body as overlapping start and does not delete
active state. This race repair is isolated under
`stress-cleanup-run-serialization` and
`managed-stress-cleanup-oracle-evidence-v3`.

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

This remains an incremental content-filter milestone, not a claim that every
combination, malformed MIME case, failure injection, concurrency path, or soak
case is complete. The default-enabled `SPAM_KEYWORDS` and `SUSPICIOUS_URL`
implementation and their normal composition with `MISSING_HEADERS` are now
externally differential. Evidence is recorded in
`evidence/compatibility/smtp-content-filter-default-v1.json`,
`evidence/compatibility/smtp-content-filter-body-v1.json`,
`evidence/compatibility/smtp-content-filter-new-domain-v1.json`, and
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
