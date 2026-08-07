# Compatibility contract

The frozen Java oracle is the behavioral authority except for the new product
name and configuration aliases. The differential harness compares bytes,
status, headers, bodies, state transitions, persistence, and recovery behavior.

Configuration resolution is deterministic:

1. Read `lmyzmail.*`.
2. If absent, read the exact frozen alias. Most aliases are `botmail.*`; the
   frozen MX cache settings are bare `dns.cache.mx.*` keys.
3. If both are absent, apply the frozen oracle default.
4. Never merge scalar values or silently accept conflicting structured values.

Only genuine nondeterminism such as wall-clock time, random identifiers, and
ephemeral ports may be normalized. Each normalizer is field-scoped and tested;
there is no whole-response masking or assertion weakening.

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

## Approved security differences

The authoritative allowlist is
`blackbox/manifests/behavior-differences.json`. Every entry binds the frozen
commit and source hash, describes the exact scope, and states a stricter
candidate requirement. An allowlisted difference never relaxes surrounding
wire, state, storage, or recovery assertions.

- Maildir publication must use a flushed same-filesystem temporary file,
  atomic rename, and directory fsync instead of exposing a partially written
  final file.
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
- RFC null MX is an explicit permanent no-service route and cannot become an
  empty hostname or coexist with ordinary MX records.
- MX, address, MTA-STS TXT, policy-pattern, and policy-body processing have the
  exact hard ceilings recorded in the allowlist rather than the oracle's
  unbounded DNS fanout.
- A live legacy MTA-STS NONE value is reusable only for its remaining Redis TTL,
  capped at five minutes. This repairs the oracle's restart-only negative-cache
  expiry bug without changing bytes, keys, or post-expiry discovery.
- Outbound HTTP status reads have a bounded Redis deadline. The frozen oracle
  leaves known-ID and sent-file requests unanswered beyond the ten-second
  blackbox observation window after Redis disappears; lmyzmail returns a fixed
  `500 {"error":"internal_error"}` for a known status and still resolves an
  unknown sent file to `404` through PostgreSQL within the same request budget.

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
