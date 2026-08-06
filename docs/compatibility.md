# Compatibility contract

The frozen Java oracle is the behavioral authority except for the new product
name and configuration aliases. The differential harness compares bytes,
status, headers, bodies, state transitions, persistence, and recovery behavior.

Configuration resolution is deterministic:

1. Read `lmyzmail.*`.
2. If absent, read the corresponding legacy `botmail.*` key.
3. If both are absent, apply the frozen oracle default.
4. Never merge scalar values or silently accept conflicting structured values.

Only genuine nondeterminism such as wall-clock time, random identifiers, and
ephemeral ports may be normalized. Each normalizer is field-scoped and tested;
there is no whole-response masking or assertion weakening.

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
