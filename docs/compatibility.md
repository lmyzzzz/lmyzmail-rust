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
