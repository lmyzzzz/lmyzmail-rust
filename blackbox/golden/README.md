# Java golden sets

Golden observations are create-once, attested to the frozen oracle JAR and runtime
inputs, and must never be overwritten in place.

- `managed-basic/` is the rejected first repeatability probe. A second JVM run proved
  that `Map.of` JSON key iteration order changes between processes. It is retained as
  evidence and is not consumed by tests.
- `managed-basic-v2/` declares field-scoped canonicalization only for response objects
  whose frozen source constructs them with `Map.of`. Other JSON key order remains a
  wire-level assertion. It predates source-tree and request-contract attestation.
- `managed-basic-v3/` additionally binds the then-current Python source tree and exact
  request contracts. Independent JVM verification passed, but later dependency and
  provisioner attestation work made its provenance incomplete. It is retained and no
  longer consumed by tests.
- `managed-basic-v4/` binds the full harness definition tree, every Python/runtime/
  Playwright lock, and every exact request contract. Persistence-profile and formatting
  work changed the definition tree, so it is retained and no longer consumed by tests.
- `managed-basic-v5/` binds the durable PostgreSQL/Redis/Maildir takeover profile,
  crash-recovery assertions, formatted harness tree, locks, and exact HTTP contracts.
  A pre-index CRLF manifest made its definition hash non-reproducible after a clean
  checkout, so it is retained and no longer consumed by tests.
- `managed-basic-v6/` additionally normalizes every attested text definition to the
  repository LF policy. It is the accepted, clean-checkout-reproducible HTTP-only set
  from the preceding milestone and is retained unchanged.
- `managed-basic-v7/` extends the same managed profile with raw SMTP DATA,
  PIPELINING, and BDAT observations. Each SMTP acceptance is followed through to its
  exact normalized Maildir bytes, asynchronous PostgreSQL `email_index` row, and
  Redis mail-count value/type/no-TTL contract. It was the active HTTP+SMTP set for the
  preceding harness revision and is retained unchanged.
- `managed-basic-v8/` keeps the v7 wire scenarios while requiring server-driven EOF
  after QUIT, strict Java RFC 1123 and UTC filename timestamps, and jointly converged
  exactly-once PostgreSQL/Redis/Maildir state with no orphan, temp, or symlink residue.
  It is retained unchanged after deadline and pre-existing-file integrity review.
- `managed-basic-v9/` additionally carries one absolute deadline through PostgreSQL
  statement waits, Redis I/O, Maildir hashing, and final verification. Maildir baselines
  bind each existing file's length and SHA-256 so later deliveries cannot mutate prior
  messages. It is retained unchanged after strengthening the integrity regression.
- `managed-basic-v10/` keeps the v9 behavior while proving that an equal-length mutation
  of a pre-existing Maildir message is rejected by its SHA-256 identity. It is the active
  HTTP+SMTP set consumed by tests at this milestone.
