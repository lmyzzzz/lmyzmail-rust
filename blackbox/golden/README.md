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
  repository LF policy. It is the accepted, clean-checkout-reproducible HTTP set
  consumed by tests at this milestone.
