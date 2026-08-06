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
  of a pre-existing Maildir message is rejected by its SHA-256 identity. It is retained
  unchanged after introducing the isolated STARTTLS profile.
- `managed-basic-v11/` re-attests the unchanged HTTP and plaintext SMTP observations to
  the harness definition that adds the isolated STARTTLS profile. It is retained after
  removing the ephemeral keystore password from the Java process command line.
- `managed-basic-v12/` re-attests the unchanged HTTP and plaintext SMTP observations
  after the STARTTLS runtime moved its password to a non-inherited environment variable.
  It is retained after the AUTH contract was added to the harness definition.
- `managed-basic-v13/` re-attests the unchanged HTTP and plaintext SMTP observations
  after the isolated AUTH profiles and their raw-socket contract were added. It is the
  active basic set consumed by tests at this milestone.
- `managed-basic-v14/` re-attests the unchanged HTTP and plaintext SMTP observations
  after the SMTP command/state, parser-limit, error-budget, and security-evidence
  profiles were added. It is the active basic set for the command-contract milestone.
- `managed-starttls-v1/` freezes normal STARTTLS advertisement, certificate semantics,
  TLS 1.2/1.3 negotiation, TLS 1.1 rejection, state reset, malformed-handshake recovery,
  and a storage-backed TLS DATA delivery. It is retained after password transport
  hardening changed the harness definition.
- `managed-starttls-oracle-evidence-v1/` records the frozen Java plaintext-command
  smuggling behavior under that preceding definition and is retained unchanged.
- `managed-starttls-v2/` is the preceding normal STARTTLS differential set with the PKCS12
  password absent from argv and supplied only through the isolated process environment. It
  is retained after the AUTH contract was added.
- `managed-starttls-oracle-evidence-v2/` is the corresponding retained evidence set for
  the approved plaintext-command smuggling difference. It must never be used as the
  candidate expectation.
- `managed-starttls-v3/` re-attests the unchanged normal STARTTLS observations after the
  AUTH contract was added to the harness definition. It is the active STARTTLS set.
- `managed-starttls-oracle-evidence-v3/` re-attests the unchanged smuggling evidence under
  the same definition and remains evidence only, never a candidate expectation.
- `managed-starttls-v4/` re-attests the unchanged normal STARTTLS observations after the
  SMTP command/security contract was added. It is the active STARTTLS set for this
  milestone.
- `managed-starttls-oracle-evidence-v4/` re-attests the unchanged smuggling evidence under
  the same definition and remains evidence only, never a candidate expectation.
- `managed-smtp-auth-v1/` freezes the first isolated plaintext AUTH recording. It is retained
  as create-once evidence after the contract was strengthened with line-length and partial-
  disconnect recovery checks.
- `managed-smtp-auth-starttls-v1/` freezes the first isolated AUTH-over-STARTTLS recording
  and is retained for the same reason.
- `managed-smtp-auth-v2/` is the active plaintext AUTH profile: AUTH is not advertised,
  all mechanism-shaped inputs return the exact 502 probe sink, the 20th failure blocks a
  later MAIL command, loopback Cringe persistence remains absent, and line/disconnect
  recovery is bounded.
- `managed-smtp-auth-starttls-v2/` is the active AUTH-over-STARTTLS profile, including the
  post-upgrade EHLO reset and absence of AUTH advertisement on both sides of TLS.
- `managed-smtp-auth-v3/` re-attests the unchanged plaintext AUTH profile after the SMTP
  command/security contract was added.
- `managed-smtp-auth-starttls-v3/` re-attests the unchanged AUTH-over-STARTTLS profile
  after the SMTP command/security contract was added.
- `managed-smtp-command-v1/` is the active command profile: utility-command state rules,
  permissive MAIL/RCPT envelope parsing, 1000-byte line framing, handler-vs-dispatcher
  error accounting, the ten-error `421` close, and fresh-connection recovery.
- `managed-smtp-command-oracle-evidence-v1/` records Java-only evidence for control-byte
  reflection and fragmented-overlong double errors. It is evidence for documented
  security differences and never a candidate expectation.
- `managed-outbound-queue-v1.json` is the rejected first outbound recording. It
  exposed generated sent-filenames before field-scoped normalization and is
  retained only as historical evidence.

## Attestation generations

The following retained historical sets are bound to the old
`attestation.harness.definition_tree_sha256`
`c736c362b0caca8562368a51cab6b1f9b0150c2c39e3c2c28f9f95a6fb6199b3`:

- `managed-basic-v15/`
- `managed-starttls-v5/`
- `managed-starttls-oracle-evidence-v5/`
- `managed-smtp-auth-v4/`
- `managed-smtp-auth-starttls-v4/`
- `managed-smtp-command-v2/`
- `managed-smtp-command-oracle-evidence-v2/`
- `managed-smtp-data-v1/`
- `managed-smtp-data-oracle-evidence-v1/`
- `managed-smtp-mime-v1/`

The current active sets are bound to
`attestation.harness.definition_tree_sha256`
`df8f7cae03892b566a36d9e77b8eb930a237af21896ac18418b06120d2d9dbae`:

- `managed-basic-v17/`
- `managed-starttls-v7/`
- `managed-starttls-oracle-evidence-v7/`
- `managed-smtp-auth-v6/`
- `managed-smtp-auth-starttls-v6/`
- `managed-smtp-command-v4/`
- `managed-smtp-command-oracle-evidence-v4/`
- `managed-smtp-data-v3/`
- `managed-smtp-data-oracle-evidence-v3/`
- `managed-smtp-mime-v3/`

The active outbound attestation is `managed-outbound-queue-v2.json`, using the
field-scoped `outbound:generated-sent-filename` normalizer. The rejected raw
`v1` recording is never used as an expectation.

The `oracle-evidence` sets remain evidence only and are never candidate
expectations.
