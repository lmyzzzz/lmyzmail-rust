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

The following retained historical sets are bound to
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

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`bcd157754e50c30e6d5273df5974e25944cedaf23fb849397bc6d823faad43a4`:

- `managed-basic-v18/`
- `managed-starttls-v8/`
- `managed-starttls-oracle-evidence-v8/`
- `managed-smtp-auth-v7/`
- `managed-smtp-auth-starttls-v7/`
- `managed-smtp-command-v5/`
- `managed-smtp-command-oracle-evidence-v5/`
- `managed-smtp-data-v4/`
- `managed-smtp-data-oracle-evidence-v4/`
- `managed-smtp-mime-v4/`

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`c70d3add99029320171cd4a5f933f2cdfd667881cbc29748de21f55449f50ecc`:

- `managed-basic-v20/`
- `managed-starttls-v10/`
- `managed-starttls-oracle-evidence-v10/`
- `managed-smtp-auth-v9/`
- `managed-smtp-auth-starttls-v9/`
- `managed-smtp-command-v7/`
- `managed-smtp-command-oracle-evidence-v7/`
- `managed-smtp-data-v6/`
- `managed-smtp-data-oracle-evidence-v6/`
- `managed-smtp-mime-v6/`

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`932a01a5dfb7199c63a9f40979e36fb7c27c4b0020f291a9e2321e5e59899f48`:

- `managed-basic-v21/`
- `managed-starttls-v11/`
- `managed-starttls-oracle-evidence-v11/`
- `managed-smtp-auth-v10/`
- `managed-smtp-auth-starttls-v10/`
- `managed-smtp-command-v8/`
- `managed-smtp-command-oracle-evidence-v8/`
- `managed-smtp-data-v7/`
- `managed-smtp-data-oracle-evidence-v7/`
- `managed-smtp-mime-v7/`

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`734ba1889bc691971e9c4ff052580ad7edc5310cab7ebb60579d4a74b33752d9`:

- `managed-basic-v22/`
- `managed-starttls-v12/`
- `managed-starttls-oracle-evidence-v12/`
- `managed-smtp-auth-v11/`
- `managed-smtp-auth-starttls-v11/`
- `managed-smtp-command-v9/`
- `managed-smtp-command-oracle-evidence-v9/`
- `managed-smtp-data-v8/`
- `managed-smtp-data-oracle-evidence-v8/`
- `managed-smtp-mime-v8/`

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`aeef79516587832136169c710c59d5992f8d0f6a7993e66c88b9ad027f292810`:

- `managed-candidate-public-config-v4/`
- `managed-basic-v26/`
- `managed-candidate-auth-v3/`
- `managed-starttls-v14/`
- `managed-starttls-oracle-evidence-v14/`
- `managed-smtp-auth-v13/`
- `managed-smtp-auth-starttls-v13/`
- `managed-smtp-command-v11/`
- `managed-smtp-command-oracle-evidence-v11/`
- `managed-smtp-data-v10/`
- `managed-smtp-data-oracle-evidence-v10/`
- `managed-smtp-mime-v10/`

The following retained mail-read recording is bound to
`attestation.harness.definition_tree_sha256`
`6e4ea8542bbc43fd4eab7d1833c8a37eb888b7b4afb5fb443ab891890478507f`:

- `managed-mail-read-v1/`

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`2dfe8ac1f80acb8a0088fc6ef40a4883cbe58818409c7f2bc7d6271567913dba`:

- `managed-candidate-public-config-v5/`
- `managed-basic-v27/`
- `managed-candidate-auth-v4/`
- `managed-mail-read-v2/`
- `managed-starttls-v15/`
- `managed-starttls-oracle-evidence-v15/`
- `managed-smtp-auth-v14/`
- `managed-smtp-auth-starttls-v14/`
- `managed-smtp-command-v12/`
- `managed-smtp-command-oracle-evidence-v12/`
- `managed-smtp-data-v11/`
- `managed-smtp-data-oracle-evidence-v11/`
- `managed-smtp-mime-v11/`

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`7613d070973c6ca423156f2fdce69a8dc34fb0cd076a2b2e71067cefebd4aecf`:

- `managed-candidate-public-config-v6/`
- `managed-basic-v28/`
- `managed-candidate-auth-v5/`
- `managed-mail-read-v3/`
- `managed-mail-state-v1/`
- `managed-starttls-v16/`
- `managed-starttls-oracle-evidence-v16/`
- `managed-smtp-auth-v15/`
- `managed-smtp-auth-starttls-v15/`
- `managed-smtp-command-v13/`
- `managed-smtp-command-oracle-evidence-v13/`
- `managed-smtp-data-v12/`
- `managed-smtp-data-oracle-evidence-v12/`
- `managed-smtp-mime-v12/`

Later create-once generations through the pre-outbound HTTP milestone remain
under `blackbox/golden/java/` with their exact attestation envelopes. They are
historical and are not consumed by the current tests.

The first outbound HTTP recording under definition-tree hash
`d427c2c16e71da43b28bf3403b7325a3e9b2ad8109ce14a372e1ee037b7c5f23`
is retained as evidence that the frozen Java quota response uses nondeterministic
`Map.of` wire ordering. Its generations are `managed-basic-v33`,
`managed-candidate-public-config-v11`, `managed-candidate-auth-v10`,
`managed-mail-read-v8`, `managed-mail-attachment-v3`, `managed-mail-state-v6`,
`managed-mail-mutations-v5`, `managed-mail-delete-v5`, `managed-starttls-v21`,
`managed-starttls-oracle-evidence-v21`, `managed-smtp-auth-v20`,
`managed-smtp-auth-starttls-v20`, `managed-smtp-command-v18`,
`managed-smtp-command-oracle-evidence-v18`, `managed-smtp-data-v17`,
`managed-smtp-data-oracle-evidence-v17`, `managed-smtp-mime-v17`,
`managed-outbound-http-v1`, and `managed-outbound-queue-v17.json`.

The second recording under definition-tree hash
`2a9e5d77a5452f2ac86dda28808b08a487677c2018d280e9033172af864b8efa`
canonicalized the standalone quota scenario but proved that the quota response
captured after API admission has the same Java-only ordering instability. Its
corresponding generations advance the sets above by one: `managed-basic-v34`,
`managed-candidate-public-config-v12`, `managed-candidate-auth-v11`,
`managed-mail-read-v9`, `managed-mail-attachment-v4`, `managed-mail-state-v7`,
`managed-mail-mutations-v6`, `managed-mail-delete-v6`, `managed-starttls-v22`,
`managed-starttls-oracle-evidence-v22`, `managed-smtp-auth-v21`,
`managed-smtp-auth-starttls-v21`, `managed-smtp-command-v19`,
`managed-smtp-command-oracle-evidence-v19`, `managed-smtp-data-v18`,
`managed-smtp-data-oracle-evidence-v18`, `managed-smtp-mime-v18`,
`managed-outbound-http-v2`, and `managed-outbound-queue-v18.json`.

The following retained historical sets are bound to
`attestation.harness.definition_tree_sha256`
`44c18bbec88ceec3d34b71bfbe62e34852f18aaec204248e6cc27cce24d16844`:

- `managed-candidate-public-config-v13/`
- `managed-basic-v35/`
- `managed-candidate-auth-v12/`
- `managed-mail-read-v10/`
- `managed-mail-attachment-v5/`
- `managed-mail-state-v8/`
- `managed-mail-mutations-v7/`
- `managed-mail-delete-v7/`
- `managed-starttls-v23/`
- `managed-starttls-oracle-evidence-v23/`
- `managed-smtp-auth-v22/`
- `managed-smtp-auth-starttls-v22/`
- `managed-smtp-command-v20/`
- `managed-smtp-command-oracle-evidence-v20/`
- `managed-smtp-data-v19/`
- `managed-smtp-data-oracle-evidence-v19/`
- `managed-smtp-mime-v19/`
- `managed-outbound-http-v3/`
- `managed-outbound-queue-v19.json`

The preceding active sets were bound to
`attestation.harness.definition_tree_sha256`
`65da9f3ce4f1a51b77fff6732deb36ffb0bb086aa49ac4f6f06e47d7ad732ebb`:

- `managed-candidate-public-config-v14/`
- `managed-basic-v36/`
- `managed-candidate-auth-v13/`
- `managed-mail-read-v11/`
- `managed-mail-attachment-v6/`
- `managed-mail-state-v9/`
- `managed-mail-mutations-v8/`
- `managed-mail-delete-v8/`
- `managed-starttls-v24/`
- `managed-starttls-oracle-evidence-v24/`
- `managed-smtp-auth-v23/`
- `managed-smtp-auth-starttls-v23/`
- `managed-smtp-command-v21/`
- `managed-smtp-command-oracle-evidence-v21/`
- `managed-smtp-data-v20/`
- `managed-smtp-data-oracle-evidence-v20/`
- `managed-smtp-mime-v20/`
- `managed-outbound-http-v5/`
- `managed-outbound-http-v6/`
- `managed-outbound-queue-v21.json`

The preceding active sets were bound to
`attestation.harness.definition_tree_sha256`
`40b6e82187bceeb93d3f61dd6ddeeff72ce411ce5eaac8c11693bee94fd3ee4c`:

- `managed-candidate-public-config-v15/`
- `managed-basic-v37/`
- `managed-candidate-auth-v14/`
- `managed-mail-read-v12/`
- `managed-mail-attachment-v7/`
- `managed-mail-state-v10/`
- `managed-mail-mutations-v9/`
- `managed-mail-delete-v9/`
- `managed-starttls-v25/`
- `managed-starttls-oracle-evidence-v25/`
- `managed-smtp-auth-v24/`
- `managed-smtp-auth-starttls-v24/`
- `managed-smtp-command-v22/`
- `managed-smtp-command-oracle-evidence-v22/`
- `managed-smtp-data-v21/`
- `managed-smtp-data-oracle-evidence-v21/`
- `managed-smtp-mime-v21/`
- `managed-outbound-http-v7/`
- `managed-outbound-queue-v22.json`
- `managed-userdata-v5/`
- `managed-userdata-oracle-evidence-v4/`

The preceding active sets were bound to
`attestation.harness.definition_tree_sha256`
`44a194fc8f84ef63c19d5c75f6896f6f1227ec220e0841f142fc5434f0c7be54`:

- `managed-candidate-public-config-v16/`
- `managed-basic-v38/`
- `managed-candidate-auth-v15/`
- `managed-mail-read-v13/`
- `managed-mail-attachment-v8/`
- `managed-mail-state-v11/`
- `managed-mail-mutations-v10/`
- `managed-mail-delete-v10/`
- `managed-starttls-v26/`
- `managed-starttls-oracle-evidence-v26/`
- `managed-smtp-auth-v25/`
- `managed-smtp-auth-starttls-v25/`
- `managed-smtp-command-v23/`
- `managed-smtp-command-oracle-evidence-v23/`
- `managed-smtp-data-v22/`
- `managed-smtp-data-oracle-evidence-v22/`
- `managed-smtp-mime-v22/`
- `managed-outbound-http-v8/`
- `managed-outbound-queue-v23.json`
- `managed-userdata-v6/`
- `managed-userdata-oracle-evidence-v5/`
- `managed-mailbox-api-v2/`

The first interrupted HTCPCP recording pass is complete but superseded. These
sets bind definition hash
`44689ba264c6f0eb8eca7b62ab07d2090742c831fc734b9ba885cfc9411a9097` and
remain create-once history:

- `managed-candidate-public-config-v17/`
- `managed-basic-v39/`
- `managed-candidate-auth-v16/`
- `managed-mail-read-v14/`
- `managed-mail-attachment-v9/`
- `managed-mail-state-v12/`
- `managed-mail-mutations-v11/`
- `managed-mail-delete-v11/`
- `managed-starttls-v27/`
- `managed-starttls-oracle-evidence-v27/`
- `managed-smtp-auth-v26/`

The later interrupted pass binds definition hash
`ed6e12b5ee5a5e439b57e3bec0055830d0fa6833be4a5d463ef04a0998427638`.
It is also retained and never overwritten:

- `managed-smtp-auth-starttls-v26/`
- `managed-smtp-command-v24/`
- `managed-smtp-command-oracle-evidence-v24/`
- `managed-smtp-data-v23/`
- `managed-smtp-data-oracle-evidence-v23/`
- `managed-smtp-mime-v23/`
- `managed-outbound-http-v9/`
- `managed-outbound-queue-v24.json`
- `managed-userdata-v7/`
- `managed-userdata-oracle-evidence-v6/`
- `managed-mailbox-api-v3/`
- `managed-htcpcp-v6/`
- `managed-htcpcp-oracle-evidence-v3/`

The preceding complete sets bind
`attestation.harness.definition_tree_sha256`
`c31293c84c74c9ec7a57b3321735e996cf21dca376bff5c6f142fbd89d421b5b`:

- `managed-candidate-public-config-v18/`
- `managed-basic-v40/`
- `managed-candidate-auth-v17/`
- `managed-mail-read-v15/`
- `managed-mail-attachment-v10/`
- `managed-mail-state-v13/`
- `managed-mail-mutations-v12/`
- `managed-mail-delete-v12/`
- `managed-starttls-v28/`
- `managed-starttls-oracle-evidence-v28/`
- `managed-smtp-auth-v27/`
- `managed-smtp-auth-starttls-v27/`
- `managed-smtp-command-v25/`
- `managed-smtp-command-oracle-evidence-v25/`
- `managed-smtp-data-v24/`
- `managed-smtp-data-oracle-evidence-v24/`
- `managed-smtp-mime-v24/`
- `managed-outbound-http-v10/`
- `managed-outbound-queue-v25.json`
- `managed-userdata-v8/`
- `managed-userdata-oracle-evidence-v7/`
- `managed-mailbox-api-v4/`
- `managed-htcpcp-v7/`
- `managed-htcpcp-oracle-evidence-v4/`

The current active sets re-attest the frozen oracle after the authentication
COMMIT-response-loss reconciliation contract was strengthened. They bind
`attestation.harness.definition_tree_sha256`
`e2cf9e0c7f524c2b365659ea867ba7971b2ca23edc0aa3264037332be7522336`:

- `managed-candidate-public-config-v19/`
- `managed-basic-v41/`
- `managed-candidate-auth-v18/`
- `managed-mail-read-v16/`
- `managed-mail-attachment-v11/`
- `managed-mail-state-v14/`
- `managed-mail-mutations-v13/`
- `managed-mail-delete-v13/`
- `managed-starttls-v29/`
- `managed-starttls-oracle-evidence-v29/`
- `managed-smtp-auth-v28/`
- `managed-smtp-auth-starttls-v28/`
- `managed-smtp-command-v26/`
- `managed-smtp-command-oracle-evidence-v26/`
- `managed-smtp-data-v25/`
- `managed-smtp-data-oracle-evidence-v25/`
- `managed-smtp-mime-v25/`
- `managed-outbound-http-v11/`
- `managed-outbound-queue-v26.json`
- `managed-userdata-v9/`
- `managed-userdata-oracle-evidence-v8/`
- `managed-mailbox-api-v5/`
- `managed-htcpcp-v8/`
- `managed-htcpcp-oracle-evidence-v5/`

HTCPCP v1-v5 and oracle-evidence v1-v2 are earlier create-once generations,
each bound to its own historical definition hash. HTCPCP v6 and evidence v3
belong to the superseded `ed6e12...` pass above. HTCPCP v7 and evidence v4 bind
the preceding complete `c31293...` pass. Only HTCPCP v8 is an active candidate
expectation; evidence v5 records Java-only defects and is never compared to the
candidate.

The earlier candidate-health v1-v4, candidate-public-http v1,
candidate-api-status v1, candidate-public-config v1-v3, candidate-auth v1-v2,
HTTP v19-v25, SMTP v5-v12, outbound v5-v9, userdata v1-v7, userdata evidence
v1-v6, and mailbox API v1-v3 recordings remain create-once provenance. None is
consumed by the active tests.

The active outbound queue attestation is `managed-outbound-queue-v26.json`,
using the field-scoped `outbound:generated-sent-filename` normalizer. The active
outbound HTTP attestation is `managed-outbound-http-v11`; only its two quota
subresponses canonicalize Java `Map.of` object ordering. Status codes, headers,
field values, and every other response retain exact wire assertions. Rejected or
superseded outbound generations remain historical evidence and are never
candidate expectations.

All `oracle-evidence` sets remain evidence only and are never candidate
expectations.
