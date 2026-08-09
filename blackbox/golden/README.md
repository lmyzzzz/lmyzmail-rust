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
- `managed-mail-api-poll-v1/` is the first exploratory recording for the
  mailbox polling/raw API and is retained unchanged after the active harness
  definition was re-attested.
- `managed-mail-api-poll-v2/` re-attests the same seven API scenarios under the
  frozen oracle and is retained unchanged.
- `managed-mail-api-poll-v3/` is the active mailbox polling/raw API set. It
  adds limit-zero fallback and missing-key validation for poll/raw/rawDecoded,
  and is retained unchanged after adding decoded-missing behavior.
- `managed-mail-api-poll-v4/` freezes the Java
  `500 {"error":"not found"}` response for a missing rawDecoded file and is
  retained unchanged.
- `managed-mail-api-poll-v5/` additionally freezes the full signed 64-bit
  `sinceEpochMillis` range and is retained unchanged after the complete active
  definition tree was re-attested.
- `managed-mail-api-poll-v6/` is the active mailbox polling/raw API set. It
  preserves the v5 scenarios and binds them to the complete current harness
  definition alongside the Minecraft status contract.

The mailbox polling/raw profile is intentionally kept outside
`blackbox/tests`: adding it to the attested definition roots would invalidate
all existing create-once generations before the next complete recording pass.
Run its Java and candidate verification explicitly from WSL:

```sh
PYTHONPATH=blackbox/src:blackbox/tests:blackbox/tools \
  blackbox/.venv/bin/python -m pytest blackbox/tools/test_mail_api_poll.py
```

Creating a new immutable generation requires
`LMYZMAIL_RECORD_JAVA_GOLDEN=1`; an existing generation is never overwritten.

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

The following recording pass bound the harness definition tree to
`0689ae5c8dd4af78748280da7ceea8b779e6b9f23eed8abac39a7a17bb7c0191`. It was
interrupted by a discovered Java default Tomcat port collision; the successful
create-once sets remain historical and are not active expectations:

- `managed-candidate-public-config-v20/`
- `managed-basic-v42/`
- `managed-candidate-auth-v19/`
- `managed-mail-read-v17/`
- `managed-mail-attachment-v12/`
- `managed-mail-state-v15/`
- `managed-mail-delete-v14/`
- `managed-userdata-v10/`
- `managed-userdata-oracle-evidence-v9/`
- `managed-mailbox-api-v6/`

The current active sets bind the isolated Java runtime, including its loopback
ephemeral embedded-servlet port, to definition tree
`d15cd3a2940ab76b00c74b9fab9bdee9139071158a920da5fde80040950f4143`:

- `managed-candidate-public-config-v21/`
- `managed-basic-v43/`
- `managed-candidate-auth-v20/`
- `managed-mail-read-v18/`
- `managed-mail-attachment-v13/`
- `managed-mail-state-v16/`
- `managed-mail-mutations-v15/`
- `managed-mail-delete-v15/`
- `managed-starttls-v31/`
- `managed-starttls-oracle-evidence-v31/`
- `managed-smtp-auth-v30/`
- `managed-smtp-auth-starttls-v30/`
- `managed-smtp-command-v28/`
- `managed-smtp-command-oracle-evidence-v28/`
- `managed-smtp-data-v27/`
- `managed-smtp-data-oracle-evidence-v27/`
- `managed-smtp-mime-v27/`
- `managed-outbound-http-v13/`
- `managed-outbound-queue-v28.json`
- `managed-userdata-v11/`
- `managed-userdata-oracle-evidence-v10/`
- `managed-mailbox-api-v7/`
- `managed-htcpcp-v10/`
- `managed-htcpcp-oracle-evidence-v7/`
- `managed-honeypot-v6/`
- `managed-honeypot-oracle-evidence-v6/`
- `managed-minecraft-status-v1/`

The d15... sets that are not superseded below remain active. The 0689... sets
and all earlier generations remain immutable provenance; `oracle-evidence`
remains evidence only.

Minecraft status v1 is the create-once recording from before its two bounded
lifecycle differences were added to the behavior manifest. Its v2 recording
captured the intermediate definition tree while the foundation references were
being advanced. Minecraft status v3 binds the stable foundation-only successor
definition tree; v1 through v3 remain immutable historical provenance.

The foundation HTTP, SMTP, and authentication sets were re-attested after the
Minecraft safety definitions were added, under definition tree
`41f2866c3d4adec2d48e319e1a946a6d9aa4c7d332c110cdb6338bd8db2cc9d6`:

- `managed-candidate-public-config-v22/`
- `managed-basic-v44/`
- `managed-candidate-auth-v21/`
- `managed-minecraft-status-v3/`

The preceding d15... foundation generations remain immutable history.

The complete active recording pass binds every referenced oracle suite to
`attestation.harness.definition_tree_sha256`
`76fcf2c2e2afc79ceeca0320470d47da3ab6d3ff54320b62e7f9a67b10a990c1`:

- `managed-candidate-public-config-v23/`
- `managed-basic-v45/`
- `managed-candidate-auth-v22/`
- `managed-mail-read-v19/`
- `managed-mail-attachment-v14/`
- `managed-mail-state-v17/`
- `managed-mail-mutations-v16/`
- `managed-mail-delete-v16/`
- `managed-mailbox-api-v8/`
- `managed-starttls-v32/`
- `managed-starttls-oracle-evidence-v32/`
- `managed-smtp-auth-v31/`
- `managed-smtp-auth-starttls-v31/`
- `managed-smtp-command-v29/`
- `managed-smtp-command-oracle-evidence-v29/`
- `managed-smtp-data-v28/`
- `managed-smtp-data-oracle-evidence-v28/`
- `managed-smtp-mime-v28/`
- `managed-outbound-http-v14/`
- `managed-outbound-queue-v29.json`
- `managed-userdata-v12/`
- `managed-userdata-oracle-evidence-v11/`
- `managed-htcpcp-v11/`
- `managed-htcpcp-oracle-evidence-v8/`
- `managed-honeypot-v7/`
- `managed-honeypot-oracle-evidence-v7/`
- `managed-minecraft-status-v4/`
- `managed-minecraft-status-config-v1/`
- `managed-mail-api-poll-v6/`

Minecraft status v4 is the active default status/framing expectation. The
separate status-config v1 generation freezes custom max-player, MOTD, favicon
trimming, and exact response bytes. Mail API poll v6 remains an explicitly run
tool profile, while every other non-evidence generation above is consumed by
the regular blackbox tests. All earlier generations remain create-once history.

The Minecraft offline-login milestone adds strict compression-envelope evidence
and advances every referenced suite to definition tree
`f1084837b01f3fe2a57b90e216fd6ba13f65f7dc93214d01f00a39352c5f4b35`:

- `managed-candidate-public-config-v24/`
- `managed-basic-v46/`
- `managed-candidate-auth-v23/`
- `managed-mail-read-v20/`
- `managed-mail-attachment-v15/`
- `managed-mail-state-v18/`
- `managed-mail-mutations-v17/`
- `managed-mail-delete-v17/`
- `managed-mailbox-api-v9/`
- `managed-starttls-v33/`
- `managed-starttls-oracle-evidence-v33/`
- `managed-smtp-auth-v32/`
- `managed-smtp-auth-starttls-v32/`
- `managed-smtp-command-v30/`
- `managed-smtp-command-oracle-evidence-v30/`
- `managed-smtp-data-v29/`
- `managed-smtp-data-oracle-evidence-v29/`
- `managed-smtp-mime-v29/`
- `managed-outbound-http-v15/`
- `managed-outbound-queue-v30.json`
- `managed-userdata-v13/`
- `managed-userdata-oracle-evidence-v12/`
- `managed-htcpcp-v12/`
- `managed-htcpcp-oracle-evidence-v9/`
- `managed-honeypot-v8/`
- `managed-honeypot-oracle-evidence-v8/`
- `managed-minecraft-status-v5/`
- `managed-minecraft-status-config-v2/`
- `managed-minecraft-login-v2/`
- `managed-minecraft-login-admission-v2/`
- `managed-mail-api-poll-v7/`

Minecraft login v2 freezes offline UUID derivation, Set Compression ordering,
Login Success, the first seven PLAY packets, UTF-8 replacement behavior,
unknown-packet handling, and malformed/compression rejection boundaries. The
separate login-admission v2 suite freezes case-insensitive blacklist priority,
whitelist rejection, and exact disconnect bytes. Minecraft v1 login recordings
and the complete `76fc...` generation remain immutable historical provenance;
the `f108...` generations above form the next immutable provenance generation.

The reviewed offline-login generation advances all active references to
definition tree
`4527bafacf7d0e8887a82e842218082735aa650698302282878f235e68d401c2`:

- `managed-candidate-public-config-v25/`
- `managed-basic-v47/`
- `managed-candidate-auth-v24/`
- `managed-mail-read-v21/`
- `managed-mail-attachment-v16/`
- `managed-mail-state-v19/`
- `managed-mail-mutations-v18/`
- `managed-mail-delete-v18/`
- `managed-mailbox-api-v10/`
- `managed-starttls-v35/`
- `managed-starttls-oracle-evidence-v35/`
- `managed-smtp-auth-v34/`
- `managed-smtp-auth-starttls-v34/`
- `managed-smtp-command-v32/`
- `managed-smtp-command-oracle-evidence-v32/`
- `managed-smtp-data-v31/`
- `managed-smtp-data-oracle-evidence-v31/`
- `managed-smtp-mime-v31/`
- `managed-outbound-http-v18/`
- `managed-outbound-queue-v31.json`
- `managed-userdata-v14/`
- `managed-userdata-oracle-evidence-v13/`
- `managed-htcpcp-v13/`
- `managed-htcpcp-oracle-evidence-v10/`
- `managed-honeypot-v9/`
- `managed-honeypot-oracle-evidence-v9/`
- `managed-minecraft-status-v6/`
- `managed-minecraft-status-config-v3/`
- `managed-minecraft-login-v3/`
- `managed-minecraft-login-admission-v3/`
- `managed-mail-api-poll-v8/`

Minecraft login v3 adds frozen JDK malformed-sequence replacement for a UTF-8
surrogate encoding, legacy spawn-coordinate wire behavior, and Unicode
`String.equalsIgnoreCase` admission evidence. The candidate also preserves the
oracle's one-entry-per-UUID online count while generation-fencing disconnect
cleanup so an old duplicate session cannot erase the current session. These
`4527bafa...` generations are the active references; every earlier generation
remains create-once history.

The bounded Minecraft world milestone records the frozen mailroom bootstrap at
definition tree
`538e2e8f9e547e91001efc02b99582de1d0111943b3ea13953443fca3189d318`:

- `managed-minecraft-login-v4/`
- `managed-minecraft-world-v1/`

The world golden contains 3,209 Chunk Data packets, five Update Tile Entity
packets, and Player Position And Look. Its aggregate expanded payload is
356,583,182 bytes and its ordered chunk digest is
`e9a89a4afae34f9ac9ca80fa8abdce2d7fa14f5acf1c62bda7ac464bbd10d90e`.
No world fields are normalized. Login v4 is a byte-identical re-attestation of
the v3 observations under the same definition tree.

The static PLAY bootstrap milestone adds:

- `managed-minecraft-static-play-v1/`

It captures, without normalization, the complete wire frames after Player
Position And Look: Player List Item, header/footer, three Title packets, four
Chat packets, and the Book & Quill plus menu Nether Star SetSlot packets. This
freezes UUID bytes, chat JSON, title timing, item metadata, NBT field order, and
compression-envelope behavior against the same frozen Java oracle.

The post-static Minecraft bootstrap milestone adds:

- `managed-minecraft-post-static-v1/`

It freezes the next 20 uncompressed PLAY frames without normalization: four
empty-draft sign updates, sidebar objective/display initialization, and seven
default hologram armor stands with their separate custom-name metadata. The
evidence preserves block positions, JSON text, objective fields, entity IDs,
Java floating-point coordinate truncation, entity flags, and metadata order.

The scheduled Minecraft PLAY milestone adds three zero-normalization sets under
the same `538e2e8f9e547e91001efc02b99582de1d0111943b3ea13953443fca3189d318`
definition tree:

- `managed-minecraft-scheduled-play-v1/`
- `managed-minecraft-time-update-v1/`
- `managed-minecraft-position-rebound-v1/`

Scheduled PLAY v1 freezes the first two-second anti-gravity tick as seven exact
Entity Teleport frames. Time-update v1 observes seven such ticks followed by the
15-second scheduler packet and preserves the oracle oddity that the task sends
`Time Update(0, -6000)`, not a Keep Alive packet. Position-rebound v1 sends a
compressed-envelope Player Position more than 100 blocks from spawn and freezes
the response order: Player Position And Look, red Chat, then the seven hologram
teleports. It also proves that both implementations require the trailing
`onGround` byte. All three sets preserve exact packet bytes, compression-envelope
behavior, entity IDs, coordinates, and Java floating-point truncation.

The Minecraft email-authentication entry milestone adds:

- `managed-minecraft-email-prompt-v1/`

It freezes the zero-normalization `AwaitingEmail` chat flow: an address without
`@` receives one red error, while an ASCII-padded valid address is trimmed and
receives the exact email echo, password prompt, and password-visibility warning.
The suite also binds the C2S Chat limit to 100 UTF-16 code units and preserves
Java `String.trim()` semantics rather than broader Unicode whitespace trimming.

The Minecraft password-authentication milestone adds:

- `managed-minecraft-password-auth-v1/`

It freezes the zero-normalization `AwaitingPassword` flow for a wrong password
and a fresh-connection successful password. The failure path preserves the
exact remaining-attempt message and prompt. The success path preserves the
eleven instruction chats, four empty-draft sign updates, book item, and
sidebar scoreboard/objective packets byte-for-byte.

The basic authenticated-command milestone adds:

- `managed-minecraft-authenticated-commands-v1/`

It preserves Java ASCII trim and case-insensitive command dispatch, the eight
`/help` instruction chats, `/stuck` teleport and acknowledgement, `/skibidi`,
the three no-argument `/video` usage messages, and the unknown-command error.
All 15 response frames are frozen without normalization.

The initial draft-command milestone adds:

- `managed-minecraft-draft-commands-v1/`

It freezes empty `/draft`, `/clear`, and the cleared `/draft` state without
normalization. The clear response includes the exact confirmation chat, four
empty Update Sign packets, and refreshed empty Book & Quill SetSlot packet.

The Minecraft main-menu opening milestone adds:

- `managed-minecraft-main-menu-v1/`

It freezes the first `/menu` Open Window and complete 90-slot Window Items
frames without normalization. The latter expands to 2,771 bytes and fixes the
54 chest slots, 36 player slots, every item/NBT field, the initial window ID,
and the exact JDK Deflater-compatible zlib wire bytes.

The Minecraft main-menu lifecycle milestone adds:

- `managed-minecraft-main-menu-lifecycle-v1/`

It freezes a filler-slot Click Window with its action number and empty clicked
slot, the rejected Confirm Transaction, cursor clear, full compressed menu
refresh, and the two Set Slot packets emitted when the client closes the
window. All five response frames are preserved without normalization.

The synchronous Minecraft main-menu action milestone adds:

- `managed-minecraft-main-menu-actions-v1/`

It freezes Help, Close Menu, and Switch Account clicks across window IDs 1, 2,
and 3. The golden preserves each rejected transaction and compressed refresh,
server close, hotbar restoration, all six Help messages, the new-email prompt,
and the post-switch return to the email-authentication state without
normalization.

The Minecraft logout confirmation milestone adds:

- `managed-minecraft-logout-confirmation-v1/`

It freezes opening the three-row confirmation GUI, cancelling back to a newly
allocated main-menu window, reopening confirmation, and the common confirmed
logout prefix. The frozen Java write/close race is normalized only for that
terminal prefix; the candidate must instead flush the exact Disconnect Play
frame and then reach EOF under the approved
`minecraft-logout-flush-before-close` difference.

The Minecraft render-settings milestone adds:

- `managed-minecraft-render-settings-v1/`

It freezes slot 22 across six menu windows, the exact Update Tile Entity and
Sign Editor Open wire, all four instruction chats, and five Update Sign cases:
valid upper bounds, invalid width, invalid height, invalid font, and non-integer
width. Reopened menu frames prove per-session state and the oracle's partial
font-validation commit. An overlong sign field must close the connection
without a business response. Only independently frozen periodic `0x03` time and
`0x18` hologram ticks may be excluded when they interleave; every render packet
and state-bearing frame remains byte exact.

The Minecraft render-size command milestone adds:

- `managed-minecraft-render-size-commands-v1/`

It freezes `/mail rendersize` and its `rs` alias for direct upper-bound updates,
invalid width and height, a silently retained prior font, non-integer usage,
and the parameterless sign-editor path. The final sign submission and reopened
menu prove that both public entry points share one connection-local state.
Periodic `0x03` and `0x18` packets use the same narrow scheduled-play exclusion;
all command, scoreboard, sign, and menu packets remain byte exact.

The Minecraft folder GUI milestone adds:

- `managed-minecraft-folder-gui-v1/`

It freezes isolated PostgreSQL-backed Inbox, Sent, Trash, and Spam lists with
37/36 pagination, an attachment glow, null subject/from rendering, Java
UTF-16 truncation at the NBT boundary, same-window previous/next refresh, and
return-to-menu window allocation. Only periodic `0x03` and `0x18` PLAY ticks
are excluded while a bounded database load completes; all folder, navigation,
slot, and hotbar frames remain byte exact.

The first report-management API recording adds the retained historical set:

- `managed-reports-v48/`

It binds five raw-socket scenarios to definition tree
`fddabe9ab83120f7ad395ec3c4a4777bf2416d3fc1f939a7b6b9a8ff2c0f5416`:
reporting status, inclusive minimum-volume domain selection from both legacy
report tables, all three invalid-date surfaces, a no-data global trigger, and
a no-data single-domain trigger. Java `Map.of` response objects are compared
after recursive key canonicalization; arrays, values, status, headers, and
compact body lengths remain exact. The recording also proves temporary volume
changes are restored and no-data generation leaves report row counts and core
fields unchanged. A second independently initialized Java workspace replayed
the create-once generation immediately after recording. The set was superseded
when the new profile's generation reference was corrected to the conventional
`v1` name; the attestation correctly rejected reuse after that source change,
so the immutable `v48` envelope remains provenance rather than being rewritten.

The first conventional report-management API set is retained as:

- `managed-reports-v1/`

It preserves the same five strict scenarios under the final conventional
generation reference and binds definition tree
`2ac6c9877c5e3de758e293633e4130ed8eae36c7f4f4730b2dfa828bed614974`.
Recording and immediate verification used two separately initialized Java,
PostgreSQL, Redis, and Maildir workspaces.

The deterministic DNS extension retained three subsequent create-once
generations without rewriting them:

- `managed-reports-v2/` contains the suite and the original five observations,
  but the first scripted DNS fixture rejected dnsjava's EDNS additional record
  before the address observation could be written.
- `managed-reports-v3/` also stops before the address observation; it captured
  the oracle's deterministic second NXDOMAIN attempt and was not weakened or
  overwritten.
- `managed-reports-v4/` is complete, but adding the independent scripted DNS
  unit tests changed the attested definition tree, so it remains immutable
  historical provenance.

The active report-management API set is:

- `managed-reports-v5/`

It binds definition tree
`3e27020a525dac35658bf96da956de1ea83371b1aac2f2800379a25acff9f867`
and adds `GET /api/reports/addresses/{domain}` under an isolated UDP DNS
fixture. The observation freezes TXT chunk joining, exact first version tags,
multiple-policy rejection, mailto/HTTPS deduplication, external DMARC
authorization, one authorization query per destination domain, the combined
10-address limit, and dnsjava's two NXDOMAIN attempts. Recording and immediate
verification used two separate Java, PostgreSQL, Redis, Maildir, and DNS
workspaces; a third fresh workspace replayed the generation independently.

The post-recording Rust candidate driver remains in `blackbox/tools` so it does
not invalidate create-once generations. Advance it to the active generation
only after the matching Rust behavior exists.
