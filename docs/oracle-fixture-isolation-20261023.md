# Isolating the two retained Java replay failures

The historical golden files and business assertions are unchanged. The frozen
Java sources and JAR are unchanged. The exact retained `bf6c0d53` release ELF
passed all four affected Java/candidate tests after these fixture corrections.
The campaign audit compared six observations/artifacts with their historical
counterparts, found no differences, and retained all 6,897 original files.

## DMARC reverse lookup

The TXT fixture was local, but `InetAddress.getCanonicalHostName()` still used
the host's separate name service for unassigned loopback sender addresses.
In `oracle-dmarc-diagnostic-20261023-v2/java-application.log`, the SPF and DMARC
TXT responses finish around `16:22:24.323Z`. Java's aggregate DNS future times
out at `16:22:29.270Z`, discards the completed SPF value, and sends another SPF
query. This explains why the failing edge case moved between repeated runs.

Only the DMARC Java fixture now supplies `jdk.net.hosts.file` with a private
hosts file containing `127.0.0.1 localhost`. Unassigned sender loopback
addresses fail reverse lookup locally. dnsjava continues using the scripted
TXT server, and the original unverified `Received` bytes remain unchanged.
An instrumented replay with this isolation passed against the previous
campaign before any harness definition changed. The actual corrected fixture
then passed create-once re-attestation and paired replay.

## Multi-domain Write-Behind archive

The Java scheduler starts with a five-second initial delay. The fixture set a
60-second poll interval while requiring a PostgreSQL archive row within 20
seconds. Redis admission does not immediately create that row: the persister
archives terminal tasks. A direct capture that caught the first scheduler tick
published in about 4.4 seconds. Deliberately starting after that tick reproduced
the original 20-second failure; the row appeared about 63 seconds after stress
start, without changing the message or database.

Both implementations now use a one-second active poll interval in this
specific multi-domain fixture. The original 20-second deadline, HTTP result,
sender/recipient values, PostgreSQL assertion and golden bytes are unchanged.
This fixture verifies domain selection and archival, not disabled scheduling.

## Evidence

All paths below are relative to `evidence/compatibility/`:

- `oracle-dmarc-unchanged-20261023-v1.{log,xml}` retains the unmodified failure.
- `oracle-dmarc-diagnostic-20261023-v2/` retains timestamped DNS observations
  and Java logs proving the aggregate timeout and second SPF request.
- `oracle-dmarc-local-hosts-20261023-v1/` retains the passing isolated replay
  with the old harness definition and all exact historical assertions.
- `oracle-multi-domain-diagnostic-20261023-v1/observations.json` records the
  first-tick success; `...-v2/observations.json` records the delayed failure,
  pending Redis task and later PostgreSQL terminal archive.
- `oracle-fixture-isolation-20261023-create-v2.{log,xml}` and
  `oracle-fixture-isolation-20261023-replay-v1.{log,xml}` record re-attestation
  and the four passing Java/candidate tests. The initial create command omitted
  the DMARC test's explicit recording flag; its missing-golden failure is kept
  in `oracle-fixture-isolation-20261023-create.{log,xml}`.

The diagnostic utility is `tools/diagnose_oracle_replay.py`. It neither edits
goldens nor patches the JAR. A full fresh oracle campaign is required in
addition to these focused checks; focused success alone does not close the
whole differential gate.
