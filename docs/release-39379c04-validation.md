# Validation supplement for release candidate 39379c04

This supplement records results produced after packaging. It does not change
the runtime or its source commit, and does not declare production acceptance.

The release executable is from commit
`39379c04187bea3157210f2dd65d5fe1a2a8a516`, SHA-256
`9cdbddfd461daf163dbf36ae9348fd490de0e5f44be541871e16091bbd60c7c2`.
Two independent frozen clean builds were byte-identical. Installation,
upgrade, uninstall, configuration preservation and installation from the
actual runtime archive passed. The compact model Scalar/Auto SMTP/DB checks
and real Java -> Rust -> Java -> Rust ordinary-mailbox takeover passed with
this exact executable. Source archive inventory matched all 17110 tracked
paths; the history bundle and Windows copies passed their checksums.

The latest full candidate run against the same product source, using a
separately built executable, returned 117 passes and 9 failures. Seven content
filter failures were caused by `tools/pytest-release.py` supplying a global
candidate command: some profiles then selected `from_environment()` instead
of their own command templates and lost their rule overrides. The corrected
runner requires the pinned executable at the normal target path and preserves
every profile's original arguments. All seven tests passed unchanged against
the reproduced release. Both incorrect runs and the correction are retained;
no golden, assertion, filter threshold or product rule was modified to pass.

Two failures remain after excluding that proven invocation mistake:

- MTA-STS discovery observed AAAA before A where the exact test expects A
  before AAAA. Query ordering needs evidence and resolution; it is not silently
  normalized or whitelisted. An isolated unchanged rerun against the reproduced
  ELF passed; that does not erase the observed intermittent full-run failure.
- SIGTERM during stress delivery leaves a recoverable PENDING task and its
  Sent copy. The test also requires the stress mailboxes to be completely
  cleaned, so preservation alone does not pass its gate.

The full frozen-Java replay returned 105 passes and two failures (DMARC query
count and multi-domain stress PostgreSQL publication), both repeated in
isolation. The multi-domain Java log confirms Redis task admission, narrowing
the latter failure to the later archival observation. These results do not
constitute a clean full differential replay.

Other outstanding production gates remain in `acceptance-status.md`, including
formal SMTP stability and same-process recovery, complete mailbox rollback,
and native AVX-512 execution/performance. The user confirmed no AVX-512 host is
available; that gate remains open while local acceptance continues.

Post-release evidence includes:

- `evidence/build/release-reproducibility-39379c04.json`
- `evidence/build/installation-39379c04-verified.log`
- `evidence/build/package-installation-39379c04.log`
- `evidence/compatibility/release-39379c04-verified.xml`
- `evidence/compatibility/takeover-39379c04-verified.json`
- `evidence/compatibility/release-39379c04-candidate-replay.xml`
- `evidence/compatibility/release-39379c04-profile-preservation.xml`
- `evidence/compatibility/release-39379c04-mta-isolated.xml`

The runtime archive's embedded acceptance document predates these final
results. Read this supplement alongside it. Release-candidate availability
is a usable handoff for evaluation, not completion of the rewrite goal.
