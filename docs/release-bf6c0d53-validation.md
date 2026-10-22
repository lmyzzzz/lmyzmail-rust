# Validation supplement for release candidate bf6c0d53

The Windows delivery directory is
`D:\MiscProjects\lmyzmail-rust\releases\20261022-rc.bf6c0d53`.
Its runtime archive, complete tracked source archive and all-branch history
bundle identify source commit `bf6c0d53e3184fdae5e36793fe9a44dfd0529c3d`.
The source archive inventory matches all 17,152 tracked paths. All four
published checksums passed again after copying to Windows.

The retained release ELF SHA-256 is
`3b60ca5856f23abff1985bb7435b5bda8527c646885ddeb422cbd22cb906a536`.
Two clean frozen builds in independent Cargo target directories within the
same clean source checkout produced identical bytes and ELF Build IDs.
This verifies the recorded build layout; it does not establish byte identity
across different source checkout paths. The development-checkout build has
a different hash and its earlier tests are recorded separately.

The release has no unresolved dynamic dependencies or Java/JVM imports.
Installation, upgrade, configuration preservation and uninstall passed against
the retained ELF. Installation and uninstall from the actual unpacked runtime
archive also passed, with the installed ELF matching the retained one.
The compact-model Scalar/Auto SMTP/DB checks and ordinary-address same-state
Java/Rust/Java/Rust takeover passed against this exact retained ELF.

The included compact model is the final checkpoint from thread
`01a16323-de1d-7a11-976d-8e2ff3322839`, SHA-256
`4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428`.
Its tokenizer SHA-256 is
`6624adb41b9274bf0cc73c62ebd26eb2bcf281d533f30607ba415105917d81f3`.

All 959 Rust tests and strict Clippy passed for this product source.
The development ELF passed 88 candidate-marked checks and 178 disjoint
unmarked non-oracle checks in `blackbox/tests`, plus 44 checks in
`blackbox/tools`. An incorrectly launched RBL check failed before executing
the product assertion; its required namespace runner subsequently passed
against the retained ELF, without assertion or golden changes.
The retained ELF subsequently passed all 310 non-oracle checks in both
`blackbox/tests` and `blackbox/tools`, with RBL executed separately through its
required runner and also passing. The main replay lasted 903.29 seconds.
There were no assertion or golden changes. Both audits confirmed all 6,897
historical golden files unchanged and all 346 campaign observations/artifacts
equal to their historical counterparts. The retained and staged ELF hashes
were identical before and after the complete replay.

Earlier negative evidence remains available. The frozen-Java replay has
unresolved DMARC TXT-query-count and multi-domain stress archival observations.
An intermittent A/AAAA request-order failure also remains recorded; a
successful later run does not prove that the ordering race is eliminated.
Formal 250,000-message SMTP stability, same-process 100,000-message recovery,
the disk-budgeted 10 MiB tier, complete ambiguous-mailbox takeover/rollback,
and native AVX-512 execution/performance remain open acceptance gates.
No AVX-512 host is available; the user authorized continuing local validation.
This package is a usable release candidate, not a completed production goal.

Build/export mistakes are retained as negative evidence: an earlier log-wrapper
exit-code error was followed by a clean successful Rust run, and the first
two-build attempt failed to export its ELF because the requested output parent
directory was absent. Only the second complete build/export run supplies this
package's reproducibility manifest.
