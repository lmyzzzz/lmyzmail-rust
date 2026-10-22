# Validation supplement for release candidate 22dae7d0

The Windows delivery directory is
`D:\MiscProjects\lmyzmail-rust\releases\20261023-rc.22dae7d0`.
The runtime archive, complete tracked source archive and Git history bundle
identify source commit `22dae7d0f8728f355fc6a31bdc65263bd21aa10d`.
This is a usable Linux x86_64 release candidate; the production goal remains
open until every gate in [acceptance status](acceptance-status.md) passes.

## Artifact identity and installation

The retained ELF SHA-256 is
`78a4c31145010e479ec64a9e0a2f3ac767b2860e32180100cad699a155c37790`.
Two frozen release builds in separate Cargo target directories inside one
clean detached source checkout produced identical bytes and ELF Build IDs.
They took 217 and 218 seconds. This establishes the recorded build layout,
not byte identity across different source checkout paths. The ELF has no
unresolved shared libraries or Java/JVM imports.

`tools/verify-release-package.py` verified all four checksums, the complete
decompressed source stream against `git archive`, all 17,240 tracked source
paths, the packaged ELF and the complete Git bundle. The same verification
passed against the copies in the Windows delivery directory. The runtime
archive includes the installer, uninstaller and its own reproduced-build
manifest; no development checkout or Java installation is required.

The full installation regression passed against this retained ELF, including
upgrade, configuration preservation and uninstall. A second check used the
actual unpacked runtime archive: install, configuration validation, reinstall,
uninstall and retained configuration/model checks passed. Negative invocation
logs remain available: a development installation without the required new
manifest rejected the new ELF, and passing `RELEASE.json` instead of the
reproducibility record was also rejected. The package's default manifest
worked without an environment override.

## Model, storage and external checks

The included 512-wide feed-forward checkpoint is the final compact model from
thread `01a16323-de1d-7a11-976d-8e2ff3322839`. The weight SHA-256 is
`4fc4f7a0eb5d7e1210ddd7fee63a756775f5b7155db210080cfd8cc759403428`;
the tokenizer SHA-256 is
`6624adb41b9274bf0cc73c62ebd26eb2bcf281d533f30607ba415105917d81f3`.
The frozen original model remains an independent compatibility fixture.

All 961 Rust workspace tests and strict Clippy passed for the product source.
The retained release passed 188 disjoint unmarked non-oracle checks and the
separately isolated RBL Java/candidate checks. Compact-model Scalar/Auto
SMTP/database checks and ordinary/ambiguous-name same-state takeover passed.

The new offline rollback exporter passed five consecutive end-to-end checks
using the retained ELF. Each created real Rust v2 messages for underscore,
consecutive-dot, literal `v1-` and Unicode owners, exported a separate tree,
verified unchanged source/index rows, read byte-exact messages in frozen Java,
and reopened them in Rust. Budget, non-offline, owner-collision and symlink
cases failed closed. These five passes do not prove that the earlier rare
exact-port reservation failure is fixed; the diagnostic retained the original
assertion and would capture the socket tables if it recurred.
The final exporter then added deadline checks between one-MiB verification
reads and nonblocking special-file rejection. Four focused source-boundary
checks and a fresh complete Java/Rust rollback cycle passed for that version
(`maildir-export-source-boundaries-20261023` and
`v2-export-takeover-20261023-v5`). No lmyzmail runtime source changed.

`pending-takeover-20261023-v6.json` records real HTTP-created PENDING memory
and file-mode tasks in both Java/Rust directions. It verifies Redis TTL,
source spool, exact SMTP DATA bytes, decoded MIME, SENT archives and no
retry/duplicate. Rust was then restarted and observed for a complete queue
scheduling cycle to reject resurrection of completed tasks.

## Matrix and stability qualification

The full fresh Java campaign passed all 107 selected oracle tests in
2,129.89 seconds. RBL was run separately in its required network namespace
and also passed for both Java and the candidate. The audit kept all 6,897
historical golden files unchanged and found all 346 campaign observations
equal to their historical counterparts, with no differences requiring review.
The complete reproduced-ELF candidate replay passed all 126 selected checks
in 899.16 seconds against that completed campaign. Its audit also retained
all historical files and matched all 346 observations. The staged and retained
ELF hashes remained identical before and after the full run. Together with
the disjoint 188 unmarked checks and separately required candidate RBL check,
all 315 non-oracle checks in the two blackbox directories passed.

The first reproduced-ELF 1,800-second, 16-worker soak completed 254,064 HTTP,
SMTP, HTCPCP and Minecraft operations with zero protocol failures. It is
nonqualifying: the filesystem-wide disk delta peaked at 2,767,642,624 bytes,
above the unchanged 1 GiB ceiling, while other matrix/package tasks ran.
The candidate's own workspace grew by 5,787,648 bytes (PostgreSQL data),
peak RSS was 413,272 KiB, FD count stayed at 27, and peak tasks were 61.
Steady RSS grew by 768 KiB and FD/tasks by zero. All other resource gates,
immutable-input checks, ELF checks and managed-process cleanup passed.
The complete failure evidence is retained; an isolated run under the same
policy is required rather than raising its disk ceiling.

Six fresh Scalar/AVX2 renderer benchmark rounds retained identical output
hashes across backend, size and dither cases. The benchmark records source,
binary, capabilities and host telemetry. The 275HX exposes AVX2/FMA and no
AVX-512F; requesting the latter safely resolved to AVX2 and refused fallback
timing. This is local comparative evidence, not AVX-512 qualification.
The retained runtime ELF separately passed both Minecraft video and mail-view
Scalar/AVX2 wire/pixel golden checks in 51.32 seconds. Observer events proved
the requested runtime dispatch actually ran; Scalar and AVX2 observations
were identical, with all historical/campaign files unchanged.

The current-source privileged XDP checker was freshly rebuilt with frozen
dependencies and passed real isolated-kernel execution. It checked legacy
pin takeover and retention, new-pin priority, incompatible/partial-state
rejection, ownership guards, initialization cancellation, detach retry,
no database connection or automatic ban when recording is disabled, and
IPv4/IPv6 pass/ban/drop/restart/drop/unban/pass. The kernel observed five
passed packets and three dropped packets. It used a private veth, mount and
network namespace; no production interface was attached. Evidence is
`xdp-privileged-22dae7d0.json` and its original stderr log.

An early candidate replay started before Java had finished recording. It
passed 82 checks and failed 44 because the required campaign golden files
did not yet exist. No product mismatch was reached in those 44 failures;
the negative log/XML remain retained. A complete candidate replay after
oracle completion is required. An early local-renderer attempt hit the same
missing-golden precondition and is also retained.

Formal 250,000-message SMTP tiers, the same-process 100,000-message follow-up,
fsync-off Java comparison, fsync-on durability/stability, disk-budgeted 10 MiB
stress, and native AVX-512 execution/performance remain open. The user has no
available AVX-512 host and authorized continuing every locally verifiable
gate. This does not waive the native AVX-512 gate.
