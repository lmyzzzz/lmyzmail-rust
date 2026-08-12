# TLSRPT HTTPS contract evidence

This note records the source evidence used for the Rust TLSRPT HTTPS
vertical slice. The Java checkout is frozen at commit
`5dac2ab2922c30c726c4a83d7626c95ad4e231c8`; it was read only while this
implementation was developed.

## Frozen Java sources

| File | SHA-256 |
| --- | --- |
| `src/main/java/net/lmyz/lmyzmail/report/service/ReportDeliveryService.java` | `C100081C5CB094D7F53BDD68B4AF6E68864A4E95DC2AB107E98FE0A74FCEE310` |
| `src/main/java/net/lmyz/lmyzmail/util/PinnedHttpClient.java` | `482D9DD53FF61A9EC6C2F48EE97B2CF3862DDADCAECF8AD5F173D21E74EBD2BC` |
| `src/main/java/net/lmyz/lmyzmail/util/NetworkValidator.java` | `E73F561F524C588B5E21998178FCCA59979FF096854B640EE94F967EDE227DD9` |

The Java service sends TLS reports only over HTTPS, with
`Content-Type: application/tlsrpt+gzip` and a 2xx success range. It reports
non-2xx responses as `HTTP {status}`, follows no redirects, rejects endpoint
userinfo/fragments and ports other than 443, validates every DNS answer as
public, and keeps one deadline across DNS, connect, TLS, request, and response
processing. `PinnedHttpClient` caps validated address attempts at 16, response
headers at 64 KiB/200 lines/8 KiB per line, and does not read the TLS report
POST response body.

## Frozen Java security tests

| File | SHA-256 |
| --- | --- |
| `src/test/java/net/lmyz/lmyzmail/report/service/ReportDeliverySecurityTest.java` | `B9B0E5E7B77C994E9F9F1F04C0C3B9271693E6F217A4995EC400F328F790472B` |
| `src/test/java/net/lmyz/lmyzmail/util/NetworkValidatorSecurityTest.java` | `C7C0A85D2A581099AAEA5B77EE176886AF81BC434461A04C480A5A6925417CE0` |
| `src/test/java/net/lmyz/lmyzmail/util/PinnedHttpClientSecurityTest.java` | `DDE10D157D69ADD725B9346041DEE6E9BB98BA643DD5874C9081B26CC7D597E1` |

## Rust evidence

The implementation is in `crates/lmyzmail/src/reporting.rs`. Its injected
resolver/backend tests cover endpoint validation, Java-equivalent IPv4/IPv6
special ranges, mixed-answer fail-closed behavior, one lookup with pinned
addresses, the 16-address ceiling, exact request headers and raw path/query,
2xx and `HTTP 302` outcomes, timeout/cancellation/admission, no response-body
consumption, interim-response limits, and all response-header budgets.

The active external `managed-tlsrpt-https-v10.json` profile drives both the
frozen Java oracle and the Rust candidate through the real
`POST /api/reports/domain/{domain}` API over independent PostgreSQL state. Its
five-case matrix freezes a successful `204`, a non-followed `302`, an
untrusted collector certificate, a private-address SSRF rejection, and a
stalled response under one two-second delivery deadline. The fixture observes
exact TXT/address queries, TLS SNI/protocol/cipher, Host and request-target
bytes, complete bounded gzip body framing, normalized decompressed JSON, the
API delivery result, and an unchanged source `outbound_tls_log` row. v1 through
v9 remain immutable pre-final-definition history.

The candidate deliberately emits `lmyzmail-TLSRPT/1.0` instead of the frozen
Java `Botmail-TLSRPT/1.0` identifier. This is the explicitly authorized brand
change; no other TLSRPT wire or security behavior is relaxed.

## TLS-RPT HTTPS v10 verification

- Fresh Java recording, Rust candidate replay, and a second fresh Java replay:
  passed for v10.
- HTTPS fixture tests: 9 passed; the TLS-RPT bounded decompression test also
  passed.
- Python non-integration suite: 161 passed, 158 deselected.
- Ruff and strict mypy across the full black-box source and test tree: passed.
- `cargo fmt --all -- --check`: passed.
- `cargo test --workspace --locked`: 637 passed.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`:
  passed.
- Two locked release builds, including one cold build in an independent target
  directory, were byte-identical. The Linux x86_64 binary SHA-256 is
  `a57663cb11fad457c7cbad6c7aefef85f2856aee59b9ee3c5840bf3236eb5220`.

## Earlier milestone verification

- `cargo fmt --all -- --check`: passed.
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`:
  passed.
- `cargo test --workspace`: 313 library tests and every integration/doc target
  passed.
- Reporting HTTPS/rendering tests: 18 passed.
- Python non-integration suite: 121 passed, 81 deselected.
- Ruff: passed; report-specific strict mypy passed for three source files.
- Frozen `managed-reports-v12` candidate replay: 1 passed in 1.70 seconds.
- `cargo build --release --locked --target x86_64-unknown-linux-gnu`: passed.
- Release binary SHA-256:
  `65dcb6eb6fc4145b47280e79c04fe214c7aa59eb8ef485f990f1199787bea5e2`.
