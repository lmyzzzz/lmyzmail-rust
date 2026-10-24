# lmyzmail

[中文](README.md) · [English](README.en.md) · [日本語](README.ja.md)

lmyzmail is a single-process mail server for Linux x86_64. SMTP, Webmail, management APIs, mail security/reporting, a Minecraft mailbox world and the complete Skibidi/brainrot features share one modular Rust runtime. PostgreSQL, Redis and Maildir retain persistent state. The installed service requires no Java, JVM, Python or Rust toolchain.

The current release is a **0.1.0 release candidate**. Reproducible builds, installation, differential checks and a half-hour multi-module soak have evidence; formal high-volume SMTP and native AVX-512 acceptance remain open. Implemented functionality is separate from complete production acceptance. See the [remaining work items](docs/goal-remaining.zh-CN.md) and [acceptance record](docs/acceptance-status.md).

## Contents

- [Features and usage](#features-and-usage)
- [Installation and first start](#installation-and-first-start)
- [Configuration loading](#configuration-loading)
- [Complete configuration reference](#complete-configuration-reference)
- [HTTP endpoints](#http-endpoints)
- [Operations and troubleshooting](#operations-and-troubleshooting)
- [Existing data and rollback](#existing-data-and-rollback)
- [Build and validation](#build-and-validation)

## Features and usage

### Mail and Webmail

Open `/` for Webmail. It provides mailbox login, configurable public registration, inbox/sent/spam and other mail folders, pagination, HTML/plain-text messages, raw source/headers, attachment download, JSON or multipart sending, delivery state, quotas, stars, labels, contacts and preferences. `/cringe.html` supports connection, threat statistics, list sorting, search and pagination. Per-IP detail remains incomplete, as listed below. Message, attachment and user-data access is scoped to the authenticated mailbox.

Inbound SMTP implements EHLO, MAIL/RCPT, DATA, BDAT, PIPELINING, STARTTLS, SMTPUTF8, MIME and recipient-domain/mailbox validation. DATA clients must wait for `354` before sending the body. This listener **does not provide SMTP AUTH submission**: AUTH returns `502`. Authenticated sending uses Webmail or HTTP APIs; do not send mailbox passwords to this port's AUTH command.

Outbound delivery uses a persistent queue, renewable leases, bounded concurrency and connection pooling, with MX routing, STARTTLS, DKIM signing, temporary-failure backoff, terminal archival and DSN bounces. Sent files, database indexes, queue records and spool ownership have recovery checks; unfinished work is recovered after restart. HTTP sending is asynchronous by default; `async=false` is unsupported.

### Security, reporting and honeypots

Features include SPF/DKIM/DMARC verification, outbound MTA-STS, TLS-RPT and DMARC aggregate reports. Reports support manual triggers and a daily UTC schedule, with DNS/HTTP destination restrictions. Administrators must publish domain DNS and configure DKIM keys, SMTP certificates and report mailboxes.

Content scoring covers RBL, an SOA domain heuristic, missing headers, subject encoding tricks, excessive recipients, spam/phishing terms, suspicious URLs, dangerous/double extensions and MIME mismatches. Connection-level Spamhaus DNSBL/DBL and scoring-layer RBL are configured independently.

There are 104 HTTP scanner-decoy classes and TCP traps for `NONE/SMTP/SSH/FTP/MYSQL/POP3/IMAP/VNC`. They record source IPs, activity and current/historical cringe scores, with search, export, decay and threshold bans. The complete embedded registry is in [honeypot handling](crates/lmyzmail/src/honeypot.rs) and the [protocol asset inventory](crates/lmyzmail/src/honeypot_assets.json). These traps do not provide actual SSH, FTP, database or VNC services.

SSH-log monitoring tails the first readable log and handles rotation, failure windows, report cooldown and bounded IP tracking. Optional XDP uses a pinned C/eBPF ABI for IPv4/IPv6 bans, allowlists, statistics, PPS/SYN monitoring, score synchronization and restart persistence. The default systemd unit permits low-port binding only; **it cannot attach XDP**. Follow the [privileged XDP deployment and gate](docs/xdp-privileged-gate.md) instead of making the entire service unrestricted root.

HTTP applies proxy-IP and CORS policies. Authentication, uploads, paths, recipient domains, MIME, queues and caches are bounded. Strip forged forwarding headers at the proxy and trust only actual proxy addresses. CORS does not authenticate callers.

### Skibidi, quiz, inference and video

SMTP banners, random text, probability thresholds, seeds and batch semantics use pinned Skibidi C 1.8.0 throughout; there is no emulation of the old Java fast path. SIMD selection checks CPU and OS support. See the [generator ABI/probability contract](docs/skibidi-banner-contract.md) for provenance and ownership.

`SKIBIDITOILET` has a 474-question pool and three modes: BABYGRONK (15 questions), SKIBIDITOILET (30), OHIOFINALBOSS (60). On an SMTP connection:

```text
SKIBIDITOILET HELP
SKIBIDITOILET START BABYGRONK
SKIBIDITOILET ANSWER A
SKIBIDITOILET QUIT
SKIBIDITOILET WATCHSKIBIDITOILET WIDTH=160 FPS=12 CONTRAST=1.5
```

ASCII playback also accepts `BRIGHTNESS`, `GAMMA`, `ASPECT` and `INVERT`, within configured width/FPS limits. Frames use monochrome ANSI and `250-` lines. There is one global viewer; disconnect to stop playback.

SkibidiInferX implements read-only SafeTensors mmap, BPE, KV cache, sampling, seeds, cancellation and deadlines in Rust. The package ships compact-20261022 (12,192,512 parameters, 48,779,520 bytes, FFN width 512). Original weights remain available through explicit paths. Replace weights/tokenizer atomically and restart; never truncate a mapped model. Busy, timed-out or unavailable inference uses fixed fallback text. See the [model contract and compatibility parameters](docs/skibidi-inferx-contract.md).

Rust owns ASCII, mail HTML, image/video, Minecraft block/map palettes, dithering, resizing, pagination and incremental frames over pinned FFmpeg and litehtml/Cairo foundations. **The old libasciiart is not required.** Scalar, AVX2+FMA and AVX-512 have safe runtime dispatch. Local Scalar/AVX2 wire, pixel and frame goldens passed; native AVX-512 execution/performance still needs suitable hardware.

### Minecraft and HTCPCP

The Minecraft client version is **1.8.9**. Features include status queries, online/offline login, in-game mailbox authentication, folder GUIs, map-rendered messages and pages, contact interactions, book drafts/sending, a world template, block video and map-wall video. Mojang authentication does not replace mailbox authentication. Main commands:

```text
/help
/stuck
/skibidi
/draft
/clear
/mail rendersize 256 256 16
/mail next
/mail prev
/mail close
/video play width=48 fps=6
/video play map width=5 fps=10 dither=1
/video pause
/video stop
```

The in-game UI guides mailbox input. `/mail rs` aliases rendersize. Configuration defaults can differ from compatibility defaults of argument-free commands; explicit arguments avoid ambiguity. Stop, disconnect and timeout release video resources.

HTCPCP runs on its own TCP port, with coffee/tea pot state machines, `GET HEAD OPTIONS PROPFIND BREW POST WHEN`, additions, varieties, brew timing and protocol errors. The example config defines eight pots; omitting pots yields one coffee pot. Inspect with `curl -i http://127.0.0.1:8888/pot-0`; raw clients can send `HTCPCP/1.0` requests. Unsupported drinks/additions are rejected according to pot capabilities.

## Installation and first start

### Platform and dependencies

Only Linux x86_64 is supported. Ubuntu 24.04 / WSL2 is the validated development environment; PostgreSQL 16 and Redis are the validated data services. Install the x86_64 shared libraries listed in the specific package's `RELEASE.json`. Build tools and Python are needed only for building, validation or offline utilities.

The [release guide](docs/release.md) explains runtime archives, complete source, history bundles, models and video assets. Verify the accompanying `SHA256SUMS` and unpack on Linux with Unix permissions intact:

```bash
sha256sum -c SHA256SUMS
tar -xzf lmyzmail-0.1.0-rc.COMMIT-linux-x86_64.tar.gz
cd lmyzmail-0.1.0-rc.COMMIT
./bin/lmyzmail --version
sudo tools/install-lmyzmail.sh
```

Replace `COMMIT` in these commands with the actual release identifier.

The installer validates the ELF and asset hashes and **leaves the unit stopped**. Existing configuration is never overwritten.

| Path | Purpose |
| --- | --- |
| /usr/bin/lmyzmail | Service binary |
| /etc/lmyzmail/application.properties | Administrator configuration |
| /usr/share/lmyzmail/models/skibidi-inferx | Model and tokenizer |
| /var/lib/lmyzmail/data/mail | Maildir and default spool |
| /var/log/lmyzmail | Writable log directory; stdout/stderr go to the journal |
| /run/lmyzmail | Private runtime directory |
| deploy/lmyzmail.service | Unit source |

`--binary PATH` selects an ELF. `--destdir ABS` stages files without system-user/systemd changes. `--legacy-rw ABS` / `--legacy-ro ABS` grant exact existing data/certificate paths. `--enable` enables and starts a fresh, already configured installation; do not use it before preparing credentials.

### Database and configuration

Startup adds recovery/coordinator structures, **not all base business tables**. Adopt an existing schema directly. For a new empty database, the repository includes a [DDL-only PostgreSQL schema](blackbox/fixtures/legacy/postgres-schema.sql), without test accounts or seed rows. From the source root, after verifying the target is a new empty database:

```bash
sudo -u postgres createuser --pwprompt lmyzmail
sudo -u postgres createdb --owner=lmyzmail lmyzmail
set -o pipefail
sed 's/^CREATE SCHEMA "public";$/CREATE SCHEMA IF NOT EXISTS "public";/' \
  blackbox/fixtures/legacy/postgres-schema.sql |
  PGHOST=127.0.0.1 PGUSER=lmyzmail PGDATABASE=lmyzmail \
    psql -X -W --set=ON_ERROR_STOP=1
```

The schema already converts incompatible LONGTEXT expressions to PostgreSQL text. **Never run initialization DDL against an existing database.** Set dedicated database credentials, Redis ACL/password and filesystem permissions.

Edit `/etc/lmyzmail/application.properties` for PostgreSQL, Redis, domains, listeners, Maildir, sending domains, TLS and management API keys. Keep secrets in protected deployment files; never commit real credentials. The example binds loopback and disables public registration, Minecraft, XDP and stress tests; it explicitly enables HTCPCP and IP DNSBL.

The HTTP listener is plaintext: use an HTTPS reverse proxy for public Webmail. SMTP PKCS12 does not enable HTTPS. PostgreSQL currently uses NoTls; use a trusted local link or protected tunnel. Redis supports its own TLS setting.

```bash
sudo -u lmyzmail /usr/bin/lmyzmail \
  --config /etc/lmyzmail/application.properties --check-config
sudo systemctl enable --now lmyzmail
curl --fail http://127.0.0.1:8080/api/health
journalctl -u lmyzmail -n 100 --no-pager
```

`--check-config` parses the main configuration and prints a summary. It does not connect to databases or replace module startup checks. Verify logs, mailbox APIs, SMTP and actual mail publication after starting; health alone is insufficient.

### Public DNS

Configure MX and matching A/AAAA, reverse DNS, SPF, DKIM selector TXT and DMARC. Add MTA-STS HTTPS policy and `_mta-sts` / `_smtp._tls` TXT as required. Open intended inbound ports and verify outbound TCP 25. Publish records only for actual deployed services.

## Configuration loading

The main-file selection order is `--config PATH` (or `--config=PATH`), `LMYZMAIL_CONFIG`, `./application.properties`, then `/etc/lmyzmail/application.properties`. Only one main file is selected. CLI options include `--check-config`, `--version/-V`, `--help/-h` and `--lmyzmail.key=value` overrides.

Normal configuration is UTF-8 properties with continuations/escapes; the last identical key wins. `spring.profiles.include=a,b` overlays sibling `application-a.properties` then `application-b.properties`. Missing ordinary profiles are ignored; missing keywords uses the embedded word list. Order: main file, profiles, same-key CLI overrides.

Per field, supported `lmyzmail.*` keys take precedence over `botmail.*` aliases. **An old-namespace CLI value cannot override a present new key.** Arbitrary environment variables are not automatically mapped to properties. Limits: 1 MiB/file, 16384 keys, 32 included profiles, 4 MiB aggregate.

A file starting with `{` after whitespace is accepted as `schema_version=1` semantic JSON for external test/orchestration tooling. This is a grouped snake_case schema, **not an arbitrary properties dictionary**. Top-level fields: `schema_version, profile, listen, postgres, redis, maildir, storage, domain, domains, allowed_origins, trusted_proxies, api_keys, features, skibidi_inferx, fail2ban, smtp, content_filter, xdp, cringe, reporting, stress, htcpcp, minecraft, mail_render, tls, limits`. [Typed definitions](crates/lmyzmail/src/config.rs) specify nested fields and validation; unknown fields fail. JSON defaults can differ from properties omission, such as send_enabled=false in domain entries. Prefer properties for routine deployment.

## Complete configuration reference

Keys below are fully expanded with `lmyzmail.`. `/` separates independent keys in a row; defaults correspond in order. `""` means empty string, `[]` empty list and `<maildir>` means maildir.base. Unless noted, these are **properties defaults when omitted**, not explicit values in the example. `[n]` is a contiguous zero-based index; `<name>` and `<RULE>` are placeholders. Restart after changes; no general hot-reload endpoint is provided.

### Listeners, HTTP and message sizes

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.listen.host` | `127.0.0.1` | Bind address shared by listeners; change explicitly for public access. |
| `lmyzmail.http.port` / `lmyzmail.smtp.port` / `lmyzmail.htcpcp.port` / `lmyzmail.minecraft.port` | `8080 / 25 / 8888 / 25565` | Protocol ports; optional services also require enabled. |
| `lmyzmail.profile` | `production` | Descriptive label; does not load a profile file. |
| `lmyzmail.http.max-request-bytes` | `10485760` | Ordinary HTTP body limit; attachment limits apply separately. |
| `lmyzmail.http.max-multipart-bytes` | `209715200` | Multipart body limit, not the deliverable message size. |
| `lmyzmail.http.max-connections` / `lmyzmail.http.request-timeout-ms` | `256 / 10000` | Concurrent HTTP connections and request timeout. |
| `lmyzmail.http.upload-temp-dir` | `<maildir>/.lmyzmail-upload` | Writable temporary directory for streamed uploads. |
| `lmyzmail.http.trusted-proxies` | `[]` | Trusted proxy IPs/CIDRs for forwarded client IPs; CSV or [n]. |
| `lmyzmail.allowed-origins[n]` | `[]` | Allowed CORS origins, including explicit scheme://*.domain patterns. |
| `lmyzmail.max-email-size-bytes` / `lmyzmail.max-attachment-size-bytes` / `lmyzmail.max-total-attachments-size-bytes` | `15728640 / 10485760 / 15728640` | Whole message, individual attachment and aggregate attachment limits; allow for MIME overhead. |

### PostgreSQL, Redis and persistence

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.postgres.host` / `lmyzmail.postgres.port` / `lmyzmail.postgres.database` | `localhost / 5432 / lmyzmail` | PostgreSQL endpoint and database. |
| `lmyzmail.postgres.username` / `lmyzmail.postgres.password` | `lmyzmail / ""` | Database identity; use dedicated production credentials. |
| `lmyzmail.postgres.url` | `""` | Optional JDBC/PostgreSQL URL; supplies host/port/database only. Credentials remain separate. |
| `lmyzmail.postgres.pool.max-size` | `32` | Bounded PostgreSQL pool; current connections use NoTls. |
| `lmyzmail.redis.host` / `lmyzmail.redis.port` / `lmyzmail.redis.database` | `localhost / 6379 / 0` | Redis endpoint and logical database; existing keys/TTLs are retained. |
| `lmyzmail.redis.username` / `lmyzmail.redis.password` | `"" / ""` | ACL username/password; empty for unauthenticated Redis. |
| `lmyzmail.redis.tls-enabled` | `false` | Redis TLS; same-namespace alias: redis.ssl.enabled. |
| `lmyzmail.redis.pool.max-active` | `32` | Bounded Redis connection pool. |
| `lmyzmail.maildir.base` | `/var/lib/lmyzmail/data/mail` | Mail storage root; preserve existing layout and permissions. |
| `lmyzmail.maildir.max-files-per-directory` | `10000` | Directory sharding threshold; use 1..1000000 for the whole service, not -1. |
| `lmyzmail.storage.fsync-enabled` | `true` | File/directory durability barriers. false retains atomic publication but can lose acknowledged data on failure; does not change PostgreSQL WAL or Redis persistence. |

### Domains, identities and rate limits

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.domain` | `lmyz.net` | Primary domain; domains.main.domain takes precedence. |
| `lmyzmail.domains.<name>.domain` | `domain (main)` | Named domain entries, up to 256; main may inherit domain. |
| `lmyzmail.domains.<name>.receive-enabled` / `lmyzmail.domains.<name>.send-enabled` / `lmyzmail.domains.<name>.require-existing-mailbox` | `true / true / true` | Receive/send permissions and existing-recipient requirement; these do not enable SMTP AUTH. |
| `lmyzmail.domains.<name>.dkim-selector` / `lmyzmail.domains.<name>.dkim-private-key-path` | `"" / ""` | Configure selector and private-key path together and publish matching DNS TXT. |
| `lmyzmail.domains.<name>.list-unsubscribe-mailto` / `lmyzmail.domains.<name>.list-unsubscribe-url` | `"" / ""` | Outbound List-Unsubscribe targets. |
| `lmyzmail.api-keys[n].key` / `lmyzmail.api-keys[n].label` | `required / api` | Contiguous API key entries, up to 256; keys are unique and at most 4096 bytes. |
| `lmyzmail.api-keys[n].read` / `lmyzmail.api-keys[n].write` | `true / false` | Independent read/write grants; aliases readEnabled/writeEnabled. |
| `lmyzmail.public-registration-enabled` | `false` | Public signup switch; management API can still create mailboxes. |
| `lmyzmail.session.expiry-days` / `lmyzmail.session.max-per-user` / `lmyzmail.session.track-last-used` | `7 / 10 / true` | Session lifetime, per-user cap and last-use tracking. |
| `lmyzmail.rate-limit.enabled` | `true` | Authentication/registration rate limiting. |
| `lmyzmail.rate-limit.max-failed-login-attempts` / `lmyzmail.rate-limit.failed-login-window-minutes` / `lmyzmail.rate-limit.ip-ban-duration-hours` | `10 / 5 / 3` | Failed-login window and IP ban duration. |
| `lmyzmail.rate-limit.max-registrations-per-ip` / `lmyzmail.rate-limit.registration-rate-window-hours` | `5 / 3` | Per-IP registration quota/window. |
| `lmyzmail.rate-limit.max-emails-per-account` / `lmyzmail.rate-limit.email-rate-window-hours` | `100 / 3` | Per-account sending quota/window; concurrency does not bypass it. |

### Outbound delivery, queue and DNS

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.outbound.spool-dir` | `<maildir>/.lmyzmail-outbound` | Large-message spool until durable terminal archival; legacy alias botmail.outbound.temp-dir. |
| `lmyzmail.outbound.max-pending-tasks` / `lmyzmail.outbound.retry-count` | `10000 / 5` | Hard pending-task cap and retry count. |
| `lmyzmail.outbound.helo-hostname` | `domain` | Outbound EHLO/HELO hostname. |
| `lmyzmail.outbound.connection-timeout-ms` / `lmyzmail.outbound.read-timeout-ms` | `30000 / 60000` | Connect and SMTP command-read timeouts. |
| `lmyzmail.outbound.pool-enabled` / `lmyzmail.outbound.max-connections-per-host` / `lmyzmail.outbound.max-messages-per-connection` | `true / 5 / 100` | Reuse successful sessions after RSET; failed/ambiguous sessions close. |
| `lmyzmail.outbound.max-idle-time-ms` / `lmyzmail.outbound.connection-life-time-ms` / `lmyzmail.outbound.pool-cleanup-interval-ms` | `60000 / 300000 / 30000` | Idle timeout, lifetime and pool cleanup interval. |
| `lmyzmail.queue.worker-id` | `lmyzmail-<pid>` | Lease owner; example uses lmyzmail-worker. Do not share an ID across instances. |
| `lmyzmail.queue.max-concurrent-sends` / `lmyzmail.queue.batch-size` / `lmyzmail.queue.poll-interval-ms` | `100 / 50 / 1000` | Bounded concurrency, scheduling claim size and poll interval. |
| `lmyzmail.queue.migration-batch-size` | `1000` | Scan batch size for existing queue recovery. |
| `lmyzmail.queue.lease-seconds` / `lmyzmail.queue.renew-seconds` / `lmyzmail.queue.processing-timeout-minutes` | `90 / 10 / 10` | Lease, renewal and processing deadlines; renewal must satisfy validation constraints. |
| `lmyzmail.queue.retry-base-seconds` / `lmyzmail.queue.retry-max-seconds` | `30 / 3600` | Retry backoff base and ceiling. |
| `lmyzmail.outbound.dns.mx.l1-max-entries` / `lmyzmail.outbound.dns.mx.l1-ttl-minutes` / `lmyzmail.outbound.dns.mx.l2-ttl-minutes` / `lmyzmail.outbound.dns.mx.negative-ttl-minutes` | `10000 / 15 / 30 / 5` | MX local capacity, local/Redis TTLs and negative-cache TTL. |
| `lmyzmail.outbound.dns.query-timeout-seconds` / `lmyzmail.outbound.route-deadline-seconds` | `15 / 30` | DNS query timeout and overall routing deadline. |
| `lmyzmail.smtp.mta-sts-enabled` / `lmyzmail.smtp.mta-sts-fetch-timeout-ms` | `true / 10000` | MTA-STS discovery, HTTPS fetch and outbound TLS policy. |
| `lmyzmail.ssl.use-custom-certificate` / `lmyzmail.ssl.keystore-path` / `lmyzmail.ssl.keystore-password` | `false / "" / ""` | PKCS12 certificate for SMTP STARTTLS; does not enable HTTP HTTPS. |

### SMTP security and content filtering

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.smtp-security.tarpit-enabled` | `true` | Delayed responses for abusive clients. |
| `lmyzmail.smtp-security.dns-server` | `""` | Optional numeric IP:port DNS override; empty uses the system resolver. |
| `lmyzmail.smtp-security.spamhaus-enabled` / `lmyzmail.smtp-security.spamhaus-zones` | `false / zen.spamhaus.org` | Inbound IP DNSBL; explicitly enabled in the installation example. Follow provider access rules. |
| `lmyzmail.smtp-security.spamhaus-reject-on-listed` / `lmyzmail.smtp-security.spamhaus-timeout-ms` / `lmyzmail.smtp-security.spamhaus-cache-ttl-seconds` | `true / 3000 / 300` | Reject listed IPs, query timeout and cache TTL. |
| `lmyzmail.smtp-security.spamhaus-ignored-codes` | `[]` | Ignored response-code CSV. |
| `lmyzmail.smtp-security.spamhaus-dbl-enabled` / `lmyzmail.smtp-security.spamhaus-dbl-zone` | `false / dbl.spamhaus.org` | Domain DBL queries. |
| `lmyzmail.contentfilter.enabled` / `lmyzmail.contentfilter.suspicious-threshold` / `lmyzmail.contentfilter.spam-threshold` | `true / 5.0 / 10.0` | Weighted suspicious/spam thresholds and spam headers/classification. |
| `lmyzmail.contentfilter.stream-buffer-size` | `65536` | Streaming scan buffer, at most 1048576 bytes. |
| `lmyzmail.contentfilter.rules.<RULE>.enabled` / `lmyzmail.contentfilter.rules.<RULE>.weight` | `true / 1.0` | Per-rule switch and weight, 0..100; complete rule set below. |
| `lmyzmail.contentfilter.rbl.enabled` / `lmyzmail.contentfilter.rbl.servers` | `true / zen.spamhaus.org,bl.spamcop.net` | Scoring-layer RBL, separate from connection-layer DNSBL rejection. |
| `lmyzmail.contentfilter.rbl.timeout-ms` / `lmyzmail.contentfilter.rbl.score-per-hit` / `lmyzmail.contentfilter.rbl.max-score` | `3000 / 3.0 / 6.0` | RBL timeout, score per hit and cap. |
| `lmyzmail.contentfilter.keywords.enabled` / `lmyzmail.contentfilter.keywords.density-threshold` / `lmyzmail.contentfilter.keywords.base-score` / `lmyzmail.contentfilter.keywords.max-score` | `true / 0.05 / 2.0 / 8.0` | Keyword and density scoring. |
| `lmyzmail.contentfilter.keywords.spam-keywords` / `lmyzmail.contentfilter.keywords.phishing-keywords` | `[] (keywords profile)` | CSV/indexed lists; the keywords profile supplies the shipped word lists. |
| `lmyzmail.contentfilter.url.enabled` / `lmyzmail.contentfilter.url.shortener-domains` / `lmyzmail.contentfilter.url.suspicious-tlds` | `true / [] / []` | URL scanning; keywords profile supplies shortener and suspicious-TLD lists. |
| `lmyzmail.contentfilter.url.shortener-score` / `lmyzmail.contentfilter.url.suspicious-tld-score` / `lmyzmail.contentfilter.url.ip-url-score` / `lmyzmail.contentfilter.url.max-score` | `1.5 / 2.0 / 3.0 / 8.0` | Shortener, TLD, IP-URL scores and total cap. |
| `lmyzmail.contentfilter.attachment.enabled` / `lmyzmail.contentfilter.attachment.dangerous-extensions` | `true / exe,scr,bat,cmd,com,pif,vbs,vbe,js,jse,wsf,wsh,msi,msp,hta,cpl,reg,inf,scf,lnk,ps1,psm1,jar` | Attachment checks and configurable dangerous extensions. |
| `lmyzmail.contentfilter.attachment.dangerous-extension-score` / `lmyzmail.contentfilter.attachment.double-extension-score` / `lmyzmail.contentfilter.attachment.mime-type-mismatch-score` | `5.0 / 4.0 / 3.0` | Dangerous extension, double-extension and MIME-mismatch scores. |

Rules: `RBL_CHECK`, `NEW_DOMAIN`, `MISSING_HEADERS`, `SUBJECT_ENCODING_TRICK`, `EXCESSIVE_RECIPIENTS`, `SPAM_KEYWORDS`, `SUSPICIOUS_URL`, `DANGEROUS_EXTENSION`, `DOUBLE_EXTENSION`, `MIME_TYPE_MISMATCH`. All have implemented processing paths. `NEW_DOMAIN` uses an SOA-serial heuristic, not a registration-age database. The example loads `spring.profiles.include=keywords`; lists may be empty without that profile.

### Skibidi, InferX and ASCII rendering

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.smtp.skibidi-generator-mode` | `AUTO_SAFE` | AUTO_SAFE/AUTO/NATIVE/SCALAR/AVX2/AVX512; JAVA is a legacy alias for scalar C. All probabilities and seed/batch semantics follow pinned C 1.8.0. |
| `lmyzmail.smtp.skibidi-generator-enable-avx512` / `lmyzmail.smtp.skibidi-generator-enable-simd-rng` | `true / true` | Permit these backends subject to CPU/OS feature detection. |
| `lmyzmail.smtp.skibidi-insults-enabled` / `lmyzmail.smtp.skibidi-toilet-quiz-enabled` | `true / true` | SMTP interactive text and the 474-question quiz. |
| `lmyzmail.smtp.asciiart.simd-mode` / `lmyzmail.mailrender.simd-mode` | `AUTO / AUTO` | AUTO/SCALAR/AVX2/AVX512 with safe runtime dispatch; the latter covers mail pixels and Minecraft color pipelines. |
| `lmyzmail.smtp.asciiart.max-width` / `lmyzmail.smtp.asciiart.max-fps` / `lmyzmail.smtp.asciiart.default-width` / `lmyzmail.smtp.asciiart.default-fps` | `450 / 20 / 120 / 10` | SMTP ASCII video width/FPS caps and defaults. |
| `lmyzmail.smtp.asciiart.default-contrast` / `lmyzmail.smtp.asciiart.char-aspect` | `1.2 / 2.0` | Contrast and character aspect correction. |
| `lmyzmail.skibidi-inferx.enabled` | `true` | Enable Rust SafeTensors/BPE generation; unavailable engines use fixed fallback text. |
| `lmyzmail.skibidi-inferx.model-path` | `/usr/share/lmyzmail/models/skibidi-inferx/skibidi_ai.safetensors` | Read-only mmap weights; package ships compact-20261022, with original weights retained separately. |
| `lmyzmail.skibidi-inferx.tokenizer-path` | `/usr/share/lmyzmail/models/skibidi-inferx/tokenizer.json` | Matching BPE tokenizer. |
| `lmyzmail.skibidi-inferx.temperature` / `lmyzmail.skibidi-inferx.top-k` / `lmyzmail.skibidi-inferx.top-p` | `0.85 / 50 / 0.92` | Sampling parameters. |
| `lmyzmail.skibidi-inferx.max-tokens` | `80 (effective 120)` | Compatibility behavior: validated/reported setting, but generation retains the effective 120-token limit. |
| `lmyzmail.skibidi-inferx.timeout-ms` / `lmyzmail.skibidi-inferx.max-concurrent-generations` | `500 / 1` | Per-request deadline; one effective worker, immediate fallback when busy. Values above 1 do not add inference workers. |
| `lmyzmail.skibidi-inferx.fallback-on-error` | `true` | Compatibility setting: outer error/timeout handling returns fallback even when false. |
| `lmyzmail.skibidi-inferx.simd-level` | `auto` | auto/scalar/avx2/avx512; AVX2 requires FMA, AVX512 also AVX-512F; unsupported requests fall back safely. |

### HTCPCP

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.htcpcp.enabled` / `lmyzmail.htcpcp.default-brew-time-seconds` | `false / 30` | Enabled explicitly by the example; GET/HEAD/OPTIONS/PROPFIND/BREW/POST/WHEN state machine. |
| `lmyzmail.htcpcp.pots[n].id` / `lmyzmail.htcpcp.pots[n].type` | `pot-0 / coffee` | One default pot if omitted; type=coffee/tea/both. Up to 64, contiguous indices, unique IDs. |
| `lmyzmail.htcpcp.pots[n].tea-varieties` | `darjeeling,earl-grey,peppermint` | Allowed tea varieties as CSV. |
| `lmyzmail.htcpcp.pots[n].supported-additions` | `Cream,…,Stevia` | Allowed additions as CSV; full defaults and an eight-pot setup are in the example. |

### Minecraft 1.8.9

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.minecraft.enabled` / `lmyzmail.minecraft.online-mode` | `false / true` | Enable service and Mojang session authentication; mailbox authentication is still required in-game. |
| `lmyzmail.minecraft.compression-threshold` / `lmyzmail.minecraft.max-players` | `256 / 20` | Protocol compression threshold and player cap. |
| `lmyzmail.minecraft.motd` / `lmyzmail.minecraft.favicon` | `§6LMYZMAIL §7- Send emails in Minecraft / ""` | Server-list MOTD and favicon asset. |
| `lmyzmail.minecraft.read-timeout-seconds` / `lmyzmail.minecraft.session-server-url` | `30 / https://sessionserver.mojang.com/session/minecraft/hasJoined` | Read deadline and session-authentication URL. |
| `lmyzmail.minecraft.world-template` / `lmyzmail.minecraft.view-distance` / `lmyzmail.minecraft.max-concurrent-videos` | `worlds/mailroom / 32 / 2` | World template, view distance and global video concurrency budget. |
| `lmyzmail.minecraft.spawn.x` / `lmyzmail.minecraft.spawn.y` / `lmyzmail.minecraft.spawn.z` / `lmyzmail.minecraft.spawn.yaw` / `lmyzmail.minecraft.spawn.pitch` | `0.5 / 160 / 0.5 / 0 / 0` | Spawn coordinates and orientation. |
| `lmyzmail.minecraft.whitelist.enabled` / `lmyzmail.minecraft.whitelist.players` / `lmyzmail.minecraft.blacklist.players` | `false / [] / []` | Name allow/deny lists; CSV/[n] supported. |
| `lmyzmail.minecraft.auth.max-attempts` / `lmyzmail.minecraft.auth.lockout-seconds` / `lmyzmail.minecraft.auth.window-seconds` | `5 / 300 / 600` | Mailbox-login failure window and lockout. |
| `lmyzmail.minecraft.video.center-x` / `lmyzmail.minecraft.video.center-y` / `lmyzmail.minecraft.video.wall-z` | `0 / 180 / -20` | Block-video wall position. |
| `lmyzmail.minecraft.video.max-width` / `lmyzmail.minecraft.video.max-fps` / `lmyzmail.minecraft.video.default-width` / `lmyzmail.minecraft.video.default-fps` / `lmyzmail.minecraft.video.default-contrast` | `64 / 20 / 32 / 10 / 1.2` | Block-video limits and defaults. |
| `lmyzmail.minecraft.video.spawn-protect-radius` / `lmyzmail.minecraft.video.clear-margin` | `8 / 2` | Spawn protection radius and video cleanup margin. |
| `lmyzmail.minecraft.map-video.center-x` / `lmyzmail.minecraft.map-video.center-y` / `lmyzmail.minecraft.map-video.center-z` / `lmyzmail.minecraft.map-video.facing` | `0 / 180 / -20 / SOUTH` | Map wall position and facing (SOUTH/WEST/NORTH/EAST). |
| `lmyzmail.minecraft.map-video.max-maps-x` / `lmyzmail.minecraft.map-video.max-maps-y` / `lmyzmail.minecraft.map-video.max-fps` | `10 / 10 / 20` | Map-wall tile and FPS caps. |
| `lmyzmail.minecraft.map-video.default-maps-x` / `lmyzmail.minecraft.map-video.default-fps` / `lmyzmail.minecraft.map-video.default-contrast` | `5 / 10 / 1.2` | Default map-video width, FPS and contrast. |
| `lmyzmail.minecraft.map-video.base-map-id` / `lmyzmail.minecraft.map-video.base-entity-id` | `10000 / 100000` | Map/entity ID bases; avoid conflicts with custom worlds. |

### Honeypots, threat scores and SSH monitoring

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.honeypot.enabled` / `lmyzmail.honeypot.initial-delay-ms` / `lmyzmail.honeypot.post-banner-timeout-ms` | `false / 1500 / 10000` | TCP trap switch, pre-banner delay and post-banner read deadline. |
| `lmyzmail.honeypot.max-connections-per-trap` / `lmyzmail.honeypot.max-read-bytes` | `100 / 1024` | Per-trap connection cap and read budget. |
| `lmyzmail.honeypot.traps[n].port` / `lmyzmail.honeypot.traps[n].protocol` / `lmyzmail.honeypot.traps[n].label` / `lmyzmail.honeypot.traps[n].bind-address` | `required / NONE / trap / listen.host` | Up to 256; NONE/SMTP/SSH/FTP/MYSQL/POP3/IMAP/VNC. server-protocol aliases protocol. |
| `lmyzmail.cringe.decay.interval` / `lmyzmail.cringe.decay.amount` | `24h / 10` | Time-based score decay with current/historical statistics. |
| `lmyzmail.cringe.decay.check-interval` | `auto` | Defaults to interval/4 clamped to 1m..1h; alias `lmyzmail.cringe.decay.checkInterval`. |
| `lmyzmail.cringe.decay.activity-retention-days` | `360` | Activity retention in days. |
| `lmyzmail.fail2ban.enabled` / `lmyzmail.fail2ban.ssh-log-paths` | `false / /var/log/auth.log,/var/log/secure,/var/log/messages` | Tail the first readable SSH log from EOF; do not replay old history. |
| `lmyzmail.fail2ban.scan-interval` / `lmyzmail.fail2ban.max-retries` / `lmyzmail.fail2ban.find-time` | `10s / 5 / 10m` | Scan interval, failure threshold and observation window. |
| `lmyzmail.fail2ban.report-cooldown` / `lmyzmail.fail2ban.max-tracked-ips` / `lmyzmail.fail2ban.cleanup-interval` | `5m / 10000 / 5m` | Report cooldown, tracked-IP cap and cleanup interval. |

### XDP firewall and PPS

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.xdp.enabled` / `lmyzmail.xdp.interface-name` / `lmyzmail.xdp.bpf-object-path` / `lmyzmail.xdp.pin-path` | `false / eth0 / "" / /sys/fs/bpf/lmyzmail` | Empty object path uses pinned embedded BPF; configure kernel privileges and bpffs separately. |
| `lmyzmail.xdp.ban-threshold` / `lmyzmail.xdp.unban-threshold` | `50 / -1` | Score-based ban/unban; -1 derives ban-threshold/2. |
| `lmyzmail.xdp.force-generic-mode` / `lmyzmail.xdp.verbose` / `lmyzmail.xdp.sync-on-startup` | `false / false / true` | Generic XDP mode, verbose logging and startup score synchronization. |
| `lmyzmail.xdp.whitelist` | `127.0.0.1,::1` | IP allowlist, CSV or contiguous [n]. |
| `lmyzmail.xdp.reason-code-default` / `lmyzmail.xdp.reason-code-pps-overlimit` / `lmyzmail.xdp.reason-code-syn-flood` | `0 / 5 / 6` | Default, PPS and SYN event reason codes. |
| `lmyzmail.xdp.pps-monitor.enabled` / `lmyzmail.xdp.pps-monitor.poll-interval-ms` | `true / 1000` | Poll traffic statistics when XDP is enabled. |
| `lmyzmail.xdp.pps-monitor.pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.pps-critical-threshold` | `100000 / 200000` | Total PPS warning/critical thresholds. |
| `lmyzmail.xdp.pps-monitor.syn-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.syn-pps-critical-threshold` | `10000 / 20000` | Total SYN PPS thresholds. |
| `lmyzmail.xdp.pps-monitor.per-ip-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.per-ip-pps-critical-threshold` | `1000 / 5000` | Per-IP PPS thresholds. |
| `lmyzmail.xdp.pps-monitor.per-ip-syn-pps-warn-threshold` / `lmyzmail.xdp.pps-monitor.per-ip-syn-pps-critical-threshold` | `100 / 500` | Per-IP SYN PPS thresholds. |
| `lmyzmail.xdp.pps-monitor.consecutive-exceed-count` / `lmyzmail.xdp.pps-monitor.record-to-cringe` | `3 / true` | Consecutive excess polls and score recording. |
| `lmyzmail.xdp.pps-monitor.max-ips-per-poll` / `lmyzmail.xdp.pps-monitor.ring-buffer-size` | `10000 / 1024` | IP cap per poll and bounded event ring. |

### DMARC / TLS-RPT reporting

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.reporting.enabled` / `lmyzmail.reporting.auto-send-enabled` | `false / false` | Report collection/generation and automatic sending at 01:00 UTC daily. |
| `lmyzmail.reporting.batch-size` / `lmyzmail.reporting.flush-interval-ms` / `lmyzmail.reporting.retention-days` | `500 / 2000 / 90` | Accepted compatibility settings; bounded writers use internal budgets. Do not infer automatic history deletion from these values. |
| `lmyzmail.reporting.min-volume-for-report` | `10` | Minimum message count for date-based report-domain enumeration. |
| `lmyzmail.reporting.dmarc-report-sender-address` / `lmyzmail.reporting.dmarc-report-sender-password` / `lmyzmail.reporting.tls-report-sender-address` / `lmyzmail.reporting.tls-report-sender-password` | `"" / "" / "" / ""` | Mailbox credentials for report delivery; configure before enabling it. |
| `lmyzmail.reporting.organization-name` / `lmyzmail.reporting.organization-email` | `"" / ""` | Organization identity in aggregate reports. |
| `lmyzmail.reporting.dns-server` | `""` | Numeric IP:port DNS override for report RUA discovery. |
| `lmyzmail.reporting.http-delivery-enabled` / `lmyzmail.reporting.http-delivery-timeout-seconds` | `true / 30` | TLS-RPT HTTPS delivery; explicitly false in the example. Destination-address restrictions apply. |

### Built-in stress test and UI

| Key | Default | Purpose and behavior |
| --- | --- | --- |
| `lmyzmail.stress-test-enabled` | `false` | Enable only in isolated tests; management endpoints create real SMTP/disk/database load. |
| `lmyzmail.stress-test-sender-prefix` / `lmyzmail.stress-test-receiver-prefix` | `stresstest_send / stresstest_receive` | Test mailbox prefixes; keep separate from real mailboxes. |
| `lmyzmail.stress-test-password` | `explicit secret` | Set a protected password explicitly before enabling; do not rely on a historical fallback. |
| `lmyzmail.stress-test-count` / `lmyzmail.stress-test-warmup-count` / `lmyzmail.stress-test-warmup-rounds` | `5000 / 1000 / 2` | Production count, warmup count/rounds; each /start advances one round. |
| `lmyzmail.stress-test-email-size-kb` | `100` | KiB, clamped to 1..10240; set a hard disk budget for large tiers. |
| `lmyzmail.show-internet-nl-badge` | `false` | Web UI badge switch. |

### Compatibility aliases

See the complete editable [lmyzmail.properties.example](config/lmyzmail.properties.example). For example, set `lmyzmail.domains.main.domain=example.com`; additional domains need their own `<name>` entry.

Ordinary settings accept their supported legacy namespace aliases. This table lists mappings that involve more than a prefix change. Within a namespace, prefer the recommended canonical key. Domain entries also accept `receiveEnabled/sendEnabled/requireExistingMailbox/dkimSelector/dkimPrivateKeyPath/listUnsubscribeMailto/listUnsubscribeUrl`; API keys accept `readEnabled/writeEnabled`, and traps accept `server-protocol`.

| Canonical key | Compatibility alias |
| --- | --- |
| `lmyzmail.http.port` | `lmyzmail.netty.http.port; botmail.netty.http.port` |
| `lmyzmail.http.max-request-bytes / lmyzmail.http.max-multipart-bytes` | `lmyzmail.netty.http.max-content-length / lmyzmail.netty.http.max-multipart-size; botmail.netty.http.*` |
| `lmyzmail.http.trusted-proxies` | `lmyzmail.netty.http.trusted-proxies; botmail.netty.http.trusted-proxies` |
| `lmyzmail.http.request-timeout-ms` | `botmail.netty.http.idle-timeout-seconds (seconds → ms)` |
| `lmyzmail.postgres.url / host / port / database / username / password` | `spring.datasource.url / host / port / database / username / password` |
| `lmyzmail.postgres.pool.max-size` | `spring.datasource.hikari.maximum-pool-size` |
| `lmyzmail.redis.host / port / database / username / password` | `spring.data.redis.host / port / database / username / password` |
| `lmyzmail.redis.username / password / tls-enabled` | `spring.redis.username / password / ssl; spring.data.redis.ssl.enabled; lmyzmail.redis.ssl.enabled` |
| `lmyzmail.redis.pool.max-active` | `spring.data.redis.lettuce.pool.max-active` |
| `lmyzmail.outbound.dns.mx.l1-max-entries / l1-ttl-minutes / l2-ttl-minutes / negative-ttl-minutes` | `dns.cache.mx.l1-max-size / l1-ttl-minutes / l2-ttl-minutes / negative-ttl-minutes` |
| `lmyzmail.outbound.dns.query-timeout-seconds` | `dns.cache.mx.query-timeout-seconds` |
| `lmyzmail.outbound.spool-dir` | `botmail.outbound.temp-dir` |


## HTTP endpoints

These are all normal application routes; scanner-decoy paths use the separate registry described above. `public` needs no session. `session` uses `X-Session-Token`. `read/write` requires the respective `X-API-Key` permission. An API key does not replace mailbox credentials or grant access to Web session routes. URI-encode path components; use file identifiers returned by listing, not arbitrary filesystem paths.

| Method | Path | Auth | Purpose |
| --- | --- | --- | --- |
| GET | `/`<br>`/index.html`<br>`/cringe.html`<br>`/favicon.ico`<br>`/images/embed-badge-emailtest-internet.nl.svg` | `public` | Webmail, threat dashboard and static assets |
| GET | `/api/health`<br>`/api/skibidi`<br>`/web/domains`<br>`/web/config` | `public` | Health, banner, domains and public capabilities |
| POST | `/web/login`<br>`/web/register` | `public` | JSON address/password; signup respects configuration and rate limits |
| POST | `/web/logout` | `public` | Revoke the supplied X-Session-Token; callable without a token |
| POST | `/api/status` | `read` | Service status |
| POST | `/api/mailboxes` | `write` | Create mailbox; JSON address/password |
| GET | `/api/mailboxes/{address}/exists` | `read` | Mailbox existence |
| POST | `/api/mail/send` | `write` | Mailbox credentials and mail JSON; asynchronous queueing |
| POST | `/api/mail/poll`<br>`/api/mail/raw`<br>`/api/mail/rawDecoded` | `read` | Mailbox credentials additionally required; fields below |
| GET | `/api/mail/status/{queueId}`<br>`/api/mail/status/message/{messageId}`<br>`/api/mail/quota` | `read` | Queue/Message-ID status; quota?address= |
| GET | `/api/reports/status`<br>`/api/reports/domains`<br>`/api/reports/addresses/{domain}` | `read` | Report state, ?date=YYYY-MM-DD and RUA addresses |
| POST | `/api/reports/trigger`<br>`/api/reports/domain/{domain}` | `write` | Generate/deliver reports; optional ?date=YYYY-MM-DD |
| POST | `/api/stress/start`<br>`/api/stress/reset`<br>`/api/stress/cleanup` | `write` | Run one round, reset rounds, clean stress-test data |
| POST | `/api/stress/status` | `read` | Uses POST, not GET |
| GET | `/api/xdp-firewall/status`<br>`/api/xdp-firewall/stats`<br>`/api/xdp-firewall/check`<br>`/api/xdp-firewall/whitelist/check` | `read` | State/statistics; checks use ?ip= |
| POST | `/api/xdp-firewall/ban`<br>`/api/xdp-firewall/unban`<br>`/api/xdp-firewall/sync` | `write` | ?ip=; ban accepts &reason=; sync reconciles scores |
| DELETE | `/api/xdp-firewall/clear` | `write` | Clear bans; use carefully |
| GET | `/api/cringe-ips/insults`<br>`/api/cringe-ips/export`<br>`/api/cringe-ips/above-score/{score}` | `read` | Paged search, export and score filtering |
| GET | `/api/cringe-ips/{ip}/activities`<br>`/api/cringe-ips/{ip}/decay-estimate`<br>`/api/cringe-ips/decay-config` | `read` | Activities and decay estimate/configuration |
| GET | `/api/cringe-ips` | `read` | Paginated threat-IP list with score/count/time/IP sorting, search and XDP status |
| GET | `/api/cringe-ips/stats` | `read` | IP/activity counts, independent historical/current risk thresholds and decay configuration; current activity writes use direct mode |
| GET | `/api/cringe-ips/{ip}` | `read` | Successful handler is absent in this candidate; authorized requests still return 404 |
| POST | `/api/cringe-ips/decay` | `write` | Trigger score decay |
| GET | `/web/mail/list`<br>`/web/mail/list/{folder}` | `session` | page=0&size=50&starredOnly=false |
| GET | `/web/mail/detail/{folder}/{file}`<br>`/web/mail/raw/{folder}/{file}`<br>`/web/mail/headers/{folder}/{file}`<br>`/web/mail/attachment/{folder}/{file}/{index}` | `session` | Detail, raw message, headers and attachment |
| POST | `/web/mail/send`<br>`/web/mail/send/multipart` | `session` | JSON or streamed multipart sending |
| GET | `/web/mail/send/status/{queueId}`<br>`/web/mail/send/status/file/{fileName}`<br>`/web/mail/quota` | `session` | Own-mailbox delivery state and quota |
| DELETE | `/web/mail/{folder}/{file}` | `session` | Delete a message |
| POST | `/web/mail/star/{folder}/{file}`<br>`/web/userdata/stars/{folder}/{fileName}` | `session` | Toggle star |
| GET | `/web/userdata/stars/{folder}` | `session` | Folder stars |
| GET POST | `/web/userdata/preferences`<br>`/web/userdata/contacts`<br>`/web/userdata/labels` | `session` | Read/write preferences, contacts and labels |
| PUT DELETE | `/web/userdata/contacts/{id}`<br>`/web/userdata/labels/{id}` | `session` | Update/delete contacts or labels |
| GET | `/web/userdata/labels/email/{folder}/{fileName}` | `session` | Assigned message labels |
| POST DELETE | `/web/userdata/labels/email/{folder}/{fileName}/{labelId}` | `session` | Assign/remove a message label |


Threat-IP listing defaults to `page=0`, `size=50`, `sortBy=currentScore`, `sortDir=desc` and `search=`; page size is capped at 500. Sort fields use an allowlist, with unknown fields falling back to current score. Only case-insensitive `asc` selects ascending order. Search ignores case and retains `%`/`_` wildcards. Responses preserve the original `searchQuery`, include `xdpBanned`/`whitelisted` per IP and report total rows/pages. Malformed pagination returns 400.

The statistics endpoint counts `totalIPs`, historical scores `>=50`, current scores `>=50`, current scores `>0`, and actual activity rows. `decayConfig` contains an ISO duration string, amount and hourly rate. Activity producers currently commit directly: `batchStats.running=false`, and queue/cache/batch counters are zero because no batch worker exists. Legacy batch-enabled operation and its five configuration keys remain an explicit gap (G20); these zero values do not prove batch-mode support. Per-IP detail remains G19. See the [statistics/dashboard validation](docs/cringe-stats-validation-20261024.md) and [list validation](docs/cringe-list-validation-20261024.md).

The implemented insults list accepts `page`, `size` and `search`; exports accept `minScore` and `scoreType`. User-data payloads follow the [user-data types](crates/lmyzmail/src/userdata.rs); the Web UI uses these same endpoints.

### Request examples

Add an administrator key to protected configuration, replacing the placeholder, then restart:

```properties
lmyzmail.api-keys[0].key=REPLACE_WITH_A_RANDOM_SECRET
lmyzmail.api-keys[0].label=operations
lmyzmail.api-keys[0].read=true
lmyzmail.api-keys[0].write=true
```

Set `API_KEY` in the caller's environment from its secret store. Create a mailbox; passwords require at least eight UTF-16 code units:

```bash
curl --fail-with-body http://127.0.0.1:8080/api/mailboxes \
  -H "X-API-Key: $API_KEY" -H 'Content-Type: application/json' \
  --data '{"address":"alice@example.com","password":"REPLACE_WITH_MAILBOX_PASSWORD"}'
```

Send this JSON to `POST /api/mail/send` with the API key. `to/cc/bcc` are address arrays; `inReplyTo/references` are optional. Attachment content uses Base64; account for MIME expansion in message-size limits.

```json
{
  "from": "alice@example.com",
  "password": "REPLACE_WITH_MAILBOX_PASSWORD",
  "to": ["bob@example.net"],
  "cc": [],
  "bcc": [],
  "subject": "Hello",
  "text": "Hello from lmyzmail",
  "html": "<p>Hello from lmyzmail</p>",
  "attachments": [{
    "filename": "note.txt",
    "contentType": "text/plain",
    "contentBase64": "SGVsbG8K",
    "inline": false,
    "contentId": null
  }],
  "async": true
}
```

`POST /api/mail/poll` accepts `address,password,sinceEpochMillis,limit`. `/api/mail/raw` accepts `address,password,file`; `/api/mail/rawDecoded` additionally accepts `html`. These compatibility raw APIs retain a 32 KiB source limit. Use session downloads for complete messages/attachments; changing the overall message limit does not remove this separate limit.

Log in with `POST /web/login` and `{"address":"alice@example.com","password":"…"}`. Send the returned `token` as `X-Session-Token`. Session sending uses the authenticated mailbox identity without resubmitting its password. For large attachments, streamed multipart uses a JSON `data` part and file parts named `attachments`:

```bash
curl --fail-with-body http://127.0.0.1:8080/web/mail/send/multipart \
  -H "X-Session-Token: $SESSION_TOKEN" \
  -F 'data={"to":["bob@example.net"],"subject":"Report","text":"Attached"};type=application/json' \
  -F 'attachments=@report.pdf;type=application/pdf'
```

`202` means accepted, not delivered. Poll queueId/messageId status. Route-specific errors include `400` invalid input, `401` invalid credentials/session, `403` permission/ban, `404` absent resource, `413` size limit, `429` rate limit and `500/503` backend/capacity failure. Read the JSON `error`; do not retry every non-200 response indiscriminately.

## Operations and troubleshooting

- **Startup:** check journal output, ownership/permissions, occupied ports, database schema and Redis ACL. Parsing configuration does not prove connectivity. SMTP 25 needs low-port privileges; XDP needs a separate profile. Never start competing runtimes against the same state.
- **Queued mail:** inspect queueId/Message-ID, then MX/DNS, outbound TCP 25, TLS/MTA-STS, quotas, leases and retry times. Preserve matching Sent/spool/queue identities instead of deleting one side to clear counters.
- **Capacity/backpressure:** observe RSS, FDs, tasks, queue depth/oldest task, latency/errors, PostgreSQL connections/locks, Redis memory/latency and Maildir/spool bytes/inodes. Concurrency, quotas, pools and deadlines govern different resources. Raising one limit does not guarantee throughput. Put all persistent services on appropriate storage.
- **Durability:** fsync=true is the default. false is for deployments explicitly accepting data loss, or benchmarks aligned with non-fsync behavior; it does not change database commit policy. Test durability with fsync enabled.
- **Shutdown/recovery:** use `systemctl stop lmyzmail` or SIGTERM and allow bounded shutdown; the process deadline is 35 seconds. Forced-kill recovery validates unfinished state, but remaining crash-boundary acceptance is tracked separately. Preserve recovery/quarantine diagnostics; do not clear intent records manually.
- **Models/video:** inspect paths, permissions, hashes, model metadata, selected backend and deadlines. Fallback text does not prove model health. Restart after configuration, model or certificate changes.
- **Upgrade:** back up, rerun the installer, inspect preserved configuration and explicitly start after upgrading. Packaged assets are replaced atomically. Keep old binaries/configuration until verification.
- **Uninstall:** `sudo tools/uninstall-lmyzmail.sh` removes managed binaries/unit only after verified shutdown. It retains configuration, PostgreSQL/Redis, Maildir/spool, logs, model/video assets, user and BPF pins. Failure to stop or detach XDP prevents removal. Uninstall is not data erasure.

There is no promised Prometheus exporter or generic online configuration API. Use APIs, journal and external resource sampling. Keep benchmark state isolated from production. `/api/stress/start` sends and receives real mail for one round; reset changes round counters and cleanup removes owned stress data. Formal throughput uses one complete endpoint invocation, without harness batching; hard resource budgets and independent audits belong to the [external harness](blackbox/src/lmyzmail_blackbox).

## Existing data and rollback

Existing PostgreSQL schema/transaction behavior, Redis keys/TTLs, Maildir bytes, certificates, models and supported configuration aliases are preserved. Additive `lmyzmail_*` recovery tables do not replace legacy business columns; retain them during rollback. Take a consistent backup of PostgreSQL, Redis, the full Maildir/spool, configuration, certificates and models. Stop the previous service and disable automatic restarts. **Never run both outbound workers against one queue.**

Ordinary existing addresses can be adopted directly. Underscores, repeated dots, literal v1- prefixes and Unicode involve historical directory aliases; follow [Maildir ownership/takeover](docs/maildir-takeover.md). Colliding lossy aliases belonging to different real mailboxes are refused, rather than reproducing insecure ownership. For an old reader, export encoded mail to a new directory using the [copy-only, fsynced offline exporter](docs/maildir-offline-rollback.md), preserving the source. Retain original absolute spool paths because PENDING file-mode tasks may reference them.

Other compatibility edges include InferX's effective 120 tokens/single worker/outer fallback, historical `BDAT 0 LAST` acknowledgement/discard behavior and the raw API's 32 KiB cap. See the [compatibility record](docs/compatibility.md) for evidenced exceptions. Using C probability semantics is an explicit behavior choice. Tested handoff does not prove every in-flight crash boundary.

## Build and validation

The repository contains pinned native sources, third-party foundations, models, resources, tests, goldens and evidence. Rust is pinned to **stable 1.94.0**, target `x86_64-unknown-linux-gnu`, with `Cargo.lock`. Build dependencies include C/C++, Clang **18.1.3**, pkg-config, libbpf/libelf, zlib/OpenSSL and Cairo/FreeType development packages. FFmpeg 7.1 is built from pinned repository sources. The production service needs no oracle.

```bash
rustup show
LMYZMAIL_BPF_CLANG=clang-18 cargo build --release --locked \
  --target x86_64-unknown-linux-gnu -p lmyzmail
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
tools/test-installation.sh
tools/verify-release-reproducibility.sh /absolute/path/to/new-verification-output
```

The Python 3.12/pytest, raw-socket and Playwright harness starts isolated ports, temporary directories and PostgreSQL/Redis state. `blackbox/bin/bootstrap-python.sh` installs locked dependencies; `provision-runtime.sh` / `provision-playwright.sh` prepare validation runtimes. Java is used only as a development oracle. See [local validation](docs/local-validation-20261023.md) for campaign conditions and evidence. Never run acceptance against production state.

Retained evidence covers HTTP/UI/permissions/attachments, security, SMTP/MIME/retries/reports, Redis/PostgreSQL/Maildir, scheduling/restart, HTCPCP, Minecraft, honeypots, inference and rendering. Long-running load, malformed/fuzz/fault inputs and every requirement still need item-level evidence; a test total is not a coverage proof. Historical goldens remain unchanged, only genuine nondeterminism is normalized, and failures are retained.

Further references: [queue](docs/outbound-queue-contract.md), [routing](docs/outbound-route-contract.md), [report triggers](docs/reporting-trigger-contract.md), [HTTPS reporting](docs/reporting-https-contract.md), [SSH monitoring](docs/fail2ban-contract.md), [release](docs/release.md), [acceptance](docs/acceptance-status.md). Historical evidence keeps its original SHAs; the [identity migration map](docs/git-identity-migration-20261023.md) resolves rewritten commits.
