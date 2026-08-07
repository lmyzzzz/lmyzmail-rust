# Outbound route contract

`lmyzmail::outbound_route` resolves one recipient domain into ordered, pinned
SMTP endpoints and an effective TLS mode. It is an internal component of the
single process. It never opens an SMTP connection and is not a background
worker by itself.

## Compatibility surface

Configuration uses the new key first and then the exact frozen alias:

| New key | Frozen alias | Default |
| --- | --- | ---: |
| `lmyzmail.outbound.dns.mx.l1-max-entries` | `dns.cache.mx.l1-max-size` | 10000 |
| `lmyzmail.outbound.dns.mx.l1-ttl-minutes` | `dns.cache.mx.l1-ttl-minutes` | 15 |
| `lmyzmail.outbound.dns.mx.l2-ttl-minutes` | `dns.cache.mx.l2-ttl-minutes` | 30 |
| `lmyzmail.outbound.dns.mx.negative-ttl-minutes` | `dns.cache.mx.negative-ttl-minutes` | 5 |
| `lmyzmail.outbound.dns.query-timeout-seconds` | `dns.cache.mx.query-timeout-seconds` | 15 |
| `lmyzmail.smtp.mta-sts-fetch-timeout-ms` | `botmail.smtp.mta-sts-fetch-timeout-ms` | 10000 |
| `lmyzmail.outbound.route-deadline-seconds` | none | 30 |

The Redis keys and values remain byte-compatible:

- `dns:mx:{domain}` stores a comma-separated stable MX list or the exact
  `\0FALLBACK\0` marker. Positive and fallback TTLs retain the configured 30
  and 5 minute defaults.
- `mta-sts:{domain}` stores the frozen six-field pipe serialization. Positive
  TTL is `min(max_age, 604800)` seconds; NONE uses 300 seconds.
- Cache reads accept only strings with a positive TTL and at most 128 KiB.
  Wrong types, persistent keys, corrupt values, and oversized values are
  ignored without deleting caller-owned Redis data.

## Resolution sequence

1. Normalize the recipient domain to a bounded lower-case ASCII hostname.
2. Resolve MX through bounded Moka singleflight, the legacy Redis key, and
   Hickory DNS. Sort by preference with stable equal-preference ordering.
3. Use direct-domain delivery after no MX or a DNS failure, as the Java oracle
   does. Recognize RFC 7505 null MX before fallback.
4. Load MTA-STS through its L1 cache, legacy Redis value, strict TXT selection,
   and a pinned HTTPS GET to
   `https://mta-sts.{domain}/.well-known/mta-sts.txt`.
5. In enforce mode, keep matching MX hosts only and require STARTTLS. Testing
   retains every MX host and uses opportunistic TLS. NONE does the same without
   a policy.
6. Resolve every host's A/AAAA answer, reject the entire hostname if any answer
   is non-public, preserve the frozen A-before-AAAA family order, and pin the
   first validated address on TCP port 25. A failed hostname advances to the
   next ordered MX host.

The policy HTTP client disables proxies and redirects, retains the policy
hostname for SNI and certificate verification, pins only the already validated
addresses, requires status 200 and `text/plain`, and streams the response into
a 64 KiB buffer ceiling.

## Budgets and cancellation

One route has a monotonic absolute deadline. Redis operations are additionally
limited to two seconds. DNS and HTTPS have bounded per-operation timeouts.
Every singleflight waiter observes its own cancellation and deadline; cancelling
one waiter does not cancel another waiter's route.

The fixed adversarial ceilings are 1024 admitted routes, 32 active Hickory DNS
requests, 32 active policy HTTPS fetches, 8192 Hickory response-cache entries,
64 MX records, 16 addresses per hostname, 16 TXT records, 4096 aggregate TXT
bytes, 64 policy MX patterns, 64 KiB policy body, 128 KiB Redis value, 100000 L1
MX entries, and 10000 MTA-STS L1 entries.
The approved differences are recorded in
`blackbox/manifests/behavior-differences.json`.

## Verification boundary

Crate-internal tests inject deterministic DNS and HTTPS backends for ordering,
fallback, policy modes, malformed responses, budgets, singleflight, deadline,
and cancellation. A real isolated Redis process verifies legacy keys,
serialization, TTL preservation, corrupt-entry handling, and negative-cache
reuse across resolver reconstruction.

This component is production route logic consumed by the internal outbound
coordinator. `main` now owns the bounded delivery worker and supervises it under
the process cancellation token; constructing the resolver itself still creates
no background task or independent service.
