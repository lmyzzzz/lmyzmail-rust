use std::{
    collections::HashMap,
    fs,
    net::{IpAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use deadpool_redis::redis;
use tokio::{task::JoinSet, time::sleep};

use super::*;
use crate::{
    config::{Properties, RuntimeConfig},
    redis::create_pool,
};

type FakeDnsResults<T> = Mutex<HashMap<String, Result<T, DnsFailure>>>;
type FakeHttpResults = Mutex<HashMap<String, Result<PolicyHttpResponse, RouteError>>>;

struct FakeDnsState {
    mx: FakeDnsResults<Vec<MxAnswer>>,
    txt: FakeDnsResults<Vec<Vec<u8>>>,
    addresses: FakeDnsResults<Vec<IpAddr>>,
    mx_calls: AtomicUsize,
    txt_calls: AtomicUsize,
    address_calls: AtomicUsize,
    delay: Duration,
}

#[derive(Clone)]
struct FakeDns {
    state: Arc<FakeDnsState>,
}

impl FakeDns {
    fn new(delay: Duration) -> Self {
        Self {
            state: Arc::new(FakeDnsState {
                mx: Mutex::new(HashMap::new()),
                txt: Mutex::new(HashMap::new()),
                addresses: Mutex::new(HashMap::new()),
                mx_calls: AtomicUsize::new(0),
                txt_calls: AtomicUsize::new(0),
                address_calls: AtomicUsize::new(0),
                delay,
            }),
        }
    }

    fn set_mx(&self, name: &str, result: Result<Vec<MxAnswer>, DnsFailure>) {
        self.state.mx.lock().unwrap().insert(name.into(), result);
    }

    fn set_txt(&self, name: &str, result: Result<Vec<Vec<u8>>, DnsFailure>) {
        self.state.txt.lock().unwrap().insert(name.into(), result);
    }

    fn set_addresses(&self, name: &str, result: Result<Vec<IpAddr>, DnsFailure>) {
        self.state
            .addresses
            .lock()
            .unwrap()
            .insert(name.into(), result);
    }

    fn mx_calls(&self) -> usize {
        self.state.mx_calls.load(Ordering::Acquire)
    }

    fn txt_calls(&self) -> usize {
        self.state.txt_calls.load(Ordering::Acquire)
    }

    fn address_calls(&self) -> usize {
        self.state.address_calls.load(Ordering::Acquire)
    }
}

async fn delayed_dns<T>(
    result: Result<T, DnsFailure>,
    delay: Duration,
    deadline: Instant,
    cancellation: &CancellationToken,
) -> Result<T, DnsFailure> {
    tokio::select! {
        _ = cancellation.cancelled() => Err(DnsFailure::Cancelled),
        _ = tokio::time::sleep_until(deadline) => Err(DnsFailure::Temporary),
        _ = sleep(delay) => result,
    }
}

impl DnsBackend for FakeDns {
    fn mx<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<MxAnswer>, DnsFailure>> {
        Box::pin(async move {
            self.state.mx_calls.fetch_add(1, Ordering::AcqRel);
            let result = self
                .state
                .mx
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or(Err(DnsFailure::NoRecords));
            delayed_dns(result, self.state.delay, deadline, cancellation).await
        })
    }

    fn txt<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<Vec<u8>>, DnsFailure>> {
        Box::pin(async move {
            self.state.txt_calls.fetch_add(1, Ordering::AcqRel);
            let result = self
                .state
                .txt
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or(Err(DnsFailure::NoRecords));
            delayed_dns(result, self.state.delay, deadline, cancellation).await
        })
    }

    fn addresses<'a>(
        &'a self,
        name: &'a str,
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<Vec<IpAddr>, DnsFailure>> {
        Box::pin(async move {
            self.state.address_calls.fetch_add(1, Ordering::AcqRel);
            let result = self
                .state
                .addresses
                .lock()
                .unwrap()
                .get(name)
                .cloned()
                .unwrap_or(Err(DnsFailure::NoRecords));
            delayed_dns(result, self.state.delay, deadline, cancellation).await
        })
    }
}

struct FakeHttpState {
    responses: FakeHttpResults,
    calls: AtomicUsize,
    delay: Duration,
}

#[derive(Clone)]
struct FakeHttp {
    state: Arc<FakeHttpState>,
}

impl FakeHttp {
    fn new(delay: Duration) -> Self {
        Self {
            state: Arc::new(FakeHttpState {
                responses: Mutex::new(HashMap::new()),
                calls: AtomicUsize::new(0),
                delay,
            }),
        }
    }

    fn set_response(&self, domain: &str, response: PolicyHttpResponse) {
        self.state
            .responses
            .lock()
            .unwrap()
            .insert(domain.into(), Ok(response));
    }

    fn calls(&self) -> usize {
        self.state.calls.load(Ordering::Acquire)
    }
}

impl PolicyHttpBackend for FakeHttp {
    fn fetch<'a>(
        &'a self,
        domain: &'a str,
        _addresses: &'a [IpAddr],
        deadline: Instant,
        cancellation: &'a CancellationToken,
    ) -> BoxFuture<'a, Result<PolicyHttpResponse, RouteError>> {
        Box::pin(async move {
            self.state.calls.fetch_add(1, Ordering::AcqRel);
            let result = self
                .state
                .responses
                .lock()
                .unwrap()
                .get(domain)
                .cloned()
                .unwrap_or_else(|| {
                    Err(route_error(
                        RouteErrorKind::Temporary,
                        "fake policy response missing",
                    ))
                });
            tokio::select! {
                _ = cancellation.cancelled() => Err(cancelled()),
                _ = tokio::time::sleep_until(deadline) => Err(route_error(
                    RouteErrorKind::Temporary,
                    "fake policy request timed out",
                )),
                _ = sleep(self.state.delay) => result,
            }
        })
    }
}

fn mx(preference: u16, host: &str) -> MxAnswer {
    MxAnswer {
        preference,
        host: host.into(),
    }
}

fn ip(value: &str) -> IpAddr {
    IpAddr::from_str(value).unwrap()
}

fn policy_response(mode: &str, pattern: &str) -> PolicyHttpResponse {
    PolicyHttpResponse {
        status: 200,
        content_type: Some("text/plain; charset=utf-8".into()),
        body: format!("version: STSv1\r\nmode: {mode}\r\nmx: {pattern}\r\nmax_age: 300\r\n")
            .into_bytes(),
    }
}

fn route_config() -> OutboundRouteConfig {
    OutboundRouteConfig {
        mx_l1_max_entries: 128,
        mx_l1_ttl_minutes: 15,
        mx_l2_ttl_minutes: 30,
        mx_negative_ttl_minutes: 5,
        dns_query_timeout_seconds: 2,
        mta_sts_fetch_timeout_ms: 2_000,
        resolution_deadline_seconds: 3,
    }
}

fn pool_at(port: u16) -> Pool {
    let mut properties = Properties::default();
    properties
        .insert("lmyzmail.redis.host".into(), "127.0.0.1".into())
        .unwrap();
    properties
        .insert("lmyzmail.redis.port".into(), port.to_string())
        .unwrap();
    create_pool(&RuntimeConfig::from_properties(properties).unwrap()).unwrap()
}

fn unavailable_pool() -> Pool {
    let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    pool_at(port)
}

fn resolver(
    config: OutboundRouteConfig,
    mta_sts_enabled: bool,
    pool: Pool,
    dns: FakeDns,
    http: FakeHttp,
) -> OutboundRouteResolver {
    OutboundRouteResolver::new(config, mta_sts_enabled, pool, Arc::new(dns), Arc::new(http))
}

fn resolver_with_limit(limit: usize, dns: FakeDns, http: FakeHttp) -> OutboundRouteResolver {
    OutboundRouteResolver::new_with_route_limit(
        route_config(),
        false,
        unavailable_pool(),
        Arc::new(dns),
        Arc::new(http),
        limit,
    )
}

#[test]
fn mta_sts_dns_record_selection_is_strict_and_bounded() {
    assert_eq!(
        parse_mta_sts_record_id("v=STSv1; id=Policy123;"),
        Some("Policy123".into())
    );
    assert_eq!(
        parse_mta_sts_record_id("v=STSv1\t; id=first; id=second;"),
        Some("first".into())
    );
    assert!(parse_mta_sts_record_id("V=STSv1; id=x;").is_none());
    assert!(parse_mta_sts_record_id("v=STSv1;; id=x;").is_none());
    assert!(parse_mta_sts_record_id("v=STSv1; id=with-dash;").is_none());
    assert_eq!(
        select_mta_sts_record(&[b"invalid".to_vec(), b"v=STSv1; id=one;".to_vec()]),
        Some("one".into())
    );
    assert!(
        select_mta_sts_record(&[b"v=STSv1; id=one;".to_vec(), b"v=STSv1; id=two;".to_vec()])
            .is_none()
    );
    assert!(select_mta_sts_record(&vec![b"v=STSv1; id=x;".to_vec(); 17]).is_none());
    assert!(select_mta_sts_record(&[vec![b'x'; MAX_TXT_BYTES + 1]]).is_none());
}

#[test]
fn policy_parser_preserves_first_fields_and_one_label_wildcards() {
    let policy = parse_policy_file(
        "# comment\r\nversion: STSv1\r\nmode: enforce\r\n\
         mode: testing\r\nmx: mail.example.test\r\nmx: *.mx.example.test\r\n\
         max_age: 9999999999\r\nmax_age: 1\r\nignored: value\r\n",
        "Policy1",
        1_700_000_000_000,
    )
    .unwrap();
    assert_eq!(policy.mode, MtaStsMode::Enforce);
    assert_eq!(policy.max_age_seconds, MAX_MTA_STS_AGE_SECONDS);
    assert!(policy.matches_mx("MAIL.EXAMPLE.TEST."));
    assert!(policy.matches_mx("a.mx.example.test"));
    assert!(!policy.matches_mx("a.b.mx.example.test"));
    assert!(!policy.matches_mx("mx.example.test"));
    assert_eq!(
        validate_mx_pattern("mx_bad.example.test").unwrap(),
        "mx_bad.example.test"
    );
    assert_eq!(
        validate_mx_pattern("*.mx..example.test").unwrap(),
        "*.mx..example.test"
    );
    assert!(
        parse_policy_file("version: bad\nmode: enforce\nmx: a.b\nmax_age: 1", "x", 1).is_none()
    );
    assert!(parse_policy_file("version: STSv1\nmode: enforce\nmax_age: 1", "x", 1).is_none());

    let mut too_many_patterns = String::from("version: STSv1\nmode: enforce\nmax_age: 1\n");
    for index in 0..=MAX_POLICY_PATTERNS {
        too_many_patterns.push_str(&format!("mx: mx{index}.example.test\n"));
    }
    assert!(parse_policy_file(&too_many_patterns, "x", 1).is_none());
}

#[test]
fn legacy_policy_cache_round_trip_and_negative_entry_are_compatible() {
    let policy = MtaStsPolicy {
        version: Some("STSv1".into()),
        mode: MtaStsMode::Testing,
        mx_patterns: vec!["mail.example.test".into()],
        max_age_seconds: 300,
        policy_id: Some("abc123".into()),
        fetched_at_epoch_millis: 1_700_000_000_000,
    };
    assert_eq!(
        MtaStsPolicy::deserialize_legacy(&policy.serialize_legacy()),
        Some(policy)
    );
    let none = MtaStsPolicy::none(1_700_000_000_000);
    assert_eq!(
        MtaStsPolicy::deserialize_legacy(&none.serialize_legacy()),
        Some(none)
    );
    assert!(MtaStsPolicy::deserialize_legacy("STSv1|BAD||||").is_none());
    let permissive = MtaStsPolicy::deserialize_legacy(
        "STSv1|ENFORCE|mx_bad.example.test,*.mx..example.test|300|id|1700000000000",
    )
    .unwrap();
    assert_eq!(
        permissive.mx_patterns,
        ["mx_bad.example.test", "*.mx..example.test"]
    );
}

#[test]
fn host_and_cache_parsing_are_bounded() {
    assert_eq!(normalize_host("ExAmPle.Test.").unwrap(), "example.test");
    assert!(normalize_host("127.0.0.1").is_err());
    assert!(normalize_host("a..example.test").is_err());
    assert_eq!(
        deserialize_mx_hosts("mx1.example.test,mx2.example.test").unwrap(),
        ["mx1.example.test", "mx2.example.test"]
    );
    assert!(deserialize_mx_hosts("").is_none());
    assert!(is_plain_text(Some("Text/Plain; charset=utf-8")));
    assert!(!is_plain_text(Some("text/html")));
    assert!(!is_plain_text(None));
}

#[tokio::test]
async fn routes_mx_in_stable_preference_order_and_uses_direct_fallback() {
    let dns = FakeDns::new(Duration::ZERO);
    dns.set_mx(
        "ordered.test",
        Ok(vec![
            mx(20, "mx3.ordered.test."),
            mx(10, "mx1.ordered.test."),
            mx(10, "mx2.ordered.test."),
        ]),
    );
    dns.set_addresses("mx1.ordered.test", Ok(vec![ip("1.1.1.1")]));
    dns.set_addresses("mx2.ordered.test", Ok(vec![ip("8.8.8.8")]));
    dns.set_addresses("mx3.ordered.test", Ok(vec![ip("9.9.9.9")]));
    dns.set_mx("fallback.test", Err(DnsFailure::Temporary));
    dns.set_addresses("fallback.test", Ok(vec![ip("1.0.0.1")]));
    let route_resolver = resolver(
        route_config(),
        false,
        unavailable_pool(),
        dns,
        FakeHttp::new(Duration::ZERO),
    );

    let ordered = route_resolver
        .resolve("ORDERED.TEST.", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(
        ordered
            .candidates
            .iter()
            .map(|candidate| candidate.mx_host.as_str())
            .collect::<Vec<_>>(),
        ["mx1.ordered.test", "mx2.ordered.test", "mx3.ordered.test"]
    );
    assert_eq!(ordered.tls_mode, TlsMode::Opportunistic);

    let fallback = route_resolver
        .resolve("fallback.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(fallback.candidates[0].mx_host, "fallback.test");
    assert_eq!(fallback.candidates[0].connect_addr.ip(), ip("1.0.0.1"));
}

#[tokio::test]
async fn rejects_null_mx_and_every_mixed_null_mx_ordering() {
    let dns = FakeDns::new(Duration::ZERO);
    dns.set_mx("null.test", Ok(vec![mx(0, ".")]));
    dns.set_mx(
        "mixed-first.test",
        Ok(vec![mx(0, "."), mx(10, "mail.mixed-first.test")]),
    );
    dns.set_mx(
        "mixed-last.test",
        Ok(vec![mx(10, "mail.mixed-last.test"), mx(20, ".")]),
    );
    let route_resolver = resolver(
        route_config(),
        false,
        unavailable_pool(),
        dns,
        FakeHttp::new(Duration::ZERO),
    );

    for domain in ["null.test", "mixed-first.test", "mixed-last.test"] {
        let error = route_resolver
            .resolve(domain, &CancellationToken::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind, RouteErrorKind::Permanent, "{domain}");
    }
}

#[tokio::test]
async fn address_and_mx_answer_budgets_fail_closed() {
    let dns = FakeDns::new(Duration::ZERO);
    dns.set_mx("poison.test", Ok(vec![mx(10, "mail.poison.test")]));
    dns.set_addresses("mail.poison.test", Ok(vec![ip("1.1.1.1"), ip("127.0.0.1")]));
    dns.set_mx(
        "address-cap.test",
        Ok(vec![mx(10, "mail.address-cap.test")]),
    );
    dns.set_addresses("mail.address-cap.test", Ok(vec![ip("8.8.8.8"); 17]));
    dns.set_mx(
        "mx-cap.test",
        Ok((0..65)
            .map(|index| mx(index, &format!("mx{index}.mx-cap.test")))
            .collect()),
    );
    let route_resolver = resolver(
        route_config(),
        false,
        unavailable_pool(),
        dns,
        FakeHttp::new(Duration::ZERO),
    );

    let poisoned = route_resolver
        .resolve("poison.test", &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(poisoned.kind, RouteErrorKind::Configuration);
    let address_cap = route_resolver
        .resolve("address-cap.test", &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(address_cap.kind, RouteErrorKind::Temporary);
    let mx_cap = route_resolver
        .resolve("mx-cap.test", &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(mx_cap.kind, RouteErrorKind::Temporary);
}

#[tokio::test]
async fn mta_sts_enforce_filters_mx_while_testing_and_none_preserve_it() {
    let dns = FakeDns::new(Duration::ZERO);
    let http = FakeHttp::new(Duration::ZERO);
    for (domain, policy_id) in [("enforce.test", "Enforce1"), ("testing.test", "Testing1")] {
        dns.set_mx(
            domain,
            Ok(vec![
                mx(10, &format!("good.{domain}")),
                mx(20, &format!("other.{domain}")),
            ]),
        );
        dns.set_txt(
            &format!("_mta-sts.{domain}"),
            Ok(vec![format!("v=STSv1; id={policy_id};").into_bytes()]),
        );
        dns.set_addresses(&format!("mta-sts.{domain}"), Ok(vec![ip("1.1.1.1")]));
        dns.set_addresses(&format!("good.{domain}"), Ok(vec![ip("8.8.8.8")]));
        dns.set_addresses(&format!("other.{domain}"), Ok(vec![ip("9.9.9.9")]));
    }
    dns.set_mx(
        "none.test",
        Ok(vec![mx(10, "good.none.test"), mx(20, "other.none.test")]),
    );
    dns.set_txt("_mta-sts.none.test", Err(DnsFailure::NoRecords));
    dns.set_addresses("good.none.test", Ok(vec![ip("1.0.0.1")]));
    dns.set_addresses("other.none.test", Ok(vec![ip("8.8.4.4")]));
    http.set_response(
        "enforce.test",
        policy_response("enforce", "good.enforce.test"),
    );
    http.set_response(
        "testing.test",
        policy_response("testing", "good.testing.test"),
    );
    let route_resolver = resolver(route_config(), true, unavailable_pool(), dns, http.clone());

    let enforce = route_resolver
        .resolve("enforce.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(enforce.tls_mode, TlsMode::Required);
    assert_eq!(enforce.candidates.len(), 1);
    assert_eq!(enforce.candidates[0].mx_host, "good.enforce.test");
    assert_eq!(enforce.policy.policy_id.as_deref(), Some("Enforce1"));

    let testing = route_resolver
        .resolve("testing.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(testing.tls_mode, TlsMode::Opportunistic);
    assert_eq!(testing.candidates.len(), 2);
    assert_eq!(testing.policy.mode, MtaStsMode::Testing);

    let none = route_resolver
        .resolve("none.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(none.tls_mode, TlsMode::Opportunistic);
    assert_eq!(none.candidates.len(), 2);
    assert_eq!(none.policy.mode, MtaStsMode::None);
    assert_eq!(http.calls(), 2);
}

#[tokio::test]
async fn invalid_policy_discovery_and_https_responses_never_apply_a_policy() {
    let dns = FakeDns::new(Duration::ZERO);
    let http = FakeHttp::new(Duration::ZERO);
    let responses = [
        (
            "redirect.test",
            PolicyHttpResponse {
                status: 302,
                content_type: Some("text/plain".into()),
                body: policy_response("enforce", "mail.redirect.test").body,
            },
        ),
        (
            "status.test",
            PolicyHttpResponse {
                status: 503,
                content_type: Some("text/plain".into()),
                body: policy_response("enforce", "mail.status.test").body,
            },
        ),
        (
            "content-type.test",
            PolicyHttpResponse {
                status: 200,
                content_type: Some("text/html".into()),
                body: policy_response("enforce", "mail.content-type.test").body,
            },
        ),
        (
            "utf8.test",
            PolicyHttpResponse {
                status: 200,
                content_type: Some("text/plain".into()),
                body: vec![0xff],
            },
        ),
        (
            "oversized.test",
            PolicyHttpResponse {
                status: 200,
                content_type: Some("text/plain".into()),
                body: vec![b'x'; MAX_POLICY_BYTES + 1],
            },
        ),
        (
            "malformed.test",
            PolicyHttpResponse {
                status: 200,
                content_type: Some("text/plain".into()),
                body: b"version: STSv1\nmode: enforce\nmax_age: 300\n".to_vec(),
            },
        ),
    ];
    for (domain, response) in responses {
        dns.set_mx(domain, Ok(vec![mx(10, &format!("mail.{domain}"))]));
        dns.set_txt(
            &format!("_mta-sts.{domain}"),
            Ok(vec![b"v=STSv1; id=Policy1;".to_vec()]),
        );
        dns.set_addresses(&format!("mta-sts.{domain}"), Ok(vec![ip("1.1.1.1")]));
        dns.set_addresses(&format!("mail.{domain}"), Ok(vec![ip("8.8.8.8")]));
        http.set_response(domain, response);
    }
    for domain in [
        "multiple-txt.test",
        "too-many-txt.test",
        "too-large-txt.test",
    ] {
        dns.set_mx(domain, Ok(vec![mx(10, &format!("mail.{domain}"))]));
        dns.set_addresses(&format!("mail.{domain}"), Ok(vec![ip("9.9.9.9")]));
    }
    dns.set_txt(
        "_mta-sts.multiple-txt.test",
        Ok(vec![
            b"v=STSv1; id=One;".to_vec(),
            b"v=STSv1; id=Two;".to_vec(),
        ]),
    );
    dns.set_txt(
        "_mta-sts.too-many-txt.test",
        Ok(vec![b"v=STSv1; id=One;".to_vec(); MAX_TXT_RECORDS + 1]),
    );
    dns.set_txt(
        "_mta-sts.too-large-txt.test",
        Ok(vec![vec![b'x'; MAX_TXT_BYTES + 1]]),
    );
    let route_resolver = resolver(route_config(), true, unavailable_pool(), dns, http.clone());

    for domain in [
        "redirect.test",
        "status.test",
        "content-type.test",
        "utf8.test",
        "oversized.test",
        "malformed.test",
        "multiple-txt.test",
        "too-many-txt.test",
        "too-large-txt.test",
    ] {
        let route = route_resolver
            .resolve(domain, &CancellationToken::new())
            .await
            .unwrap();
        assert_eq!(route.policy.mode, MtaStsMode::None, "{domain}");
        assert_eq!(route.tls_mode, TlsMode::Opportunistic, "{domain}");
    }
    assert_eq!(http.calls(), 6);
}

#[tokio::test]
async fn concurrent_route_resolution_singleflights_mx_txt_and_policy_fetches() {
    let dns = FakeDns::new(Duration::from_millis(60));
    let http = FakeHttp::new(Duration::from_millis(60));
    dns.set_mx(
        "singleflight.test",
        Ok(vec![mx(10, "mail.singleflight.test")]),
    );
    dns.set_txt(
        "_mta-sts.singleflight.test",
        Ok(vec![b"v=STSv1; id=Shared1;".to_vec()]),
    );
    dns.set_addresses("mta-sts.singleflight.test", Ok(vec![ip("1.1.1.1")]));
    dns.set_addresses("mail.singleflight.test", Ok(vec![ip("8.8.8.8")]));
    http.set_response(
        "singleflight.test",
        policy_response("enforce", "mail.singleflight.test"),
    );
    let route_resolver = resolver(
        route_config(),
        true,
        unavailable_pool(),
        dns.clone(),
        http.clone(),
    );
    let mut tasks = JoinSet::new();
    for _ in 0..24 {
        let route_resolver = route_resolver.clone();
        tasks.spawn(async move {
            route_resolver
                .resolve("singleflight.test", &CancellationToken::new())
                .await
        });
    }
    while let Some(result) = tasks.join_next().await {
        let route = result.unwrap().unwrap();
        assert_eq!(route.tls_mode, TlsMode::Required);
        assert_eq!(route.candidates.len(), 1);
    }
    assert_eq!(dns.mx_calls(), 1);
    assert_eq!(dns.txt_calls(), 1);
    assert_eq!(http.calls(), 1);
    assert_eq!(dns.address_calls(), 25);
}

#[tokio::test]
async fn every_singleflight_waiter_honors_its_own_cancellation() {
    let dns = FakeDns::new(Duration::from_secs(5));
    dns.set_mx("cancel.test", Ok(vec![mx(10, "mail.cancel.test")]));
    dns.set_addresses("mail.cancel.test", Ok(vec![ip("1.1.1.1")]));
    let route_resolver = resolver(
        route_config(),
        false,
        unavailable_pool(),
        dns.clone(),
        FakeHttp::new(Duration::ZERO),
    );

    let first_token = CancellationToken::new();
    let first_cancel = first_token.clone();
    let first_resolver = route_resolver.clone();
    let first =
        tokio::spawn(async move { first_resolver.resolve("cancel.test", &first_token).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while dns.mx_calls() == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    let second_token = CancellationToken::new();
    let second_cancel = second_token.clone();
    let second_resolver = route_resolver.clone();
    let second =
        tokio::spawn(async move { second_resolver.resolve("cancel.test", &second_token).await });
    sleep(Duration::from_millis(20)).await;
    second_cancel.cancel();
    let second_error = tokio::time::timeout(Duration::from_millis(300), second)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(second_error.kind, RouteErrorKind::Cancelled);

    first_cancel.cancel();
    let first_error = tokio::time::timeout(Duration::from_millis(300), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert_eq!(first_error.kind, RouteErrorKind::Cancelled);
}

#[tokio::test]
async fn route_resolution_has_an_absolute_deadline() {
    let dns = FakeDns::new(Duration::from_secs(5));
    dns.set_mx("deadline.test", Ok(vec![mx(10, "mail.deadline.test")]));
    let mut config = route_config();
    config.resolution_deadline_seconds = 1;
    let route_resolver = resolver(
        config,
        false,
        unavailable_pool(),
        dns,
        FakeHttp::new(Duration::ZERO),
    );
    let error = tokio::time::timeout(
        Duration::from_millis(1_500),
        route_resolver.resolve("deadline.test", &CancellationToken::new()),
    )
    .await
    .unwrap()
    .unwrap_err();
    assert_eq!(error.kind, RouteErrorKind::Temporary);
}

#[tokio::test]
async fn route_admission_is_hard_bounded_without_an_internal_wait_queue() {
    let dns = FakeDns::new(Duration::from_secs(5));
    dns.set_mx("admission.test", Ok(vec![mx(10, "mail.admission.test")]));
    let route_resolver = resolver_with_limit(1, dns.clone(), FakeHttp::new(Duration::ZERO));
    let first_token = CancellationToken::new();
    let first_cancel = first_token.clone();
    let first_resolver = route_resolver.clone();
    let first =
        tokio::spawn(async move { first_resolver.resolve("admission.test", &first_token).await });
    tokio::time::timeout(Duration::from_secs(1), async {
        while dns.mx_calls() == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();

    let overloaded = route_resolver
        .resolve("admission.test", &CancellationToken::new())
        .await
        .unwrap_err();
    assert_eq!(overloaded.kind, RouteErrorKind::Temporary);
    assert!(overloaded.message.contains("concurrency limit"));

    first_cancel.cancel();
    let first_error = first.await.unwrap().unwrap_err();
    assert_eq!(first_error.kind, RouteErrorKind::Cancelled);
}

struct RedisProcess {
    child: Child,
    directory: PathBuf,
    port: u16,
}

impl RedisProcess {
    fn start() -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);

        let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        let binary = std::env::var_os("LMYZMAIL_TEST_REDIS_SERVER")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                repository.join(".blackbox/runtime/redis-root/usr/bin/redis-server")
            });
        let library_directory =
            repository.join(".blackbox/runtime/redis-root/usr/lib/x86_64-linux-gnu");
        assert!(
            binary.is_file(),
            "Redis test binary missing at {}",
            binary.display()
        );
        assert!(library_directory.is_dir());

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "lmyzmail-redis-route-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        let child = Command::new(binary)
            .args([
                "--bind",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--protected-mode",
                "yes",
                "--dir",
                directory.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env("LD_LIBRARY_PATH", library_directory)
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while TcpStream::connect(("127.0.0.1", port)).is_err() {
            assert!(
                std::time::Instant::now() < deadline,
                "Redis test process did not start"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Self {
            child,
            directory,
            port,
        }
    }
}

impl Drop for RedisProcess {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if self
            .directory
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|value| value.starts_with("lmyzmail-redis-route-"))
        {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
}

#[tokio::test]
async fn redis_legacy_keys_serialization_ttls_and_restart_semantics_are_compatible() {
    let process = RedisProcess::start();
    let pool = pool_at(process.port);
    let mut connection = pool.get().await.unwrap();
    let now = now_epoch_millis().unwrap();
    let _: () = redis::cmd("SET")
        .arg("dns:mx:cache.test")
        .arg("mx1.cache.test,mx2.cache.test")
        .arg("EX")
        .arg(120)
        .query_async(&mut connection)
        .await
        .unwrap();
    let cached_policy = MtaStsPolicy {
        version: Some("STSv1".into()),
        mode: MtaStsMode::Enforce,
        mx_patterns: vec!["mx1.cache.test".into()],
        max_age_seconds: 300,
        policy_id: Some("Cache1".into()),
        fetched_at_epoch_millis: now,
    };
    let _: () = redis::cmd("SET")
        .arg("mta-sts:cache.test")
        .arg(cached_policy.serialize_legacy())
        .arg("EX")
        .arg(120)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);

    let cached_dns = FakeDns::new(Duration::ZERO);
    cached_dns.set_addresses("mx1.cache.test", Ok(vec![ip("1.1.1.1")]));
    let cached_http = FakeHttp::new(Duration::ZERO);
    let cached_resolver = resolver(
        route_config(),
        true,
        pool.clone(),
        cached_dns.clone(),
        cached_http.clone(),
    );
    let route = cached_resolver
        .resolve("cache.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(route.tls_mode, TlsMode::Required);
    assert_eq!(route.candidates.len(), 1);
    assert_eq!(route.candidates[0].mx_host, "mx1.cache.test");
    assert_eq!(cached_dns.mx_calls(), 0);
    assert_eq!(cached_dns.txt_calls(), 0);
    assert_eq!(cached_http.calls(), 0);

    let mut connection = pool.get().await.unwrap();
    for key in ["dns:mx:cache.test", "mta-sts:cache.test"] {
        let ttl: i64 = redis::cmd("PTTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((100_000..=120_000).contains(&ttl), "{key} ttl={ttl}");
    }
    let _: () = redis::cmd("HSET")
        .arg("route:wrong-type")
        .arg("field")
        .arg("value")
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg("route:persistent")
        .arg("value")
        .query_async(&mut connection)
        .await
        .unwrap();
    let _: () = redis::cmd("SET")
        .arg("route:oversized")
        .arg("x".repeat(MAX_CACHE_VALUE_BYTES + 1))
        .arg("EX")
        .arg(60)
        .query_async(&mut connection)
        .await
        .unwrap();
    drop(connection);
    let deadline = Instant::now() + Duration::from_secs(2);
    for key in ["route:wrong-type", "route:persistent", "route:oversized"] {
        assert!(
            cached_resolver
                .read_cache(key, deadline, &CancellationToken::new())
                .await
                .is_none(),
            "{key}"
        );
    }

    let mut short_config = route_config();
    short_config.mx_l2_ttl_minutes = 1;
    short_config.mx_negative_ttl_minutes = 1;
    let write_dns = FakeDns::new(Duration::ZERO);
    write_dns.set_mx("fallback.cache.test", Err(DnsFailure::NoRecords));
    write_dns.set_addresses("fallback.cache.test", Ok(vec![ip("8.8.8.8")]));
    write_dns.set_mx(
        "positive.cache.test",
        Ok(vec![
            mx(20, "mx2.positive.cache.test"),
            mx(10, "mx1.positive.cache.test"),
        ]),
    );
    write_dns.set_addresses("mx1.positive.cache.test", Ok(vec![ip("1.1.1.1")]));
    write_dns.set_addresses("mx2.positive.cache.test", Ok(vec![ip("9.9.9.9")]));
    let write_resolver = resolver(
        short_config.clone(),
        false,
        pool.clone(),
        write_dns,
        FakeHttp::new(Duration::ZERO),
    );
    write_resolver
        .resolve("fallback.cache.test", &CancellationToken::new())
        .await
        .unwrap();
    write_resolver
        .resolve("positive.cache.test", &CancellationToken::new())
        .await
        .unwrap();
    let mut connection = pool.get().await.unwrap();
    let fallback: String = redis::cmd("GET")
        .arg("dns:mx:fallback.cache.test")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(fallback, FALLBACK_MARKER);
    let positive: String = redis::cmd("GET")
        .arg("dns:mx:positive.cache.test")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(positive, "mx1.positive.cache.test,mx2.positive.cache.test");
    for key in ["dns:mx:fallback.cache.test", "dns:mx:positive.cache.test"] {
        let ttl: i64 = redis::cmd("TTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .unwrap();
        assert!((55..=60).contains(&ttl), "{key} ttl={ttl}");
    }
    drop(connection);

    let negative_dns = FakeDns::new(Duration::ZERO);
    negative_dns.set_mx(
        "negative.cache.test",
        Ok(vec![mx(10, "mx.negative.cache.test")]),
    );
    negative_dns.set_txt("_mta-sts.negative.cache.test", Err(DnsFailure::NoRecords));
    negative_dns.set_addresses("mx.negative.cache.test", Ok(vec![ip("8.8.4.4")]));
    let negative_resolver = resolver(
        short_config.clone(),
        true,
        pool.clone(),
        negative_dns,
        FakeHttp::new(Duration::ZERO),
    );
    let negative_route = negative_resolver
        .resolve("negative.cache.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(negative_route.policy.mode, MtaStsMode::None);
    let mut connection = pool.get().await.unwrap();
    let serialized: String = redis::cmd("GET")
        .arg("mta-sts:negative.cache.test")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        MtaStsPolicy::deserialize_legacy(&serialized).unwrap().mode,
        MtaStsMode::None
    );
    let negative_ttl: i64 = redis::cmd("TTL")
        .arg("mta-sts:negative.cache.test")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert!((295..=300).contains(&negative_ttl));
    drop(connection);

    let restart_dns = FakeDns::new(Duration::ZERO);
    restart_dns.set_txt("_mta-sts.negative.cache.test", Err(DnsFailure::NoRecords));
    restart_dns.set_addresses("mx.negative.cache.test", Ok(vec![ip("8.8.4.4")]));
    let restart_http = FakeHttp::new(Duration::ZERO);
    let restart_resolver = resolver(
        short_config,
        true,
        pool,
        restart_dns.clone(),
        restart_http.clone(),
    );
    let restarted = restart_resolver
        .resolve("negative.cache.test", &CancellationToken::new())
        .await
        .unwrap();
    assert_eq!(restarted.policy.mode, MtaStsMode::None);
    assert_eq!(restart_dns.mx_calls(), 0);
    assert_eq!(restart_dns.txt_calls(), 1);
    assert_eq!(restart_http.calls(), 0);
}
