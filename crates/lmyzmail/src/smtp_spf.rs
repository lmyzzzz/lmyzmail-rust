use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::{IpAddr, SocketAddr},
    str::FromStr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    proto::rr::RData,
};
use ipnet::IpNet;
use mail_auth::{
    MessageAuthenticator, Parameters, ResolverCache, SpfResult, Txt,
    common::parse::TxtRecordParser,
    spf::{Spf, verify::SpfParameters},
};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const SPF_DEADLINE: Duration = Duration::from_secs(10);
const MAX_TRANSACTION_TXT_CACHE_ENTRIES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct SpfVerification {
    result: &'static str,
    reason: String,
}

impl SpfVerification {
    pub(crate) fn result(&self) -> &'static str {
        self.result
    }

    pub(crate) fn reason(&self) -> &str {
        &self.reason
    }

    pub(crate) fn passed(&self) -> bool {
        self.result == "pass"
    }

    pub(crate) fn protocol_score(&self) -> f64 {
        match self.result {
            "fail" => 3.0,
            "softfail" => 1.0,
            _ => 0.0,
        }
    }

    pub(crate) fn should_quarantine(&self) -> bool {
        self.result == "fail"
    }

    fn no_record(domain: &str) -> Self {
        Self {
            result: "none",
            reason: format!("No SPF record found for {domain}"),
        }
    }

    fn temporary_failure(reason: &str) -> Self {
        Self {
            result: "temperror",
            reason: reason.to_owned(),
        }
    }
}

#[derive(Clone)]
pub(crate) struct SpfVerifier {
    authenticator: MessageAuthenticator,
}

impl SpfVerifier {
    pub(crate) fn new(name_server: Option<SocketAddr>) -> Result<Self, String> {
        let authenticator = if let Some(server) = name_server {
            let mut name_server = NameServerConfig::udp(server.ip());
            name_server.connections[0].port = server.port();
            MessageAuthenticator::new(
                ResolverConfig::from_parts(None, Vec::new(), vec![name_server]),
                ResolverOpts::default(),
            )
        } else {
            MessageAuthenticator::new_system_conf()
        }
        .map_err(|error| error.to_string())?;
        Ok(Self { authenticator })
    }

    pub(crate) async fn verify(
        &self,
        peer: IpAddr,
        helo: &str,
        host_domain: &str,
        sender: &str,
        cancellation: &CancellationToken,
    ) -> SpfVerification {
        let Some((_, domain)) = sender.rsplit_once('@') else {
            return SpfVerification {
                result: "none",
                reason: "Cannot extract domain from MAIL FROM".to_owned(),
            };
        };
        let operation = async {
            let Some(record) = self.lookup_record(domain).await else {
                return SpfVerification::no_record(domain);
            };
            let Ok(parsed) = Spf::parse(record.as_bytes()) else {
                return SpfVerification {
                    result: "neutral",
                    reason: "No mechanism matched".to_owned(),
                };
            };
            let cache = TransactionTxtCache::with_spf(domain, parsed);
            let parameters = Parameters::new(SpfParameters::verify_mail_from(
                peer,
                helo,
                host_domain,
                sender,
            ))
            .with_txt_cache(&cache);
            let output = self.authenticator.verify_spf(parameters).await;
            let result = output.result();
            let (name, fallback) = result_and_fallback_reason(result, domain, output.explanation());
            SpfVerification {
                result: name,
                reason: java_simple_mechanism_reason(&record, peer, name).unwrap_or(fallback),
            }
        };

        tokio::select! {
            _ = cancellation.cancelled() => {
                SpfVerification::temporary_failure("SPF check error: operation cancelled")
            }
            result = timeout(SPF_DEADLINE, operation) => match result {
                Ok(result) => result,
                Err(_) => SpfVerification::temporary_failure("SPF check error: DNS query timed out"),
            }
        }
    }

    async fn lookup_record(&self, domain: &str) -> Option<String> {
        let lookup = self.authenticator.0.txt_lookup(domain).await.ok()?;
        lookup.answers().iter().find_map(|record| {
            let RData::TXT(record) = &record.data else {
                return None;
            };
            let bytes = record
                .txt_data
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();
            let value = String::from_utf8(bytes).ok()?;
            value
                .to_ascii_lowercase()
                .starts_with("v=spf1")
                .then_some(value)
        })
    }
}

#[derive(Default)]
struct TransactionTxtCache {
    entries: Mutex<HashMap<Box<str>, (Txt, Instant)>>,
}

impl TransactionTxtCache {
    fn with_spf(domain: &str, record: Spf) -> Self {
        let mut entries = HashMap::with_capacity(1);
        entries.insert(
            cache_key(domain),
            (Txt::Spf(Arc::new(record)), Instant::now() + SPF_DEADLINE),
        );
        Self {
            entries: Mutex::new(entries),
        }
    }
}

fn cache_key(domain: &str) -> Box<str> {
    let domain = domain.to_ascii_lowercase();
    if domain.ends_with('.') {
        domain.into_boxed_str()
    } else {
        format!("{domain}.").into_boxed_str()
    }
}

impl ResolverCache<Box<str>, Txt> for TransactionTxtCache {
    fn get<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        let mut entries = self.entries.lock().ok()?;
        match entries.get(name) {
            Some((value, valid_until)) if *valid_until > Instant::now() => Some(value.clone()),
            Some(_) => {
                entries.remove(name);
                None
            }
            None => None,
        }
    }

    fn remove<Q>(&self, name: &Q) -> Option<Txt>
    where
        Box<str>: Borrow<Q>,
        Q: Hash + Eq + ?Sized,
    {
        self.entries
            .lock()
            .ok()?
            .remove(name)
            .map(|(value, _)| value)
    }

    fn insert(&self, key: Box<str>, value: Txt, valid_until: Instant) {
        let Ok(mut entries) = self.entries.lock() else {
            return;
        };
        if entries.len() < MAX_TRANSACTION_TXT_CACHE_ENTRIES || entries.contains_key(&key) {
            entries.insert(key, (value, valid_until));
        }
    }
}

fn result_and_fallback_reason(
    result: SpfResult,
    domain: &str,
    explanation: Option<&str>,
) -> (&'static str, String) {
    let name = match result {
        SpfResult::Pass => "pass",
        SpfResult::Fail => "fail",
        SpfResult::SoftFail => "softfail",
        SpfResult::Neutral => "neutral",
        SpfResult::TempError => "temperror",
        SpfResult::PermError => "permerror",
        SpfResult::None => "none",
    };
    let reason = explanation.map_or_else(
        || match result {
            SpfResult::None => format!("No SPF record found for {domain}"),
            SpfResult::Pass => "SPF validation passed".to_owned(),
            SpfResult::Fail => "SPF policy rejected the client IP".to_owned(),
            SpfResult::SoftFail => "SPF policy soft-failed the client IP".to_owned(),
            SpfResult::Neutral => "SPF policy returned neutral".to_owned(),
            SpfResult::TempError => "SPF DNS lookup failed temporarily".to_owned(),
            SpfResult::PermError => "SPF record is invalid".to_owned(),
        },
        str::to_owned,
    );
    (name, reason)
}

fn java_simple_mechanism_reason(record: &str, peer: IpAddr, result: &str) -> Option<String> {
    for raw in record.split_ascii_whitespace().skip(1) {
        let (qualifier, mechanism) = match raw.as_bytes().first().copied() {
            Some(b'+' | b'-' | b'~' | b'?') => (raw.as_bytes()[0], &raw[1..]),
            _ => (b'+', raw),
        };
        let qualified_result = match qualifier {
            b'+' => "pass",
            b'-' => "fail",
            b'~' => "softfail",
            b'?' => "neutral",
            _ => return None,
        };
        if let Some(cidr) = mechanism.strip_prefix("ip4:") {
            if peer.is_ipv4() && address_matches(peer, cidr) && qualified_result == result {
                return Some(format!("Matched ip4:{cidr}"));
            }
            continue;
        }
        if let Some(cidr) = mechanism.strip_prefix("ip6:") {
            if peer.is_ipv6() && address_matches(peer, cidr) && qualified_result == result {
                return Some(format!("Matched ip6:{cidr}"));
            }
            continue;
        }
        if mechanism == "all" {
            return (qualified_result == result).then(|| "Matched 'all'".to_owned());
        }
        if !mechanism.contains('=') {
            return None;
        }
    }
    None
}

fn address_matches(peer: IpAddr, value: &str) -> bool {
    IpNet::from_str(value)
        .map(|network| network.contains(&peer))
        .or_else(|_| IpAddr::from_str(value).map(|address| address == peer))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn java_reason_preserves_simple_mechanism_text() {
        assert_eq!(
            java_simple_mechanism_reason(
                "v=spf1 ip4:192.0.2.0/24 -all",
                "192.0.2.8".parse().unwrap(),
                "pass",
            ),
            Some("Matched ip4:192.0.2.0/24".to_owned()),
        );
        assert_eq!(
            java_simple_mechanism_reason("v=spf1 ~all", "2001:db8::1".parse().unwrap(), "softfail",),
            Some("Matched 'all'".to_owned()),
        );
    }

    #[test]
    fn transaction_cache_is_hard_bounded() {
        let cache = TransactionTxtCache::default();
        for index in 0..64 {
            cache.insert(
                format!("{index}.example").into_boxed_str(),
                Txt::Spf(Arc::new(Spf::parse(b"v=spf1 -all").unwrap())),
                Instant::now() + Duration::from_secs(60),
            );
        }
        assert_eq!(cache.entries.lock().unwrap().len(), 16);
    }

    #[test]
    fn transaction_cache_uses_mail_auth_fqdn_keys() {
        assert_eq!(&*cache_key("Example.COM"), "example.com.");
        assert_eq!(&*cache_key("Example.COM."), "example.com.");
    }

    #[test]
    fn result_mapping_and_protocol_scores_are_complete() {
        let cases = [
            (SpfResult::Pass, "pass", "SPF validation passed", 0.0),
            (
                SpfResult::Fail,
                "fail",
                "SPF policy rejected the client IP",
                3.0,
            ),
            (
                SpfResult::SoftFail,
                "softfail",
                "SPF policy soft-failed the client IP",
                1.0,
            ),
            (
                SpfResult::Neutral,
                "neutral",
                "SPF policy returned neutral",
                0.0,
            ),
            (
                SpfResult::TempError,
                "temperror",
                "SPF DNS lookup failed temporarily",
                0.0,
            ),
            (
                SpfResult::PermError,
                "permerror",
                "SPF record is invalid",
                0.0,
            ),
            (
                SpfResult::None,
                "none",
                "No SPF record found for blackbox.example.com",
                0.0,
            ),
        ];
        for (result, expected_name, expected_reason, expected_score) in cases {
            let (name, reason) = result_and_fallback_reason(result, "blackbox.example.com", None);
            let verification = SpfVerification {
                result: name,
                reason: reason.clone(),
            };
            assert_eq!(name, expected_name);
            assert_eq!(reason, expected_reason);
            assert_eq!(verification.protocol_score(), expected_score);
            assert_eq!(verification.should_quarantine(), result == SpfResult::Fail);
        }
        assert_eq!(
            result_and_fallback_reason(
                SpfResult::Fail,
                "blackbox.example.com",
                Some("oracle explanation"),
            ),
            ("fail", "oracle explanation".to_owned()),
        );
    }

    proptest! {
        #[test]
        fn compatibility_reason_parser_never_panics(
            record in prop::collection::vec(any::<u8>(), 0..4096),
            peer in any::<[u8; 16]>(),
        ) {
            let record = String::from_utf8_lossy(&record);
            let _ = java_simple_mechanism_reason(
                &record,
                IpAddr::from(peer),
                "neutral",
            );
        }
    }
}
