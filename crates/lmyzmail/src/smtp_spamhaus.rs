use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use futures_util::future::join_all;
use hickory_resolver::{
    TokioResolver,
    net::NetError,
    proto::{
        op::{Message, MessageType, OpCode, Query, ResponseCode},
        rr::{DNSClass, Name, RData, RecordType},
    },
};
use moka::future::Cache;
use tokio::{net::UdpSocket, sync::Semaphore, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::config::SpamhausConfig;

const MAX_CACHE_ENTRIES: u64 = 10_000;
const MAX_ACTIVE_DNS_REQUESTS: usize = 64;
const DNS_RESPONSE_CACHE_ENTRIES: u64 = 8_192;
const MAX_EXPLICIT_DNS_RESPONSE_BYTES: usize = 4_096;

#[derive(Clone, Debug, Eq, PartialEq)]
struct Listing {
    zone: String,
    return_code: Ipv4Addr,
    description: String,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SpamhausResult {
    ip: Option<Listing>,
    domain: Option<Listing>,
}

impl SpamhausResult {
    pub(crate) const fn is_any_listed(&self) -> bool {
        self.ip.is_some() || self.domain.is_some()
    }

    pub(crate) fn metadata(&self) -> String {
        let ip_zone = self.ip.as_ref().map_or("", |listing| listing.zone.as_str());
        let domain_zone = self
            .domain
            .as_ref()
            .map(|listing| format!(", {}", listing.zone))
            .unwrap_or_default();
        format!("Listed in: {ip_zone}{domain_zone}")
    }

    pub(crate) fn rejection_wire(&self, client_ip: IpAddr, domain: &str) -> Vec<u8> {
        let mut message = String::from("550 5.7.1 Service unavailable; ");
        if let Some(listing) = &self.ip {
            message.push_str(&format!(
                "client host [{client_ip}] blocked using {}; {}",
                listing.zone, listing.description
            ));
        }
        if let Some(listing) = &self.domain {
            if self.ip.is_some() {
                message.push_str("; ");
            }
            message.push_str(&format!(
                "sender domain [{domain}] blocked using {}; {}",
                listing.zone, listing.description
            ));
        }
        message.push_str(&format!(
            "; see https://www.spamhaus.org/query/ip/{client_ip}\r\n"
        ));
        encode_latin1_lossy(&message)
    }
}

#[derive(Clone)]
pub(crate) struct SpamhausService {
    config: SpamhausConfig,
    resolver: Option<SpamhausResolver>,
    dns_permits: Arc<Semaphore>,
    cache: Option<Cache<String, SpamhausResult>>,
}

#[derive(Clone)]
enum SpamhausResolver {
    System(Box<TokioResolver>),
    Explicit(SocketAddr),
}

#[derive(Debug, Eq, PartialEq)]
enum DirectLookup {
    Answer(Vec<Ipv4Addr>),
    NxDomain,
    Failed,
}

#[derive(Clone, Copy, Debug)]
struct Cancelled;

impl SpamhausService {
    pub(crate) fn new(
        config: SpamhausConfig,
        dns_server: Option<SocketAddr>,
    ) -> Result<Self, String> {
        let needs_dns = config.enabled && (config.dbl_enabled || !config.zones.is_empty());
        let resolver = needs_dns
            .then(|| build_resolver(dns_server, config.timeout))
            .transpose()
            .map_err(|error| format!("Spamhaus DNS resolver cannot start: {error}"))?;
        let cache = (config.enabled && !config.cache_ttl.is_zero()).then(|| {
            Cache::builder()
                .max_capacity(MAX_CACHE_ENTRIES)
                .time_to_live(config.cache_ttl)
                .build()
        });
        Ok(Self {
            config,
            resolver,
            dns_permits: Arc::new(Semaphore::new(MAX_ACTIVE_DNS_REQUESTS)),
            cache,
        })
    }

    pub(crate) async fn check(
        &self,
        client_ip: IpAddr,
        sender_domain: &str,
        cancellation: &CancellationToken,
    ) -> SpamhausResult {
        if !self.config.enabled {
            return SpamhausResult::default();
        }
        let ascii_domain =
            idna::domain_to_ascii(sender_domain).unwrap_or_else(|_| sender_domain.to_owned());
        let cache_key = format!("{client_ip}:{ascii_domain}");
        let cancellation = cancellation.clone();
        if let Some(cache) = &self.cache {
            let service = self.clone();
            cache
                .try_get_with(cache_key, async move {
                    service
                        .check_uncached(client_ip, ascii_domain, &cancellation)
                        .await
                })
                .await
                .unwrap_or_default()
        } else {
            self.check_uncached(client_ip, ascii_domain, &cancellation)
                .await
                .unwrap_or_default()
        }
    }

    async fn check_uncached(
        &self,
        client_ip: IpAddr,
        ascii_domain: String,
        cancellation: &CancellationToken,
    ) -> Result<SpamhausResult, Cancelled> {
        let queries = async {
            let (ip, domain) =
                tokio::join!(self.check_ip(client_ip), self.check_domain(&ascii_domain),);
            SpamhausResult { ip, domain }
        };
        tokio::select! {
            biased;
            _ = cancellation.cancelled() => Err(Cancelled),
            result = timeout(self.config.timeout, queries) => {
                Ok(result.unwrap_or_default())
            }
        }
    }

    async fn check_ip(&self, client_ip: IpAddr) -> Option<Listing> {
        let IpAddr::V4(address) = client_ip else {
            return None;
        };
        if is_private_ip(IpAddr::V4(address)) {
            return None;
        }
        let reversed = address
            .octets()
            .into_iter()
            .rev()
            .map(|octet| octet.to_string())
            .collect::<Vec<_>>()
            .join(".");
        let lookups = self.config.zones.iter().map(|zone| {
            let query = format!("{reversed}.{zone}");
            async move { self.lookup_listing(&query, zone).await }
        });
        for listing in join_all(lookups).await.into_iter().flatten() {
            if !self.config.ignored_codes.contains(&listing.return_code) {
                return Some(listing);
            }
        }
        None
    }

    async fn check_domain(&self, ascii_domain: &str) -> Option<Listing> {
        if !self.config.dbl_enabled {
            return None;
        }
        let query = format!(
            "{}.{}",
            ascii_domain.to_ascii_lowercase(),
            self.config.dbl_zone
        );
        self.lookup_listing(&query, &self.config.dbl_zone).await
    }

    async fn lookup_listing(&self, query: &str, zone: &str) -> Option<Listing> {
        let resolver = self.resolver.as_ref()?;
        let addresses =
            lookup_ipv4_with_oracle_nxdomain_retry(resolver, Arc::clone(&self.dns_permits), query)
                .await?;
        let return_code = addresses.into_iter().next()?;
        Some(Listing {
            zone: zone.to_owned(),
            return_code,
            description: return_code_description(return_code, zone),
        })
    }
}

fn build_resolver(
    server: Option<SocketAddr>,
    query_timeout: Duration,
) -> Result<SpamhausResolver, NetError> {
    let Some(server) = server else {
        let mut builder = TokioResolver::builder_tokio()?;
        builder.options_mut().attempts = 2;
        builder.options_mut().timeout = query_timeout;
        builder.options_mut().max_active_requests = MAX_ACTIVE_DNS_REQUESTS;
        builder.options_mut().num_concurrent_reqs = 1;
        builder.options_mut().cache_size = DNS_RESPONSE_CACHE_ENTRIES;
        builder.options_mut().negative_max_ttl = Some(Duration::ZERO);
        return Ok(SpamhausResolver::System(Box::new(builder.build()?)));
    };
    Ok(SpamhausResolver::Explicit(server))
}

async fn lookup_ipv4_with_oracle_nxdomain_retry(
    resolver: &SpamhausResolver,
    permits: Arc<Semaphore>,
    query: &str,
) -> Option<Vec<Ipv4Addr>> {
    match resolver {
        SpamhausResolver::System(resolver) => {
            let first = resolver.ipv4_lookup(query).await;
            let lookup = match first {
                Err(error) if error.is_nx_domain() => resolver.ipv4_lookup(query).await,
                result => result,
            }
            .ok()?;
            Some(
                lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        RData::A(address) => Some(address.0),
                        _ => None,
                    })
                    .collect(),
            )
        }
        SpamhausResolver::Explicit(server) => {
            let _permit = permits.acquire().await.ok()?;
            match direct_ipv4_lookup(*server, query).await {
                DirectLookup::Answer(addresses) => Some(addresses),
                DirectLookup::NxDomain => match direct_ipv4_lookup(*server, query).await {
                    DirectLookup::Answer(addresses) => Some(addresses),
                    DirectLookup::NxDomain | DirectLookup::Failed => None,
                },
                DirectLookup::Failed => None,
            }
        }
    }
}

async fn direct_ipv4_lookup(server: SocketAddr, query: &str) -> DirectLookup {
    let name = match Name::from_ascii(format!("{}.", query.trim_end_matches('.'))) {
        Ok(name) => name,
        Err(_) => return DirectLookup::Failed,
    };
    let mut question = Query::query(name, RecordType::A);
    question.set_query_class(DNSClass::IN);
    let mut request = Message::query();
    request.metadata.recursion_desired = true;
    request.add_query(question.clone());
    let request_bytes = match request.to_vec() {
        Ok(bytes) => bytes,
        Err(_) => return DirectLookup::Failed,
    };

    let bind_address = match server {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0)),
    };
    let socket = match UdpSocket::bind(bind_address).await {
        Ok(socket) => socket,
        Err(_) => return DirectLookup::Failed,
    };
    if socket.connect(server).await.is_err()
        || socket.send(&request_bytes).await.ok() != Some(request_bytes.len())
    {
        return DirectLookup::Failed;
    }

    let mut response_bytes = [0_u8; MAX_EXPLICIT_DNS_RESPONSE_BYTES + 1];
    let received = match socket.recv(&mut response_bytes).await {
        Ok(received) if received <= MAX_EXPLICIT_DNS_RESPONSE_BYTES => received,
        Ok(_) | Err(_) => return DirectLookup::Failed,
    };
    classify_direct_ipv4_response(&request, &question, &response_bytes[..received])
}

fn classify_direct_ipv4_response(
    request: &Message,
    question: &Query,
    response_bytes: &[u8],
) -> DirectLookup {
    if response_bytes.len() > MAX_EXPLICIT_DNS_RESPONSE_BYTES {
        return DirectLookup::Failed;
    }
    let response = match Message::from_vec(response_bytes) {
        Ok(response) => response,
        Err(_) => return DirectLookup::Failed,
    };
    if response.metadata.id != request.metadata.id
        || response.metadata.message_type != MessageType::Response
        || response.metadata.op_code != OpCode::Query
        || response.metadata.truncation
        || response.queries.as_slice() != std::slice::from_ref(question)
    {
        return DirectLookup::Failed;
    }
    match response.metadata.response_code {
        ResponseCode::NoError => DirectLookup::Answer(
            response
                .answers
                .iter()
                .filter_map(|record| match &record.data {
                    RData::A(address) => Some(address.0),
                    _ => None,
                })
                .collect(),
        ),
        ResponseCode::NXDomain => DirectLookup::NxDomain,
        _ => DirectLookup::Failed,
    }
}

fn is_private_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            address.is_private()
                || address.is_loopback()
                || address.is_link_local()
                || address.is_unspecified()
        }
        IpAddr::V6(address) => {
            let first = address.segments()[0];
            address.is_loopback()
                || address.is_unspecified()
                || (first & 0xffc0) == 0xfe80
                || (first & 0xffc0) == 0xfec0
                || (first & 0xfe00) == 0xfc00
        }
    }
}

fn return_code_description(return_code: Ipv4Addr, zone: &str) -> String {
    let description = match return_code.octets() {
        [127, 0, 0, 2] => "SBL (Spamhaus Block List)",
        [127, 0, 0, 3] => "SBL CSS (Spamhaus CSS)",
        [127, 0, 0, 4..=7] => "XBL (CBL - Exploited host)",
        [127, 0, 0, 9] => "SBL DROP/EDROP",
        [127, 0, 0, 10] => "PBL (ISP maintained)",
        [127, 0, 0, 11] => "PBL (Spamhaus maintained)",
        [127, 0, 1, 2] => "DBL (spam domain)",
        [127, 0, 1, 4] => "DBL (phish domain)",
        [127, 0, 1, 5] => "DBL (malware domain)",
        [127, 0, 1, 6] => "DBL (botnet C&C domain)",
        [127, 0, 1, 102] => "DBL (abused legit spam)",
        [127, 0, 1, 103] => "DBL (abused legit spammed redirector)",
        [127, 0, 1, 104] => "DBL (abused legit phish)",
        [127, 0, 1, 105] => "DBL (abused legit malware)",
        [127, 0, 1, 106] => "DBL (abused legit botnet C&C)",
        _ => return format!("Listed in {zone}"),
    };
    description.to_owned()
}

fn encode_latin1_lossy(value: &str) -> Vec<u8> {
    value
        .chars()
        .map(|character| u8::try_from(u32::from(character)).unwrap_or(b'?'))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_resolver::proto::rr::{Record, rdata::A};
    use proptest::prelude::*;
    use std::net::Ipv6Addr;

    fn direct_response_fixture() -> (Message, Query, Message) {
        let name = Name::from_ascii("4.3.2.1.zen.example.").unwrap();
        let mut question = Query::query(name.clone(), RecordType::A);
        question.set_query_class(DNSClass::IN);
        let mut request = Message::query();
        request.metadata.id = 0x4a51;
        request.metadata.recursion_desired = true;
        request.add_query(question.clone());
        let mut response = request.clone().into_response();
        response.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A(Ipv4Addr::new(127, 0, 0, 2))),
        ));
        (request, question, response)
    }

    #[test]
    fn return_codes_match_the_frozen_java_table() {
        assert_eq!(
            return_code_description(Ipv4Addr::new(127, 0, 1, 4), "dbl.example"),
            "DBL (phish domain)"
        );
        assert_eq!(
            return_code_description(Ipv4Addr::new(127, 42, 42, 42), "dbl.example"),
            "Listed in dbl.example"
        );
    }

    #[test]
    fn domain_only_rejection_preserves_metadata_and_latin1_wire() {
        let result = SpamhausResult {
            ip: None,
            domain: Some(Listing {
                zone: "dbl.example".into(),
                return_code: Ipv4Addr::new(127, 0, 1, 2),
                description: "DBL (spam domain)".into(),
            }),
        };
        assert_eq!(result.metadata(), "Listed in: , dbl.example");
        let wire = result.rejection_wire(IpAddr::V4(Ipv4Addr::LOCALHOST), "bücher.de");
        assert!(wire.windows(9).any(|window| window == b"b\xfccher.de"));
        assert!(
            !wire
                .windows(10)
                .any(|window| window == "bücher.de".as_bytes())
        );
    }

    #[test]
    fn combined_rejection_matches_java_separator_order() {
        let result = SpamhausResult {
            ip: Some(Listing {
                zone: "zen.example".into(),
                return_code: Ipv4Addr::new(127, 0, 0, 2),
                description: "SBL (Spamhaus Block List)".into(),
            }),
            domain: Some(Listing {
                zone: "dbl.example".into(),
                return_code: Ipv4Addr::new(127, 0, 1, 5),
                description: "DBL (malware domain)".into(),
            }),
        };
        assert_eq!(result.metadata(), "Listed in: zen.example, dbl.example");
        let wire = String::from_utf8(
            result.rejection_wire(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), "mail.com"),
        )
        .unwrap();
        assert!(wire.contains("client host [8.8.8.8] blocked using zen.example"));
        assert!(wire.contains("; sender domain [mail.com] blocked using dbl.example"));
    }

    #[test]
    fn java_private_address_classes_are_skipped() {
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(is_private_ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(is_private_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!is_private_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
    }

    #[test]
    fn direct_dns_response_accepts_only_exact_a_and_nxdomain_messages() {
        let (request, question, response) = direct_response_fixture();
        assert_eq!(
            classify_direct_ipv4_response(&request, &question, &response.to_vec().unwrap()),
            DirectLookup::Answer(vec![Ipv4Addr::new(127, 0, 0, 2)])
        );

        let mut nxdomain = request.clone().into_response();
        nxdomain.metadata.response_code = ResponseCode::NXDomain;
        assert_eq!(
            classify_direct_ipv4_response(&request, &question, &nxdomain.to_vec().unwrap()),
            DirectLookup::NxDomain
        );
    }

    #[test]
    fn direct_dns_response_rejects_mismatched_metadata_and_question() {
        let (request, question, response) = direct_response_fixture();

        let mut wrong_id = response.clone();
        wrong_id.metadata.id = request.metadata.id.wrapping_add(1);

        let mut wrong_question = response.clone();
        wrong_question.queries.clear();
        wrong_question.add_query(Query::query(
            Name::from_ascii("other.zen.example.").unwrap(),
            RecordType::A,
        ));

        let mut truncated = response.clone();
        truncated.metadata.truncation = true;

        let mut wrong_opcode = response.clone();
        wrong_opcode.metadata.op_code = OpCode::Update;

        let mut server_failure = response.clone();
        server_failure.metadata.response_code = ResponseCode::ServFail;

        for invalid in [
            wrong_id,
            wrong_question,
            truncated,
            wrong_opcode,
            server_failure,
            request.clone(),
        ] {
            assert_eq!(
                classify_direct_ipv4_response(&request, &question, &invalid.to_vec().unwrap()),
                DirectLookup::Failed
            );
        }
    }

    #[test]
    fn direct_dns_structured_fuzz_corpus_is_bounded_and_fail_open() {
        let (request, question, response) = direct_response_fixture();
        let valid = response.to_vec().unwrap();
        let request_bytes = request.to_vec().unwrap();

        for truncated_at in 0..valid.len() {
            assert_eq!(
                classify_direct_ipv4_response(&request, &question, &valid[..truncated_at]),
                DirectLookup::Failed,
                "truncated response accepted at byte {truncated_at}"
            );
        }
        for malformed in [
            Vec::new(),
            vec![0_u8; 11],
            vec![0_u8; 12],
            vec![0xff_u8; 127],
            request_bytes,
            vec![0_u8; MAX_EXPLICIT_DNS_RESPONSE_BYTES + 1],
        ] {
            assert_eq!(
                classify_direct_ipv4_response(&request, &question, &malformed),
                DirectLookup::Failed
            );
        }
    }

    proptest! {
        #[test]
        fn direct_dns_transaction_id_mismatch_is_always_rejected(
            delta in 1_u16..=u16::MAX,
        ) {
            let (request, question, mut response) = direct_response_fixture();
            response.metadata.id = request.metadata.id.wrapping_add(delta);
            prop_assert_eq!(
                classify_direct_ipv4_response(
                    &request,
                    &question,
                    &response.to_vec().unwrap(),
                ),
                DirectLookup::Failed
            );
        }
    }
}
