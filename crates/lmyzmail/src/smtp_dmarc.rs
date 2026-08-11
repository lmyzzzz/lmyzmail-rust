use std::{net::SocketAddr, sync::Arc, time::Duration};

use hickory_resolver::{
    config::{NameServerConfig, ResolverConfig, ResolverOpts},
    proto::rr::RData,
};
use mail_auth::{
    MessageAuthenticator,
    common::parse::TxtRecordParser,
    dmarc::{Alignment, Dmarc, Policy},
};
use mail_parser::{Address, HeaderName, Message};
use tokio::{sync::Semaphore, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::smtp_dkim::DkimVerification;
use crate::smtp_spf::SpfVerification;

const DMARC_DEADLINE: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_DMARC_LOOKUPS: usize = 16;
const MAX_DMARC_TXT_RECORDS: usize = 32;
const MAX_DMARC_RECORD_BYTES: usize = 4 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DmarcRecord {
    policy: Policy,
    adkim: Alignment,
    aspf: Alignment,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DmarcVerification {
    result: &'static str,
    policy: Option<&'static str>,
    reason: String,
    header_from_domain: Option<String>,
    spf_aligned: bool,
    dkim_aligned: bool,
}

impl DmarcVerification {
    pub(crate) fn authentication_result(&self) -> String {
        self.policy.map_or_else(
            || format!("dmarc={} {}", self.result, self.reason),
            |policy| format!("dmarc={} (p={policy}) {}", self.result, self.reason),
        )
    }

    pub(crate) fn passed(&self) -> bool {
        self.result == "pass"
    }

    pub(crate) fn protocol_score(&self) -> f64 {
        if self.result == "fail" { 2.0 } else { 0.0 }
    }

    pub(crate) fn should_quarantine(&self) -> bool {
        self.result == "fail" && self.policy == Some("quarantine")
    }

    pub(crate) fn should_reject(&self) -> bool {
        self.result == "fail" && self.policy == Some("reject")
    }

    fn none(header_from_domain: Option<String>) -> Self {
        Self {
            result: "none",
            policy: None,
            reason: "No DMARC record found".to_owned(),
            header_from_domain,
            spf_aligned: false,
            dkim_aligned: false,
        }
    }
}

#[derive(Clone)]
pub(crate) struct DmarcVerifier {
    authenticator: MessageAuthenticator,
    permits: Arc<Semaphore>,
}

impl DmarcVerifier {
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
        Ok(Self {
            authenticator,
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DMARC_LOOKUPS)),
        })
    }

    pub(crate) async fn lookup_sender_record(
        &self,
        sender: &str,
        cancellation: &CancellationToken,
    ) -> Option<DmarcRecord> {
        let domain = sender.rsplit_once('@').map(|(_, domain)| domain)?;
        let domain = normalize_domain(domain)?;
        self.lookup_record(&domain, cancellation).await
    }

    pub(crate) async fn verify(
        &self,
        message: Option<&Message<'_>>,
        sender: Option<&str>,
        spf: Option<&SpfVerification>,
        dkim: Option<&DkimVerification>,
        cached_sender_record: Option<DmarcRecord>,
        cancellation: &CancellationToken,
    ) -> DmarcVerification {
        let header_from_domain = message.and_then(header_from_domain);
        let Some(header_domain) = header_from_domain.as_deref() else {
            return DmarcVerification::none(header_from_domain);
        };
        let envelope_domain = sender
            .and_then(|sender| sender.rsplit_once('@').map(|(_, domain)| domain))
            .and_then(normalize_domain);
        let record = if envelope_domain.as_deref() == Some(header_domain) {
            match cached_sender_record {
                Some(record) => Some(record),
                None => self.lookup_record(header_domain, cancellation).await,
            }
        } else {
            self.lookup_record(header_domain, cancellation).await
        };
        let Some(record) = record else {
            return DmarcVerification::none(header_from_domain);
        };

        let spf_aligned = spf.is_some_and(SpfVerification::passed)
            && domains_align(envelope_domain.as_deref(), Some(header_domain), record.aspf);
        let dkim_aligned = dkim.is_some_and(DkimVerification::passed)
            && domains_align(
                dkim.and_then(DkimVerification::signing_domain),
                Some(header_domain),
                record.adkim,
            );
        let policy = policy_name(record.policy);
        if spf_aligned || dkim_aligned {
            let mechanism = match (spf_aligned, dkim_aligned) {
                (true, true) => "SPF and DKIM aligned",
                (true, false) => "SPF aligned",
                (false, true) => "DKIM aligned",
                (false, false) => unreachable!(),
            };
            DmarcVerification {
                result: "pass",
                policy: Some(policy),
                reason: format!("DMARC passed: {mechanism}"),
                header_from_domain,
                spf_aligned,
                dkim_aligned,
            }
        } else {
            DmarcVerification {
                result: "fail",
                policy: Some(policy),
                reason: format!(
                    "DMARC failed: authenticated identifiers are not aligned with RFC5322.From {header_domain}"
                ),
                header_from_domain,
                spf_aligned: false,
                dkim_aligned: false,
            }
        }
    }

    async fn lookup_record(
        &self,
        domain: &str,
        cancellation: &CancellationToken,
    ) -> Option<DmarcRecord> {
        let operation = async {
            let _permit = self.permits.acquire().await.ok()?;
            if let Some(record) = self.query_record(domain).await {
                return Some(DmarcRecord {
                    policy: record.p,
                    adkim: record.adkim,
                    aspf: record.aspf,
                });
            }
            let organizational = organizational_domain(domain)?;
            if organizational == domain {
                return None;
            }
            let record = self.query_record(organizational).await?;
            Some(DmarcRecord {
                policy: record.sp,
                adkim: record.adkim,
                aspf: record.aspf,
            })
        };

        tokio::select! {
            _ = cancellation.cancelled() => None,
            result = timeout(DMARC_DEADLINE, operation) => result.ok().flatten(),
        }
    }

    async fn query_record(&self, domain: &str) -> Option<Dmarc> {
        let lookup = self
            .authenticator
            .0
            .txt_lookup(format!("_dmarc.{domain}."))
            .await
            .ok()?;
        lookup
            .answers()
            .iter()
            .take(MAX_DMARC_TXT_RECORDS)
            .find_map(|record| {
                let RData::TXT(record) = &record.data else {
                    return None;
                };
                let total = record
                    .txt_data
                    .iter()
                    .try_fold(0_usize, |total, chunk| total.checked_add(chunk.len()))?;
                if total > MAX_DMARC_RECORD_BYTES {
                    return None;
                }
                let bytes = record
                    .txt_data
                    .iter()
                    .flat_map(|chunk| chunk.iter().copied())
                    .collect::<Vec<_>>();
                Dmarc::parse(&bytes).ok()
            })
    }
}

fn header_from_domain(message: &Message<'_>) -> Option<String> {
    let from_headers = message
        .root_part()
        .headers
        .iter()
        .filter(|header| header.name == HeaderName::From)
        .count();
    if from_headers != 1 {
        return None;
    }
    let Address::List(addresses) = message.from()? else {
        return None;
    };
    let [address] = addresses.as_slice() else {
        return None;
    };
    let address = address.address.as_deref()?;
    let (_, domain) = address.rsplit_once('@')?;
    normalize_domain(domain)
}

fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain.trim().strip_suffix('.').unwrap_or(domain.trim());
    if domain.is_empty() {
        return None;
    }
    let ascii = idna::domain_to_ascii(domain).ok()?.to_ascii_lowercase();
    (ascii.len() <= 253).then_some(ascii)
}

fn organizational_domain(domain: &str) -> Option<&str> {
    psl::domain_str(domain)
}

fn domains_align(
    authenticated_domain: Option<&str>,
    from_domain: Option<&str>,
    alignment: Alignment,
) -> bool {
    let (Some(authenticated), Some(from)) = (
        authenticated_domain.and_then(normalize_domain),
        from_domain.and_then(normalize_domain),
    ) else {
        return false;
    };
    if authenticated == from {
        return true;
    }
    alignment == Alignment::Relaxed
        && organizational_domain(&authenticated)
            .zip(organizational_domain(&from))
            .is_some_and(|(authenticated, from)| authenticated == from)
}

fn policy_name(policy: Policy) -> &'static str {
    match policy {
        Policy::Quarantine => "quarantine",
        Policy::Reject => "reject",
        Policy::None | Policy::Unspecified => "none",
    }
}

#[cfg(test)]
mod tests {
    use mail_parser::MessageParser;

    use super::*;

    #[test]
    fn header_from_requires_one_mailbox_and_rejects_groups() {
        let one = MessageParser::default()
            .parse_headers(b"From: Sender <sender@Example.COM>\r\n\r\n")
            .unwrap();
        assert_eq!(header_from_domain(&one).as_deref(), Some("example.com"));

        let many = MessageParser::default()
            .parse_headers(b"From: a@example.com, b@example.com\r\n\r\n")
            .unwrap();
        assert_eq!(header_from_domain(&many), None);

        let group = MessageParser::default()
            .parse_headers(b"From: Group: a@example.com;\r\n\r\n")
            .unwrap();
        assert_eq!(header_from_domain(&group), None);
    }

    #[test]
    fn strict_and_relaxed_alignment_use_the_registrable_domain() {
        assert!(domains_align(
            Some("mail.example.co.uk"),
            Some("mail.example.co.uk"),
            Alignment::Strict,
        ));
        assert!(!domains_align(
            Some("mail.example.co.uk"),
            Some("from.example.co.uk"),
            Alignment::Strict,
        ));
        assert!(domains_align(
            Some("mail.example.co.uk"),
            Some("from.example.co.uk"),
            Alignment::Relaxed,
        ));
        assert!(!domains_align(
            Some("example.co.uk"),
            Some("example.com"),
            Alignment::Relaxed,
        ));
    }

    #[test]
    fn java_protocol_score_and_dispositions_are_policy_specific() {
        let pass = DmarcVerification {
            result: "pass",
            policy: Some("reject"),
            reason: "DMARC passed: SPF aligned".to_owned(),
            header_from_domain: Some("example.com".to_owned()),
            spf_aligned: true,
            dkim_aligned: false,
        };
        assert!(pass.passed());
        assert_eq!(pass.protocol_score(), 0.0);
        assert!(!pass.should_quarantine());
        assert!(!pass.should_reject());

        let mut fail = pass.clone();
        fail.result = "fail";
        fail.policy = Some("quarantine");
        assert_eq!(fail.protocol_score(), 2.0);
        assert!(fail.should_quarantine());
        assert!(!fail.should_reject());
        fail.policy = Some("reject");
        assert!(!fail.should_quarantine());
        assert!(fail.should_reject());
    }
}
