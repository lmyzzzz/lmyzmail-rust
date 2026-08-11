use std::{
    borrow::Borrow,
    collections::HashMap,
    hash::Hash,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use hickory_resolver::config::{NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RData;
use mail_auth::{
    AuthenticatedMessage, DkimResult, Error, MessageAuthenticator, Parameters, ResolverCache, Txt,
    common::{crypto::CryptoError, parse::TxtRecordParser, verify::DomainKey},
    dkim::DkimError,
};
use tokio::{sync::Semaphore, time::timeout};
use tokio_util::sync::CancellationToken;

const DKIM_DEADLINE: Duration = Duration::from_secs(10);
const MAX_CONCURRENT_DKIM_VERIFICATIONS: usize = 16;
const MAX_TRANSACTION_TXT_CACHE_ENTRIES: usize = 16;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DkimVerification {
    result: &'static str,
    reason: String,
}

impl DkimVerification {
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
        if self.result == "fail" { 3.0 } else { 0.0 }
    }

    pub(crate) fn should_quarantine(&self) -> bool {
        self.result == "fail"
    }

    fn none() -> Self {
        Self {
            result: "none",
            reason: "No DKIM signature present".to_owned(),
        }
    }

    fn parse_error() -> Self {
        Self {
            result: "permerror",
            reason: "Failed to parse email headers".to_owned(),
        }
    }

    fn malformed_signature() -> Self {
        Self {
            result: "permerror",
            reason: "Missing required DKIM tags".to_owned(),
        }
    }

    fn missing_key(domain: &str) -> Self {
        Self {
            result: "permerror",
            reason: format!("DKIM public key not found for {domain}"),
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
pub(crate) struct DkimVerifier {
    authenticator: MessageAuthenticator,
    permits: Arc<Semaphore>,
}

impl DkimVerifier {
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
            permits: Arc::new(Semaphore::new(MAX_CONCURRENT_DKIM_VERIFICATIONS)),
        })
    }

    pub(crate) async fn verify(
        &self,
        raw_message: &[u8],
        cancellation: &CancellationToken,
    ) -> DkimVerification {
        let operation = async {
            let Ok(_permit) = self.permits.acquire().await else {
                return DkimVerification::temporary_failure(
                    "Verification error: DKIM verification pool closed",
                );
            };
            let Some(mut message) = AuthenticatedMessage::parse(raw_message) else {
                return DkimVerification::parse_error();
            };
            if message.dkim_headers.is_empty() {
                return if message.has_dkim_errors {
                    DkimVerification::malformed_signature()
                } else {
                    DkimVerification::none()
                };
            }

            message.dkim_headers.truncate(1);
            message.errors.clear();
            let signature = &message.dkim_headers[0].header;
            let signing_domain = signature.d.as_str();
            let domain_key = format!(
                "{}._domainkey.{}.",
                signature.s.trim_end_matches('.'),
                signature.d.trim_end_matches('.'),
            );
            let Some(domain_key_record) = self.lookup_domain_key(&domain_key).await else {
                return DkimVerification::missing_key(signing_domain);
            };
            let cache = TransactionTxtCache::with_domain_key(&domain_key, domain_key_record);
            self.authenticator
                .verify_dkim(Parameters::new(&message).with_txt_cache(&cache))
                .await
                .into_iter()
                .next()
                .map(|output| {
                    map_result(
                        output.result(),
                        output
                            .signature()
                            .map(|signature| signature.d.as_str())
                            .unwrap_or(signing_domain),
                    )
                })
                .unwrap_or_else(DkimVerification::malformed_signature)
        };

        tokio::select! {
            _ = cancellation.cancelled() => {
                DkimVerification::temporary_failure(
                    "Verification error: operation cancelled",
                )
            }
            result = timeout(DKIM_DEADLINE, operation) => match result {
                Ok(result) => result,
                Err(_) => DkimVerification::temporary_failure("Verification error: DNS query timed out"),
            }
        }
    }

    async fn lookup_domain_key(&self, domain_key: &str) -> Option<DomainKey> {
        let lookup = self.authenticator.0.txt_lookup(domain_key).await.ok()?;
        lookup.answers().iter().find_map(|record| {
            let RData::TXT(record) = &record.data else {
                return None;
            };
            let bytes = record
                .txt_data
                .iter()
                .flat_map(|chunk| chunk.iter().copied())
                .collect::<Vec<_>>();
            DomainKey::parse(&bytes).ok()
        })
    }
}

fn map_result(result: &DkimResult, domain: &str) -> DkimVerification {
    match result {
        DkimResult::Pass => DkimVerification {
            result: "pass",
            reason: format!("DKIM signature verified for {domain}"),
        },
        DkimResult::Neutral(Error::Dkim(DkimError::FailedBodyHashMatch))
        | DkimResult::Fail(Error::Dkim(DkimError::FailedBodyHashMatch)) => DkimVerification {
            result: "fail",
            reason: "Body hash mismatch".to_owned(),
        },
        DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)) => DkimVerification {
            result: "fail",
            reason: format!("Signature verification failed for {domain}: Signature mismatch"),
        },
        DkimResult::Fail(error) => DkimVerification {
            result: "fail",
            reason: format!("Signature verification failed for {domain}: {error}"),
        },
        DkimResult::PermError(Error::Dns(_)) | DkimResult::TempError(Error::Dns(_)) => {
            DkimVerification::missing_key(domain)
        }
        DkimResult::PermError(error) | DkimResult::Neutral(error) => DkimVerification {
            result: "permerror",
            reason: format!("Verification error: {error}"),
        },
        DkimResult::TempError(error) => {
            DkimVerification::temporary_failure(&format!("Verification error: {error}"))
        }
        DkimResult::None => DkimVerification::none(),
    }
}

#[derive(Default)]
struct TransactionTxtCache {
    entries: Mutex<HashMap<Box<str>, (Txt, Instant)>>,
}

impl TransactionTxtCache {
    fn with_domain_key(domain_key: &str, record: DomainKey) -> Self {
        let mut entries = HashMap::with_capacity(1);
        entries.insert(
            domain_key.to_owned().into_boxed_str(),
            (
                Txt::DomainKey(Arc::new(record)),
                Instant::now() + DKIM_DEADLINE,
            ),
        );
        Self {
            entries: Mutex::new(entries),
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_result_mapping_preserves_protocol_scores_and_reasons() {
        let domain = "dkim.blackbox-example.com";
        let pass = map_result(&DkimResult::Pass, domain);
        assert_eq!(pass.result(), "pass");
        assert_eq!(
            pass.reason(),
            "DKIM signature verified for dkim.blackbox-example.com"
        );
        assert!(pass.passed());
        assert_eq!(pass.protocol_score(), 0.0);

        let body = map_result(
            &DkimResult::Neutral(Error::Dkim(DkimError::FailedBodyHashMatch)),
            domain,
        );
        assert_eq!(body.result(), "fail");
        assert_eq!(body.reason(), "Body hash mismatch");
        assert!(body.should_quarantine());
        assert_eq!(body.protocol_score(), 3.0);

        let signature = map_result(
            &DkimResult::Fail(Error::Crypto(CryptoError::FailedVerification)),
            domain,
        );
        assert_eq!(signature.result(), "fail");
        assert_eq!(
            signature.reason(),
            "Signature verification failed for dkim.blackbox-example.com: Signature mismatch"
        );
    }

    #[test]
    fn transaction_txt_cache_is_hard_bounded() {
        let cache = TransactionTxtCache::default();
        for index in 0..64 {
            ResolverCache::<Box<str>, Txt>::insert(
                &cache,
                format!("{index}._domainkey.example").into_boxed_str(),
                Txt::Error(Error::ParseError),
                Instant::now() + Duration::from_secs(60),
            );
        }
        assert_eq!(cache.entries.lock().unwrap().len(), 16);
    }

    #[test]
    fn unsigned_message_has_java_none_verdict() {
        let message = AuthenticatedMessage::parse(b"From: sender@example.test\r\n\r\nbody\r\n")
            .expect("message should parse");
        assert!(message.dkim_headers.is_empty());
        assert!(!message.has_dkim_errors);
        assert_eq!(DkimVerification::none().result(), "none");
        assert_eq!(
            DkimVerification::none().reason(),
            "No DKIM signature present"
        );
    }
}
