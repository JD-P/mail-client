use crate::{
    DkimAuthentication, DkimAuthenticationStatus, DkimDnsResolver, DkimSignatureEvidence,
    DkimSignatureStatus,
};
use mail_auth::{
    crypto::Algorithm,
    dkim::{DkimError, DkimVerificationOptions},
    AuthenticatedMessage, AuthenticationLimits, DkimResult, Error, MessageAuthenticator,
};
use std::time::Duration;

const DKIM_TIMEOUT: Duration = Duration::from_secs(15);

pub(crate) struct DkimVerifier {
    authenticator: MessageAuthenticator,
}

impl DkimVerifier {
    pub(crate) fn new(resolver: DkimDnsResolver) -> Result<Self, String> {
        let authenticator = match resolver {
            DkimDnsResolver::Quad9Tls => MessageAuthenticator::new_quad9_tls(),
            DkimDnsResolver::System => MessageAuthenticator::new_system_conf(),
        }
        .map_err(|error| error.to_string())?;
        Ok(Self { authenticator })
    }

    pub(crate) async fn verify(&self, raw: &[u8], evaluated_at: i64) -> DkimAuthentication {
        let message =
            match AuthenticatedMessage::parse_with_limits(raw, AuthenticationLimits::default()) {
                Ok(message) => message,
                Err(error) => {
                    return DkimAuthentication {
                        status: DkimAuthenticationStatus::NotEvaluated,
                        signatures: Vec::new(),
                        evaluated_at,
                        detail: Some(error.to_string()),
                    };
                }
            };
        let from_domain = (message.from_addresses().len() == 1)
            .then(|| address_domain(&message.from_addresses()[0]))
            .flatten();
        let verification = self.authenticator.verify_dkim_with_options(
            &message,
            DkimVerificationOptions {
                max_signatures: 16,
                max_dns_lookups: 16,
                check_atps: false,
                discover_failure_reports: false,
            },
        );
        let outputs = match tokio::time::timeout(DKIM_TIMEOUT, verification).await {
            Ok(outputs) => outputs,
            Err(_) => {
                return DkimAuthentication {
                    status: DkimAuthenticationStatus::TemporaryFailure,
                    signatures: Vec::new(),
                    evaluated_at,
                    detail: Some("DKIM verification timed out".into()),
                };
            }
        };
        if outputs.is_empty() {
            return DkimAuthentication {
                status: DkimAuthenticationStatus::Unsigned,
                signatures: Vec::new(),
                evaluated_at,
                detail: None,
            };
        }

        let signatures = outputs
            .iter()
            .map(|output| {
                let signature = output.signature();
                let (status, error) = match output.result() {
                    DkimResult::Pass => (DkimSignatureStatus::Pass, None),
                    DkimResult::Fail(error) => (DkimSignatureStatus::Fail, Some(error)),
                    DkimResult::Neutral(error) => (DkimSignatureStatus::Neutral, Some(error)),
                    DkimResult::PermError(error) => {
                        (DkimSignatureStatus::PermanentError, Some(error))
                    }
                    DkimResult::TempError(error) => {
                        (DkimSignatureStatus::TemporaryError, Some(error))
                    }
                    DkimResult::None => (DkimSignatureStatus::Neutral, None),
                };
                DkimSignatureEvidence {
                    header_index: output
                        .header_index()
                        .and_then(|index| u32::try_from(index).ok()),
                    status,
                    reason_code: error.map(error_code).map(str::to_owned),
                    reason: error.map(ToString::to_string),
                    signing_domain: signature.map(|signature| signature.d.clone()),
                    selector: signature.map(|signature| signature.s.clone()),
                    identity: signature.and_then(|signature| {
                        (!signature.i.is_empty()).then(|| signature.i.clone())
                    }),
                    algorithm: signature.map(|signature| algorithm_name(signature.a).to_owned()),
                    signed_headers: signature
                        .map(|signature| signature.h.clone())
                        .unwrap_or_default(),
                    from_domain_aligned: signature.and_then(|signature| {
                        from_domain
                            .as_deref()
                            .map(|from| domains_align(from, &signature.d))
                    }),
                    key_bits: output.key_bits().and_then(|bits| u32::try_from(bits).ok()),
                    key_testing: output.key_is_testing(),
                    raw_header_value: output
                        .raw_header()
                        .map(|(_, value)| String::from_utf8_lossy(value).into_owned()),
                }
            })
            .collect::<Vec<_>>();
        let status = if signatures
            .iter()
            .any(|signature| signature.status == DkimSignatureStatus::Pass)
        {
            DkimAuthenticationStatus::Pass
        } else if signatures
            .iter()
            .any(|signature| signature.status == DkimSignatureStatus::TemporaryError)
        {
            DkimAuthenticationStatus::TemporaryFailure
        } else {
            DkimAuthenticationStatus::Failed
        };
        DkimAuthentication {
            status,
            signatures,
            evaluated_at,
            detail: None,
        }
    }
}

fn address_domain(address: &str) -> Option<String> {
    address
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

fn domains_align(from: &str, signing: &str) -> bool {
    let from = from.trim_end_matches('.').to_ascii_lowercase();
    let signing = signing.trim_end_matches('.').to_ascii_lowercase();
    from == signing
        || matches!(
            (psl::domain_str(&from), psl::domain_str(&signing)),
            (Some(from), Some(signing)) if from.eq_ignore_ascii_case(signing)
        )
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::RsaSha1 => "rsa-sha1",
        Algorithm::RsaSha256 => "rsa-sha256",
        Algorithm::Ed25519Sha256 => "ed25519-sha256",
        Algorithm::MlDsa44 => "mldsa44",
    }
}

fn error_code(error: &Error) -> &'static str {
    match error {
        Error::Parse => "parse",
        Error::MissingParameters => "missing_parameters",
        Error::ResourceLimit(_) => "resource_limit",
        Error::NoHeadersFound => "no_headers_found",
        Error::Base64 => "invalid_base64",
        Error::NotAligned => "not_aligned",
        Error::Io(_) => "io",
        Error::Crypto(_) => "cryptographic_verification",
        Error::Dns(_) => "dns",
        Error::Dkim(error) => match error {
            DkimError::DuplicateTag => "duplicate_tag",
            DkimError::MissingVersion => "missing_version",
            DkimError::MissingAlgorithm => "missing_algorithm",
            DkimError::VersionNotFirst => "version_not_first",
            DkimError::InvalidTagValue => "invalid_tag_value",
            DkimError::UnsupportedQueryMethod => "unsupported_query_method",
            DkimError::FromNotSigned => "from_not_signed",
            DkimError::UnsupportedVersion => "unsupported_version",
            DkimError::UnsupportedAlgorithm => "unsupported_algorithm",
            DkimError::UnsupportedCanonicalization => "unsupported_canonicalization",
            DkimError::UnsupportedKeyType => "unsupported_key_type",
            DkimError::BodyHashMismatch => "body_hash_mismatch",
            DkimError::AuidMismatch => "identity_domain_mismatch",
            DkimError::PublicKeyRevoked => "public_key_revoked",
            DkimError::SignatureExpired => "signature_expired",
            DkimError::BodyLengthTag => "body_length_tag",
            DkimError::MultipleKeyRecords => "multiple_key_records",
            DkimError::HashNotAllowed => "hash_not_allowed",
            DkimError::ServiceNotAllowed => "service_not_allowed",
            DkimError::WeakRsaKey => "weak_rsa_key",
            DkimError::TooManySignatures => "too_many_signatures",
            DkimError::DnsLookupBudget => "dns_lookup_budget",
        },
        Error::Dkim2(_) => "dkim2",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relaxed_alignment_uses_registrable_domains() {
        assert!(domains_align("mail.example.com", "example.com"));
        assert!(!domains_align("example.com", "example.net"));
        assert!(!domains_align("example.co.uk", "attacker.co.uk"));
    }
}
