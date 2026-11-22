use crate::heuristic::ProducedFinding;
use crate::{
    ArchiveInspectionState, ArchiveLimits, AuthenticationMethodKind, AuthenticationMethodResult,
    AuthenticationResultsTrust, Backend, DkimAuthenticationStatus, DkimSignatureStatus,
    FindingPresentation, FindingSeverity, FindingTargetKind, Heuristic, HeuristicEvaluationStatus,
    HeuristicId, HeuristicSourceKind, Message, MessageContentAvailability, OpenPgpSignatureStatus,
    Result, ThreadSenderTrust,
};
use html5ever::tendril::StrTendril;
use html5ever::tokenizer::states::RawKind;
use html5ever::tokenizer::{
    BufferQueue, EndTag, StartTag, TagToken, Token, TokenSink, TokenSinkResult, Tokenizer,
    TokenizerOpts,
};
use serde_json::json;
use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use turso::{params_from_iter, Connection, Value};
use unicode_security::skeleton;
use url::{Host, Url};
use uuid::Uuid;

const BUILTIN_ID: Uuid = Uuid::from_u128(0x5f01da21_0f79_5f3e_b210_0d96438890ac);
const BUILTIN_VERSION: u32 = 5;
const BUILTIN_SOURCE: &str = "native:security-evidence";
const MAX_FINDINGS: usize = 256;
const MAX_HTML_TOKENS: usize = 100_000;
const MAX_HTML_ANCHORS: usize = 2_048;
const MAX_REMOTE_RESOURCES: usize = 128;
const MAX_CREDENTIAL_FORMS: usize = 64;
const MAX_STYLE_BYTES: usize = 64 * 1024;
const MAX_CONTACT_FACTS: usize = 4_096;
const ARCHIVE_INPUT_BYTES: u64 = 8 * 1024 * 1024;

pub(crate) struct NativeEvaluation {
    pub status: HeuristicEvaluationStatus,
    pub detail: Option<String>,
    pub findings: Vec<ProducedFinding>,
}

pub(crate) fn builtin_id() -> HeuristicId {
    HeuristicId::from_uuid(BUILTIN_ID)
}

pub(crate) fn is_builtin_native(heuristic: &Heuristic) -> bool {
    heuristic.id == builtin_id() && heuristic.source == BUILTIN_SOURCE
}

pub(crate) fn definition() -> Heuristic {
    Heuristic {
        id: builtin_id(),
        name: "Built-in security evidence".into(),
        version: BUILTIN_VERSION,
        source: BUILTIN_SOURCE.into(),
        source_kind: HeuristicSourceKind::BuiltIn,
        enabled: true,
        required_features: vec![
            "identity".into(),
            "dkim".into(),
            "links".into(),
            "bounded_html_tokens".into(),
            "attachment_magic".into(),
            "zip_directory_metadata".into(),
        ],
        maximum_steps: 200_000,
        created_at: 0,
        updated_at: 0,
    }
}

pub(crate) async fn initialize(connection: &mut Connection) -> Result<()> {
    let heuristic = definition();
    let required = serde_json::to_string(&heuristic.required_features)?;
    connection
        .execute(
            r#"INSERT INTO heuristics(
                id, name, version, source, source_kind, enabled,
                compiled_json, required_features_json, maximum_steps,
                created_at, updated_at, deleted_at
            ) VALUES (?1, ?2, ?3, ?4, 'built_in', 1, 'null', ?5, ?6, 0, 0, NULL)
            ON CONFLICT(id) DO UPDATE SET
                name = excluded.name,
                version = excluded.version,
                source = excluded.source,
                source_kind = 'built_in',
                enabled = 1,
                compiled_json = 'null',
                required_features_json = excluded.required_features_json,
                maximum_steps = excluded.maximum_steps,
                updated_at = 0,
                deleted_at = NULL"#,
            (
                heuristic.id.to_string(),
                heuristic.name,
                i64::from(heuristic.version),
                heuristic.source,
                required.clone(),
                i64::from(heuristic.maximum_steps),
            ),
        )
        .await?;
    connection
        .execute(
            r#"INSERT OR IGNORE INTO heuristic_versions(
                heuristic_id, version, source, source_kind, compiled_json,
                required_features_json, maximum_steps, created_at
            ) VALUES (?1, ?2, ?3, 'built_in', 'null', ?4, ?5, 0)"#,
            (
                builtin_id().to_string(),
                i64::from(BUILTIN_VERSION),
                BUILTIN_SOURCE.to_owned(),
                required,
                i64::from(definition().maximum_steps),
            ),
        )
        .await?;
    Ok(())
}

pub(crate) async fn evaluate(backend: &Backend, message: &Message) -> Result<NativeEvaluation> {
    let facts = load_contact_facts(backend).await?;
    evaluate_with_contact_facts(backend, message, &facts).await
}

pub(crate) async fn evaluate_many(
    backend: &Backend,
    messages: &[Message],
) -> Result<Vec<NativeEvaluation>> {
    let facts = load_contact_facts(backend).await?;
    let mut evaluations = Vec::with_capacity(messages.len());
    for message in messages {
        evaluations.push(evaluate_with_contact_facts(backend, message, &facts).await?);
    }
    Ok(evaluations)
}

async fn evaluate_with_contact_facts(
    backend: &Backend,
    message: &Message,
    facts: &ContactFacts,
) -> Result<NativeEvaluation> {
    let context = contact_context(facts, message.summary.from_address.as_deref());
    let mut collector = FindingCollector::default();
    sender_header_findings(backend, message, &mut collector).await?;
    identity_findings(backend, message, &context, &mut collector).await?;

    if message.summary.content_availability == MessageContentAvailability::Complete {
        dkim_findings(message, &mut collector);
        openpgp_identity_findings(message, &mut collector);
        navigation_findings(message, &context, &mut collector);
        attachment_findings(backend, message, &mut collector).await;
    }

    let limited = collector.limited;
    if limited {
        collector.push(message_finding(
            "security_analysis_limited",
            FindingPresentation::MessageAnnotation,
            FindingSeverity::Warning,
            json!({"maximum_findings": MAX_FINDINGS}),
        ));
    }
    Ok(NativeEvaluation {
        status: if limited {
            HeuristicEvaluationStatus::NotEvaluatedBudget
        } else {
            HeuristicEvaluationStatus::Complete
        },
        detail: limited.then(|| "built-in security evidence reached a configured budget".into()),
        findings: collector.values,
    })
}

async fn sender_header_findings(
    backend: &Backend,
    message: &Message,
    collector: &mut FindingCollector,
) -> Result<()> {
    // The MIME projection accepts an author only after proving the From shape
    // is singular. Avoid rereading ordinary message blobs; raw-header
    // diagnostics are needed only when that projection deliberately refused
    // to establish an identity.
    if message.summary.from_address.is_some() {
        return Ok(());
    }
    let blob_hash = {
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT blob_hash FROM messages WHERE id = ?1",
                (message.summary.id.to_string(),),
            )
            .await?;
        rows.next()
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?
    };
    let Some(blob_hash) = blob_hash else {
        return Ok(());
    };
    let raw = backend.inner.blobs.get(&blob_hash).await?;
    let Some(parsed) = mail_parser::MessageParser::new().parse_headers(&raw) else {
        collector.push(message_finding(
            "malformed_sender_header",
            FindingPresentation::OpenInterstitial,
            FindingSeverity::Danger,
            json!({"detail": "RFC 5322 headers could not be parsed"}),
        ));
        return Ok(());
    };
    let fields = parsed.all_from().collect::<Vec<_>>();
    let contains_group = fields.iter().any(|field| {
        field
            .iter()
            .any(|address| matches!(address, mail_parser::Address::Group(_)))
    });
    let mailboxes = fields
        .iter()
        .flat_map(|field| field.mailboxes())
        .filter_map(|mailbox| mailbox.address())
        .take(9)
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let overlong = mailboxes
        .iter()
        .any(|address| address.chars().count() > 320);
    if fields.len() != 1 || mailboxes.len() != 1 || contains_group || overlong {
        collector.push(message_finding(
            "ambiguous_sender_header",
            FindingPresentation::OpenInterstitial,
            FindingSeverity::Danger,
            json!({
                "from_field_count": fields.len(),
                "mailboxes": mailboxes.into_iter().take(8).collect::<Vec<_>>(),
                "contains_group": contains_group,
                "overlong": overlong,
            }),
        ));
    }
    Ok(())
}

#[derive(Default)]
struct FindingCollector {
    values: Vec<ProducedFinding>,
    limited: bool,
}

impl FindingCollector {
    fn push(&mut self, finding: ProducedFinding) {
        if self.values.len() < MAX_FINDINGS {
            self.values.push(finding);
        } else {
            self.limited = true;
        }
    }
}

struct ContactFacts {
    names_by_address: HashMap<String, Vec<String>>,
    all_names: Arc<HashSet<String>>,
    all_name_skeletons: Arc<HashSet<String>>,
    meaningful_domains: Arc<BTreeSet<String>>,
    limited: bool,
}

struct ContactContext {
    matched_names: Vec<String>,
    all_names: Arc<HashSet<String>>,
    all_name_skeletons: Arc<HashSet<String>>,
    meaningful_domains: Arc<BTreeSet<String>>,
    sender_domain: Option<String>,
    limited: bool,
}

async fn load_contact_facts(backend: &Backend) -> Result<ContactFacts> {
    let connection = backend.inner.connection.lock().await;
    let mut rows = connection
        .query(
            "SELECT c.display_name, ca.address, ca.accepted_name FROM contacts c JOIN contact_addresses ca ON ca.contact_id = c.id ORDER BY c.id, ca.address LIMIT ?1",
            (i64::try_from(MAX_CONTACT_FACTS + 1).unwrap_or(i64::MAX),),
        )
        .await?;
    let mut names_by_address = HashMap::<String, Vec<String>>::new();
    let mut all_names = HashSet::new();
    let mut all_name_skeletons = HashSet::new();
    let mut meaningful_domains = BTreeSet::new();
    let mut limited = false;
    let mut count = 0usize;
    while let Some(row) = rows.next().await? {
        count += 1;
        if count > MAX_CONTACT_FACTS {
            limited = true;
            break;
        }
        let display_name = row.get::<String>(0)?;
        let address = row.get::<String>(1)?;
        let accepted_name = row.get::<Option<String>>(2)?;
        all_names.insert(normalize_name(&display_name));
        all_name_skeletons.insert(skeleton_string(&display_name));
        let names = names_by_address
            .entry(normalize_address(&address))
            .or_default();
        names.push(display_name);
        if let Some(name) = accepted_name.as_deref() {
            all_names.insert(normalize_name(name));
            all_name_skeletons.insert(skeleton_string(name));
            names.push(name.to_owned());
        }
        if let Some(domain) = address_domain(&address) {
            meaningful_domains.insert(domain);
        }
    }
    Ok(ContactFacts {
        names_by_address,
        all_names: Arc::new(all_names),
        all_name_skeletons: Arc::new(all_name_skeletons),
        meaningful_domains: Arc::new(meaningful_domains),
        limited,
    })
}

fn contact_context(facts: &ContactFacts, from: Option<&str>) -> ContactContext {
    let matched_names = from
        .and_then(|address| facts.names_by_address.get(&normalize_address(address)))
        .cloned()
        .unwrap_or_default();
    ContactContext {
        matched_names,
        all_names: Arc::clone(&facts.all_names),
        all_name_skeletons: Arc::clone(&facts.all_name_skeletons),
        meaningful_domains: Arc::clone(&facts.meaningful_domains),
        sender_domain: from.and_then(address_domain),
        limited: facts.limited,
    }
}

async fn identity_findings(
    backend: &Backend,
    message: &Message,
    context: &ContactContext,
    collector: &mut FindingCollector,
) -> Result<()> {
    collector.limited |= context.limited;
    if message
        .summary
        .from_address
        .as_deref()
        .is_some_and(has_invisible_or_bidi)
        || message
            .summary
            .from_name
            .as_deref()
            .is_some_and(has_invisible_or_bidi)
    {
        collector.push(message_finding(
            "invisible_or_bidi_sender_identity",
            FindingPresentation::OpenInterstitial,
            FindingSeverity::Danger,
            json!({
                "from_address": message.summary.from_address,
                "claimed_name": message.summary.from_name,
            }),
        ));
    }

    if let Some(sender_domain) = message
        .summary
        .from_address
        .as_deref()
        .and_then(address_domain)
    {
        if let Some(embedded) = embedded_popular_domain(&sender_domain) {
            collector.push(message_finding(
                "embedded_popular_sender_domain",
                FindingPresentation::OpenInterstitial,
                FindingSeverity::Danger,
                json!({
                    "sender_domain": sender_domain,
                    "actual_registrable_domain": registrable(&sender_domain),
                    "embedded_popular_domain": embedded,
                }),
            ));
        }
        if let Some(confusable) = confusable_popular_domain(&sender_domain) {
            collector.push(message_finding(
                "confusable_popular_sender_domain",
                FindingPresentation::OpenInterstitial,
                FindingSeverity::Danger,
                json!({
                    "sender_domain": sender_domain,
                    "confusable_with": confusable,
                }),
            ));
        }
        let sender_skeleton = skeleton_string(&sender_domain);
        if let Some(confusable) = context.meaningful_domains.iter().find(|candidate| {
            !candidate.eq_ignore_ascii_case(&sender_domain)
                && skeleton_string(candidate) == sender_skeleton
        }) {
            collector.push(message_finding(
                "confusable_sender_domain",
                FindingPresentation::OpenInterstitial,
                FindingSeverity::Danger,
                json!({
                    "sender_domain": sender_domain,
                    "confusable_with": confusable,
                }),
            ));
        }
    }
    if let Some(claimed_name) = message.summary.from_name.as_deref() {
        let claimed = normalize_name(claimed_name);
        if !context.matched_names.is_empty()
            && context
                .matched_names
                .iter()
                .all(|name| normalize_name(name) != claimed)
        {
            collector.push(message_finding(
                "warm_sender_name_mismatch",
                FindingPresentation::MessageAnnotation,
                FindingSeverity::Warning,
                json!({
                    "claimed_name": claimed_name,
                    "local_names": context.matched_names,
                    "from_address": message.summary.from_address,
                }),
            ));
        } else if context.matched_names.is_empty()
            && (context.all_names.contains(&claimed)
                || context
                    .all_name_skeletons
                    .contains(&skeleton_string(claimed_name)))
        {
            collector.push(message_finding(
                "cold_contact_name_collision",
                FindingPresentation::MessageAnnotation,
                FindingSeverity::Warning,
                json!({
                    "claimed_name": claimed_name,
                    "from_address": message.summary.from_address,
                }),
            ));
        }
    }

    if let Some(from) = message.summary.from_address.as_deref() {
        let from = normalize_address(from);
        let different_senders = message
            .sender_addresses
            .iter()
            .filter(|address| normalize_address(address) != from)
            .cloned()
            .collect::<Vec<_>>();
        if !different_senders.is_empty() {
            collector.push(message_finding(
                "sender_from_mismatch",
                FindingPresentation::MessageAnnotation,
                FindingSeverity::Warning,
                json!({"from": from, "sender": different_senders}),
            ));
        }
        let different_replies = message
            .reply_to_addresses
            .iter()
            .filter(|address| normalize_address(address) != from)
            .cloned()
            .collect::<Vec<_>>();
        if !different_replies.is_empty() {
            collector.push(message_finding(
                "reply_to_mismatch",
                FindingPresentation::MessageAnnotation,
                FindingSeverity::Warning,
                json!({"from": from, "reply_to": different_replies}),
            ));
        }
        for reply in &message.reply_to_addresses {
            if let Some(reply_domain) = address_domain(reply) {
                if let Some(embedded) = embedded_popular_domain(&reply_domain) {
                    collector.push(message_finding(
                        "embedded_popular_reply_domain",
                        FindingPresentation::OpenInterstitial,
                        FindingSeverity::Danger,
                        json!({
                            "reply_to": reply,
                            "reply_domain": reply_domain,
                            "actual_registrable_domain": registrable(&reply_domain),
                            "embedded_popular_domain": embedded,
                        }),
                    ));
                }
                if let Some(confusable) = confusable_popular_domain(&reply_domain) {
                    collector.push(message_finding(
                        "confusable_popular_reply_domain",
                        FindingPresentation::OpenInterstitial,
                        FindingSeverity::Danger,
                        json!({
                            "reply_to": reply,
                            "reply_domain": reply_domain,
                            "confusable_with": confusable,
                        }),
                    ));
                }
            }
        }
    }

    if message.threading.sender_trust == ThreadSenderTrust::Unknown {
        let mut identifiers = message.references.clone();
        identifiers.extend(message.in_reply_to.iter().cloned());
        identifiers.sort_unstable();
        identifiers.dedup();
        identifiers.truncate(100);
        if !identifiers.is_empty() && references_known_thread(backend, &identifiers).await? {
            collector.push(message_finding(
                "conversation_injection",
                FindingPresentation::MessageAnnotation,
                FindingSeverity::Warning,
                json!({"claimed_message_ids": identifiers}),
            ));
        }
    }
    Ok(())
}

fn openpgp_identity_findings(message: &Message, collector: &mut FindingCollector) {
    if message.openpgp.protected_header_mismatch {
        collector.push(message_finding(
            "openpgp_protected_header_mismatch",
            FindingPresentation::OpenInterstitial,
            FindingSeverity::Danger,
            json!({"protected_headers": message.openpgp.protected_headers}),
        ));
    }
    if message
        .openpgp
        .signatures
        .iter()
        .any(|signature| signature.status == OpenPgpSignatureStatus::Invalid)
    {
        collector.push(message_finding(
            "invalid_openpgp_signature",
            FindingPresentation::OpenInterstitial,
            FindingSeverity::Danger,
            json!({}),
        ));
    }
}

async fn references_known_thread(backend: &Backend, identifiers: &[String]) -> Result<bool> {
    let placeholders = std::iter::repeat_n("?", identifiers.len())
        .collect::<Vec<_>>()
        .join(",");
    let sql = format!(
        "SELECT 1 FROM messages WHERE sender_trust = 'known' AND thread_message_id IN ({placeholders}) LIMIT 1"
    );
    let parameters = identifiers
        .iter()
        .cloned()
        .map(Value::Text)
        .collect::<Vec<_>>();
    let connection = backend.inner.connection.lock().await;
    let mut rows = connection.query(sql, params_from_iter(parameters)).await?;
    Ok(rows.next().await?.is_some())
}

fn dkim_findings(message: &Message, collector: &mut FindingCollector) {
    if message.dkim.status == DkimAuthenticationStatus::NotEvaluated {
        return;
    }
    let aligned = message.dkim.signatures.iter().any(|signature| {
        signature.status == DkimSignatureStatus::Pass && signature.from_domain_aligned == Some(true)
    });
    if aligned {
        return;
    }
    let from_domain = message
        .summary
        .from_address
        .as_deref()
        .and_then(address_domain)
        .and_then(|domain| registrable(&domain));
    if message.dkim.status == DkimAuthenticationStatus::Unsigned
        && trusted_aligned_spf_delivery(message)
    {
        collector.push(message_finding(
            "unsigned_dkim_provider_verified",
            FindingPresentation::PersistentWarningFooter,
            FindingSeverity::Warning,
            json!({
                "from_domain": from_domain,
                "status": message.dkim.status,
                "delivery_evidence": "trusted_dmarc_and_aligned_spf_pass",
            }),
        ));
        return;
    }
    let unaligned_signing_domains = message
        .dkim
        .signatures
        .iter()
        .filter(|signature| signature.status == DkimSignatureStatus::Pass)
        .filter_map(|signature| signature.signing_domain.as_deref())
        .map(str::to_ascii_lowercase)
        .collect::<BTreeSet<_>>();
    let unaligned = message
        .dkim
        .signatures
        .iter()
        .any(|signature| signature.status == DkimSignatureStatus::Pass);
    let severity = missing_aligned_dkim_severity(message.dkim.status);
    collector.push(message_finding(
        if unaligned {
            "unaligned_dkim"
        } else {
            "missing_aligned_dkim"
        },
        FindingPresentation::OpenInterstitial,
        severity,
        json!({
            "from_domain": from_domain,
            "status": message.dkim.status,
            "valid_unaligned_signature": unaligned,
            "signing_domains": unaligned_signing_domains,
        }),
    ));
}

fn missing_aligned_dkim_severity(status: DkimAuthenticationStatus) -> FindingSeverity {
    if status == DkimAuthenticationStatus::Failed {
        FindingSeverity::Danger
    } else {
        FindingSeverity::Warning
    }
}

/// A trusted DMARC pass establishes that the receiver accepted an aligned
/// authentication path.  Requiring an SPF pass whose RFC5321.MailFrom domain
/// independently aligns with the visible From domain lets the UI make the
/// narrower statement that the delivery path was authorized without calling
/// the message signed.  Both results must come from the same trusted physical
/// Authentication-Results field.
fn trusted_aligned_spf_delivery(message: &Message) -> bool {
    let Some(from_domain) = message
        .summary
        .from_address
        .as_deref()
        .and_then(address_domain)
    else {
        return false;
    };
    message
        .delivery_authentication
        .observations
        .iter()
        .flat_map(|observation| &observation.headers)
        .filter(|header| header.trust == AuthenticationResultsTrust::Trusted)
        .any(|header| {
            let dmarc_pass = header.methods.iter().any(|method| {
                method.kind == AuthenticationMethodKind::Dmarc
                    && method.result == AuthenticationMethodResult::Pass
            });
            let aligned_spf_pass = header.methods.iter().any(|method| {
                method.kind == AuthenticationMethodKind::Spf
                    && method.result == AuthenticationMethodResult::Pass
                    && method.properties.iter().any(|property| {
                        property.namespace.as_deref() == Some("smtp")
                            && property.name == "mailfrom"
                            && authentication_domain(&property.value)
                                .is_some_and(|domain| domains_align(&from_domain, &domain))
                    })
            });
            dmarc_pass && aligned_spf_pass
        })
}

fn authentication_domain(value: &str) -> Option<String> {
    let value = value.trim().trim_matches(['<', '>']);
    let domain = value
        .rsplit_once('@')
        .map_or(value, |(_, domain)| domain)
        .trim_end_matches('.')
        .to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

fn domains_align(left: &str, right: &str) -> bool {
    let left = left.trim_end_matches('.');
    let right = right.trim_end_matches('.');
    left.eq_ignore_ascii_case(right)
        || matches!(
            (psl::domain_str(left), psl::domain_str(right)),
            (Some(left), Some(right)) if left.eq_ignore_ascii_case(right)
        )
}

fn navigation_findings(
    message: &Message,
    context: &ContactContext,
    collector: &mut FindingCollector,
) {
    let account_action = contains_account_action(message);
    let from_domain = message
        .summary
        .from_address
        .as_deref()
        .and_then(address_domain);
    for link in &message.links {
        let target = Some(link.id.clone());
        if let Some(host) = link.host.as_deref() {
            if let Some(embedded) = embedded_popular_domain(host) {
                collector.push(link_or_message_finding(
                    "embedded_popular_link_domain",
                    target.clone(),
                    FindingSeverity::Danger,
                    json!({
                        "destination": link.destination,
                        "destination_host": host,
                        "actual_registrable_domain": link.registrable_domain,
                        "embedded_popular_domain": embedded,
                    }),
                ));
            }
            // `url` canonicalizes host names. Use the spelling from the raw
            // destination when possible so an ASCII lookalike such as the
            // capital `I` in `paypaI.com` remains available to UTS #39.
            let presented_host = raw_host(&link.destination).unwrap_or_else(|| host.to_owned());
            if let Some(confusable) = confusable_popular_domain(&presented_host) {
                collector.push(link_or_message_finding(
                    "confusable_popular_link_domain",
                    target.clone(),
                    FindingSeverity::Danger,
                    json!({
                        "destination": link.destination,
                        "destination_host": presented_host,
                        "confusable_with": confusable,
                    }),
                ));
            }
        }
        let Ok(url) = Url::parse(&link.destination) else {
            continue;
        };
        if !url.username().is_empty() || url.password().is_some() {
            collector.push(link_finding(
                "misleading_userinfo",
                target.clone(),
                FindingSeverity::Danger,
                json!({"destination": link.destination, "username": url.username()}),
            ));
        }
        if matches!(url.host(), Some(Host::Ipv4(_)) | Some(Host::Ipv6(_))) {
            collector.push(link_finding(
                "raw_ip_destination",
                target.clone(),
                FindingSeverity::Warning,
                json!({"destination": link.destination, "host": link.host}),
            ));
        }
        if let Some(port) = url.port() {
            let ordinary = matches!((url.scheme(), port), ("http", 80) | ("https", 443));
            if !ordinary {
                collector.push(link_finding(
                    "unusual_port",
                    target.clone(),
                    FindingSeverity::Warning,
                    json!({"destination": link.destination, "port": port}),
                ));
            }
        }
        if is_dangerous_scheme(url.scheme()) {
            collector.push(link_finding(
                "dangerous_scheme",
                target.clone(),
                FindingSeverity::Danger,
                json!({"destination": link.destination, "scheme": url.scheme()}),
            ));
        }
        if let Some(nested) = nested_destination(&url) {
            collector.push(link_finding(
                "nested_redirect",
                target.clone(),
                FindingSeverity::Warning,
                json!({"destination": link.destination, "nested_destination": nested}),
            ));
        }
        if account_action
            && from_domain.is_some()
            && link.registrable_domain.is_some()
            && from_domain.as_ref() != link.registrable_domain.as_ref()
        {
            collector.push(link_finding(
                "cross_domain_account_action",
                target,
                FindingSeverity::Warning,
                json!({
                    "from_domain": from_domain,
                    "destination_domain": link.registrable_domain,
                }),
            ));
        }
    }

    if let Some(html) = message.body_html.as_deref() {
        let evidence = parse_html_evidence(html);
        collector.limited |= evidence.limited;
        for anchor in &evidence.anchors {
            anchor_findings(message, context, anchor, collector);
        }
        if !evidence.remote_resources.is_empty() {
            collector.push(message_finding(
                "remote_tracking_resource",
                FindingPresentation::MessageAnnotation,
                FindingSeverity::Warning,
                json!({"resources": evidence.remote_resources}),
            ));
        }
        if !evidence.credential_forms.is_empty() {
            collector.push(message_finding(
                "interactive_credential_form",
                FindingPresentation::OpenInterstitial,
                FindingSeverity::Danger,
                json!({"forms": evidence.credential_forms}),
            ));
        }
    }
}

fn contains_account_action(message: &Message) -> bool {
    let mut text = message
        .summary
        .subject
        .as_deref()
        .unwrap_or_default()
        .to_lowercase();
    text.push(' ');
    text.push_str(&message.body_text.to_lowercase());
    text_contains_account_action(&text)
}

fn text_contains_account_action(text: &str) -> bool {
    [
        "password",
        "reset",
        "sign in",
        "signin",
        "log in",
        "login",
        "verify your account",
        "verify account",
        "verify your identity",
        "verify identity",
        "verify your email",
        "verify email",
        "confirm your account",
        "confirm account",
        "confirm your identity",
        "confirm identity",
        "confirm your email",
        "confirm email",
        "account access",
        "account locked",
        "account suspended",
        "account disabled",
        "account security",
        "account alert",
        "security alert",
        "unlock",
        "unusual activity",
    ]
    .iter()
    .any(|term| text.contains(term))
}

fn nested_destination(url: &Url) -> Option<String> {
    for (_, value) in url.query_pairs().take(32) {
        let Ok(nested) = Url::parse(&value) else {
            continue;
        };
        if matches!(nested.scheme(), "http" | "https")
            && nested.host_str().is_some()
            && nested.host_str() != url.host_str()
        {
            return Some(nested.into());
        }
    }
    None
}

fn anchor_findings(
    message: &Message,
    context: &ContactContext,
    anchor: &HtmlAnchor,
    collector: &mut FindingCollector,
) {
    let target = message
        .links
        .iter()
        .find(|link| link.destination.trim() == anchor.href.trim())
        .map(|link| link.id.clone());
    let displayed_host = displayed_host(&anchor.text);
    let raw_host = raw_host(&anchor.href);
    if let (Some(displayed), Ok(destination)) =
        (displayed_host.as_deref(), Url::parse(anchor.href.trim()))
    {
        let actual = destination.host_str().map(str::to_lowercase);
        if actual.as_deref().is_some_and(|actual| actual != displayed)
            && registrable(actual.as_deref().unwrap()) != registrable(displayed)
        {
            collector.push(link_or_message_finding(
                "misleading_link_text",
                target.clone(),
                FindingSeverity::Danger,
                json!({
                    "displayed_text": anchor.text,
                    "displayed_host": displayed,
                    "destination": anchor.href,
                    "destination_host": actual,
                }),
            ));
        }
    }
    if has_invisible_or_bidi(&anchor.href) || raw_host.as_deref().is_some_and(has_invisible_or_bidi)
    {
        collector.push(link_or_message_finding(
            "invisible_or_bidi_domain",
            target.clone(),
            FindingSeverity::Danger,
            json!({"destination": anchor.href, "raw_host": raw_host}),
        ));
    }
    let Some(raw_host) = raw_host else {
        return;
    };
    let normalized = raw_host.trim_end_matches('.');
    if normalized.is_empty() {
        return;
    }
    let mut meaningful = context.meaningful_domains.as_ref().clone();
    if let Some(sender_domain) = &context.sender_domain {
        meaningful.insert(sender_domain.clone());
    }
    if let Some(displayed) = displayed_host {
        meaningful.insert(displayed);
    }
    let normalized_skeleton = skeleton_string(normalized);
    for candidate in meaningful {
        let candidate = candidate.trim_end_matches('.').to_lowercase();
        if !candidate.eq_ignore_ascii_case(normalized)
            && skeleton_string(&candidate) == normalized_skeleton
        {
            collector.push(link_or_message_finding(
                if normalized.is_ascii() {
                    "ascii_confusable_domain"
                } else {
                    "unicode_confusable_domain"
                },
                target,
                FindingSeverity::Danger,
                json!({
                    "destination": anchor.href,
                    "raw_host": normalized,
                    "confusable_with": candidate,
                }),
            ));
            break;
        }
    }
}

async fn attachment_findings(
    backend: &Backend,
    message: &Message,
    collector: &mut FindingCollector,
) {
    for attachment in &message.attachments {
        let name = attachment.name.as_deref().unwrap_or_default();
        let extension_executable = executable_name(name);
        let detected_executable = attachment
            .detected_media_type
            .as_deref()
            .is_some_and(executable_media_type);
        if has_invisible_or_bidi(name) {
            collector.push(attachment_finding(
                "bidi_filename",
                &attachment.id,
                FindingSeverity::Danger,
                json!({"filename": name}),
            ));
        }
        if double_extension(name) {
            collector.push(attachment_finding(
                "double_extension",
                &attachment.id,
                FindingSeverity::Warning,
                json!({"filename": name}),
            ));
        }
        if extension_executable || detected_executable {
            collector.push(attachment_finding(
                "executable_attachment",
                &attachment.id,
                FindingSeverity::Danger,
                json!({
                    "filename": attachment.name,
                    "declared_type": attachment.declared_media_type,
                    "detected_type": attachment.detected_media_type,
                    "extension_executable": extension_executable,
                    "magic_executable": detected_executable,
                }),
            ));
        }
        if media_type_mismatch(
            attachment.declared_media_type.as_deref(),
            attachment.detected_media_type.as_deref(),
        ) {
            collector.push(attachment_finding(
                "attachment_type_mismatch",
                &attachment.id,
                if detected_executable {
                    FindingSeverity::Danger
                } else {
                    FindingSeverity::Warning
                },
                json!({
                    "filename": attachment.name,
                    "declared_type": attachment.declared_media_type,
                    "detected_type": attachment.detected_media_type,
                }),
            ));
        }

        let is_zip = attachment
            .detected_media_type
            .as_deref()
            .or(attachment.declared_media_type.as_deref())
            .is_some_and(|value| value.eq_ignore_ascii_case("application/zip"));
        if !is_zip {
            continue;
        }
        if attachment.decoded_size > ARCHIVE_INPUT_BYTES {
            collector.push(uninspectable_archive(
                &attachment.id,
                "compressed archive exceeds the automatic metadata-inspection byte budget",
                json!({"compressed_bytes": attachment.decoded_size, "limit": ARCHIVE_INPUT_BYTES}),
            ));
            continue;
        }
        let limits = ArchiveLimits {
            max_archive_bytes: ARCHIVE_INPUT_BYTES,
            max_entries: 256,
            max_entry_bytes: 32 * 1024 * 1024,
            max_total_uncompressed_bytes: 64 * 1024 * 1024,
            max_compression_ratio: 100,
        };
        let inspection = tokio::time::timeout(
            Duration::from_secs(2),
            backend
                .mime()
                .inspect_archive(message.summary.id, &attachment.id, limits),
        )
        .await;
        let inspection = match inspection {
            Ok(Ok(inspection)) => inspection,
            Ok(Err(error)) => {
                collector.push(uninspectable_archive(
                    &attachment.id,
                    "archive directory metadata could not be inspected",
                    json!({"error": error.to_string()}),
                ));
                continue;
            }
            Err(_) => {
                collector.push(uninspectable_archive(
                    &attachment.id,
                    "archive directory metadata inspection exceeded its wall-clock budget",
                    json!({"timeout_seconds": 2}),
                ));
                continue;
            }
        };
        match inspection.state {
            ArchiveInspectionState::Complete => {
                let executable_entries = inspection
                    .entries
                    .iter()
                    .filter(|entry| !entry.directory && executable_name(&entry.path))
                    .map(|entry| entry.path.clone())
                    .take(32)
                    .collect::<Vec<_>>();
                if !executable_entries.is_empty() {
                    collector.push(attachment_finding(
                        "executable_in_archive",
                        &attachment.id,
                        FindingSeverity::Danger,
                        json!({
                            "entries": executable_entries,
                            "inspection": "zip_directory_metadata_only",
                        }),
                    ));
                }
                let nested = inspection
                    .entries
                    .iter()
                    .filter(|entry| !entry.directory && archive_name(&entry.path))
                    .map(|entry| entry.path.clone())
                    .take(32)
                    .collect::<Vec<_>>();
                if !nested.is_empty() {
                    collector.push(uninspectable_archive(
                        &attachment.id,
                        "nested archives are not opened automatically",
                        json!({"nested_entries": nested}),
                    ));
                }
            }
            ArchiveInspectionState::Limited => collector.push(uninspectable_archive(
                &attachment.id,
                "archive metadata exceeds expansion, entry, path, or compression-ratio budgets",
                json!({
                    "state": inspection.state,
                    "entries_seen": inspection.entries.len(),
                    "declared_uncompressed_bytes": inspection.total_uncompressed_bytes,
                }),
            )),
            ArchiveInspectionState::Encrypted => collector.push(uninspectable_archive(
                &attachment.id,
                "encrypted archive entries cannot be inspected",
                json!({"state": inspection.state}),
            )),
            ArchiveInspectionState::Invalid | ArchiveInspectionState::Unsupported => {
                collector.push(uninspectable_archive(
                    &attachment.id,
                    "archive container metadata is invalid or unsupported",
                    json!({"state": inspection.state, "detail": inspection.detail}),
                ));
            }
        }
    }
}

fn media_type_mismatch(declared: Option<&str>, detected: Option<&str>) -> bool {
    let (Some(declared), Some(detected)) = (declared, detected) else {
        return false;
    };
    if declared.eq_ignore_ascii_case(detected)
        || declared.eq_ignore_ascii_case("application/octet-stream")
    {
        return false;
    }
    if detected.eq_ignore_ascii_case("application/zip")
        && (declared.contains("openxmlformats")
            || declared.contains("opendocument")
            || declared.eq_ignore_ascii_case("application/java-archive"))
    {
        return false;
    }
    true
}

fn executable_media_type(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "application/x-executable"
            | "application/vnd.microsoft.portable-executable"
            | "application/x-msdownload"
            | "application/x-mach-binary"
    )
}

fn executable_name(value: &str) -> bool {
    let extension = value
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase());
    extension.as_deref().is_some_and(|extension| {
        matches!(
            extension,
            "exe"
                | "com"
                | "scr"
                | "msi"
                | "msp"
                | "bat"
                | "cmd"
                | "ps1"
                | "vbs"
                | "vbe"
                | "js"
                | "jse"
                | "wsf"
                | "wsh"
                | "lnk"
                | "jar"
                | "apk"
                | "app"
                | "dmg"
                | "pkg"
                | "deb"
                | "rpm"
                | "desktop"
                | "sh"
        )
    })
}

fn double_extension(value: &str) -> bool {
    let name = value.rsplit(['/', '\\']).next().unwrap_or(value);
    if !executable_name(name) {
        return false;
    }
    let mut pieces = name.rsplitn(3, '.');
    let _last = pieces.next();
    let Some(previous) = pieces.next() else {
        return false;
    };
    let Some(_) = pieces.next() else {
        return false;
    };
    !previous.is_empty()
}

fn archive_name(value: &str) -> bool {
    value
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .as_deref()
        .is_some_and(|extension| matches!(extension, "zip" | "7z" | "rar" | "tar" | "gz" | "xz"))
}

fn normalize_name(value: &str) -> String {
    value
        .chars()
        .flat_map(char::to_lowercase)
        .filter(|character| character.is_alphanumeric())
        .collect()
}

fn normalize_address(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn address_domain(value: &str) -> Option<String> {
    value
        .rsplit_once('@')
        .map(|(_, domain)| domain.trim_end_matches('.').to_owned())
        .filter(|domain| !domain.is_empty())
}

fn registrable(value: &str) -> Option<String> {
    psl::domain_str(value.trim_end_matches('.')).map(str::to_owned)
}

fn popular_domains() -> &'static HashSet<&'static str> {
    static DOMAINS: OnceLock<HashSet<&'static str>> = OnceLock::new();
    DOMAINS.get_or_init(|| {
        include_str!("popular_domains.txt")
            .lines()
            .filter_map(|domain| psl::domain_str(domain).or(Some(domain)))
            .collect()
    })
}

fn popular_domain_skeletons() -> &'static BTreeMap<String, &'static str> {
    static SKELETONS: OnceLock<BTreeMap<String, &'static str>> = OnceLock::new();
    SKELETONS.get_or_init(|| {
        let mut values = BTreeMap::new();
        for domain in include_str!("popular_domains.txt").lines() {
            let domain = psl::domain_str(domain).unwrap_or(domain);
            values.entry(skeleton_string(domain)).or_insert(domain);
        }
        values
    })
}

fn confusable_popular_domain(domain: &str) -> Option<String> {
    let domain = domain.trim_end_matches('.');
    let actual = registrable(domain).unwrap_or_else(|| domain.to_owned());
    popular_domain_skeletons()
        .get(&skeleton_string(&actual))
        .filter(|popular| !popular.eq_ignore_ascii_case(&actual))
        .map(|popular| (*popular).to_owned())
}

fn embedded_popular_domain(sender_domain: &str) -> Option<String> {
    let sender_domain = sender_domain.trim_end_matches('.').to_ascii_lowercase();
    let actual = registrable(&sender_domain)?;
    let labels = sender_domain.split('.').collect::<Vec<_>>();
    for width in (2..=labels.len()).rev() {
        for start in 0..=labels.len() - width {
            let candidate = labels[start..start + width].join(".");
            if candidate != actual
                && registrable(&candidate).as_deref() == Some(candidate.as_str())
                && popular_domains().contains(candidate.as_str())
            {
                return Some(candidate);
            }
        }
    }
    None
}

fn skeleton_string(value: &str) -> String {
    skeleton(value).flat_map(char::to_lowercase).collect()
}

fn has_invisible_or_bidi(value: &str) -> bool {
    value.chars().any(|character| {
        matches!(
            character,
            '\u{061c}'
                | '\u{200b}'..='\u{200f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2060}'..='\u{2069}'
                | '\u{feff}'
        )
    })
}

fn raw_host(destination: &str) -> Option<String> {
    let (_, rest) = destination.trim().split_once("://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host_port = authority.rsplit('@').next()?;
    if let Some(bracketed) = host_port.strip_prefix('[') {
        return bracketed.split_once(']').map(|(host, _)| host.to_owned());
    }
    Some(
        host_port
            .rsplit_once(':')
            .filter(|(_, port)| port.chars().all(|character| character.is_ascii_digit()))
            .map_or(host_port, |(host, _)| host)
            .trim_end_matches('.')
            .to_owned(),
    )
}

fn displayed_host(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if let Ok(url) = Url::parse(trimmed) {
        return url.host_str().map(str::to_lowercase);
    }
    for token in trimmed.split_whitespace() {
        let token = token.trim_matches(|character: char| {
            !character.is_alphanumeric() && !matches!(character, '.' | '-' | '_')
        });
        if token.contains('.') && !token.contains('@') {
            if let Ok(url) = Url::parse(&format!("https://{token}")) {
                if let Some(host) = url.host_str() {
                    return Some(host.to_lowercase());
                }
            }
        }
    }
    None
}

fn is_dangerous_scheme(value: &str) -> bool {
    matches!(
        value.to_ascii_lowercase().as_str(),
        "javascript" | "vbscript" | "data" | "file"
    )
}

fn message_finding(
    code: &str,
    presentation: FindingPresentation,
    severity: FindingSeverity,
    evidence: serde_json::Value,
) -> ProducedFinding {
    ProducedFinding {
        code: code.into(),
        presentation,
        severity,
        target_kind: FindingTargetKind::Message,
        target_id: None,
        text: None,
        evidence,
    }
}

fn link_finding(
    code: &str,
    target_id: Option<String>,
    severity: FindingSeverity,
    evidence: serde_json::Value,
) -> ProducedFinding {
    link_or_message_finding(code, target_id, severity, evidence)
}

fn link_or_message_finding(
    code: &str,
    target_id: Option<String>,
    severity: FindingSeverity,
    evidence: serde_json::Value,
) -> ProducedFinding {
    ProducedFinding {
        code: code.into(),
        presentation: if target_id.is_some() {
            FindingPresentation::LinkInterstitial
        } else {
            FindingPresentation::MessageAnnotation
        },
        severity,
        target_kind: if target_id.is_some() {
            FindingTargetKind::Link
        } else {
            FindingTargetKind::Message
        },
        target_id,
        text: None,
        evidence,
    }
}

fn attachment_finding(
    code: &str,
    target_id: &str,
    severity: FindingSeverity,
    evidence: serde_json::Value,
) -> ProducedFinding {
    ProducedFinding {
        code: code.into(),
        presentation: FindingPresentation::AttachmentInterstitial,
        severity,
        target_kind: FindingTargetKind::Attachment,
        target_id: Some(target_id.into()),
        text: None,
        evidence,
    }
}

fn uninspectable_archive(
    target_id: &str,
    reason: &str,
    mut evidence: serde_json::Value,
) -> ProducedFinding {
    if let Some(object) = evidence.as_object_mut() {
        object.insert("reason".into(), json!(reason));
        object.insert("inspection".into(), json!("zip_directory_metadata_only"));
        object.insert("entries_decompressed".into(), json!(0));
    }
    attachment_finding(
        "uninspectable_archive",
        target_id,
        FindingSeverity::Warning,
        evidence,
    )
}

#[derive(Clone, Debug)]
struct HtmlAnchor {
    href: String,
    text: String,
}

#[derive(Clone, Debug)]
struct ActiveAnchor {
    href: String,
    text: String,
}

#[derive(Clone, Debug, serde::Serialize)]
struct CredentialForm {
    action: Option<String>,
    password_input: bool,
}

#[derive(Default)]
struct HtmlEvidence {
    anchors: Vec<HtmlAnchor>,
    remote_resources: Vec<String>,
    credential_forms: Vec<CredentialForm>,
    limited: bool,
}

fn parse_html_evidence(html: &str) -> HtmlEvidence {
    let sink = SecurityHtmlSink::default();
    let input = BufferQueue::default();
    input.push_back(StrTendril::from(html));
    let tokenizer = Tokenizer::new(sink, TokenizerOpts::default());
    let _ = tokenizer.feed(&input);
    tokenizer.end();
    tokenizer.sink.finish()
}

#[derive(Default)]
struct SecurityHtmlSink {
    tokens: Cell<usize>,
    limited: Cell<bool>,
    active_anchor: RefCell<Option<ActiveAnchor>>,
    anchors: RefCell<Vec<HtmlAnchor>>,
    active_form: RefCell<Option<CredentialForm>>,
    credential_forms: RefCell<Vec<CredentialForm>>,
    remote_resources: RefCell<Vec<String>>,
    in_style: Cell<bool>,
    style_text: RefCell<String>,
}

impl SecurityHtmlSink {
    fn finish(&self) -> HtmlEvidence {
        self.finish_anchor();
        self.finish_form();
        self.record_style_urls();
        HtmlEvidence {
            anchors: self.anchors.borrow().clone(),
            remote_resources: self.remote_resources.borrow().clone(),
            credential_forms: self.credential_forms.borrow().clone(),
            limited: self.limited.get(),
        }
    }

    fn finish_anchor(&self) {
        let Some(anchor) = self.active_anchor.borrow_mut().take() else {
            return;
        };
        let mut anchors = self.anchors.borrow_mut();
        if anchors.len() < MAX_HTML_ANCHORS {
            anchors.push(HtmlAnchor {
                href: anchor.href,
                text: anchor.text.trim().to_owned(),
            });
        } else {
            self.limited.set(true);
        }
    }

    fn finish_form(&self) {
        let Some(form) = self.active_form.borrow_mut().take() else {
            return;
        };
        if !form.password_input {
            return;
        }
        let mut forms = self.credential_forms.borrow_mut();
        if forms.len() < MAX_CREDENTIAL_FORMS {
            forms.push(form);
        } else {
            self.limited.set(true);
        }
    }

    fn record_remote(&self, value: &str) {
        let value = value.trim().trim_matches(['\'', '"']);
        let Ok(url) = Url::parse(value) else {
            return;
        };
        if !matches!(url.scheme(), "http" | "https") {
            return;
        }
        let mut resources = self.remote_resources.borrow_mut();
        if resources.len() < MAX_REMOTE_RESOURCES {
            let value = value.to_owned();
            if !resources.contains(&value) {
                resources.push(value);
            }
        } else {
            self.limited.set(true);
        }
    }

    fn record_css(&self, value: &str) {
        let lower = value.to_ascii_lowercase();
        let mut offset = 0usize;
        while let Some(position) = lower[offset..].find("url(") {
            let start = offset + position + 4;
            let Some(end_offset) = value[start..].find(')') else {
                break;
            };
            self.record_remote(&value[start..start + end_offset]);
            offset = start + end_offset + 1;
            if offset >= value.len() {
                break;
            }
        }
    }

    fn record_style_urls(&self) {
        let style = self.style_text.borrow();
        self.record_css(&style);
    }
}

impl TokenSink for SecurityHtmlSink {
    type Handle = ();

    fn process_token(&self, token: Token, _line_number: u64) -> TokenSinkResult<Self::Handle> {
        let count = self.tokens.get().saturating_add(1);
        self.tokens.set(count);
        if count > MAX_HTML_TOKENS {
            self.limited.set(true);
            return TokenSinkResult::Continue;
        }
        match token {
            TagToken(tag) => {
                let name: &str = tag.name.as_ref();
                if tag.kind == StartTag {
                    let attribute = |wanted: &str| {
                        tag.attrs.iter().find_map(|attribute| {
                            let name: &str = attribute.name.local.as_ref();
                            (name == wanted).then(|| attribute.value.to_string())
                        })
                    };
                    if name == "a" {
                        self.finish_anchor();
                        if let Some(href) = attribute("href") {
                            self.active_anchor.replace(Some(ActiveAnchor {
                                href,
                                text: String::new(),
                            }));
                        }
                    }
                    if name == "form" {
                        self.finish_form();
                        self.active_form.replace(Some(CredentialForm {
                            action: attribute("action"),
                            password_input: false,
                        }));
                    }
                    if name == "input"
                        && attribute("type")
                            .as_deref()
                            .is_some_and(|value| value.eq_ignore_ascii_case("password"))
                    {
                        if let Some(form) = self.active_form.borrow_mut().as_mut() {
                            form.password_input = true;
                        } else {
                            let mut forms = self.credential_forms.borrow_mut();
                            if forms.len() < MAX_CREDENTIAL_FORMS {
                                forms.push(CredentialForm {
                                    action: None,
                                    password_input: true,
                                });
                            } else {
                                self.limited.set(true);
                            }
                        }
                    }
                    let resource = match name {
                        "img" | "script" | "iframe" | "audio" | "source" => attribute("src"),
                        "video" => attribute("poster").or_else(|| attribute("src")),
                        "link" => attribute("href"),
                        "object" => attribute("data"),
                        "body" | "table" | "td" => attribute("background"),
                        _ => None,
                    };
                    if let Some(resource) = resource {
                        self.record_remote(&resource);
                    }
                    if let Some(style) = attribute("style") {
                        self.record_css(&style);
                    }
                    if name == "style" {
                        self.in_style.set(true);
                    }
                    return match name {
                        "title" | "textarea" => TokenSinkResult::RawData(RawKind::Rcdata),
                        "style" | "xmp" | "iframe" | "noembed" | "noframes" | "noscript" => {
                            TokenSinkResult::RawData(RawKind::Rawtext)
                        }
                        "script" => TokenSinkResult::RawData(RawKind::ScriptData),
                        _ => TokenSinkResult::Continue,
                    };
                }
                if tag.kind == EndTag {
                    match name {
                        "a" => self.finish_anchor(),
                        "form" => self.finish_form(),
                        "style" => self.in_style.set(false),
                        _ => {}
                    }
                }
            }
            Token::CharacterTokens(value) => {
                if let Some(anchor) = self.active_anchor.borrow_mut().as_mut() {
                    append_bounded(&mut anchor.text, &value, 512, &self.limited);
                }
                if self.in_style.get() {
                    append_bounded(
                        &mut self.style_text.borrow_mut(),
                        &value,
                        MAX_STYLE_BYTES,
                        &self.limited,
                    );
                }
            }
            _ => {}
        }
        TokenSinkResult::Continue
    }
}

fn append_bounded(target: &mut String, value: &str, limit: usize, limited: &Cell<bool>) {
    let remaining = limit.saturating_sub(target.len());
    if value.len() <= remaining {
        target.push_str(value);
        return;
    }
    let mut end = remaining;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    target.push_str(&value[..end]);
    limited.set(true);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_evidence_is_bounded_and_passive() {
        let evidence = parse_html_evidence(
            r#"<style>body{background:url(https://tracker.example/open)}</style>
            <a href="https://accounts.example@evil.example/login">accounts.example</a>
            <form action="https://evil.example/collect"><input type="password"></form>"#,
        );
        assert!(!evidence.limited);
        assert_eq!(evidence.anchors.len(), 1);
        assert_eq!(evidence.anchors[0].text, "accounts.example");
        assert_eq!(
            evidence.remote_resources,
            vec!["https://tracker.example/open"]
        );
        assert_eq!(evidence.credential_forms.len(), 1);
    }

    #[test]
    fn uts39_skeleton_matches_unicode_and_ascii_lookalikes() {
        assert_eq!(skeleton_string("раypal.com"), skeleton_string("paypal.com"));
        assert_eq!(skeleton_string("paypaI.com"), skeleton_string("paypal.com"));
    }

    #[test]
    fn spf_mailfrom_alignment_uses_the_organizational_domain() {
        assert_eq!(
            authentication_domain("<bounce@mailer.example.com>"),
            Some("mailer.example.com".into())
        );
        assert!(domains_align("notices.example.com", "mailer.example.com"));
        assert!(!domains_align("example.com", "example.net"));
    }

    #[test]
    fn generic_account_copy_does_not_trigger_cross_domain_action_evidence() {
        assert!(!text_contains_account_action(
            "manage your account preferences or read our monthly account newsletter"
        ));
        assert!(text_contains_account_action(
            "reset your password to restore account access"
        ));
        assert!(text_contains_account_action(
            "security alert: verify your identity"
        ));
    }

    #[test]
    fn failed_dkim_is_more_severe_than_an_unsigned_message() {
        assert_eq!(
            missing_aligned_dkim_severity(DkimAuthenticationStatus::Failed),
            FindingSeverity::Danger
        );
        assert_eq!(
            missing_aligned_dkim_severity(DkimAuthenticationStatus::Unsigned),
            FindingSeverity::Warning
        );
    }
}
