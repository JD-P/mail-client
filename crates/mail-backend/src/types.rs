use crate::{
    AccountId, ContactId, FilterRuleId, FindingId, FolderId, HeuristicId, ImapMutationConflictId,
    ImapMutationId, MessageId, ThreadId,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendConfig {
    pub profile_dir: PathBuf,
    pub limits: IngestLimits,
    pub event_buffer: usize,
    /// Resolver policy for DKIM selector lookups. The default encrypts DNS
    /// transport and enables local DNSSEC validation.
    #[serde(default)]
    pub dkim_dns: DkimDnsResolver,
}

impl BackendConfig {
    pub fn new(profile_dir: impl Into<PathBuf>) -> Self {
        Self {
            profile_dir: profile_dir.into(),
            limits: IngestLimits::default(),
            event_buffer: 1_024,
            dkim_dns: DkimDnsResolver::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimDnsResolver {
    /// Quad9 over DNS-over-TLS, with DNSSEC validation enabled locally.
    #[default]
    Quad9Tls,
    /// The operating system resolver. This can be useful on private networks,
    /// but its transport and validation policy are controlled outside Lizard.
    System,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestLimits {
    pub max_message_bytes: usize,
    pub max_mime_depth: u8,
    pub max_mime_parts: usize,
    pub max_text_bytes: usize,
    pub max_html_bytes: usize,
    pub max_html_nodes: usize,
    pub max_links: usize,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 64 * 1024 * 1024,
            max_mime_depth: 16,
            max_mime_parts: 512,
            max_text_bytes: 2 * 1024 * 1024,
            max_html_bytes: 4 * 1024 * 1024,
            max_html_nodes: 100_000,
            max_links: 2_048,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccountKind {
    Imap,
    Local,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImapSecurity {
    ImplicitTls,
    StartTls,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    /// Plaintext IMAP is intentionally not representable.
    pub security: ImapSecurity,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Account {
    pub id: AccountId,
    pub name: String,
    pub kind: AccountKind,
    pub credential_ref: Option<String>,
    pub imap: Option<ImapSettings>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewAccount {
    pub name: String,
    pub kind: AccountKind,
    /// An opaque reference into a platform credential store. Never a password.
    pub credential_ref: Option<String>,
    pub imap: Option<ImapSettings>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FolderKind {
    Remote,
    Local,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Folder {
    pub id: FolderId,
    pub account_id: Option<AccountId>,
    pub name: String,
    pub kind: FolderKind,
    pub remote_name: Option<String>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewFolder {
    pub account_id: Option<AccountId>,
    pub name: String,
    pub kind: FolderKind,
    pub remote_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RemoteMessageIdentity {
    pub account_id: AccountId,
    pub folder_id: FolderId,
    pub uid_validity: u32,
    pub uid: u32,
    pub mod_sequence: Option<u64>,
    pub flags: Vec<String>,
}

/// A complete RFC 5322 payload fetched by an IMAP protocol adapter.
///
/// Keeping this type independent of a particular IMAP crate lets the
/// hardened vendored client, test fixtures, and later protocol versions share
/// the same persistence pipeline.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImapFetchedMessage {
    pub uid: u32,
    pub mod_sequence: Option<u64>,
    pub flags: Vec<String>,
    pub internal_date: Option<i64>,
    pub raw: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SyncBatchResult {
    pub message_ids: Vec<MessageId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestMessage {
    pub raw: Vec<u8>,
    pub remote: Option<RemoteMessageIdentity>,
    pub received_at: Option<i64>,
    pub user_classification: Option<UserClassification>,
}

impl IngestMessage {
    pub fn local(raw: impl Into<Vec<u8>>) -> Self {
        Self {
            raw: raw.into(),
            remote: None,
            received_at: None,
            user_classification: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserClassification {
    Spam,
    NotSpam,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InboxClass {
    Warm,
    Cold,
    Spam,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentState {
    Complete,
    Limited,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// Stable within an immutable message and suitable as a finding target.
    pub id: String,
    pub ordinal: u32,
    pub name: Option<String>,
    pub declared_media_type: Option<String>,
    pub decoded_size: u64,
    pub inline: bool,
    pub content_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageSummary {
    pub id: MessageId,
    /// Stable backend identity of the conversation containing this message.
    pub thread_id: ThreadId,
    pub subject: Option<String>,
    pub from_address: Option<String>,
    pub from_name: Option<String>,
    pub preview: String,
    pub sent_at: Option<i64>,
    pub received_at: i64,
    pub size_bytes: u64,
    pub has_attachment: bool,
    pub is_read: bool,
    pub is_starred: bool,
    pub inbox_class: InboxClass,
    pub content_state: ContentState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(flatten)]
    pub summary: MessageSummary,
    pub rfc_message_id: Option<String>,
    /// Canonical message identifiers supplied by the sender. These remain
    /// untrusted evidence; [`threading`] records the backend's actual choice.
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    pub reply_to_addresses: Vec<String>,
    pub threading: ThreadMembership,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub delivered_to_addresses: Vec<String>,
    pub list_id: Option<String>,
    pub body_text: String,
    /// Original sender-authored HTML. Plain text is never synthesized into HTML.
    pub body_html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub links: Vec<MessageLink>,
    pub instances: Vec<MessageInstance>,
    pub local_folder_ids: Vec<FolderId>,
    /// DKIM evidence captured from the exact bytes stored for this message.
    pub dkim: DkimAuthentication,
    /// Active, materialized heuristic results. Clients render these through
    /// the finite [`FindingPresentation`] vocabulary; they never execute code.
    pub findings: Vec<HeuristicFinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadSenderTrust {
    /// The sender was one of the user's account identities or address-book
    /// contacts when the message was ingested.
    Known,
    /// The sender was not known when the message was ingested.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreadingSource {
    Root,
    References,
    InReplyTo,
    NormalizedSubject,
}

/// The backend's durable, security-partitioned interpretation of a message's
/// conversation headers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadMembership {
    pub thread_id: ThreadId,
    pub parent_message_id: Option<MessageId>,
    pub source: ThreadingSource,
    pub sender_trust: ThreadSenderTrust,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadSummary {
    pub id: ThreadId,
    pub subject: Option<String>,
    pub normalized_subject: Option<String>,
    pub participants: Vec<String>,
    pub message_count: u64,
    pub unread_count: u64,
    pub starred_count: u64,
    pub latest_message_id: MessageId,
    pub latest_received_at: i64,
    pub latest_preview: String,
    /// Immutable trust boundary established when the thread was created.
    /// Unknown senders cannot enter a known-origin conversation; known/self
    /// senders may continue an older cold conversation without upgrading it.
    pub sender_trust: ThreadSenderTrust,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Thread {
    #[serde(flatten)]
    pub summary: ThreadSummary,
    pub messages: Vec<Message>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ThreadFilter {
    pub account_id: Option<AccountId>,
    pub folder_id: Option<FolderId>,
    pub inbox_class: Option<InboxClass>,
    pub sort: MessageSort,
    pub page_size: usize,
    pub cursor: Option<String>,
}

impl Default for ThreadFilter {
    fn default() -> Self {
        Self {
            account_id: None,
            folder_id: None,
            inbox_class: None,
            sort: MessageSort::ReceivedNewest,
            page_size: 50,
            cursor: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplyAudience {
    Sender,
    All,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompositionKind {
    Reply,
    Forward,
}

/// Headers and durable thread intent for a future draft/outbox layer.
///
/// A reply remains in its source thread. A forward deliberately starts a new
/// thread and carries the original as `message/rfc822`; it never pretends to
/// be a reply by copying References headers.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageComposition {
    pub kind: CompositionKind,
    pub thread_id: ThreadId,
    pub source_message_id: MessageId,
    pub parent_message_id: Option<MessageId>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub subject: String,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
    pub attached_message_id: Option<MessageId>,
    pub attached_media_type: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimAuthenticationStatus {
    Unsigned,
    Pass,
    Failed,
    TemporaryFailure,
    NotEvaluated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DkimSignatureStatus {
    Pass,
    Fail,
    Neutral,
    PermanentError,
    TemporaryError,
}

/// Evidence for one physical `DKIM-Signature` header. Attacker-supplied
/// identity fields are data, never an application-authored identity claim.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DkimSignatureEvidence {
    pub header_index: Option<u32>,
    pub status: DkimSignatureStatus,
    pub reason_code: Option<String>,
    pub reason: Option<String>,
    pub signing_domain: Option<String>,
    pub selector: Option<String>,
    pub identity: Option<String>,
    pub algorithm: Option<String>,
    pub signed_headers: Vec<String>,
    pub from_domain_aligned: Option<bool>,
    pub key_bits: Option<u32>,
    pub key_testing: bool,
    /// Exact unfolded header value retained for diagnostics. It remains
    /// untrusted text and must never be rendered as markup.
    pub raw_header_value: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DkimAuthentication {
    pub status: DkimAuthenticationStatus,
    pub signatures: Vec<DkimSignatureEvidence>,
    pub evaluated_at: i64,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageLinkSource {
    PlainText,
    Html,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageLink {
    /// Stable within an immutable message and suitable as a finding target.
    pub id: String,
    pub ordinal: u32,
    pub destination: String,
    pub scheme: String,
    pub host: Option<String>,
    pub registrable_domain: Option<String>,
    pub source: MessageLinkSource,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageInstance {
    pub account_id: AccountId,
    pub folder_id: FolderId,
    pub uid_validity: u32,
    pub uid: u32,
    pub mod_sequence: Option<u64>,
    pub flags: Vec<String>,
}

/// A durable, user-requested change to one exact IMAP message instance.
///
/// Operations are always anchored to the UIDVALIDITY epoch and UID captured in
/// `source`. This prevents a delayed offline action from being applied to an
/// unrelated message after a server regenerates mailbox UIDs.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ImapMutationOperation {
    SetFlags { flags: Vec<String> },
    Copy { destination_folder_id: FolderId },
    Move { destination_folder_id: FolderId },
    Delete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImapMutationStatus {
    Pending,
    InFlight,
    Applied,
    Conflict,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapMutation {
    pub id: ImapMutationId,
    pub account_id: AccountId,
    pub message_id: MessageId,
    pub source: RemoteMessageIdentity,
    pub operation: ImapMutationOperation,
    pub status: ImapMutationStatus,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImapMutationConflictKind {
    UidValidityChanged,
    SourceMissing,
    ServerStateChanged,
    DestinationUnavailable,
    CapabilityUnavailable,
    AmbiguousOutcome,
    MissingServerMapping,
}

/// A durable explanation of why a queued mutation was not silently applied.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ImapMutationConflict {
    pub id: ImapMutationConflictId,
    pub mutation_id: ImapMutationId,
    pub kind: ImapMutationConflictKind,
    pub expected: serde_json::Value,
    pub observed: serde_json::Value,
    pub detail: String,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageFilter {
    pub account_id: Option<AccountId>,
    pub folder_id: Option<FolderId>,
    pub inbox_class: Option<InboxClass>,
    pub sort: MessageSort,
    pub page_size: usize,
    pub cursor: Option<String>,
}

impl Default for MessageFilter {
    fn default() -> Self {
        Self {
            account_id: None,
            folder_id: None,
            inbox_class: None,
            sort: MessageSort::ReceivedNewest,
            page_size: 50,
            cursor: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageSort {
    #[default]
    ReceivedNewest,
    ReceivedOldest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SearchRequest {
    pub query: String,
    pub page_size: usize,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContactAddress {
    pub address: String,
    pub accepted_name: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Contact {
    pub id: ContactId,
    pub display_name: String,
    pub addresses: Vec<ContactAddress>,
    pub created_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewContact {
    pub display_name: String,
    pub addresses: Vec<ContactAddress>,
}

/// One pure check in a filter rule. A rule's checks are an implicit AND (with
/// an empty vector meaning a catch-all) and may be reordered by the evaluator
/// because they have no side effects.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilterCondition {
    SenderAddressEquals { value: String },
    SenderDomainEquals { value: String },
    SubjectContains { value: String },
    BodyContains { value: String },
    HasAttachment { value: bool },
    AttachmentDeclaredType { value: String },
    SizeAtLeast { bytes: u64 },
    SizeAtMost { bytes: u64 },
    DeliveredTo { address: String },
    Account { id: AccountId },
    DeliveryFolder { id: FolderId },
}

/// Filter authority is intentionally confined to local organization of the
/// message being evaluated. Server-side moves will be represented separately
/// when the IMAP mutation outbox exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilterAction {
    AddToLocalFolder { folder_id: FolderId },
    RemoveFromLocalFolder { folder_id: FolderId },
    MoveToLocalFolder { folder_id: FolderId },
    Stop,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewFilterRule {
    pub name: String,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Vec<FilterCondition>,
    pub actions: Vec<FilterAction>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilterRule {
    pub id: FilterRuleId,
    pub name: String,
    pub revision: u32,
    pub priority: i32,
    pub enabled: bool,
    pub conditions: Vec<FilterCondition>,
    pub actions: Vec<FilterAction>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilterRuleApplication {
    pub rule_id: FilterRuleId,
    pub rule_revision: u32,
    pub message_id: MessageId,
    pub conditions: Vec<FilterCondition>,
    pub actions: Vec<FilterAction>,
    pub applied_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeuristicSourceKind {
    BuiltIn,
    User,
    ThirdParty,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewHeuristic {
    pub name: String,
    /// Python-shaped Lizard Rules source. It is parsed and compiled, never
    /// passed to a Python runtime.
    pub source: String,
    pub source_kind: HeuristicSourceKind,
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeuristicCompilation {
    pub required_features: Vec<String>,
    pub maximum_steps: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Heuristic {
    pub id: HeuristicId,
    pub name: String,
    pub version: u32,
    pub source: String,
    pub source_kind: HeuristicSourceKind,
    pub enabled: bool,
    pub required_features: Vec<String>,
    pub maximum_steps: u32,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingPresentation {
    MessageAnnotation,
    PersistentWarningFooter,
    OpenInterstitial,
    LinkInterstitial,
    AttachmentInterstitial,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Information,
    Warning,
    Danger,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingTargetKind {
    Message,
    Link,
    Attachment,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeuristicFinding {
    pub id: FindingId,
    pub message_id: MessageId,
    pub heuristic_id: HeuristicId,
    pub heuristic_version: u32,
    pub code: String,
    pub presentation: FindingPresentation,
    pub severity: FindingSeverity,
    pub target_kind: FindingTargetKind,
    pub target_id: Option<String>,
    /// Optional static text for user-authored rules. Built-in clients normally
    /// localize a known `code` instead. This field is always plain text.
    pub text: Option<String>,
    pub evidence: serde_json::Value,
    pub source_kind: HeuristicSourceKind,
    pub created_at: i64,
    pub dismissed_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeuristicEvaluationStatus {
    Complete,
    NotEvaluatedBudget,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeuristicEvaluation {
    pub message_id: MessageId,
    pub heuristic_id: HeuristicId,
    pub heuristic_version: u32,
    pub status: HeuristicEvaluationStatus,
    pub detail: Option<String>,
    pub evaluated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendEvent {
    pub sequence: u64,
    pub occurred_at: i64,
    pub kind: String,
    pub entity_id: String,
    pub payload: serde_json::Value,
}
