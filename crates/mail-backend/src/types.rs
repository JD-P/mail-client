use crate::{
    AccountId, AccountIdentityId, ContactId, DraftAttachmentId, DraftId, FilterRuleId, FindingId,
    FolderId, HeuristicId, ImapMutationConflictId, ImapMutationId, MessageId, SubmissionId,
    ThreadId,
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
    /// Automatic uses the operating-system credential store when a write
    /// succeeds and otherwise falls back to a profile-local encrypted vault.
    /// ProfileOnly exists for portable profiles and deterministic tests.
    #[serde(default)]
    pub credential_storage: CredentialStoragePolicy,
    /// Profile-wide free-space reserve and optional hard byte budget.
    #[serde(default)]
    pub storage_limits: crate::StorageLimits,
}

impl BackendConfig {
    pub fn new(profile_dir: impl Into<PathBuf>) -> Self {
        Self {
            profile_dir: profile_dir.into(),
            limits: IngestLimits::default(),
            event_buffer: 1_024,
            dkim_dns: DkimDnsResolver::default(),
            credential_storage: CredentialStoragePolicy::default(),
            storage_limits: crate::StorageLimits::default(),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStoragePolicy {
    #[default]
    Automatic,
    ProfileOnly,
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
    #[serde(default = "default_max_header_bytes")]
    pub max_header_bytes: usize,
    pub max_mime_depth: u8,
    pub max_mime_parts: usize,
    pub max_text_bytes: usize,
    pub max_html_bytes: usize,
    pub max_html_nodes: usize,
    pub max_links: usize,
}

const fn default_max_header_bytes() -> usize {
    512 * 1024
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 64 * 1024 * 1024,
            max_header_bytes: default_max_header_bytes(),
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
    /// Exact, case-insensitive RFC 8601 authserv-ids which this account's
    /// authenticated delivery provider is configured to own.
    #[serde(default)]
    pub trusted_authserv_ids: Vec<String>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountIdentity {
    pub id: AccountIdentityId,
    pub account_id: AccountId,
    pub revision: u32,
    pub email_address: String,
    pub display_name: Option<String>,
    pub reply_to: Option<String>,
    /// A secret-key provider owned by the same account must exist for this
    /// fingerprint before the identity can protect outgoing mail.
    pub openpgp_fingerprint: Option<String>,
    pub is_default: bool,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewAccountIdentity {
    pub account_id: AccountId,
    pub email_address: String,
    pub display_name: Option<String>,
    pub reply_to: Option<String>,
    pub openpgp_fingerprint: Option<String>,
    #[serde(default)]
    pub is_default: bool,
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

/// The cheap first phase of an IMAP download. The header bytes are the exact
/// `BODY.PEEK[HEADER.FIELDS ...]` response; `size_bytes` remains the size of
/// the complete RFC 5322 message on the server.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImapFetchedHeaders {
    pub uid: u32,
    pub mod_sequence: Option<u64>,
    pub flags: Vec<String>,
    pub internal_date: Option<i64>,
    pub size_bytes: u32,
    pub has_attachment: bool,
    pub headers: Vec<u8>,
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

/// The provider-side fact from which a spam verdict was obtained.
///
/// These are authenticated account-state observations, not RFC 5322 headers
/// supplied by the message sender. Provider-specific headers can be added
/// later only through an adapter which can establish their trusted boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSpamEvidenceSource {
    /// The message has an instance in an RFC 6154 `\\Junk` mailbox.
    ImapJunkMailbox,
    /// The server attached the registered `$Junk` IMAP keyword.
    ImapJunkKeyword,
    /// The server attached the registered `$NotJunk` IMAP keyword.
    ImapNotJunkKeyword,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpamEvidenceVerdict {
    Spam,
    NotSpam,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderSpamEvidence {
    pub source: ProviderSpamEvidenceSource,
    pub verdict: SpamEvidenceVerdict,
    pub account_id: AccountId,
    pub folder_id: FolderId,
    pub uid_validity: u32,
    pub uid: u32,
    pub observed_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderSpamVerdict {
    Unknown,
    Spam,
    NotSpam,
    /// Positive and negative provider observations coexist. This is exposed
    /// rather than silently inventing precedence between providers/instances.
    Conflicting,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProviderSpamAssessment {
    pub verdict: ProviderSpamVerdict,
    pub evidence: Vec<ProviderSpamEvidence>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalSpamVerdict {
    Spam,
    NotSpam,
    Uncertain,
}

/// One of the locally learned features which most influenced a score.
/// Tokens are deliberately exposed so a client can explain the decision and
/// diagnose a badly trained model without presenting it as cryptographic fact.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpamTokenEvidence {
    pub token: String,
    /// Learned probability for this token in the range 0.0 (ham) to 1.0
    /// (spam). The message score is a Fisher combination, not an average.
    pub probability: f64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct LocalSpamAssessment {
    pub verdict: LocalSpamVerdict,
    pub score: f64,
    pub model_version: u64,
    pub evidence: Vec<SpamTokenEvidence>,
    pub evaluated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpamClassifierStatus {
    pub seed_corpus_hash: String,
    pub seed_spam_messages: u64,
    pub seed_ham_messages: u64,
    pub user_spam_messages: u64,
    pub user_ham_messages: u64,
    pub model_version: u64,
    pub pending_messages: u64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SpamReclassificationResult {
    pub processed: usize,
    pub changed_verdicts: usize,
    pub remaining: u64,
    pub model_version: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentState {
    Complete,
    Limited,
}

/// Whether the exact RFC 5322 payload is locally available. This is separate
/// from [`ContentState`], which describes limits encountered while parsing a
/// payload that has already been downloaded.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageContentAvailability {
    HeadersOnly,
    Downloading,
    Complete,
    Failed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MessageContentStatus {
    pub message_id: MessageId,
    pub availability: MessageContentAvailability,
    pub expected_bytes: u64,
    pub downloaded_bytes: u64,
    pub last_error: Option<String>,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Attachment {
    /// Stable within an immutable message and suitable as a finding target.
    pub id: String,
    pub ordinal: u32,
    /// Part identifier in [`MimeStructure::parts`].
    pub mime_part_id: u32,
    pub name: Option<String>,
    pub declared_media_type: Option<String>,
    pub detected_media_type: Option<String>,
    pub decoded_size: u64,
    pub inline: bool,
    pub content_id: Option<String>,
    pub decode_state: MimeDecodeState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimeParseState {
    Complete,
    Limited,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimeDecodeState {
    Complete,
    Problems,
    Limited,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimePartKind {
    Text,
    Html,
    Binary,
    InlineBinary,
    Multipart,
    Message,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MimePartRole {
    Container,
    TextBody,
    HtmlBody,
    CopiedBody,
    MediaBody,
    Attachment,
    Dropped,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MimePart {
    pub id: u32,
    pub parent_id: Option<u32>,
    pub child_ids: Vec<u32>,
    pub kind: MimePartKind,
    pub role: MimePartRole,
    pub declared_media_type: Option<String>,
    pub name: Option<String>,
    pub content_id: Option<String>,
    pub content_location: Option<String>,
    pub inline: bool,
    pub attachment: bool,
    pub in_plain_body: bool,
    pub in_html_body: bool,
    pub decoded_size: u64,
    pub decode_state: MimeDecodeState,
    pub parse_flags: Vec<String>,
    pub decode_problems: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MimeStructure {
    pub message_id: MessageId,
    pub state: MimeParseState,
    pub detail: Option<String>,
    pub root_part_id: u32,
    pub parts: Vec<MimePart>,
    /// Ordered alternatives chosen by the parser's RFC 8621 body semantics.
    pub plain_body_part_ids: Vec<u32>,
    pub html_body_part_ids: Vec<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveLimits {
    /// Maximum compressed archive bytes read from the blob store.
    pub max_archive_bytes: u64,
    pub max_entries: usize,
    pub max_entry_bytes: u64,
    pub max_total_uncompressed_bytes: u64,
    pub max_compression_ratio: u32,
}

impl Default for ArchiveLimits {
    fn default() -> Self {
        Self {
            max_archive_bytes: 256 * 1024 * 1024,
            max_entries: 1_000,
            max_entry_bytes: 64 * 1024 * 1024,
            max_total_uncompressed_bytes: 256 * 1024 * 1024,
            max_compression_ratio: 200,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArchiveInspectionState {
    Complete,
    Limited,
    Encrypted,
    Unsupported,
    Invalid,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveEntry {
    pub index: u32,
    pub path: String,
    pub directory: bool,
    pub encrypted: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ArchiveInspection {
    pub state: ArchiveInspectionState,
    pub entries: Vec<ArchiveEntry>,
    pub total_uncompressed_bytes: u64,
    pub detail: Option<String>,
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
    /// Messages remain durable while snoozed; frontends decide whether the
    /// current view hides timestamps in the future.
    #[serde(default)]
    pub snoozed_until: Option<i64>,
    #[serde(default)]
    pub muted: bool,
    #[serde(default)]
    pub priority: MessagePriority,
    pub inbox_class: InboxClass,
    pub content_state: ContentState,
    /// Header-only messages are safe to list and thread, but callers must
    /// hydrate them before presenting a body, MIME tree, DKIM result, or raw
    /// export.
    pub content_availability: MessageContentAvailability,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessagePriority {
    Low,
    #[default]
    Normal,
    High,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Message {
    #[serde(flatten)]
    pub summary: MessageSummary,
    pub rfc_message_id: Option<String>,
    /// Canonical message identifiers supplied by the sender. These remain
    /// untrusted evidence; [`threading`] records the backend's actual choice.
    pub in_reply_to: Vec<String>,
    pub references: Vec<String>,
    /// RFC 5322 Sender mailboxes are message-supplied evidence. They are
    /// separate from the visible From identity and may contradict it.
    pub sender_addresses: Vec<String>,
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
    /// The user's explicit correction. This is authoritative but does not
    /// erase provider evidence, which remains available for explanation.
    pub user_classification: Option<UserClassification>,
    pub provider_spam: ProviderSpamAssessment,
    /// Local Bayesian evidence. `None` means evaluation is durably queued, not
    /// that the message was judged legitimate.
    pub local_spam: Option<LocalSpamAssessment>,
    /// DKIM evidence captured from the exact bytes stored for this message.
    pub dkim: DkimAuthentication,
    /// Delivery-time Authentication-Results evidence. Trust is scoped to the
    /// receiving account and never inferred from the header alone.
    #[serde(default)]
    pub delivery_authentication: DeliveryAuthentication,
    /// OpenPGP/MIME evidence derived from the immutable RFC 5322 bytes. This
    /// is independent of DKIM and of the contact/address trust decision.
    #[serde(default)]
    pub openpgp: OpenPgpMessageSecurity,
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
    /// Once true, replies in this conversation must be OpenPGP encrypted.
    /// Missing keys or unavailable hardware block submission rather than
    /// silently downgrading the conversation to plaintext.
    #[serde(default)]
    pub openpgp_encryption_required: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
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
pub enum SmtpSecurity {
    ImplicitTls,
    StartTls,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SmtpAuthMethod {
    Password,
    XOAuth2,
    OAuthBearer,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SmtpSettings {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub security: SmtpSecurity,
    pub auth: SmtpAuthMethod,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SmtpAccount {
    pub account_id: AccountId,
    pub settings: SmtpSettings,
    /// Opaque platform credential-store reference; never a password/token.
    pub credential_ref: String,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftStatus {
    Editing,
    Queued,
    Sent,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DraftContent {
    pub account_id: AccountId,
    /// `None` resolves to the account's default identity when saved. Loaded
    /// drafts always contain the resolved identity.
    #[serde(default)]
    pub identity_id: Option<AccountIdentityId>,
    pub thread_id: ThreadId,
    pub parent_message_id: Option<MessageId>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub subject: String,
    pub body_text: String,
    pub body_html: Option<String>,
    pub in_reply_to: Option<String>,
    pub references: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftAttachmentDisposition {
    Attachment,
    Inline,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DraftAttachment {
    pub id: DraftAttachmentId,
    pub ordinal: u32,
    pub name: String,
    pub media_type: String,
    pub disposition: DraftAttachmentDisposition,
    pub content_id: Option<String>,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Draft {
    pub id: DraftId,
    pub revision: u32,
    pub status: DraftStatus,
    #[serde(flatten)]
    pub content: DraftContent,
    pub attachments: Vec<DraftAttachment>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpSearchPolicy {
    /// The setup question has not yet been answered. No decrypted derivative
    /// may be persisted while the policy is unset.
    #[default]
    Unset,
    Enabled,
    Disabled,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpSearchStatus {
    pub policy: OpenPgpSearchPolicy,
    pub encrypted_messages: u64,
    pub indexed_messages: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpCertificateSource {
    Manual,
    AttachedKey,
    Autocrypt,
    Wkd,
    SignedMessage,
    GnuPg,
    YubiKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpBindingState {
    Candidate,
    Accepted,
    Retired,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpCertificateBinding {
    pub address: String,
    pub fingerprint: String,
    pub state: OpenPgpBindingState,
    pub source: OpenPgpCertificateSource,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpCertificate {
    /// Uppercase hexadecimal primary-key fingerprint without separators.
    pub fingerprint: String,
    pub user_ids: Vec<String>,
    pub signing_capable: bool,
    pub encryption_capable: bool,
    pub revoked: bool,
    /// Absolute Unix time derived from the newest applicable self-signature.
    /// `None` means the certificate declares no expiration.
    pub expires_at: Option<i64>,
    pub created_at: i64,
    pub imported_at: i64,
    pub source: OpenPgpCertificateSource,
    pub bindings: Vec<OpenPgpCertificateBinding>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpSecretKeyProviderKind {
    /// An explicitly imported transferable secret key encrypted in Lizard's
    /// managed credential store.
    Software,
    /// An existing key owned by a GnuPG home. Lizard stores only a reference.
    GnuPg,
    /// An OpenPGP Card key whose private operations are performed by a
    /// YubiKey through gpg-agent/scdaemon.
    YubiKey,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpSecretKeyProvider {
    pub account_id: AccountId,
    pub fingerprint: String,
    pub kind: OpenPgpSecretKeyProviderKind,
    /// GnuPG home for external providers. `None` means GnuPG's default home.
    pub gnu_pg_home: Option<PathBuf>,
    /// OpenPGP card serial for display and replacement detection. Private key
    /// bytes and PINs are never stored here.
    pub card_serial: Option<String>,
    pub is_default: bool,
    pub created_at: i64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpSignatureStatus {
    #[default]
    None,
    Valid,
    Invalid,
    MissingCertificate,
    Unsupported,
    Obsolete,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpSignatureEvidence {
    pub status: OpenPgpSignatureStatus,
    /// Primary certificate fingerprint when known.
    pub certificate_fingerprint: Option<String>,
    /// Exact signing primary/subkey fingerprint when known.
    pub signing_key_fingerprint: Option<String>,
    pub binding_state: Option<OpenPgpBindingState>,
    #[serde(default)]
    pub certificate_revoked: bool,
    #[serde(default)]
    pub certificate_expired: bool,
    pub created_at: Option<i64>,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpEncryptionStatus {
    #[default]
    NotEncrypted,
    Encrypted,
    Decrypted,
    MissingSecretKey,
    ProviderUnavailable,
    InteractionRequired,
    FailedIntegrity,
    Unsupported,
    Malformed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpMessageSecurity {
    pub encryption: OpenPgpEncryptionStatus,
    pub signatures: Vec<OpenPgpSignatureEvidence>,
    pub encrypted_to_fingerprint: Option<String>,
    pub protected_headers: bool,
    pub protected_header_mismatch: bool,
    pub decrypted_derivative_stored: bool,
    pub evaluated_at: Option<i64>,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpDecryptedMessage {
    pub message_id: MessageId,
    /// Encrypted mail is exposed as plain text only. Sender-authored HTML is
    /// never returned through this API and remote resources cannot be loaded.
    pub body_text: String,
    pub subject: Option<String>,
    pub from_address: Option<String>,
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub attachments: Vec<Attachment>,
    pub security: OpenPgpMessageSecurity,
    pub persisted_for_search: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpenPgpDraftMode {
    /// Follow the conversation requirement. New conversations remain
    /// plaintext until the user explicitly selects encryption.
    #[default]
    Automatic,
    SignOnly,
    EncryptAndSign,
    Plaintext,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OpenPgpDraftSecurity {
    pub draft_id: DraftId,
    pub requested: OpenPgpDraftMode,
    pub effective: OpenPgpDraftMode,
    pub recipient_fingerprints: Vec<String>,
    pub missing_recipient_addresses: Vec<String>,
    pub sender_fingerprint: Option<String>,
    pub conversation_requires_encryption: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailExportFormat {
    EmlDirectory,
    Maildir,
    Mbox,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MailSelection {
    All,
    Account(AccountId),
    Folder(FolderId),
    Messages(Vec<MessageId>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MailTransferLimits {
    pub max_messages: usize,
    pub max_message_bytes: u64,
    pub max_total_bytes: u64,
}

impl Default for MailTransferLimits {
    fn default() -> Self {
        Self {
            max_messages: 1_000_000,
            max_message_bytes: 128 * 1024 * 1024,
            max_total_bytes: 1024 * 1024 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MailExportReport {
    pub format: MailExportFormat,
    pub destination: PathBuf,
    pub messages: u64,
    pub raw_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct MailImportReport {
    pub format: MailExportFormat,
    pub messages: Vec<MessageId>,
    pub raw_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OfflineDownloadPolicy {
    OnDemand,
    All,
    RecentDays { days: u32 },
    SelectedFolders { folder_ids: Vec<FolderId> },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyRetentionPolicy {
    KeepAll,
    /// Only remotely recoverable, unpinned messages are eligible.
    EvictRemoteAfterDays {
        days: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AccountBodyPolicy {
    pub account_id: AccountId,
    pub offline: OfflineDownloadPolicy,
    pub retention: BodyRetentionPolicy,
    #[serde(default = "default_true")]
    pub retain_starred: bool,
    pub updated_at: i64,
}

impl AccountBodyPolicy {
    pub fn on_demand(account_id: AccountId) -> Self {
        Self {
            account_id,
            offline: OfflineDownloadPolicy::OnDemand,
            retention: BodyRetentionPolicy::KeepAll,
            retain_starred: true,
            updated_at: 0,
        }
    }
}

const fn default_true() -> bool {
    true
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BodyRetentionReport {
    pub examined: u64,
    pub evicted: Vec<MessageId>,
    pub reclaimed_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileBackupReport {
    pub destination: PathBuf,
    pub files: u64,
    pub bytes: u64,
    /// Native keychain contents are deliberately never exported. References
    /// remain useful when restoring on the same OS profile.
    pub native_credential_references: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProfileRestoreReport {
    pub destination: PathBuf,
    pub files: u64,
    pub bytes: u64,
    pub native_credential_references: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewDraftAttachment {
    pub name: String,
    pub media_type: String,
    pub disposition: DraftAttachmentDisposition,
    pub content_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubmissionStatus {
    Pending,
    InFlight,
    RetryScheduled,
    Sent,
    Failed,
    Ambiguous,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Submission {
    pub id: SubmissionId,
    pub draft_id: DraftId,
    pub account_id: AccountId,
    pub rfc_message_id: String,
    pub status: SubmissionStatus,
    pub attempts: u32,
    pub next_attempt_at: Option<i64>,
    pub last_error: Option<String>,
    pub smtp_response: Option<String>,
    pub sent_message_id: Option<MessageId>,
    pub created_at: i64,
    pub updated_at: i64,
    pub completed_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SendingLimits {
    pub max_attachments: usize,
    pub max_attachment_bytes: u64,
    pub max_total_attachment_bytes: u64,
    pub max_message_bytes: u64,
}

impl Default for SendingLimits {
    fn default() -> Self {
        Self {
            max_attachments: 100,
            max_attachment_bytes: 25 * 1024 * 1024,
            max_total_attachment_bytes: 50 * 1024 * 1024,
            max_message_bytes: 64 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DocumentExtractionLimits {
    pub max_input_bytes: u64,
    pub max_output_bytes: usize,
    pub timeout_seconds: u64,
}

impl Default for DocumentExtractionLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_output_bytes: 2 * 1024 * 1024,
            timeout_seconds: 30,
        }
    }
}

#[derive(Clone, Debug)]
pub struct DocumentExtractionRequest {
    pub declared_media_type: Option<String>,
    pub detected_media_type: Option<String>,
    pub name: Option<String>,
    pub bytes: Vec<u8>,
    pub max_output_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DocumentExtractionResult {
    pub text: String,
    pub truncated: bool,
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

/// Bounded delivery-time authentication observations grouped by the account
/// through which the exact message bytes were received.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeliveryAuthentication {
    pub observations: Vec<DeliveryAuthenticationObservation>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DeliveryAuthenticationObservation {
    pub account_id: Option<AccountId>,
    pub headers: Vec<AuthenticationResultsHeader>,
    /// More matching headers existed than the parser's fixed work budget.
    pub limited: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationResultsHeaderKind {
    AuthenticationResults,
    ArcAuthenticationResults,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationResultsParseStatus {
    Complete,
    Malformed,
    Limited,
}

/// Why a physical authentication-results header is or is not authoritative.
/// ARC-AAR remains diagnostic until its enclosing ARC chain is verified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationResultsTrust {
    Trusted,
    NoReceivingAccount,
    NoTrustedAuthservConfigured,
    AuthservIdNotTrusted,
    DuplicateTrustedAuthservId,
    Malformed,
    Limited,
    ArcChainUnverified,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationResultsHeader {
    /// Zero-based position among all RFC 5322 fields in document order.
    pub header_index: u32,
    pub kind: AuthenticationResultsHeaderKind,
    pub arc_instance: Option<u32>,
    pub authserv_id: Option<String>,
    pub authserv_version: Option<u32>,
    pub parse_status: AuthenticationResultsParseStatus,
    pub trust: AuthenticationResultsTrust,
    pub methods: Vec<AuthenticationMethodEvidence>,
    /// Bounded unfolded value for diagnostics. This is untrusted plain text.
    pub raw_header_value: String,
    pub detail: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethodKind {
    Dkim,
    Dmarc,
    Spf,
    Arc,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationMethodResult {
    None,
    Pass,
    Fail,
    SoftFail,
    Neutral,
    Policy,
    TemporaryError,
    PermanentError,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationMethodEvidence {
    pub kind: AuthenticationMethodKind,
    pub method: String,
    pub version: Option<u32>,
    pub result: AuthenticationMethodResult,
    pub raw_result: String,
    pub reason: Option<String>,
    pub properties: Vec<AuthenticationProperty>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthenticationProperty {
    pub namespace: Option<String>,
    pub name: String,
    pub value: String,
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
    #[serde(default)]
    pub snoozed: Option<bool>,
    #[serde(default)]
    pub muted: Option<bool>,
    #[serde(default)]
    pub priority: Option<MessagePriority>,
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
            snoozed: None,
            muted: None,
            priority: None,
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
pub struct SearchPage {
    pub items: Vec<MessageSummary>,
    pub next_cursor: Option<String>,
    /// False when the query uses body/attachment-name fields and at least one
    /// message is not fully downloaded, so additional matches may exist.
    pub content_results_complete: bool,
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
    #[serde(default)]
    pub provenance: ContactProvenance,
    pub created_at: i64,
    #[serde(default)]
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewContact {
    pub display_name: String,
    pub addresses: Vec<ContactAddress>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContactProvenanceKind {
    #[default]
    Manual,
    VcardImport,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContactProvenance {
    pub kind: ContactProvenanceKind,
    pub source_label: Option<String>,
    pub imported_at: Option<i64>,
}

impl ContactProvenance {
    pub fn manual() -> Self {
        Self {
            kind: ContactProvenanceKind::Manual,
            source_label: None,
            imported_at: None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ContactImportResult {
    pub imported: Vec<ContactId>,
    pub skipped_duplicate_contacts: u64,
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

/// Filter authority is confined to organization and deletion of the message
/// being evaluated. Remote changes are queued through the same durable IMAP
/// mutation outbox as explicit user actions.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FilterAction {
    AddToLocalFolder {
        folder_id: FolderId,
    },
    RemoveFromLocalFolder {
        folder_id: FolderId,
    },
    MoveToLocalFolder {
        folder_id: FolderId,
    },
    MoveToRemoteFolder {
        source_folder_id: FolderId,
        destination_folder_id: FolderId,
    },
    TrashRemote {
        source_folder_id: FolderId,
    },
    DeleteRemote {
        source_folder_id: FolderId,
    },
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
    #[serde(default)]
    pub remote_mutation_ids: Vec<ImapMutationId>,
    #[serde(default)]
    pub undone_at: Option<i64>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilterRulePreview {
    pub matching_messages: u64,
    pub affected_messages: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilterRuleReplay {
    pub matching_messages: u64,
    pub newly_applied_messages: u64,
    pub already_applied_messages: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FilterRuleUndo {
    pub restored_local_folders: Vec<FolderId>,
    pub cancelled_remote_mutations: Vec<ImapMutationId>,
    pub queued_inverse_mutations: Vec<ImapMutationId>,
    pub undone_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SavedSearch {
    pub id: crate::SavedSearchId,
    pub name: String,
    pub query: String,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NewSavedSearch {
    pub name: String,
    pub query: String,
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
