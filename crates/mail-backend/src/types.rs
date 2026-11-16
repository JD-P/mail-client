use crate::{AccountId, ContactId, FolderId, MessageId};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackendConfig {
    pub profile_dir: PathBuf,
    pub limits: IngestLimits,
    pub event_buffer: usize,
}

impl BackendConfig {
    pub fn new(profile_dir: impl Into<PathBuf>) -> Self {
        Self {
            profile_dir: profile_dir.into(),
            limits: IngestLimits::default(),
            event_buffer: 1_024,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IngestLimits {
    pub max_message_bytes: usize,
    pub max_mime_depth: u8,
    pub max_mime_parts: usize,
    pub max_text_bytes: usize,
    pub max_html_bytes: usize,
}

impl Default for IngestLimits {
    fn default() -> Self {
        Self {
            max_message_bytes: 64 * 1024 * 1024,
            max_mime_depth: 16,
            max_mime_parts: 512,
            max_text_bytes: 2 * 1024 * 1024,
            max_html_bytes: 4 * 1024 * 1024,
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
    pub to_addresses: Vec<String>,
    pub cc_addresses: Vec<String>,
    pub bcc_addresses: Vec<String>,
    pub delivered_to_addresses: Vec<String>,
    pub list_id: Option<String>,
    pub body_text: String,
    /// Original sender-authored HTML. Plain text is never synthesized into HTML.
    pub body_html: Option<String>,
    pub attachments: Vec<Attachment>,
    pub instances: Vec<MessageInstance>,
    pub local_folder_ids: Vec<FolderId>,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BackendEvent {
    pub sequence: u64,
    pub occurred_at: i64,
    pub kind: String,
    pub entity_id: String,
    pub payload: serde_json::Value,
}
