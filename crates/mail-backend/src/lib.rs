//! Headless, local-first mail storage and search.
//!
//! This crate deliberately owns no renderer. Protocol adapters feed exact RFC
//! 5322 bytes through [`Backend::ingest`] or the bounded
//! [`Backend::ingest_batch`] path, which are also used by fixture importers and
//! future POP3 support. The IMAP account engine owns verified transport,
//! credential-provider authentication, receive synchronization and a durable
//! outbound mutation queue; it still shares the same ingestion path.

mod authentication;
mod automation;
mod backend;
mod blob;
mod caldav;
mod credential;
mod delivery_auth;
mod error;
mod event;
mod heuristic;
mod id;
mod identity;
mod imap;
mod imap_engine;
mod imap_mutation;
mod lifecycle;
mod mime;
mod mime_api;
mod openpgp;
mod organization;
mod query;
mod schema;
mod search_index;
mod security;
mod sending;
mod smtp;
mod spam;
mod storage;
mod thread;
mod types;

pub use automation::{FilterRules, Heuristics};
pub use backend::{Accounts, Backend, Contacts, Events, Folders, Messages, Search, Sync};
pub use caldav::{CalDavCredentialProvider, CalDavEngine, CalendarAccounts, Calendars};
pub use credential::{CredentialStorageKind, Credentials};
pub use error::{BackendError, ErrorCode, Result};
pub use event::{ChangeCursor, EventRecvError, EventSubscription};
pub use heuristic::compile_heuristic;
pub use id::{
    AccountId, AccountIdentityId, CalendarAccountId, CalendarEventId, CalendarId, ContactId,
    DraftAttachmentId, DraftId, FilterRuleId, FindingId, FolderId, HeuristicId,
    ImapMutationConflictId, ImapMutationId, MessageId, SavedSearchId, SubmissionId, ThreadId,
};
pub use identity::AccountIdentities;
pub use imap::imap_fetch_message;
pub use imap_engine::{
    CredentialProvider, ImapAccountEngine, ImapAccountEngineConfig, ImapAccountSyncReport,
    ImapAccountSyncState, ImapAccountSyncStatus, ImapCredential, ImapFolderSyncReport,
    ImapMailboxCompleteness, ImapMailboxSyncState, ImapMutationSyncReport, SecretValue,
};
pub use imap_mutation::ImapMutations;
pub use lifecycle::{restore_profile_backup, DataLifecycle};
pub use mime_api::{Mime, SandboxedDocumentExtractor};
pub use openpgp::OpenPgp;
pub use organization::SavedSearches;
pub use query::{parse_query, QueryExpr, QueryParseError, QueryTerm};
pub use sending::{Drafts, Outbox, Sending};
pub use smtp::{SmtpEngine, SmtpEngineConfig};
pub use spam::SpamClassifier;
pub use storage::{
    AccountStorageQuota, IntegrityAuditOptions, IntegrityAuditReport, IntegrityIssue,
    IntegrityIssueKind, IntegritySeverity, Storage, StorageLimits, StorageUsage,
};
pub use thread::Threads;
pub use types::*;
