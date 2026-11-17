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
mod error;
mod event;
mod heuristic;
mod id;
mod imap;
mod imap_engine;
mod imap_mutation;
mod mime;
mod query;
mod schema;
mod search_index;
mod thread;
mod types;

pub use automation::{FilterRules, Heuristics};
pub use backend::{Accounts, Backend, Contacts, Events, Folders, Messages, Search, Sync};
pub use error::{BackendError, ErrorCode, Result};
pub use event::{ChangeCursor, EventRecvError, EventSubscription};
pub use heuristic::compile_heuristic;
pub use id::{
    AccountId, ContactId, FilterRuleId, FindingId, FolderId, HeuristicId, ImapMutationConflictId,
    ImapMutationId, MessageId, ThreadId,
};
pub use imap::imap_fetch_message;
pub use imap_engine::{
    CredentialProvider, ImapAccountEngine, ImapAccountEngineConfig, ImapAccountSyncReport,
    ImapAccountSyncState, ImapAccountSyncStatus, ImapCredential, ImapFolderSyncReport,
    ImapMailboxCompleteness, ImapMailboxSyncState, ImapMutationSyncReport, SecretValue,
};
pub use imap_mutation::ImapMutations;
pub use query::{parse_query, QueryExpr, QueryParseError, QueryTerm};
pub use thread::Threads;
pub use types::*;
