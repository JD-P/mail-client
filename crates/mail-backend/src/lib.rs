//! Headless, local-first mail storage and search.
//!
//! This crate deliberately owns no renderer. Protocol adapters feed exact RFC
//! 5322 bytes through [`Backend::ingest`] or the bounded
//! [`Backend::ingest_batch`] path, which are also used by fixture importers and
//! future POP3 support. The IMAP adapter accepts an authenticated session whose
//! TLS transport and credentials remain the embedding application's concern.

mod authentication;
mod automation;
mod backend;
mod blob;
mod error;
mod event;
mod heuristic;
mod id;
mod imap;
mod mime;
mod query;
mod schema;
mod search_index;
mod types;

pub use automation::{FilterRules, Heuristics};
pub use backend::{Accounts, Backend, Contacts, Events, Folders, Messages, Search, Sync};
pub use error::{BackendError, ErrorCode, Result};
pub use event::{ChangeCursor, EventRecvError, EventSubscription};
pub use heuristic::compile_heuristic;
pub use id::{AccountId, ContactId, FilterRuleId, FindingId, FolderId, HeuristicId, MessageId};
pub use imap::imap_fetch_message;
pub use query::{parse_query, QueryExpr, QueryParseError, QueryTerm};
pub use types::*;
