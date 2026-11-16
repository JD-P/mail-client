//! Headless, local-first mail storage and search.
//!
//! This crate deliberately owns no renderer and performs no network I/O. Protocol
//! adapters feed exact RFC 5322 bytes through [`Backend::ingest`], which is also
//! used by fixture importers and future POP3 support.

mod backend;
mod blob;
mod error;
mod event;
mod id;
mod imap;
mod mime;
mod query;
mod schema;
mod types;

pub use backend::{Accounts, Backend, Contacts, Events, Folders, Messages, Search, Sync};
pub use error::{BackendError, ErrorCode, Result};
pub use event::{ChangeCursor, EventRecvError, EventSubscription};
pub use id::{AccountId, ContactId, FolderId, MessageId};
pub use imap::imap_fetch_message;
pub use query::{parse_query, QueryExpr, QueryParseError, QueryTerm};
pub use types::*;
