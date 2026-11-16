use crate::{BackendError, ImapFetchedMessage, Result};
use async_imap::types::{Fetch, Flag};

pub(crate) struct ImapFetchMetadata {
    pub uid: u32,
    pub mod_sequence: Option<u64>,
    pub flags: Vec<String>,
    pub internal_date: Option<i64>,
    pub size: u32,
}

/// Convert a complete response from the vendored `async-imap` client into the
/// transport-neutral value consumed by [`crate::Sync::ingest_imap_batch`].
///
/// The IMAP command must request `UID`, `FLAGS`, `INTERNALDATE`, and a complete
/// `BODY.PEEK[]` (or `RFC822`) payload. `MODSEQ` is retained when the server
/// supports it. Missing UID or body data is rejected instead of silently
/// creating an unstable or partial message.
pub fn imap_fetch_message(fetch: &Fetch) -> Result<ImapFetchedMessage> {
    let uid = fetch
        .uid
        .ok_or_else(|| BackendError::InvalidInput("IMAP FETCH response has no UID".into()))?;
    let raw = fetch.body().ok_or_else(|| {
        BackendError::InvalidInput("IMAP FETCH response has no complete message body".into())
    })?;
    Ok(ImapFetchedMessage {
        uid,
        mod_sequence: fetch.modseq,
        flags: fetch.flags().map(flag_text).collect(),
        internal_date: fetch.internal_date().map(|date| date.timestamp()),
        raw: raw.to_vec(),
    })
}

pub(crate) fn imap_fetch_metadata(fetch: &Fetch) -> Result<ImapFetchMetadata> {
    Ok(ImapFetchMetadata {
        uid: fetch
            .uid
            .ok_or_else(|| BackendError::InvalidInput("IMAP FETCH response has no UID".into()))?,
        mod_sequence: fetch.modseq,
        flags: fetch.flags().map(flag_text).collect(),
        internal_date: fetch.internal_date().map(|date| date.timestamp()),
        size: fetch.size.ok_or_else(|| {
            BackendError::InvalidInput("IMAP FETCH response has no RFC822.SIZE".into())
        })?,
    })
}

fn flag_text(flag: Flag<'_>) -> String {
    match flag {
        Flag::Seen => "\\Seen".into(),
        Flag::Answered => "\\Answered".into(),
        Flag::Flagged => "\\Flagged".into(),
        Flag::Deleted => "\\Deleted".into(),
        Flag::Draft => "\\Draft".into(),
        Flag::Recent => "\\Recent".into(),
        Flag::MayCreate => "\\*".into(),
        Flag::Custom(value) => value.into_owned(),
    }
}
