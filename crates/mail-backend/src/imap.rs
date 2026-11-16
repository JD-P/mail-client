use crate::{BackendError, ImapFetchedMessage, Result};
use async_imap::types::{Fetch, Flag};

/// Convert a complete response from the vendored `async-imap` client into the
/// transport-neutral value consumed by [`crate::Sync::ingest_imap_batch`].
///
/// The IMAP command must request `UID`, `FLAGS`, `MODSEQ`, `INTERNALDATE`, and
/// a complete `BODY.PEEK[]` (or `RFC822`) payload. Missing UID or body data is
/// rejected instead of silently creating an unstable or partial message.
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
