use std::collections::HashSet;
use std::pin::Pin;
use std::task::{Context, Poll};

use futures_util::stream::Stream;
use futures_util::{TryStreamExt as _, io};
use imap_proto::rfc5464::Metadata;
use imap_proto::{self, MailboxDatum, RequestId, Response};

use crate::error::{Error, Result};
use crate::types::ResponseData;
use crate::types::*;

/// Return the result carried by a tagged completion for `command_tag`.
///
/// IMAP commands are not successful until their matching tagged `OK` response
/// is received.  Untagged data before a tagged `NO`/`BAD`, or before EOF, must
/// never be mistaken for a successful command.
pub(crate) fn command_completion(
    response: &ResponseData,
    command_tag: &RequestId,
) -> Option<Result<()>> {
    let Response::Done {
        tag,
        status,
        outcome,
    } = response.parsed()
    else {
        return None;
    };
    if tag != command_tag {
        return None;
    }

    use imap_proto::Status;
    Some(match status {
        Status::Ok => Ok(()),
        Status::Bad => Err(Error::Bad(format!("outcome: {outcome:?}"))),
        Status::No => Err(Error::No(format!("outcome: {outcome:?}"))),
        _ => Err(Error::Io(io::Error::other(format!(
            "status: {status:?}, outcome: {outcome:?}"
        )))),
    })
}

/// Read one non-completion response for a command.
///
/// `Ok(None)` means that a matching tagged `OK` was consumed.  EOF before a
/// matching completion is a connection failure, not successful completion.
pub(crate) async fn next_command_response<T>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    command_tag: &RequestId,
) -> Result<Option<ResponseData>>
where
    T: Stream<Item = io::Result<ResponseData>> + Unpin,
{
    let response = match stream.try_next().await {
        Ok(Some(response)) => response,
        Ok(None) => {
            *pending_command = None;
            return Err(Error::ConnectionLost);
        }
        Err(error) => {
            *pending_command = None;
            return Err(error.into());
        }
    };
    if let Some(result) = command_completion(&response, command_tag) {
        *pending_command = None;
        result?;
        Ok(None)
    } else {
        Ok(Some(response))
    }
}

/// A command response stream which consumes and validates tagged completion.
///
/// `pending_command` remains set if this value is dropped early.  The
/// connection drains that command before it writes another one, preventing a
/// cancelled or partially-consumed command from contaminating the next call.
pub(crate) struct CommandStream<'a, T> {
    stream: &'a mut T,
    pending_command: &'a mut Option<RequestId>,
    command_tag: RequestId,
    finished: bool,
}

impl<'a, T> CommandStream<'a, T> {
    pub(crate) fn new(
        stream: &'a mut T,
        pending_command: &'a mut Option<RequestId>,
        command_tag: RequestId,
    ) -> Self {
        *pending_command = Some(command_tag.clone());
        Self {
            stream,
            pending_command,
            command_tag,
            finished: false,
        }
    }

    fn finish(&mut self) {
        self.finished = true;
        *self.pending_command = None;
    }
}

impl<T: Unpin> Unpin for CommandStream<'_, T> {}

impl<T> Stream for CommandStream<'_, T>
where
    T: Stream<Item = io::Result<ResponseData>> + Unpin,
{
    type Item = Result<ResponseData>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if self.finished {
            return Poll::Ready(None);
        }

        match Pin::new(&mut *self.stream).poll_next(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                self.finish();
                Poll::Ready(Some(Err(Error::ConnectionLost)))
            }
            Poll::Ready(Some(Err(error))) => {
                self.finish();
                Poll::Ready(Some(Err(error.into())))
            }
            Poll::Ready(Some(Ok(response))) => {
                if let Some(result) = command_completion(&response, &self.command_tag) {
                    self.finish();
                    match result {
                        Ok(()) => Poll::Ready(None),
                        Err(error) => Poll::Ready(Some(Err(error))),
                    }
                } else {
                    Poll::Ready(Some(Ok(response)))
                }
            }
        }
    }
}

pub(crate) fn parse_names<'a, T: Stream<Item = io::Result<ResponseData>> + Unpin + Send>(
    stream: &'a mut T,
    pending_command: &'a mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> impl Stream<Item = Result<Name>> + 'a + Send + Unpin {
    use futures_util::{FutureExt, StreamExt};

    StreamExt::filter_map(
        CommandStream::new(stream, pending_command, command_tag),
        move |resp| {
            let unsolicited = unsolicited.clone();
            async move {
                match resp {
                    Ok(resp) => match resp.parsed() {
                        Response::MailboxData(MailboxDatum::List { .. }) => {
                            let name = Name::from_mailbox_data(resp);
                            Some(Ok(name))
                        }
                        _ => {
                            handle_unilateral(resp, unsolicited);
                            None
                        }
                    },
                    Err(err) => Some(Err(err)),
                }
            }
            .boxed()
        },
    )
}

pub(crate) fn parse_fetches<'a, T: Stream<Item = io::Result<ResponseData>> + Unpin + Send>(
    stream: &'a mut T,
    pending_command: &'a mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> impl Stream<Item = Result<Fetch>> + 'a + Send + Unpin {
    use futures_util::{FutureExt, StreamExt};

    StreamExt::filter_map(
        CommandStream::new(stream, pending_command, command_tag),
        move |resp| {
            let unsolicited = unsolicited.clone();

            async move {
                match resp {
                    Ok(resp) => match resp.parsed() {
                        Response::Fetch(..) => Some(Ok(Fetch::new(resp))),
                        _ => {
                            handle_unilateral(resp, unsolicited);
                            None
                        }
                    },
                    Err(err) => Some(Err(err)),
                }
            }
            .boxed()
        },
    )
}

pub(crate) async fn parse_status<T: Stream<Item = io::Result<ResponseData>> + Unpin + Send>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    expected_mailbox: &str,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<Mailbox> {
    let mut mbox = Mailbox::default();

    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::MailboxData(MailboxDatum::Status { mailbox, status })
                if mailbox == expected_mailbox =>
            {
                for attribute in status {
                    match attribute {
                        StatusAttribute::HighestModSeq(highest_modseq) => {
                            mbox.highest_modseq = Some(*highest_modseq)
                        }
                        StatusAttribute::Messages(exists) => mbox.exists = *exists,
                        StatusAttribute::Recent(recent) => mbox.recent = *recent,
                        StatusAttribute::UidNext(uid_next) => mbox.uid_next = Some(*uid_next),
                        StatusAttribute::UidValidity(uid_validity) => {
                            mbox.uid_validity = Some(*uid_validity)
                        }
                        StatusAttribute::Unseen(unseen) => mbox.unseen = Some(*unseen),
                        _ => {}
                    }
                }
            }
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }

    Ok(mbox)
}

pub(crate) fn parse_expunge<'a, T: Stream<Item = io::Result<ResponseData>> + Unpin + Send>(
    stream: &'a mut T,
    pending_command: &'a mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> impl Stream<Item = Result<u32>> + 'a + Send {
    use futures_util::StreamExt;

    StreamExt::filter_map(
        CommandStream::new(stream, pending_command, command_tag),
        move |resp| {
            let unsolicited = unsolicited.clone();

            async move {
                match resp {
                    Ok(resp) => match resp.parsed() {
                        Response::Expunge(id) => Some(Ok(*id)),
                        _ => {
                            handle_unilateral(resp, unsolicited);
                            None
                        }
                    },
                    Err(err) => Some(Err(err)),
                }
            }
        },
    )
}

pub(crate) async fn parse_capabilities<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<Capabilities> {
    let mut caps: HashSet<Capability> = HashSet::new();

    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::Capabilities(cs) => {
                for c in cs {
                    caps.insert(Capability::from(c)); // TODO: avoid clone
                }
            }
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }

    Ok(Capabilities(caps))
}

pub(crate) async fn parse_noop<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<()> {
    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        handle_unilateral(resp, unsolicited.clone());
    }

    Ok(())
}

pub(crate) async fn parse_mailbox<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<Mailbox> {
    let mut mailbox = Mailbox::default();

    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::Data { status, outcome } => {
                use imap_proto::Status;

                match status {
                    Status::Ok => {
                        use imap_proto::ResponseCode;
                        match &outcome.code {
                            Some(ResponseCode::UidValidity(uid)) => {
                                mailbox.uid_validity = Some(*uid);
                            }
                            Some(ResponseCode::UidNext(unext)) => {
                                mailbox.uid_next = Some(*unext);
                            }
                            Some(ResponseCode::HighestModSeq(highest_modseq)) => {
                                mailbox.highest_modseq = Some(*highest_modseq);
                            }
                            Some(ResponseCode::Unseen(n)) => {
                                mailbox.unseen = Some(*n);
                            }
                            Some(ResponseCode::PermanentFlags(flags)) => {
                                mailbox
                                    .permanent_flags
                                    .extend(flags.iter().map(|s| (*s).to_string()).map(Flag::from));
                            }
                            _ => {}
                        }
                    }
                    Status::Bad => {
                        return Err(Error::Bad(format!("outcome: {outcome:?}")));
                    }
                    Status::No => {
                        return Err(Error::No(format!("outcome: {outcome:?}")));
                    }
                    _ => {
                        return Err(Error::Io(io::Error::other(format!(
                            "status: {status:?}, outcome: {outcome:?}"
                        ))));
                    }
                }
            }
            Response::MailboxData(m) => match m {
                MailboxDatum::Status { .. } => handle_unilateral(resp, unsolicited.clone()),
                MailboxDatum::Exists(e) => {
                    mailbox.exists = *e;
                }
                MailboxDatum::Recent(r) => {
                    mailbox.recent = *r;
                }
                MailboxDatum::Flags(flags) => {
                    mailbox
                        .flags
                        .extend(flags.iter().map(|s| (*s).to_string()).map(Flag::from));
                }
                MailboxDatum::List { .. } => {}
                MailboxDatum::MetadataSolicited { .. } => {}
                MailboxDatum::MetadataUnsolicited { .. } => {}
                MailboxDatum::Search { .. } => {}
                MailboxDatum::Sort { .. } => {}
                _ => {}
            },
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }

    Ok(mailbox)
}

pub(crate) async fn parse_qresync_select<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<QresyncSelect> {
    let mut mailbox = Mailbox::default();
    let mut vanished = Vec::new();
    let mut changed = Vec::new();

    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::Vanished { uids, .. } => vanished.extend(uids.iter().cloned()),
            Response::Fetch(..) => changed.push(Fetch::new(resp)),
            Response::Data { status, outcome } => {
                use imap_proto::Status;

                match status {
                    Status::Ok => {
                        use imap_proto::ResponseCode;
                        match &outcome.code {
                            Some(ResponseCode::UidValidity(uid)) => {
                                mailbox.uid_validity = Some(*uid);
                            }
                            Some(ResponseCode::UidNext(uid_next)) => {
                                mailbox.uid_next = Some(*uid_next);
                            }
                            Some(ResponseCode::HighestModSeq(highest_modseq)) => {
                                mailbox.highest_modseq = Some(*highest_modseq);
                            }
                            Some(ResponseCode::Unseen(sequence)) => {
                                mailbox.unseen = Some(*sequence);
                            }
                            Some(ResponseCode::PermanentFlags(flags)) => {
                                mailbox.permanent_flags.extend(
                                    flags.iter().map(|flag| (*flag).to_string()).map(Flag::from),
                                );
                            }
                            _ => {}
                        }
                    }
                    Status::Bad => {
                        return Err(Error::Bad(format!("outcome: {outcome:?}")));
                    }
                    Status::No => {
                        return Err(Error::No(format!("outcome: {outcome:?}")));
                    }
                    _ => {
                        return Err(Error::Io(io::Error::other(format!(
                            "status: {status:?}, outcome: {outcome:?}"
                        ))));
                    }
                }
            }
            Response::MailboxData(datum) => match datum {
                MailboxDatum::Status { .. } => handle_unilateral(resp, unsolicited.clone()),
                MailboxDatum::Exists(exists) => mailbox.exists = *exists,
                MailboxDatum::Recent(recent) => mailbox.recent = *recent,
                MailboxDatum::Flags(flags) => mailbox
                    .flags
                    .extend(flags.iter().map(|flag| (*flag).to_string()).map(Flag::from)),
                MailboxDatum::List { .. }
                | MailboxDatum::MetadataSolicited { .. }
                | MailboxDatum::MetadataUnsolicited { .. }
                | MailboxDatum::Search { .. }
                | MailboxDatum::Sort { .. } => {}
                _ => {}
            },
            _ => handle_unilateral(resp, unsolicited.clone()),
        }
    }

    Ok(QresyncSelect {
        mailbox,
        vanished,
        changed,
    })
}

pub(crate) async fn parse_copy_uid<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<Option<CopyUid>> {
    let mut mapping = None;
    loop {
        let response = match stream.try_next().await {
            Ok(Some(response)) => response,
            Ok(None) => {
                *pending_command = None;
                return Err(Error::ConnectionLost);
            }
            Err(error) => {
                *pending_command = None;
                return Err(error.into());
            }
        };
        match response.parsed() {
            Response::Done {
                tag,
                status,
                outcome,
            } if tag == &command_tag => {
                *pending_command = None;
                if let Some(value) = copy_uid_from_code(outcome.code.as_ref()) {
                    mapping = Some(value);
                }
                use imap_proto::Status;
                return match status {
                    Status::Ok => Ok(mapping),
                    Status::Bad => Err(Error::Bad(format!("outcome: {outcome:?}"))),
                    Status::No => Err(Error::No(format!("outcome: {outcome:?}"))),
                    _ => Err(Error::Io(io::Error::other(format!(
                        "status: {status:?}, outcome: {outcome:?}"
                    )))),
                };
            }
            Response::Data { outcome, .. } => {
                if let Some(value) = copy_uid_from_code(outcome.code.as_ref()) {
                    mapping = Some(value);
                } else {
                    handle_unilateral(response, unsolicited.clone());
                }
            }
            _ => handle_unilateral(response, unsolicited.clone()),
        }
    }
}

fn copy_uid_from_code(code: Option<&imap_proto::ResponseCode<'_>>) -> Option<CopyUid> {
    let Some(imap_proto::ResponseCode::CopyUid(uid_validity, source, destination)) = code else {
        return None;
    };
    Some(CopyUid {
        uid_validity: *uid_validity,
        source: source.iter().map(uid_set_member_range).collect(),
        destination: destination.iter().map(uid_set_member_range).collect(),
    })
}

fn uid_set_member_range(
    member: &imap_proto::rfc4315::UidSetMember,
) -> std::ops::RangeInclusive<Uid> {
    match member {
        imap_proto::rfc4315::UidSetMember::Uid(uid) => *uid..=*uid,
        imap_proto::rfc4315::UidSetMember::UidRange(range) => range.clone(),
    }
}

pub(crate) async fn parse_ids<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<HashSet<u32>> {
    let mut ids: HashSet<u32> = HashSet::new();

    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::MailboxData(MailboxDatum::Search(cs)) => {
                for c in cs {
                    ids.insert(*c);
                }
            }
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }

    Ok(ids)
}

/// Parses [GETMETADATA](https://www.rfc-editor.org/info/rfc5464) response.
pub(crate) async fn parse_metadata<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    mailbox_name: &str,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<Vec<Metadata>> {
    let mut res_values = Vec::new();
    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            // METADATA Response with Values
            // <https://datatracker.ietf.org/doc/html/rfc5464.html#section-4.4.1>
            Response::MailboxData(MailboxDatum::MetadataSolicited { mailbox, values })
                if mailbox == mailbox_name =>
            {
                res_values.extend_from_slice(values.as_slice());
            }

            // We are not interested in
            // [Unsolicited METADATA Response without Values](https://datatracker.ietf.org/doc/html/rfc5464.html#section-4.4.2),
            // they go to unsolicited channel with other unsolicited responses.
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }
    Ok(res_values)
}

/// Sends unilateral server response
/// (see Section 7 of RFC 3501)
/// into the channel.
///
/// If the channel is full or closed,
/// i.e. the responses are not being consumed,
/// ignores new responses.
pub(crate) fn handle_unilateral(res: ResponseData, unsolicited: UnsolicitedSender) {
    match res.parsed() {
        Response::MailboxData(MailboxDatum::Status { mailbox, status }) => {
            unsolicited.send(UnsolicitedResponse::Status {
                mailbox: (mailbox.as_ref()).into(),
                attributes: status.to_vec(),
            });
        }
        Response::MailboxData(MailboxDatum::Recent(n)) => {
            unsolicited.send(UnsolicitedResponse::Recent(*n));
        }
        Response::MailboxData(MailboxDatum::Exists(n)) => {
            unsolicited.send(UnsolicitedResponse::Exists(*n));
        }
        Response::Expunge(n) => {
            unsolicited.send(UnsolicitedResponse::Expunge(*n));
        }
        _ => {
            unsolicited.send(UnsolicitedResponse::Other(res));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    fn bounded(
        capacity: usize,
    ) -> (
        UnsolicitedSender,
        async_channel::Receiver<UnsolicitedResponse>,
    ) {
        UnsolicitedSender::bounded(capacity)
    }

    fn input_stream(data: &[&str]) -> Vec<io::Result<ResponseData>> {
        data.iter()
            .copied()
            .chain(std::iter::once("A0001 OK completed\r\n"))
            .map(|line| {
                let block = BytesMut::from(line.as_bytes());
                ResponseData::try_new(block, |bytes| -> io::Result<_> {
                    let (remaining, response) = imap_proto::Response::parse(bytes).unwrap();
                    assert_eq!(remaining.len(), 0);
                    Ok(response)
                })
            })
            .collect()
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_capability_test() {
        let expected_capabilities = &["IMAP4rev1", "STARTTLS", "AUTH=GSSAPI", "LOGINDISABLED"];
        let responses =
            input_stream(&["* CAPABILITY IMAP4rev1 STARTTLS AUTH=GSSAPI LOGINDISABLED\r\n"]);

        let mut stream = async_std::stream::from_iter(responses);
        let (send, recv) = bounded(10);
        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        let capabilities = parse_capabilities(&mut stream, &mut pending, send, id)
            .await
            .unwrap();
        // shouldn't be any unexpected responses parsed
        assert!(recv.is_empty());
        assert_eq!(capabilities.len(), 4);
        for e in expected_capabilities {
            assert!(capabilities.has_str(e));
        }
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_capability_case_insensitive_test() {
        // Test that "IMAP4REV1" (instead of "IMAP4rev1") is accepted
        let expected_capabilities = &["IMAP4rev1", "STARTTLS"];
        let responses = input_stream(&["* CAPABILITY IMAP4REV1 STARTTLS\r\n"]);
        let mut stream = async_std::stream::from_iter(responses);

        let (send, recv) = bounded(10);
        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        let capabilities = parse_capabilities(&mut stream, &mut pending, send, id)
            .await
            .unwrap();

        // shouldn't be any unexpected responses parsed
        assert!(recv.is_empty());
        assert_eq!(capabilities.len(), 2);
        for e in expected_capabilities {
            assert!(capabilities.has_str(e));
        }
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_qresync_select_preserves_changes_and_vanished_uids() {
        let responses = input_stream(&[
            "* FLAGS (\\Seen \\Answered)\r\n",
            "* 4 EXISTS\r\n",
            "* OK [UIDVALIDITY 7] UIDs valid\r\n",
            "* OK [UIDNEXT 12] Predicted next UID\r\n",
            "* OK [HIGHESTMODSEQ 99] Highest\r\n",
            "* VANISHED (EARLIER) 2:3,9\r\n",
            "* 1 FETCH (UID 4 FLAGS (\\Seen) MODSEQ (99))\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);
        let (send, recv) = bounded(10);
        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());

        let selected = parse_qresync_select(&mut stream, &mut pending, send, id)
            .await
            .unwrap();

        assert!(recv.is_empty());
        assert_eq!(selected.mailbox.exists, 4);
        assert_eq!(selected.mailbox.uid_validity, Some(7));
        assert_eq!(selected.mailbox.uid_next, Some(12));
        assert_eq!(selected.mailbox.highest_modseq, Some(99));
        assert_eq!(selected.vanished, vec![2..=3, 9..=9]);
        assert_eq!(selected.changed.len(), 1);
        assert_eq!(selected.changed[0].uid, Some(4));
        assert_eq!(selected.changed[0].modseq, Some(99));
        assert!(selected.changed[0].flags().any(|flag| flag == Flag::Seen));
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_copy_uid_preserves_uidplus_mapping() {
        let responses = input_stream(&["* OK [COPYUID 1511554416 142,399 41:42] Copied UIDs\r\n"]);
        let mut stream = async_std::stream::from_iter(responses);
        let (send, recv) = bounded(10);
        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());

        let mapping = parse_copy_uid(&mut stream, &mut pending, send, id)
            .await
            .unwrap()
            .unwrap();

        assert!(recv.is_empty());
        assert_eq!(mapping.uid_validity, 1_511_554_416);
        assert_eq!(mapping.source, vec![142..=142, 399..=399]);
        assert_eq!(mapping.destination, vec![41..=42]);
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    #[should_panic]
    async fn parse_capability_invalid_test() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&["* JUNK IMAP4rev1 STARTTLS AUTH=GSSAPI LOGINDISABLED\r\n"]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        parse_capabilities(&mut stream, &mut pending, send.clone(), id)
            .await
            .unwrap();
        assert!(recv.is_empty());
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_names_test() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&["* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n"]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0001".into());
        let mut pending = None;
        let names: Vec<_> = parse_names(&mut stream, &mut pending, send, id)
            .try_collect::<Vec<Name>>()
            .await
            .unwrap();
        assert!(recv.is_empty());
        assert_eq!(names.len(), 1);
        assert_eq!(
            names[0].attributes(),
            &[NameAttribute::Extension("\\HasNoChildren".into())]
        );
        assert_eq!(names[0].delimiter(), Some("."));
        assert_eq!(names[0].name(), "INBOX");
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_fetches_empty() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[]);
        let mut stream = async_std::stream::from_iter(responses);
        let id = RequestId("A0001".into());
        let mut pending = None;

        let fetches = parse_fetches(&mut stream, &mut pending, send, id)
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert!(recv.is_empty());
        assert!(fetches.is_empty());
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_fetches_test() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[
            "* 24 FETCH (FLAGS (\\Seen) UID 4827943)\r\n",
            "* 25 FETCH (FLAGS (\\Seen))\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);
        let id = RequestId("A0001".into());
        let mut pending = None;

        let fetches = parse_fetches(&mut stream, &mut pending, send, id)
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert!(recv.is_empty());

        assert_eq!(fetches.len(), 2);
        assert_eq!(fetches[0].message, 24);
        assert_eq!(fetches[0].flags().collect::<Vec<_>>(), vec![Flag::Seen]);
        assert_eq!(fetches[0].uid, Some(4827943));
        assert_eq!(fetches[0].body(), None);
        assert_eq!(fetches[0].header(), None);
        assert_eq!(fetches[1].message, 25);
        assert_eq!(fetches[1].flags().collect::<Vec<_>>(), vec![Flag::Seen]);
        assert_eq!(fetches[1].uid, None);
        assert_eq!(fetches[1].body(), None);
        assert_eq!(fetches[1].header(), None);
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_fetches_w_unilateral() {
        // https://github.com/mattnenterprise/rust-imap/issues/81
        let (send, recv) = bounded(10);
        let responses = input_stream(&["* 37 FETCH (UID 74)\r\n", "* 1 RECENT\r\n"]);
        let mut stream = async_std::stream::from_iter(responses);
        let id = RequestId("A0001".into());
        let mut pending = None;

        let fetches = parse_fetches(&mut stream, &mut pending, send, id)
            .try_collect::<Vec<_>>()
            .await
            .unwrap();
        assert_eq!(recv.recv().await.unwrap(), UnsolicitedResponse::Recent(1));

        assert_eq!(fetches.len(), 1);
        assert_eq!(fetches[0].message, 37);
        assert_eq!(fetches[0].uid, Some(74));
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_names_w_unilateral() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[
            "* LIST (\\HasNoChildren) \".\" \"INBOX\"\r\n",
            "* 4 EXPUNGE\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0001".into());
        let mut pending = None;
        let names = parse_names(&mut stream, &mut pending, send, id)
            .try_collect::<Vec<_>>()
            .await
            .unwrap();

        assert_eq!(recv.recv().await.unwrap(), UnsolicitedResponse::Expunge(4));

        assert_eq!(names.len(), 1);
        assert_eq!(
            names[0].attributes(),
            &[NameAttribute::Extension("\\HasNoChildren".into())]
        );
        assert_eq!(names[0].delimiter(), Some("."));
        assert_eq!(names[0].name(), "INBOX");
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_capabilities_w_unilateral() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[
            "* CAPABILITY IMAP4rev1 STARTTLS AUTH=GSSAPI LOGINDISABLED\r\n",
            "* STATUS dev.github (MESSAGES 10 UIDNEXT 11 UIDVALIDITY 1408806928 UNSEEN 0)\r\n",
            "* 4 EXISTS\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);

        let expected_capabilities = &["IMAP4rev1", "STARTTLS", "AUTH=GSSAPI", "LOGINDISABLED"];

        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        let capabilities = parse_capabilities(&mut stream, &mut pending, send, id)
            .await
            .unwrap();

        assert_eq!(capabilities.len(), 4);
        for e in expected_capabilities {
            assert!(capabilities.has_str(e));
        }

        assert_eq!(
            recv.recv().await.unwrap(),
            UnsolicitedResponse::Status {
                mailbox: "dev.github".to_string(),
                attributes: vec![
                    StatusAttribute::Messages(10),
                    StatusAttribute::UidNext(11),
                    StatusAttribute::UidValidity(1408806928),
                    StatusAttribute::Unseen(0)
                ]
            }
        );
        assert_eq!(recv.recv().await.unwrap(), UnsolicitedResponse::Exists(4));
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_ids_w_unilateral() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[
            "* SEARCH 23 42 4711\r\n",
            "* 1 RECENT\r\n",
            "* STATUS INBOX (MESSAGES 10 UIDNEXT 11 UIDVALIDITY 1408806928 UNSEEN 0)\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        let ids = parse_ids(&mut stream, &mut pending, send, id)
            .await
            .unwrap();

        assert_eq!(ids, [23, 42, 4711].iter().cloned().collect());

        assert_eq!(recv.recv().await.unwrap(), UnsolicitedResponse::Recent(1));
        assert_eq!(
            recv.recv().await.unwrap(),
            UnsolicitedResponse::Status {
                mailbox: "INBOX".to_string(),
                attributes: vec![
                    StatusAttribute::Messages(10),
                    StatusAttribute::UidNext(11),
                    StatusAttribute::UidValidity(1408806928),
                    StatusAttribute::Unseen(0)
                ]
            }
        );
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_ids_test() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[
            "* SEARCH 1600 1698 1739 1781 1795 1885 1891 1892 1893 1898 1899 1901 1911 1926 1932 1933 1993 1994 2007 2032 2033 2041 2053 2062 2063 2065 2066 2072 2078 2079 2082 2084 2095 2100 2101 2102 2103 2104 2107 2116 2120 2135 2138 2154 2163 2168 2172 2189 2193 2198 2199 2205 2212 2213 2221 2227 2267 2275 2276 2295 2300 2328 2330 2332 2333 2334\r\n",
            "* SEARCH 2335 2336 2337 2338 2339 2341 2342 2347 2349 2350 2358 2359 2362 2369 2371 2372 2373 2374 2375 2376 2377 2378 2379 2380 2381 2382 2383 2384 2385 2386 2390 2392 2397 2400 2401 2403 2405 2409 2411 2414 2417 2419 2420 2424 2426 2428 2439 2454 2456 2467 2468 2469 2490 2515 2519 2520 2521\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        let ids = parse_ids(&mut stream, &mut pending, send, id)
            .await
            .unwrap();

        assert!(recv.is_empty());
        let ids: HashSet<u32> = ids.iter().cloned().collect();
        assert_eq!(
            ids,
            [
                1600, 1698, 1739, 1781, 1795, 1885, 1891, 1892, 1893, 1898, 1899, 1901, 1911, 1926,
                1932, 1933, 1993, 1994, 2007, 2032, 2033, 2041, 2053, 2062, 2063, 2065, 2066, 2072,
                2078, 2079, 2082, 2084, 2095, 2100, 2101, 2102, 2103, 2104, 2107, 2116, 2120, 2135,
                2138, 2154, 2163, 2168, 2172, 2189, 2193, 2198, 2199, 2205, 2212, 2213, 2221, 2227,
                2267, 2275, 2276, 2295, 2300, 2328, 2330, 2332, 2333, 2334, 2335, 2336, 2337, 2338,
                2339, 2341, 2342, 2347, 2349, 2350, 2358, 2359, 2362, 2369, 2371, 2372, 2373, 2374,
                2375, 2376, 2377, 2378, 2379, 2380, 2381, 2382, 2383, 2384, 2385, 2386, 2390, 2392,
                2397, 2400, 2401, 2403, 2405, 2409, 2411, 2414, 2417, 2419, 2420, 2424, 2426, 2428,
                2439, 2454, 2456, 2467, 2468, 2469, 2490, 2515, 2519, 2520, 2521
            ]
            .iter()
            .cloned()
            .collect()
        );
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_ids_search() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&["* SEARCH\r\n"]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0001".into());
        let mut pending = Some(id.clone());
        let ids = parse_ids(&mut stream, &mut pending, send, id)
            .await
            .unwrap();

        assert!(recv.is_empty());
        let ids: HashSet<u32> = ids.iter().cloned().collect();
        assert_eq!(ids, HashSet::<u32>::new());
    }

    #[cfg_attr(feature = "runtime-tokio", tokio::test)]
    #[cfg_attr(feature = "runtime-async-std", async_std::test)]
    async fn parse_mailbox_does_not_exist_error() {
        let (send, recv) = bounded(10);
        let responses = input_stream(&[
            "A0003 NO Mailbox doesn't exist: DeltaChat (0.001 + 0.140 + 0.139 secs).\r\n",
        ]);
        let mut stream = async_std::stream::from_iter(responses);

        let id = RequestId("A0003".into());
        let mut pending = Some(id.clone());
        let mailbox = parse_mailbox(&mut stream, &mut pending, send, id).await;
        assert!(recv.is_empty());

        assert!(matches!(mailbox, Err(Error::No(_))));
    }
}
