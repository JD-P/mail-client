//! Adds support for the GETQUOTA and GETQUOTAROOT commands specificed in [RFC2087](https://tools.ietf.org/html/rfc2087).

use futures_util::{Stream, io};
use imap_proto::{self, RequestId, Response};

use crate::types::*;
use crate::{
    error::Result,
    parse::{handle_unilateral, next_command_response},
};
use crate::{
    error::{Error, ParseError},
    types::{Quota, QuotaRoot, ResponseData},
};

pub(crate) async fn parse_get_quota<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<Quota> {
    let mut quota = None;
    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::Quota(q) => quota = Some(q.clone().into()),
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }

    match quota {
        Some(q) => Ok(q),
        None => Err(Error::Parse(ParseError::ExpectedResponseNotFound(
            "Quota, no quota response found".to_string(),
        ))),
    }
}

pub(crate) async fn parse_get_quota_root<T: Stream<Item = io::Result<ResponseData>> + Unpin>(
    stream: &mut T,
    pending_command: &mut Option<RequestId>,
    unsolicited: UnsolicitedSender,
    command_tag: RequestId,
) -> Result<(Vec<QuotaRoot>, Vec<Quota>)> {
    let mut roots: Vec<QuotaRoot> = Vec::new();
    let mut quotas: Vec<Quota> = Vec::new();

    loop {
        let Some(resp) = next_command_response(stream, pending_command, &command_tag).await? else {
            break;
        };
        match resp.parsed() {
            Response::QuotaRoot(qr) => {
                roots.push(qr.clone().into());
            }
            Response::Quota(q) => {
                quotas.push(q.clone().into());
            }
            _ => {
                handle_unilateral(resp, unsolicited.clone());
            }
        }
    }

    Ok((roots, quotas))
}
