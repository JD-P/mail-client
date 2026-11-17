#![cfg(feature = "runtime-tokio")]
//! Local review probes for the published 0.12.0 implementation.
use async_imap::{Authenticator, Client, Session};
use futures_util::TryStreamExt;
use std::{
    io,
    pin::Pin,
    sync::{Arc, Mutex, Once},
    task::{Context, Poll},
    time::Duration,
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct Wire {
    input: Vec<u8>,
    offset: usize,
    written: Arc<Mutex<Vec<u8>>>,
    chunk: usize,
    stay_open: bool,
}
impl Wire {
    fn new(data: &[u8]) -> Self {
        Self {
            input: data.to_vec(),
            offset: 0,
            written: Arc::default(),
            chunk: usize::MAX,
            stay_open: false,
        }
    }
}
impl AsyncRead for Wire {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.input.len() {
            return if self.stay_open {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            };
        }
        let n = out
            .remaining()
            .min(self.input.len() - self.offset)
            .min(self.chunk);
        out.put_slice(&self.input[self.offset..self.offset + n]);
        self.offset += n;
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for Wire {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.written.lock().unwrap().extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
async fn session_with_wire(mut wire: Wire) -> Session<Wire> {
    let mut input = b"A0001 OK authenticated\r\n".to_vec();
    input.extend_from_slice(&wire.input);
    wire.input = input;
    Client::new(wire)
        .login("review-user", "dummy-review-password")
        .await
        .unwrap()
}
async fn session(data: &[u8]) -> Session<Wire> {
    session_with_wire(Wire::new(data)).await
}

struct CaptureLogger;
static LOGGER: CaptureLogger = CaptureLogger;
static LOGS: Mutex<Vec<String>> = Mutex::new(Vec::new());
static INIT: Once = Once::new();
impl log::Log for CaptureLogger {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, r: &log::Record<'_>) {
        LOGS.lock().unwrap().push(r.args().to_string());
    }
    fn flush(&self) {}
}
fn trace() {
    INIT.call_once(|| log::set_logger(&LOGGER).unwrap());
    log::set_max_level(log::LevelFilter::Trace);
    LOGS.lock().unwrap().clear();
}

#[tokio::test]
async fn review_fetch_rejection_is_an_error() {
    let mut s = session(b"A0002 NO [NOPERM] Access denied\r\n").await;
    let result = s
        .uid_fetch("1", "(UID FLAGS)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await;
    assert!(
        result.is_err(),
        "FETCH rejection was reported as successful: {result:?}"
    );
}

#[tokio::test]
async fn review_search_rejection_is_an_error() {
    let mut s = session(b"A0002 BAD Unsupported search\r\n").await;
    let result = s.uid_search("ALL").await;
    assert!(
        result.is_err(),
        "SEARCH rejection was reported as successful: {result:?}"
    );
}

#[tokio::test]
async fn review_store_rejection_is_an_error() {
    let mut s = session(b"A0002 NO [NOPERM] Read only\r\n").await;
    let result = s
        .uid_store("1", "+FLAGS.SILENT (\\Seen)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await;
    assert!(
        result.is_err(),
        "STORE rejection was reported as successful: {result:?}"
    );
}

#[tokio::test]
async fn review_select_eof_requires_completion() {
    let mut s = session(b"* 4 EXISTS\r\n").await;
    let result = s.select("INBOX").await;
    assert!(
        result.is_err(),
        "SELECT returned a mailbox without tagged completion: {result:?}"
    );
}

#[tokio::test]
async fn review_fetch_eof_requires_completion() {
    let mut s = session(b"* 1 FETCH (UID 42 FLAGS ())\r\n").await;
    let result = s
        .uid_fetch("42", "(UID FLAGS)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await;
    assert!(
        result.is_err(),
        "FETCH returned success after connection closed before completion: {result:?}"
    );
}

#[tokio::test]
async fn review_login_password_is_redacted_from_trace() {
    trace();
    let _ = session(b"").await;
    assert!(
        !LOGS
            .lock()
            .unwrap()
            .iter()
            .any(|s| s.contains("dummy-review-password")),
        "LOGIN password appeared in TRACE"
    );
}

struct OAuth;
impl Authenticator for OAuth {
    type Response = &'static [u8];
    fn process(&mut self, _: &[u8]) -> Self::Response {
        b"user=review@example.invalid\x01auth=Bearer dummy-review-token\x01\x01"
    }
}
#[tokio::test]
async fn review_oauth_secret_is_redacted_from_trace() {
    use base64::Engine;
    trace();
    let c = Client::new(Wire::new(b"+ \r\nA0001 OK authenticated\r\n"));
    let _ = c.authenticate("XOAUTH2", OAuth).await.unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(OAuth.process(b""));
    assert!(
        !LOGS.lock().unwrap().iter().any(|s| s.contains(&encoded)),
        "base64-encoded bearer credential appeared in TRACE"
    );
}

#[tokio::test]
async fn review_idle_rejection_without_information_does_not_panic() {
    let s = session(b"A0002 BAD \r\n").await;
    let mut idle = s.idle();
    assert!(idle.init().await.is_err());
}

#[tokio::test]
async fn review_idle_no_rejection_returns_without_waiting_for_more_data() {
    let mut wire = Wire::new(b"A0002 NO IDLE disabled\r\n");
    wire.stay_open = true;
    let s = session_with_wire(wire).await;
    let mut idle = s.idle();
    let result = tokio::time::timeout(Duration::from_millis(40), idle.init()).await;
    assert!(
        matches!(result, Ok(Err(_))),
        "tagged NO did not finish IDLE initialization: {result:?}"
    );
}

#[tokio::test]
async fn review_idle_eof_is_not_manual_interrupt() {
    let s = session(b"+ idling\r\n").await;
    let mut idle = s.idle();
    idle.init().await.unwrap();
    let (wait, _stop) = idle.wait();
    let result = wait.await;
    assert!(
        result.is_err(),
        "EOF was reported as a successful IDLE outcome: {result:?}"
    );
}

#[tokio::test]
async fn review_append_accepts_unsolicited_response_before_continuation() {
    let mut s = session(b"* 1 EXISTS\r\n+ send literal\r\nA0002 OK appended\r\n").await;
    let result = s
        .append("INBOX", None, None, b"Subject: test\r\n\r\nbody\r\n")
        .await;
    assert!(
        result.is_ok(),
        "legal untagged update broke APPEND: {result:?}"
    );
}

#[tokio::test]
async fn review_dropped_fetch_does_not_contaminate_next_fetch() {
    let mut s = session(b"* 1 FETCH (UID 11 FLAGS ())\r\n* 2 FETCH (UID 12 FLAGS ())\r\nA0002 OK first fetch\r\n* 3 FETCH (UID 13 FLAGS ())\r\nA0003 OK second fetch\r\n").await;
    {
        let mut first = s.uid_fetch("11:12", "(UID FLAGS)").await.unwrap();
        assert_eq!(first.try_next().await.unwrap().unwrap().uid, Some(11));
    }
    let second = s
        .uid_fetch("13", "(UID FLAGS)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    let ids: Vec<_> = second.iter().map(|f| f.uid).collect();
    assert_eq!(
        ids,
        vec![Some(13)],
        "response from dropped operation leaked into next fetch"
    );
}

#[tokio::test]
async fn review_cancelled_collected_command_is_drained_before_next_command() {
    let mut wire = Wire::new(b"");
    wire.stay_open = true;
    let mut session = session_with_wire(wire).await;

    let cancelled =
        tokio::time::timeout(Duration::from_millis(20), session.uid_search("ALL")).await;
    assert!(cancelled.is_err(), "first SEARCH unexpectedly completed");

    session.get_mut().input.extend_from_slice(
        b"A0002 OK cancelled search drained\r\n* SEARCH 9\r\nA0003 OK next search\r\n",
    );
    session.get_mut().stay_open = false;

    let ids = session.uid_search("ALL").await.unwrap();
    assert_eq!(ids, [9].into_iter().collect());
}

#[tokio::test]
async fn control_login_rejects_crlf() {
    let wire = Wire::new(b"");
    let written = wire.written.clone();
    assert!(
        Client::new(wire)
            .login("user\r\nA9 LOGOUT", "password")
            .await
            .is_err()
    );
    assert!(written.lock().unwrap().is_empty());
}

#[tokio::test]
async fn review_id_values_reject_crlf() {
    let mut s = session(b"A0002 OK identity received\r\n").await;
    let result = s.id([("name", Some("client\r\nZ9 LOGOUT\r\n"))]).await;
    let written = s.get_ref().written.lock().unwrap();
    assert!(
        result.is_err()
            && !written
                .windows(b"Z9 LOGOUT".len())
                .any(|w| w == b"Z9 LOGOUT"),
        "unvalidated ID value reached the wire: {}",
        String::from_utf8_lossy(&written)
    );
}

#[tokio::test]
async fn control_binary_fetch_one_byte_at_a_time() {
    trace();
    let body = b"Subject: bytes\r\n\r\n\xff\x00\r\n";
    let mut bytes = format!("* 1 FETCH (UID 42 BODY[] {{{}}}\r\n", body.len()).into_bytes();
    bytes.extend_from_slice(body);
    bytes.extend_from_slice(b")\r\nA0002 OK fetched\r\n");
    let mut wire = Wire::new(&bytes);
    wire.chunk = 1;
    let mut s = session_with_wire(wire).await;
    let rows = s
        .uid_fetch("42", "(UID BODY.PEEK[])")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].body(), Some(body.as_slice()));
}

#[tokio::test]
async fn review_uid_body_download_streams_bounded_partial_fetches() {
    let responses = b"* 1 FETCH (UID 42 RFC822.SIZE 5)\r\nA0002 OK size\r\n\
* 1 FETCH (UID 42 BODY[]<0> {3}\r\nabc)\r\nA0003 OK first chunk\r\n\
* 1 FETCH (UID 42 BODY[]<3> {2}\r\nde)\r\nA0004 OK second chunk\r\n";
    let mut session = session(responses).await;
    let mut destination = Wire::new(b"");
    let downloaded = session
        .uid_fetch_body_to(42, &mut destination, 3)
        .await
        .unwrap();

    assert_eq!(downloaded, 5);
    assert_eq!(&*destination.written.lock().unwrap(), b"abcde");
    let commands = session.get_ref().written.lock().unwrap();
    let commands = String::from_utf8_lossy(&commands);
    assert!(commands.contains("UID FETCH 42 (UID BODY.PEEK[]<0.3>)"));
    assert!(commands.contains("UID FETCH 42 (UID BODY.PEEK[]<3.2>)"));
}

#[tokio::test]
async fn review_uid_body_download_resumes_at_durable_offset() {
    let responses = b"* 1 FETCH (UID 42 RFC822.SIZE 5)\r\nA0002 OK size\r\n\
* 1 FETCH (UID 42 BODY[]<3> {2}\r\n\
de)\r\nA0003 OK resumed chunk\r\n";
    let mut session = session(responses).await;
    let mut destination = Wire::new(b"");
    let downloaded = session
        .uid_fetch_body_to_from(42, &mut destination, 3, 3)
        .await
        .unwrap();

    assert_eq!(downloaded, 5);
    assert_eq!(&*destination.written.lock().unwrap(), b"de");
    let commands = session.get_ref().written.lock().unwrap();
    let commands = String::from_utf8_lossy(&commands);
    assert!(commands.contains("UID FETCH 42 (UID BODY.PEEK[]<3.2>)"));
    assert!(!commands.contains("BODY.PEEK[]<0."));
}

#[tokio::test]
async fn review_unsolicited_queue_reports_overflow() {
    let mut response = b"* 1 EXISTS\r\n".repeat(101);
    response.extend_from_slice(b"A0002 OK noop\r\n");
    let mut s = session(&response).await;
    s.noop().await.unwrap();
    assert_eq!(s.unsolicited_responses.len(), 100);
    let queued: Vec<_> = std::iter::from_fn(|| s.unsolicited_responses.try_recv().ok()).collect();
    assert!(queued.contains(&async_imap::types::UnsolicitedResponse::Overflow));
}

#[tokio::test]
async fn review_advertised_literal_does_not_cause_eager_allocation() {
    let mut wire = Wire::new(b"* 1 FETCH (BODY[] {8388608}\r\n");
    wire.stay_open = true;
    let mut c = Client::new(wire);
    let timeout = tokio::time::timeout(Duration::from_millis(30), c.read_response()).await;
    assert!(timeout.is_err());
    let state = format!("{c:?}");
    assert!(
        state.contains("capacity: 4096"),
        "literal was allocated eagerly: {state}"
    );
}

#[tokio::test]
async fn review_advertised_literal_over_limit_is_rejected() {
    let mut c = Client::new(Wire::new(b"* 1 FETCH (BODY[] {8388608}\r\n"));
    c.set_max_response_size(1024).unwrap();
    let result = c.read_response().await;
    assert!(
        result.is_err(),
        "oversized literal was accepted: {result:?}"
    );
}

#[tokio::test]
async fn review_excessive_response_nesting_is_rejected_before_parsing() {
    let mut response = b"* 1 FETCH (BODYSTRUCTURE ".to_vec();
    response.extend(std::iter::repeat_n(b'(', 129));
    let mut c = Client::new(Wire::new(&response));
    let result = c.read_response().await;
    assert!(
        result.is_err(),
        "excessive nesting was accepted: {result:?}"
    );
}
