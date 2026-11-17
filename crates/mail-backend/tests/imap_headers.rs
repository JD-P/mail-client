use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, BackendError, DkimAuthenticationStatus, FolderKind,
    ImapFetchedHeaders, ImapSecurity, ImapSettings, MessageContentAvailability, MessageFilter,
    NewAccount, NewFolder, SearchRequest,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Debug)]
struct StallingImap {
    input: Vec<u8>,
    offset: usize,
}

impl AsyncRead for StallingImap {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.offset == self.input.len() {
            return Poll::Pending;
        }
        let count = output.remaining().min(self.input.len() - self.offset);
        output.put_slice(&self.input[self.offset..self.offset + count]);
        self.offset += count;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for StallingImap {
    fn poll_write(
        self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn projected_headers() -> Vec<u8> {
    concat!(
        "From: Reports <reports@example.test>\r\n",
        "To: Reader <reader@example.test>\r\n",
        "Date: Mon, 16 Nov 2026 10:01:00 +0000\r\n",
        "Message-ID: <header-first@example.test>\r\n",
        "Subject: Header-first report\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=not-downloaded\r\n",
        "\r\n",
    )
    .as_bytes()
    .to_vec()
}

#[tokio::test]
async fn header_projection_is_searchable_but_never_claims_to_be_complete() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Header-only fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:headers".into()),
            imap: Some(ImapSettings {
                host: "mail.example.test".into(),
                port: 993,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let folder = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();
    let result = backend
        .sync()
        .ingest_imap_header_batch(
            account.id,
            folder.id,
            42,
            vec![ImapFetchedHeaders {
                uid: 7,
                mod_sequence: Some(9),
                flags: Vec::new(),
                internal_date: Some(1_795_000_000),
                size_bytes: 2_000_000,
                has_attachment: true,
                headers: projected_headers(),
            }],
        )
        .await
        .unwrap();
    let message_id = result.message_ids[0];

    let page = backend
        .messages()
        .list(MessageFilter::default())
        .await
        .unwrap();
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items[0].subject.as_deref(),
        Some("Header-first report")
    );
    assert!(page.items[0].has_attachment);
    assert_eq!(page.items[0].size_bytes, 2_000_000);
    assert_eq!(
        page.items[0].content_availability,
        MessageContentAvailability::HeadersOnly
    );

    let status = backend.messages().content_status(message_id).await.unwrap();
    assert_eq!(status.availability, MessageContentAvailability::HeadersOnly);
    assert_eq!(status.expected_bytes, 2_000_000);
    assert_eq!(status.downloaded_bytes, 0);
    assert!(status.last_error.is_none());

    let message = backend.messages().get(message_id).await.unwrap();
    assert!(message.body_text.is_empty());
    assert!(message.attachments.is_empty());
    assert_eq!(message.dkim.status, DkimAuthenticationStatus::NotEvaluated);
    assert!(matches!(
        backend.messages().raw(message_id).await,
        Err(BackendError::ContentUnavailable { .. })
    ));
    assert!(matches!(
        backend.mime().structure(message_id).await,
        Err(BackendError::ContentUnavailable { .. })
    ));
    let mut sink = tokio::io::sink();
    assert!(matches!(
        backend
            .mime()
            .stream_attachment(message_id, "attachment:0", &mut sink, 1024)
            .await,
        Err(BackendError::ContentUnavailable { .. })
    ));
    assert!(matches!(
        backend
            .mime()
            .stream_content_id(message_id, "cid:missing", &mut sink, 1024)
            .await,
        Err(BackendError::ContentUnavailable { .. })
    ));

    let search = backend
        .search()
        .search(SearchRequest {
            query: "subject:report".into(),
            page_size: 10,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(search.items.len(), 1);
    assert!(search.content_results_complete);
    let body_search = backend
        .search()
        .search(SearchRequest {
            query: "not-downloaded-body".into(),
            page_size: 10,
            cursor: None,
        })
        .await
        .unwrap();
    assert!(body_search.items.is_empty());
    assert!(!body_search.content_results_complete);
}

#[tokio::test]
async fn reopening_turns_an_interrupted_download_into_resumable_failure_state() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Interrupted fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:interrupted".into()),
            imap: Some(ImapSettings {
                host: "mail.example.test".into(),
                port: 993,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let folder = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();
    let message_id = backend
        .sync()
        .ingest_imap_header_batch(
            account.id,
            folder.id,
            42,
            vec![ImapFetchedHeaders {
                uid: 9,
                mod_sequence: None,
                flags: Vec::new(),
                internal_date: None,
                size_bytes: 1_000,
                has_attachment: false,
                headers: projected_headers(),
            }],
        )
        .await
        .unwrap()
        .message_ids[0];
    drop(backend);

    let database_path = profile.path().join("mail.db");
    let database = turso::Builder::new_local(database_path.to_str().unwrap())
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = database.connect().unwrap();
    connection
        .execute(
            "UPDATE messages SET content_availability = 'downloading', downloaded_bytes = ?1 WHERE id = ?2",
            (b"durable-prefix".len() as i64, message_id.to_string()),
        )
        .await
        .unwrap();
    drop(connection);
    drop(database);
    tokio::fs::write(
        profile
            .path()
            .join("downloads")
            .join(format!("{message_id}.part")),
        b"durable-prefix",
    )
    .await
    .unwrap();

    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let status = reopened
        .messages()
        .content_status(message_id)
        .await
        .unwrap();
    assert_eq!(status.availability, MessageContentAvailability::Failed);
    assert_eq!(status.downloaded_bytes, b"durable-prefix".len() as u64);
    assert!(status
        .last_error
        .as_deref()
        .unwrap()
        .contains("retry will resume"));
}

#[tokio::test]
async fn dropping_an_inflight_download_marks_it_resumable() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Cancellation fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:cancel".into()),
            imap: Some(ImapSettings {
                host: "mail.example.test".into(),
                port: 993,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let folder = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();
    let message_id = backend
        .sync()
        .ingest_imap_header_batch(
            account.id,
            folder.id,
            42,
            vec![ImapFetchedHeaders {
                uid: 9,
                mod_sequence: None,
                flags: Vec::new(),
                internal_date: None,
                size_bytes: 1_000,
                has_attachment: false,
                headers: projected_headers(),
            }],
        )
        .await
        .unwrap()
        .message_ids[0];

    let responses = concat!(
        "A0001 OK authenticated\r\n",
        "* FLAGS (\\Answered \\Flagged \\Deleted \\Seen \\Draft)\r\n",
        "* 1 EXISTS\r\n",
        "* OK [UIDVALIDITY 42] UIDs valid\r\n",
        "A0002 OK [READ-ONLY] selected\r\n",
        "* 1 FETCH (UID 9 RFC822.SIZE 1000)\r\n",
        "A0003 OK size\r\n",
    )
    .as_bytes()
    .to_vec();
    let client = async_imap::Client::new(StallingImap {
        input: responses,
        offset: 0,
    });
    let session = client.login("reader", "password").await.unwrap();
    let task = tokio::spawn({
        let backend = backend.clone();
        async move {
            let mut session = session;
            backend
                .sync()
                .fetch_imap_message_content(&mut session, account.id, message_id)
                .await
        }
    });

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            if backend
                .messages()
                .content_status(message_id)
                .await
                .unwrap()
                .availability
                == MessageContentAvailability::Downloading
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;

    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let status = backend.messages().content_status(message_id).await.unwrap();
            if status.availability == MessageContentAvailability::Failed {
                assert!(status.last_error.as_deref().unwrap().contains("cancelled"));
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
}
