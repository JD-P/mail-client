use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, FolderKind, ImapSecurity, ImapSettings, NewAccount,
    NewFolder, SearchRequest,
};
mod support;
use support::dovecot::DovecotContainer;

fn plain_message(id: &str, subject: &str, body: &str) -> Vec<u8> {
    format!(
        concat!(
            "From: Sender <sender@example.test>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Date: Mon, 16 Nov 2026 10:00:00 +0000\r\n",
            "Message-ID: <{}@example.test>\r\n",
            "Subject: {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "{}\r\n"
        ),
        id, subject, body
    )
    .into_bytes()
}

fn multipart_message() -> Vec<u8> {
    concat!(
        "From: Reports <reports@example.test>\r\n",
        "To: Reader <reader@example.test>\r\n",
        "Date: Mon, 16 Nov 2026 10:01:00 +0000\r\n",
        "Message-ID: <dovecot-multipart@example.test>\r\n",
        "Subject: Dovecot multipart report\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=fixture-boundary\r\n",
        "\r\n",
        "--fixture-boundary\r\n",
        "Content-Type: text/html; charset=utf-8\r\n",
        "\r\n",
        "<p>The amber narwhal report is attached.</p>\r\n",
        "--fixture-boundary\r\n",
        "Content-Type: text/plain; name=report.txt\r\n",
        "Content-Disposition: attachment; filename=report.txt\r\n",
        "\r\n",
        "fixture attachment\r\n",
        "--fixture-boundary--\r\n"
    )
    .as_bytes()
    .to_vec()
}

fn reply_message() -> Vec<u8> {
    concat!(
        "From: Sender <sender@example.test>\r\n",
        "To: Reader <reader@example.test>\r\n",
        "Date: Mon, 16 Nov 2026 10:02:00 +0000\r\n",
        "Message-ID: <dovecot-four@example.test>\r\n",
        "In-Reply-To: <dovecot-one@example.test>\r\n",
        "References: <dovecot-one@example.test>\r\n",
        "Subject: Re: Dovecot alpha\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "silver astrolabe\r\n"
    )
    .as_bytes()
    .to_vec()
}

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn pulls_real_mail_from_dovecot_incrementally() {
    let dovecot = DovecotContainer::start().await;
    let mut session = dovecot.login().await;

    // Cross the backend's 1 MiB IMAP body-chunk boundary and compare the exact
    // RFC bytes after multiple partial FETCH responses have been reassembled.
    let first_body = format!(
        "cobalt telescope\r\n{}",
        "0123456789abcdef\r\n".repeat(65_000)
    );
    let first_raw = plain_message("dovecot-one", "Dovecot alpha", &first_body);
    let second_raw = multipart_message();
    let third_raw = plain_message("dovecot-three", "Dovecot seen", "violet sextant");
    session
        .append("INBOX", None, None, &first_raw)
        .await
        .unwrap();
    session
        .append("INBOX", None, None, &second_raw)
        .await
        .unwrap();
    session
        .append("INBOX", Some("(\\Seen)"), None, &third_raw)
        .await
        .unwrap();

    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:dovecot".into()),
            imap: Some(ImapSettings {
                host: "127.0.0.1".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();
    let inbox = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();

    // The production API takes an already authenticated, TLS-protected session.
    // This fixture uses plaintext only across the Docker loopback port.
    let first_sync = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert_eq!(first_sync.message_ids.len(), 3);
    assert_eq!(
        backend
            .messages()
            .raw(first_sync.message_ids[0])
            .await
            .unwrap(),
        first_raw
    );
    assert!(
        !backend
            .messages()
            .get(first_sync.message_ids[0])
            .await
            .unwrap()
            .summary
            .is_read,
        "BODY.PEEK sync must not add the Seen flag"
    );
    assert!(
        backend
            .messages()
            .get(first_sync.message_ids[2])
            .await
            .unwrap()
            .summary
            .is_read
    );
    assert_eq!(search_count(&backend, "amber narwhal").await, 1);
    assert_eq!(search_count(&backend, "has:attachment").await, 1);

    let no_changes = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert!(no_changes.message_ids.is_empty());

    let fourth_raw = reply_message();
    session
        .append("INBOX", None, None, &fourth_raw)
        .await
        .unwrap();
    let incremental = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert_eq!(incremental.message_ids.len(), 1);
    assert_eq!(
        backend
            .messages()
            .get(first_sync.message_ids[0])
            .await
            .unwrap()
            .summary
            .thread_id,
        backend
            .messages()
            .get(incremental.message_ids[0])
            .await
            .unwrap()
            .summary
            .thread_id
    );
    assert_eq!(search_count(&backend, "silver astrolabe").await, 1);
    assert_eq!(search_count(&backend, "in:Inbox").await, 4);

    session.logout().await.unwrap();
}

async fn search_count(backend: &Backend, query: &str) -> usize {
    backend
        .search()
        .search(SearchRequest {
            query: query.into(),
            page_size: 100,
            cursor: None,
        })
        .await
        .unwrap()
        .items
        .len()
}
