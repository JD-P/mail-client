use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ChangeCursor, ContactAddress, FolderKind,
    ImapFetchedMessage, ImapSecurity, ImapSettings, InboxClass, IngestMessage, MessageFilter,
    MessageSort, NewAccount, NewContact, NewFolder, RemoteMessageIdentity, SearchRequest,
    UserClassification,
};

fn message(subject: &str, body: &str) -> Vec<u8> {
    format!(
        concat!(
            "From: Abigail Marie <example.friend@example.com>\r\n",
            "To: Reader <reader@example.net>\r\n",
            "Delivered-To: archive@example.net\r\n",
            "List-ID: Project List <projects.example.org>\r\n",
            "Date: Sun, 15 Nov 2026 12:30:00 +0000\r\n",
            "Message-ID: <quarterly-17@example.com>\r\n",
            "Subject: {}\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=boundary42\r\n",
            "\r\n",
            "--boundary42\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "{}\r\n",
            "--boundary42\r\n",
            "Content-Type: application/pdf; name=roadmap.pdf\r\n",
            "Content-Disposition: attachment; filename=roadmap.pdf\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "JVBERi0xLjQK\r\n",
            "--boundary42--\r\n"
        ),
        subject, body
    )
    .into_bytes()
}

#[tokio::test]
async fn complete_local_backend_flow() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let mut live_events = backend.events().subscribe();

    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Personal".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("keyring:personal".into()),
            imap: Some(ImapSettings {
                host: "imap.example.com".into(),
                port: 993,
                username: "reader@example.net".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    assert_eq!(live_events.recv().await.unwrap().kind, "account_added");

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

    let raw = message("Quarterly roadmap", "The cobalt launch is on schedule.");
    let request = IngestMessage {
        raw: raw.clone(),
        remote: Some(RemoteMessageIdentity {
            account_id: account.id,
            folder_id: folder.id,
            uid_validity: 17,
            uid: 42,
            mod_sequence: Some(9),
            flags: vec!["\\Seen".into(), "\\Flagged".into()],
        }),
        received_at: Some(1_800_000_000),
        user_classification: None,
    };
    let id = backend.messages().ingest(request.clone()).await.unwrap();
    assert_eq!(backend.messages().ingest(request).await.unwrap(), id);
    let repeated = backend
        .sync()
        .ingest_imap_batch(
            account.id,
            folder.id,
            17,
            vec![ImapFetchedMessage {
                uid: 42,
                mod_sequence: Some(9),
                flags: vec!["\\Seen".into()],
                internal_date: Some(1_800_000_000),
                raw: raw.clone(),
            }],
        )
        .await
        .unwrap();
    assert_eq!(repeated.message_ids, vec![id]);
    assert_eq!(backend.messages().raw(id).await.unwrap(), raw);

    let stored = backend.messages().get(id).await.unwrap();
    assert_eq!(stored.summary.subject.as_deref(), Some("Quarterly roadmap"));
    assert_eq!(stored.summary.inbox_class, InboxClass::Cold);
    assert!(stored.summary.is_read);
    assert!(!stored.summary.is_starred);
    assert_eq!(stored.attachments[0].name.as_deref(), Some("roadmap.pdf"));
    assert_eq!(stored.instances[0].folder_id, folder.id);
    assert_eq!(stored.instances[0].flags, vec!["\\Seen"]);
    assert_eq!(stored.delivered_to_addresses, vec!["archive@example.net"]);
    assert_eq!(stored.list_id.as_deref(), Some("projects.example.org"));
    assert_eq!(stored.body_html, None);

    let cold = backend
        .messages()
        .list(MessageFilter {
            inbox_class: Some(InboxClass::Cold),
            ..MessageFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(cold.items.len(), 1);

    backend
        .contacts()
        .add(NewContact {
            display_name: "Abigail Marie".into(),
            addresses: vec![ContactAddress {
                address: "EXAMPLE.FRIEND@example.com".into(),
                accepted_name: Some("Abigail Marie".into()),
            }],
        })
        .await
        .unwrap();
    assert_eq!(
        backend
            .messages()
            .get(id)
            .await
            .unwrap()
            .summary
            .inbox_class,
        InboxClass::Warm
    );

    let project_folder = backend
        .folders()
        .add(NewFolder {
            account_id: None,
            name: "Projects".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();
    backend
        .messages()
        .add_to_local_folder(id, project_folder.id)
        .await
        .unwrap();
    assert_eq!(
        backend.messages().get(id).await.unwrap().local_folder_ids,
        vec![project_folder.id]
    );
    assert_eq!(
        backend
            .messages()
            .list(MessageFilter {
                folder_id: Some(project_folder.id),
                ..MessageFilter::default()
            })
            .await
            .unwrap()
            .items
            .len(),
        1
    );

    for query in [
        "cobalt",
        "subject:Quarterly",
        "from:example.friend@example.com",
        "deliveredto:archive@example.net",
        "list:projects.example.org",
        "has:attachment",
        "filename:roadmap.pdf",
        "in:Inbox",
        "in:Projects",
        "account:Personal",
        "is:warm",
        "-subject:missing",
        "-is:spam",
        "is:warm AND cobalt",
        "is:spam OR subject:Quarterly",
        "cobalt AND (subject:Quarterly OR subject:missing)",
    ] {
        let results = backend
            .search()
            .search(SearchRequest {
                query: query.into(),
                page_size: 20,
                cursor: None,
            })
            .await
            .unwrap_or_else(|error| panic!("query {query:?} failed: {error}"));
        assert_eq!(results.items.len(), 1, "query {query:?}");
    }

    backend
        .messages()
        .classify(id, Some(UserClassification::Spam))
        .await
        .unwrap();
    assert_eq!(
        backend
            .messages()
            .get(id)
            .await
            .unwrap()
            .summary
            .inbox_class,
        InboxClass::Spam
    );

    let changes = backend
        .events()
        .changes_since(ChangeCursor(0), 100)
        .await
        .unwrap();
    assert!(changes
        .windows(2)
        .all(|pair| pair[0].sequence < pair[1].sequence));
    assert!(changes.iter().any(|event| event.kind == "message_ingested"));
    assert!(changes
        .iter()
        .any(|event| event.kind == "message_remote_state_changed"));
}

#[tokio::test]
async fn keyset_pagination_is_stable() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    for (index, received_at) in [30, 20, 10].into_iter().enumerate() {
        let mut request = IngestMessage::local(message(&format!("Message {index}"), "body"));
        request.received_at = Some(received_at);
        backend.ingest(request).await.unwrap();
    }
    let first = backend
        .messages()
        .list(MessageFilter {
            page_size: 2,
            ..MessageFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(first.items.len(), 2);
    let second = backend
        .messages()
        .list(MessageFilter {
            page_size: 2,
            cursor: first.next_cursor,
            ..MessageFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());

    let oldest = backend
        .messages()
        .list(MessageFilter {
            sort: MessageSort::ReceivedOldest,
            page_size: 2,
            ..MessageFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(
        oldest
            .items
            .iter()
            .map(|message| message.received_at)
            .collect::<Vec<_>>(),
        vec![10, 20]
    );
}

#[tokio::test]
async fn full_text_search_is_exact_across_time_windows_and_pages() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    for (index, received_at) in [600, 800, 950, 1_000].into_iter().enumerate() {
        let body = if received_at == 600 {
            "common-term old-needle"
        } else {
            "common-term"
        };
        let mut request = IngestMessage::local(message(&format!("Window {index}"), body));
        request.received_at = Some(received_at);
        backend.ingest(request).await.unwrap();
    }

    let first = backend
        .search()
        .search(SearchRequest {
            query: "common-term".into(),
            page_size: 2,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(
        first
            .items
            .iter()
            .map(|message| message.received_at)
            .collect::<Vec<_>>(),
        vec![1_000, 950]
    );
    assert!(first.next_cursor.is_some());

    let second = backend
        .search()
        .search(SearchRequest {
            query: "common-term".into(),
            page_size: 2,
            cursor: first.next_cursor,
        })
        .await
        .unwrap();
    assert_eq!(
        second
            .items
            .iter()
            .map(|message| message.received_at)
            .collect::<Vec<_>>(),
        vec![800, 600]
    );
    assert!(second.next_cursor.is_none());

    let old = backend
        .search()
        .search(SearchRequest {
            query: "old-needle".into(),
            page_size: 20,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(old.items.len(), 1);
    assert_eq!(old.items[0].received_at, 600);

    let timestamp_is_not_user_text = backend
        .search()
        .search(SearchRequest {
            query: "1000".into(),
            page_size: 20,
            cursor: None,
        })
        .await
        .unwrap();
    assert!(timestamp_is_not_user_text.items.is_empty());
}

#[tokio::test]
async fn profile_reopens_without_losing_raw_or_indexed_state() {
    let profile = tempfile::tempdir().unwrap();
    let raw = message("Persistent message", "durable searchable phrase");
    let id = {
        let backend = Backend::open(BackendConfig::new(profile.path()))
            .await
            .unwrap();
        backend
            .ingest(IngestMessage::local(raw.clone()))
            .await
            .unwrap()
    };

    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    assert_eq!(reopened.messages().raw(id).await.unwrap(), raw);
    let results = reopened
        .search()
        .search(SearchRequest {
            query: "durable".into(),
            page_size: 10,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(results.items[0].id, id);
}
