use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, CompositionKind, ContactAddress, ImapSecurity,
    ImapSettings, IngestMessage, NewAccount, NewContact, ReplyAudience, ThreadFilter,
    ThreadSenderTrust, ThreadingSource,
};

fn message(
    from: &str,
    to: &str,
    cc: Option<&str>,
    message_id: &str,
    subject: &str,
    threading_headers: &str,
) -> Vec<u8> {
    format!(
        "From: {from}\r\nTo: {to}\r\n{}Message-ID: <{message_id}>\r\nSubject: {subject}\r\n{threading_headers}\r\nBody for {message_id}\r\n",
        cc.map(|value| format!("Cc: {value}\r\n"))
            .unwrap_or_default()
    )
    .into_bytes()
}

#[tokio::test]
async fn threads_headers_subjects_and_composition_without_crossing_trust() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add(NewAccount {
            name: "Personal".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test:personal".into()),
            imap: Some(ImapSettings {
                host: "imap.example.net".into(),
                port: 993,
                username: "reader@example.net".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let contact = backend
        .contacts()
        .add(NewContact {
            display_name: "Abigail".into(),
            addresses: vec![ContactAddress {
                address: "friend@example.com".into(),
                accepted_name: Some("Abigail".into()),
            }],
        })
        .await
        .unwrap();

    let root = backend
        .ingest(IngestMessage::local(message(
            "Abigail <friend@example.com>",
            "Reader <reader@example.net>",
            Some("Team <team@example.org>"),
            "root@EXAMPLE.COM",
            "Project launch",
            "",
        )))
        .await
        .unwrap();
    let reply = backend
        .ingest(IngestMessage::local(message(
            "Abigail <friend@example.com>",
            "Reader <reader@example.net>",
            Some("Team <team@example.org>"),
            "reply@example.com",
            "Re: Project launch",
            "In-Reply-To: <root@example.com>\r\nReferences: <root@example.com>\r\n",
        )))
        .await
        .unwrap();
    let subject_fallback = backend
        .ingest(IngestMessage::local(message(
            "Abigail <friend@example.com>",
            "Reader <reader@example.net>",
            None,
            "fallback@example.com",
            "Re[2]: Project launch",
            "",
        )))
        .await
        .unwrap();
    let injected = backend
        .ingest(IngestMessage::local(message(
            "Mallory <mallory@evil.example>",
            "Reader <reader@example.net>",
            None,
            "injected@evil.example",
            "Re: Project launch",
            "In-Reply-To: <root@example.com>\r\nReferences: <root@example.com>\r\n",
        )))
        .await
        .unwrap();

    let root_message = backend.messages().get(root).await.unwrap();
    let reply_message = backend.messages().get(reply).await.unwrap();
    let fallback_message = backend.messages().get(subject_fallback).await.unwrap();
    let injected_message = backend.messages().get(injected).await.unwrap();
    assert_eq!(
        root_message.rfc_message_id.as_deref(),
        Some("root@EXAMPLE.COM")
    );
    assert_eq!(
        root_message.summary.thread_id,
        reply_message.summary.thread_id
    );
    assert_eq!(
        root_message.summary.thread_id,
        fallback_message.summary.thread_id
    );
    assert_ne!(
        root_message.summary.thread_id,
        injected_message.summary.thread_id
    );
    assert_eq!(reply_message.threading.parent_message_id, Some(root));
    assert_eq!(reply_message.threading.source, ThreadingSource::References);
    assert_eq!(
        fallback_message.threading.source,
        ThreadingSource::NormalizedSubject
    );
    assert_eq!(
        root_message.threading.sender_trust,
        ThreadSenderTrust::Known
    );
    assert_eq!(
        injected_message.threading.sender_trust,
        ThreadSenderTrust::Unknown
    );
    assert_eq!(reply_message.references, vec!["root@example.com"]);

    let thread = backend
        .threads()
        .get(root_message.summary.thread_id)
        .await
        .unwrap();
    assert_eq!(thread.summary.message_count, 3);
    assert_eq!(thread.messages.len(), 3);
    let listed = backend
        .threads()
        .list(ThreadFilter::default())
        .await
        .unwrap();
    assert_eq!(listed.items.len(), 2);
    let first_page = backend
        .threads()
        .list(ThreadFilter {
            page_size: 1,
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    let second_page = backend
        .threads()
        .list(ThreadFilter {
            page_size: 1,
            cursor: first_page.next_cursor.clone(),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert_ne!(first_page.items[0].id, second_page.items[0].id);
    assert!(second_page.next_cursor.is_none());

    let composition = backend
        .threads()
        .reply(reply, ReplyAudience::All)
        .await
        .unwrap();
    assert_eq!(composition.kind, CompositionKind::Reply);
    assert_eq!(composition.thread_id, root_message.summary.thread_id);
    assert_eq!(composition.to_addresses, vec!["friend@example.com"]);
    assert_eq!(composition.cc_addresses, vec!["team@example.org"]);
    assert_eq!(composition.subject, "Re: Project launch");
    assert_eq!(
        composition.in_reply_to.as_deref(),
        Some("reply@example.com")
    );
    assert_eq!(
        composition.references,
        vec!["root@example.com", "reply@example.com"]
    );

    let forward = backend.threads().forward(reply).await.unwrap();
    assert_eq!(forward.kind, CompositionKind::Forward);
    assert_ne!(forward.thread_id, root_message.summary.thread_id);
    assert_eq!(forward.subject, "Fwd: Project launch");
    assert_eq!(forward.in_reply_to, None);
    assert!(forward.references.is_empty());
    assert_eq!(forward.attached_message_id, Some(reply));
    assert_eq!(
        forward.attached_media_type.as_deref(),
        Some("message/rfc822")
    );

    let stable_thread_id = root_message.summary.thread_id;
    backend.contacts().remove(contact.id).await.unwrap();
    assert_eq!(
        backend
            .messages()
            .get(root)
            .await
            .unwrap()
            .summary
            .thread_id,
        stable_thread_id
    );
    let now_unknown = backend
        .ingest(IngestMessage::local(message(
            "Abigail <friend@example.com>",
            "Reader <reader@example.net>",
            None,
            "after-removal@example.com",
            "Re: Project launch",
            "References: <root@example.com>\r\n",
        )))
        .await
        .unwrap();
    assert_ne!(
        backend
            .messages()
            .get(now_unknown)
            .await
            .unwrap()
            .summary
            .thread_id,
        stable_thread_id
    );
    drop(backend);
    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    assert_eq!(
        reopened
            .messages()
            .get(root)
            .await
            .unwrap()
            .summary
            .thread_id,
        stable_thread_id
    );
}

#[tokio::test]
async fn thread_summary_author_is_the_latest_from_not_an_arbitrary_participant() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let id = backend
        .ingest(IngestMessage::local(
            concat!(
                "From: Actual Author <z-author@example.test>\r\n",
                "To: a-recipient@example.test\r\n",
                "Cc: aa-copy@example.test\r\n",
                "Reply-To: aaa-spoofed-contact@example.test\r\n",
                "Delivered-To: reader@example.test\r\n",
                "Message-ID: <author-projection@example.test>\r\n",
                "Subject: Author projection\r\n\r\n",
                "The queue must identify the From mailbox.\r\n"
            )
            .as_bytes(),
        ))
        .await
        .unwrap();
    let message = backend.messages().get(id).await.unwrap();
    let summary = backend
        .threads()
        .get(message.summary.thread_id)
        .await
        .unwrap()
        .summary;

    assert_eq!(
        summary.latest_from_address.as_deref(),
        Some("z-author@example.test")
    );
    assert_eq!(summary.latest_from_name.as_deref(), Some("Actual Author"));
    assert!(summary
        .participants
        .iter()
        .any(|address| address == "aaa-spoofed-contact@example.test"));
    assert_ne!(
        summary.latest_from_address.as_deref(),
        summary.participants.first().map(String::as_str)
    );
}

#[tokio::test]
async fn becoming_known_continues_but_does_not_upgrade_a_cold_thread() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let root = backend
        .ingest(IngestMessage::local(message(
            "Later contact <later@example.com>",
            "reader@example.net",
            None,
            "cold-root@example.com",
            "Import ordering",
            "",
        )))
        .await
        .unwrap();
    let cold_thread = backend
        .messages()
        .get(root)
        .await
        .unwrap()
        .summary
        .thread_id;
    backend
        .contacts()
        .add(NewContact {
            display_name: "Later contact".into(),
            addresses: vec![ContactAddress {
                address: "later@example.com".into(),
                accepted_name: None,
            }],
        })
        .await
        .unwrap();
    let reply = backend
        .ingest(IngestMessage::local(message(
            "Later contact <later@example.com>",
            "reader@example.net",
            None,
            "known-reply@example.com",
            "Re: Import ordering",
            "References: <cold-root@example.com>\r\n",
        )))
        .await
        .unwrap();
    let reply_message = backend.messages().get(reply).await.unwrap();
    assert_eq!(reply_message.summary.thread_id, cold_thread);
    assert_eq!(
        reply_message.threading.sender_trust,
        ThreadSenderTrust::Known
    );
    assert_eq!(
        backend
            .threads()
            .get(cold_thread)
            .await
            .unwrap()
            .summary
            .sender_trust,
        ThreadSenderTrust::Unknown
    );
}

#[tokio::test]
async fn late_roots_use_the_preexisting_deterministic_thread() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .contacts()
        .add(NewContact {
            display_name: "Known".into(),
            addresses: vec![ContactAddress {
                address: "known@example.com".into(),
                accepted_name: None,
            }],
        })
        .await
        .unwrap();
    let child = backend
        .ingest(IngestMessage::local(message(
            "Known <known@example.com>",
            "reader@example.net",
            None,
            "child@example.com",
            "Re: Delayed root",
            "References: <late-root@example.com>\r\n",
        )))
        .await
        .unwrap();
    let before = backend
        .messages()
        .get(child)
        .await
        .unwrap()
        .summary
        .thread_id;
    let root = backend
        .ingest(IngestMessage::local(message(
            "Known <known@example.com>",
            "reader@example.net",
            None,
            "late-root@example.com",
            "Delayed root",
            "",
        )))
        .await
        .unwrap();
    assert_eq!(
        backend
            .messages()
            .get(root)
            .await
            .unwrap()
            .summary
            .thread_id,
        before
    );
}

#[tokio::test]
async fn subject_fallback_refuses_ambiguous_same_sender_threads() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let first = backend
        .ingest(IngestMessage::local(message(
            "Sender <sender@example.com>",
            "reader@example.net",
            None,
            "first@example.com",
            "Same subject",
            "References: <unseen-root-one@example.com>\r\n",
        )))
        .await
        .unwrap();
    let second = backend
        .ingest(IngestMessage::local(message(
            "Sender <sender@example.com>",
            "reader@example.net",
            None,
            "second@example.com",
            "Same subject",
            "References: <unseen-root-two@example.com>\r\n",
        )))
        .await
        .unwrap();
    let fallback = backend
        .ingest(IngestMessage::local(message(
            "Sender <sender@example.com>",
            "reader@example.net",
            None,
            "fallback@example.com",
            "Re: Same subject",
            "",
        )))
        .await
        .unwrap();
    let first_thread = backend
        .messages()
        .get(first)
        .await
        .unwrap()
        .summary
        .thread_id;
    let second_thread = backend
        .messages()
        .get(second)
        .await
        .unwrap()
        .summary
        .thread_id;
    let fallback_message = backend.messages().get(fallback).await.unwrap();
    assert_ne!(first_thread, second_thread);
    assert_ne!(fallback_message.summary.thread_id, first_thread);
    assert_ne!(fallback_message.summary.thread_id, second_thread);
    assert_eq!(fallback_message.threading.source, ThreadingSource::Root);
}

#[tokio::test]
async fn version_seven_profiles_rebuild_thread_projection_from_raw_messages() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let id = backend
        .ingest(IngestMessage::local(message(
            "Sender <sender@example.com>",
            "reader@example.net",
            None,
            "migration@example.com",
            "Migration thread",
            "In-Reply-To: <parent@example.com>\r\nReferences: <root@example.com> <parent@example.com>\r\n",
        )))
        .await
        .unwrap();
    drop(backend);

    let database_path = profile.path().join("mail.db");
    let database = turso::Builder::new_local(database_path.to_str().unwrap())
        .experimental_index_method(true)
        .build()
        .await
        .unwrap();
    let connection = database.connect().unwrap();
    connection
        .execute_batch(
            "PRAGMA foreign_keys = ON;
             UPDATE messages SET thread_message_id = NULL, thread_id = NULL, parent_message_id = NULL,
                threading_source = NULL, sender_trust = NULL,
                normalized_subject = NULL, in_reply_to_json = '[]',
                references_json = '[]', reply_to_addresses = '[]';
             DELETE FROM thread_participants;
             DELETE FROM threads;
             UPDATE schema_meta SET version = 7;",
        )
        .await
        .unwrap();
    drop(connection);
    drop(database);

    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let rebuilt = reopened.messages().get(id).await.unwrap();
    assert_eq!(rebuilt.in_reply_to, vec!["parent@example.com"]);
    assert_eq!(
        rebuilt.references,
        vec!["root@example.com", "parent@example.com"]
    );
    assert_eq!(rebuilt.threading.source, ThreadingSource::References);
}
