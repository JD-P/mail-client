use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, FolderKind, ImapMutationOperation, ImapMutationStatus,
    ImapSecurity, ImapSettings, IngestMessage, NewAccount, NewFolder, RemoteMessageIdentity,
};

fn message() -> Vec<u8> {
    b"From: sender@example.test\r\nTo: reader@example.test\r\nSubject: mutation queue\r\n\r\nbody\r\n"
        .to_vec()
}

#[tokio::test]
async fn coalesces_offline_flag_edits_and_cancel_restores_server_snapshot() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Mutation test".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test:mutation".into()),
            imap: Some(ImapSettings {
                host: "imap.example.test".into(),
                port: 993,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
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
    let message_id = backend
        .messages()
        .ingest(IngestMessage {
            raw: message(),
            remote: Some(RemoteMessageIdentity {
                account_id: account.id,
                folder_id: inbox.id,
                uid_validity: 7,
                uid: 11,
                mod_sequence: Some(19),
                flags: Vec::new(),
            }),
            received_at: None,
            user_classification: None,
        })
        .await
        .unwrap();
    let mutations = backend.imap_mutations();

    let first = mutations
        .set_read(message_id, inbox.id, true)
        .await
        .unwrap();
    let second = mutations
        .set_starred(message_id, inbox.id, true)
        .await
        .unwrap();
    assert_eq!(first.id, second.id);
    assert_eq!(second.status, ImapMutationStatus::Pending);
    assert_eq!(
        second.operation,
        ImapMutationOperation::SetFlags {
            flags: vec!["\\Flagged".into(), "\\Seen".into()]
        }
    );
    let optimistic = backend.messages().get(message_id).await.unwrap();
    assert!(optimistic.summary.is_read);
    assert!(optimistic.summary.is_starred);
    assert_eq!(mutations.list(Some(account.id)).await.unwrap().len(), 1);

    let cancelled = mutations.cancel(first.id).await.unwrap();
    assert_eq!(cancelled.status, ImapMutationStatus::Cancelled);
    let restored = backend.messages().get(message_id).await.unwrap();
    assert!(!restored.summary.is_read);
    assert!(!restored.summary.is_starred);
    assert!(restored.instances[0].flags.is_empty());
}
