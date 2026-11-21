use lizard_mail_backend::{
    restore_profile_backup, AccountBodyPolicy, AccountKind, Backend, BackendConfig,
    BodyRetentionPolicy, CredentialStoragePolicy, FolderKind, ImapSecurity, ImapSettings,
    IngestMessage, MailExportFormat, MailSelection, MailTransferLimits, MessageContentAvailability,
    NewAccount, NewFolder, OfflineDownloadPolicy, RemoteMessageIdentity,
};

fn config(path: &std::path::Path) -> BackendConfig {
    let mut config = BackendConfig::new(path);
    config.credential_storage = CredentialStoragePolicy::ProfileOnly;
    config
}

#[tokio::test]
async fn standard_exports_roundtrip_exact_rfc_bytes() {
    let root = tempfile::tempdir().unwrap();
    let source_profile = root.path().join("source");
    let backend = Backend::open(config(&source_profile)).await.unwrap();
    let raw = b"From: writer@example.test\r\nTo: reader@example.test\r\nSubject: exact export\r\n\r\nfirst\r\nFrom dangerous body line\r\n>From already quoted\r\nno final newline".to_vec();
    let id = backend
        .messages()
        .ingest(IngestMessage::local(raw.clone()))
        .await
        .unwrap();
    for (index, format) in [
        MailExportFormat::EmlDirectory,
        MailExportFormat::Maildir,
        MailExportFormat::Mbox,
    ]
    .into_iter()
    .enumerate()
    {
        let exported = root.path().join(format!("export-{index}"));
        let report = backend
            .data_lifecycle()
            .export_mail(
                MailSelection::Messages(vec![id]),
                format.clone(),
                &exported,
                MailTransferLimits::default(),
            )
            .await
            .unwrap();
        assert_eq!(report.messages, 1);
        assert_eq!(report.raw_bytes, raw.len() as u64);

        let imported_profile = root.path().join(format!("import-{index}"));
        let imported_backend = Backend::open(config(&imported_profile)).await.unwrap();
        let imported = imported_backend
            .data_lifecycle()
            .import_mail(&exported, format, None, MailTransferLimits::default())
            .await
            .unwrap();
        assert_eq!(imported.messages.len(), 1);
        assert_eq!(
            imported_backend
                .messages()
                .raw(imported.messages[0])
                .await
                .unwrap(),
            raw
        );
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let destination = root.path().join("dangling-export");
        symlink(root.path().join("missing-target"), &destination).unwrap();
        assert!(backend
            .data_lifecycle()
            .export_mail(
                MailSelection::Messages(vec![id]),
                MailExportFormat::EmlDirectory,
                &destination,
                MailTransferLimits::default(),
            )
            .await
            .is_err());
        assert!(std::fs::symlink_metadata(destination)
            .unwrap()
            .file_type()
            .is_symlink());
    }
}

#[tokio::test]
async fn directory_import_commits_in_bounded_batches() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("many-eml");
    tokio::fs::create_dir(&source).await.unwrap();
    for index in 0..70 {
        tokio::fs::write(
            source.join(format!("{index:03}.eml")),
            format!(
                "From: source-{index}@example.test\r\nSubject: batch {index}\r\n\r\nbody {index}\r\n"
            ),
        )
        .await
        .unwrap();
    }
    let backend = Backend::open(config(&root.path().join("import-profile")))
        .await
        .unwrap();
    let report = backend
        .data_lifecycle()
        .import_mail(
            &source,
            MailExportFormat::EmlDirectory,
            None,
            MailTransferLimits::default(),
        )
        .await
        .unwrap();
    assert_eq!(report.messages.len(), 70);
    assert!(report.raw_bytes > 0);
    assert_eq!(
        backend
            .search()
            .search(lizard_mail_backend::SearchRequest {
                query: "subject:batch".into(),
                page_size: 100,
                cursor: None,
            })
            .await
            .unwrap()
            .items
            .len(),
        70
    );
}

#[tokio::test]
async fn backup_restores_authoritative_state_without_tantivy() {
    let root = tempfile::tempdir().unwrap();
    let source_profile = root.path().join("profile");
    let backup_path = root.path().join("backup");
    let restored_profile = root.path().join("restored");
    let backend = Backend::open(config(&source_profile)).await.unwrap();
    let raw = b"From: archive@example.test\r\nSubject: backup\r\n\r\nexact body\r\n".to_vec();
    let id = backend
        .messages()
        .ingest(IngestMessage::local(raw.clone()))
        .await
        .unwrap();
    tokio::fs::write(
        source_profile.join("downloads/interrupted.partial"),
        b"rebuildable partial bytes",
    )
    .await
    .unwrap();
    let backup = backend
        .data_lifecycle()
        .backup_profile(&backup_path)
        .await
        .unwrap();
    assert!(backup.files > 0);
    assert!(!backup_path.join("search-index").exists());
    assert!(!backup_path.join("search-index.json").exists());
    assert!(!backup_path.join("downloads").exists());

    let restored = restore_profile_backup(&backup_path, &restored_profile)
        .await
        .unwrap();
    assert_eq!(restored.files, backup.files);
    let reopened = Backend::open(config(&restored_profile)).await.unwrap();
    assert_eq!(reopened.messages().raw(id).await.unwrap(), raw);
    let search = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let page = reopened
                .search()
                .search(lizard_mail_backend::SearchRequest {
                    query: "subject:backup".into(),
                    page_size: 10,
                    cursor: None,
                })
                .await
                .unwrap();
            if page.index_results_complete {
                break page;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("restored search projection should finish");
    assert_eq!(search.items.len(), 1);
}

#[tokio::test]
async fn retention_never_evicts_irreplaceable_or_pinned_mail() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(config(profile.path())).await.unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Remote account".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("external:test".into()),
            imap: Some(ImapSettings {
                host: "imap.example.test".into(),
                port: 993,
                username: "owner@example.test".into(),
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
    let raw = b"From: remote@example.test\r\nSubject: recoverable\r\n\r\nbody\r\n".to_vec();
    let remote_id = backend
        .messages()
        .ingest(IngestMessage {
            raw,
            remote: Some(RemoteMessageIdentity {
                account_id: account.id,
                folder_id: folder.id,
                uid_validity: 7,
                uid: 11,
                mod_sequence: Some(1),
                flags: Vec::new(),
            }),
            received_at: Some(1),
            user_classification: None,
        })
        .await
        .unwrap();
    let local_id = backend
        .messages()
        .ingest(IngestMessage::local(
            b"From: local@example.test\r\n\r\nonly copy".to_vec(),
        ))
        .await
        .unwrap();

    assert!(backend
        .data_lifecycle()
        .evict_message_body(local_id)
        .await
        .is_err());
    backend
        .data_lifecycle()
        .set_body_pinned(remote_id, true)
        .await
        .unwrap();
    assert!(backend
        .data_lifecycle()
        .evict_message_body(remote_id)
        .await
        .is_err());
    backend
        .data_lifecycle()
        .set_body_pinned(remote_id, false)
        .await
        .unwrap();
    backend
        .data_lifecycle()
        .set_body_policy(AccountBodyPolicy {
            account_id: account.id,
            offline: OfflineDownloadPolicy::All,
            retention: BodyRetentionPolicy::KeepAll,
            retain_starred: true,
            updated_at: 0,
        })
        .await
        .unwrap();
    assert!(backend
        .data_lifecycle()
        .evict_message_body(remote_id)
        .await
        .is_err());
    backend
        .data_lifecycle()
        .set_body_policy(AccountBodyPolicy::on_demand(account.id))
        .await
        .unwrap();
    backend
        .data_lifecycle()
        .evict_message_body(remote_id)
        .await
        .unwrap();
    assert_eq!(
        backend
            .messages()
            .content_status(remote_id)
            .await
            .unwrap()
            .availability,
        MessageContentAvailability::HeadersOnly
    );
    assert!(backend.messages().raw(remote_id).await.is_err());
    assert_eq!(
        backend.messages().raw(local_id).await.unwrap(),
        b"From: local@example.test\r\n\r\nonly copy"
    );

    let policy = backend
        .data_lifecycle()
        .set_body_policy(AccountBodyPolicy {
            account_id: account.id,
            offline: OfflineDownloadPolicy::All,
            retention: BodyRetentionPolicy::EvictRemoteAfterDays { days: 30 },
            retain_starred: true,
            updated_at: 0,
        })
        .await
        .unwrap();
    assert_eq!(policy.offline, OfflineDownloadPolicy::All);
    assert_eq!(
        backend
            .data_lifecycle()
            .offline_download_candidates(account.id, 10)
            .await
            .unwrap(),
        vec![remote_id]
    );
}

#[tokio::test]
async fn remote_accounts_default_to_a_full_local_mirror_but_preserve_opt_out() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(config(profile.path())).await.unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Mirrored account".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("external:test".into()),
            imap: Some(ImapSettings {
                host: "imap.example.test".into(),
                port: 993,
                username: "owner@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();

    let default_policy = backend
        .data_lifecycle()
        .body_policy(account.id)
        .await
        .unwrap();
    assert_eq!(default_policy.offline, OfflineDownloadPolicy::All);
    assert_eq!(default_policy.retention, BodyRetentionPolicy::KeepAll);

    backend
        .data_lifecycle()
        .set_body_policy(AccountBodyPolicy::on_demand(account.id))
        .await
        .unwrap();
    let explicit_policy = backend
        .data_lifecycle()
        .body_policy(account.id)
        .await
        .unwrap();
    assert_eq!(explicit_policy.offline, OfflineDownloadPolicy::OnDemand);
}

#[tokio::test]
async fn offline_hydration_reports_progress_and_selects_newest_messages_first() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(config(profile.path())).await.unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Ordered mirror".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("external:test".into()),
            imap: Some(ImapSettings {
                host: "imap.example.test".into(),
                port: 993,
                username: "owner@example.test".into(),
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
    let mut messages = Vec::new();
    for (uid, received_at) in [(1, 100), (2, 300), (3, 200)] {
        let id = backend
            .messages()
            .ingest(IngestMessage {
                raw: format!(
                    "From: remote@example.test\r\nMessage-ID: <ordered-{uid}@example.test>\r\nSubject: ordered {uid}\r\n\r\nbody\r\n"
                )
                .into_bytes(),
                remote: Some(RemoteMessageIdentity {
                    account_id: account.id,
                    folder_id: folder.id,
                    uid_validity: 9,
                    uid,
                    mod_sequence: None,
                    flags: Vec::new(),
                }),
                received_at: Some(received_at),
                user_classification: None,
            })
            .await
            .unwrap();
        messages.push((received_at, id));
    }
    backend
        .data_lifecycle()
        .set_body_policy(AccountBodyPolicy::on_demand(account.id))
        .await
        .unwrap();
    for (_, id) in &messages {
        backend
            .data_lifecycle()
            .evict_message_body(*id)
            .await
            .unwrap();
    }
    backend
        .data_lifecycle()
        .set_body_policy(AccountBodyPolicy::local_mirror(account.id))
        .await
        .unwrap();

    let progress = backend
        .data_lifecycle()
        .offline_download_progress(account.id)
        .await
        .unwrap();
    assert_eq!(progress.completed_messages, 0);
    assert_eq!(progress.total_messages, 3);
    let candidates = backend
        .data_lifecycle()
        .offline_download_candidates(account.id, 10)
        .await
        .unwrap();
    messages.sort_by_key(|(received_at, _)| std::cmp::Reverse(*received_at));
    assert_eq!(
        candidates,
        messages.into_iter().map(|(_, id)| id).collect::<Vec<_>>()
    );
}
