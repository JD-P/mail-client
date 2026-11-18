use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ErrorCode, FolderKind, ImapSecurity, ImapSettings,
    IngestMessage, IntegrityAuditOptions, IntegrityIssueKind, NewAccount, NewFolder,
    RemoteMessageIdentity, StorageLimits,
};
use sha2::{Digest, Sha256};

fn message(subject: &str, body: &str) -> Vec<u8> {
    format!(
        concat!(
            "From: sender@example.test\r\n",
            "To: reader@example.test\r\n",
            "Date: Wed, 18 Nov 2026 12:00:00 +0000\r\n",
            "Message-ID: <{}@storage.test>\r\n",
            "Subject: {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "{}\r\n"
        ),
        uuid::Uuid::new_v4(),
        subject,
        body
    )
    .into_bytes()
}

async fn remote_target(
    backend: &Backend,
) -> (lizard_mail_backend::Account, lizard_mail_backend::Folder) {
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Storage test".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test:storage".into()),
            imap: Some(ImapSettings {
                host: "imap.example.test".into(),
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
    (account, folder)
}

#[tokio::test]
async fn audits_database_blobs_search_and_profile_usage() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let raw = message("Integrity", "The exact source bytes must remain intact.");
    backend
        .messages()
        .ingest(IngestMessage::local(raw.clone()))
        .await
        .unwrap();

    let report = backend
        .storage()
        .audit(IntegrityAuditOptions::default())
        .await
        .unwrap();
    assert!(
        report.healthy,
        "unexpected audit issues: {:?}",
        report.issues
    );
    assert!(report.database_integrity_ok);
    assert_eq!(report.database_messages, 1);
    assert_eq!(report.search_documents, 1);
    assert!(report.referenced_blobs >= 1);
    assert!(report.verified_blob_bytes >= raw.len() as u64);
    assert!(report.usage.database_bytes > 0);
    assert!(report.usage.blob_bytes >= raw.len() as u64);
    assert_eq!(
        report.usage.total_bytes,
        backend.storage().usage().await.unwrap().total_bytes
    );
}

#[tokio::test]
async fn reports_corrupt_and_orphaned_blobs_without_confusing_severity() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let raw = message("Tamper", "A same-size edit must fail the hash check.");
    backend
        .messages()
        .ingest(IngestMessage::local(raw.clone()))
        .await
        .unwrap();

    let raw_hash = hex::encode(Sha256::digest(&raw));
    let raw_path = profile
        .path()
        .join("blobs")
        .join(&raw_hash[..2])
        .join(&raw_hash[2..]);
    let mut corrupted = std::fs::read(&raw_path).unwrap();
    corrupted[0] ^= 1;
    std::fs::write(&raw_path, corrupted).unwrap();

    let orphan = b"unreferenced but internally valid blob";
    let orphan_hash = hex::encode(Sha256::digest(orphan));
    let orphan_path = profile
        .path()
        .join("blobs")
        .join(&orphan_hash[..2])
        .join(&orphan_hash[2..]);
    std::fs::create_dir_all(orphan_path.parent().unwrap()).unwrap();
    std::fs::write(orphan_path, orphan).unwrap();

    let report = backend
        .storage()
        .audit(IntegrityAuditOptions::default())
        .await
        .unwrap();
    assert!(!report.healthy);
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.kind == IntegrityIssueKind::CorruptBlob));
    assert!(report
        .issues
        .iter()
        .any(|issue| issue.kind == IntegrityIssueKind::OrphanBlob));

    let bounded = backend
        .storage()
        .audit(IntegrityAuditOptions {
            max_issues: 0,
            ..IntegrityAuditOptions::default()
        })
        .await
        .unwrap();
    assert!(!bounded.healthy);
    assert!(bounded.issues.is_empty());
    assert!(bounded.omitted_issues >= 2);
}

#[tokio::test]
async fn profile_quota_and_free_space_reserve_fail_before_database_commit() {
    let quota_profile = tempfile::tempdir().unwrap();
    let mut quota_config = BackendConfig::new(quota_profile.path());
    quota_config.storage_limits = StorageLimits {
        max_profile_bytes: Some(1),
        minimum_free_bytes: 0,
    };
    let backend = Backend::open(quota_config).await.unwrap();
    let error = backend
        .messages()
        .ingest(IngestMessage::local(message("Quota", "blocked")))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageQuotaExceeded);
    assert!(backend
        .messages()
        .list(Default::default())
        .await
        .unwrap()
        .items
        .is_empty());

    let full_profile = tempfile::tempdir().unwrap();
    let mut full_config = BackendConfig::new(full_profile.path());
    full_config.storage_limits = StorageLimits {
        max_profile_bytes: None,
        minimum_free_bytes: u64::MAX,
    };
    let backend = Backend::open(full_config).await.unwrap();
    let error = backend
        .messages()
        .ingest(IngestMessage::local(message("Full", "blocked")))
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageFull);
    assert!(backend
        .messages()
        .list(Default::default())
        .await
        .unwrap()
        .items
        .is_empty());
}

#[tokio::test]
async fn account_quota_is_durable_and_blocks_only_growth() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let (account, folder) = remote_target(&backend).await;
    let quota = backend
        .storage()
        .set_account_quota(account.id, Some(32))
        .await
        .unwrap();
    assert_eq!(quota.used_bytes, 0);
    assert_eq!(quota.max_bytes, Some(32));

    let error = backend
        .messages()
        .ingest(IngestMessage {
            raw: message(
                "Account quota",
                "This message is larger than thirty-two bytes.",
            ),
            remote: Some(RemoteMessageIdentity {
                account_id: account.id,
                folder_id: folder.id,
                uid_validity: 7,
                uid: 1,
                mod_sequence: None,
                flags: Vec::new(),
            }),
            received_at: None,
            user_classification: None,
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), ErrorCode::StorageQuotaExceeded);
    assert_eq!(
        backend
            .storage()
            .account_quota(account.id)
            .await
            .unwrap()
            .max_bytes,
        Some(32)
    );
    assert!(backend
        .messages()
        .list(Default::default())
        .await
        .unwrap()
        .items
        .is_empty());

    drop(backend);
    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    assert_eq!(
        reopened
            .storage()
            .account_quota(account.id)
            .await
            .unwrap()
            .max_bytes,
        Some(32)
    );
    assert_eq!(
        reopened
            .storage()
            .set_account_quota(account.id, None)
            .await
            .unwrap()
            .max_bytes,
        None
    );
}
