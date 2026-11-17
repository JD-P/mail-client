mod support;

use futures_util::future::BoxFuture;
use futures_util::TryStreamExt;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, CredentialProvider, ImapAccountEngineConfig,
    ImapCredential, ImapMailboxCompleteness, ImapMutationConflictKind, ImapMutationStatus,
    ImapSecurity, ImapSettings, MessageFilter, NewAccount, SecretValue,
};
use std::sync::Arc;
use std::time::Duration;
use support::dovecot::DovecotContainer;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;

struct FixtureCredentials;

impl CredentialProvider for FixtureCredentials {
    fn resolve<'a>(
        &'a self,
        reference: &'a str,
    ) -> BoxFuture<'a, lizard_mail_backend::Result<ImapCredential>> {
        Box::pin(async move {
            assert_eq!(reference, "test-only:account-engine");
            Ok(ImapCredential::Password(SecretValue::new("password")))
        })
    }
}

fn message(subject: &str) -> Vec<u8> {
    format!(
        concat!(
            "From: Sender <sender@example.test>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Date: Mon, 16 Nov 2026 10:00:00 +0000\r\n",
            "Message-ID: <{}@example.test>\r\n",
            "Subject: {}\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "account engine fixture\r\n"
        ),
        subject.to_ascii_lowercase().replace(' ', "-"),
        subject
    )
    .into_bytes()
}

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn owns_tls_auth_discovery_and_remote_reconciliation() {
    let dovecot = DovecotContainer::start().await;
    let mut fixture_session = dovecot.login().await;
    fixture_session
        .append("INBOX", None, None, message("Account engine alpha"))
        .await
        .unwrap();

    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot account engine".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:account-engine".into()),
            imap: Some(ImapSettings {
                host: "localhost".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();
    let config = ImapAccountEngineConfig {
        use_webpki_roots: false,
        additional_root_certificates_der: vec![dovecot.certificate_der.clone()],
        ..ImapAccountEngineConfig::default()
    };
    let engine = backend
        .imap_account_engine(Arc::new(FixtureCredentials), config)
        .unwrap();

    let first = engine.sync_once(account.id).await.unwrap();
    assert_eq!(
        first
            .folders
            .iter()
            .map(|folder| folder.fetched_messages)
            .sum::<usize>(),
        1
    );
    let mailbox_states = engine.mailbox_states(account.id).await.unwrap();
    let inbox = mailbox_states
        .iter()
        .find(|mailbox| mailbox.remote_name.eq_ignore_ascii_case("INBOX"))
        .unwrap();
    assert!(inbox.selectable);
    assert!(inbox.remote_present);
    assert_eq!(inbox.completeness, ImapMailboxCompleteness::Complete);
    let stored = backend
        .messages()
        .list(MessageFilter::default())
        .await
        .unwrap();
    assert_eq!(stored.items.len(), 1);
    let message_id = stored.items[0].id;
    assert!(!stored.items[0].is_read);

    let implicit_profile = tempfile::tempdir().unwrap();
    let implicit_backend = Backend::open(BackendConfig::new(implicit_profile.path()))
        .await
        .unwrap();
    let implicit_account = implicit_backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot implicit TLS".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:account-engine".into()),
            imap: Some(ImapSettings {
                host: "localhost".into(),
                port: dovecot.imaps_port,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let implicit_engine = implicit_backend
        .imap_account_engine(
            Arc::new(FixtureCredentials),
            ImapAccountEngineConfig {
                use_webpki_roots: false,
                additional_root_certificates_der: vec![dovecot.certificate_der.clone()],
                ..ImapAccountEngineConfig::default()
            },
        )
        .unwrap();
    let implicit = implicit_engine
        .sync_once(implicit_account.id)
        .await
        .unwrap();
    assert_eq!(
        implicit
            .folders
            .iter()
            .map(|folder| folder.fetched_messages)
            .sum::<usize>(),
        1
    );

    fixture_session.select("INBOX").await.unwrap();
    fixture_session
        .uid_store("1", "+FLAGS.SILENT (\\Seen)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    let second = engine.sync_once(account.id).await.unwrap();
    assert!(second
        .folders
        .iter()
        .any(|folder| folder.refreshed_instances == 1));
    if second
        .capabilities
        .iter()
        .any(|capability| capability.eq_ignore_ascii_case("QRESYNC"))
    {
        assert!(second.folders.iter().any(|folder| folder.used_qresync));
    }
    assert!(
        backend
            .messages()
            .get(message_id)
            .await
            .unwrap()
            .summary
            .is_read
    );

    fixture_session
        .uid_store("1", "+FLAGS.SILENT (\\Deleted)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    fixture_session
        .uid_expunge("1")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    let third = engine.sync_once(account.id).await.unwrap();
    assert!(third
        .folders
        .iter()
        .any(|folder| folder.removed_instances == 1));
    assert!(backend
        .messages()
        .list(MessageFilter::default())
        .await
        .unwrap()
        .items
        .is_empty());
    assert!(backend.messages().get(message_id).await.is_err());
}

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn continuous_worker_wakes_for_new_mail_and_cancels() {
    let dovecot = DovecotContainer::start().await;
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot continuous worker".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:account-engine".into()),
            imap: Some(ImapSettings {
                host: "localhost".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();
    let engine = backend
        .imap_account_engine(
            Arc::new(FixtureCredentials),
            ImapAccountEngineConfig {
                idle_refresh: Duration::from_secs(1),
                polling_interval: Duration::from_secs(1),
                use_webpki_roots: false,
                additional_root_certificates_der: vec![dovecot.certificate_der.clone()],
                ..ImapAccountEngineConfig::default()
            },
        )
        .unwrap();
    let cancellation = CancellationToken::new();
    let worker = tokio::spawn({
        let engine = engine.clone();
        let cancellation = cancellation.clone();
        async move { engine.run(account.id, cancellation).await }
    });

    timeout(Duration::from_secs(10), async {
        loop {
            if engine.state(account.id).await.unwrap().status
                == lizard_mail_backend::ImapAccountSyncStatus::Waiting
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("worker never reached its wait state");
    // Waiting is recorded immediately before the IDLE connection is opened.
    // A short grace period avoids racing the server notification; the
    // one-second IDLE refresh remains a deterministic fallback.
    sleep(Duration::from_millis(250)).await;
    let mut fixture_session = dovecot.login().await;
    fixture_session
        .append("INBOX", None, None, message("IDLE wakeup"))
        .await
        .unwrap();

    timeout(Duration::from_secs(10), async {
        loop {
            if !backend
                .messages()
                .list(MessageFilter::default())
                .await
                .unwrap()
                .items
                .is_empty()
            {
                break;
            }
            sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("IDLE worker did not synchronize the new message");

    cancellation.cancel();
    timeout(Duration::from_secs(5), worker)
        .await
        .expect("worker did not stop promptly")
        .expect("worker task panicked")
        .expect("worker returned an error");
    assert_eq!(
        engine.state(account.id).await.unwrap().status,
        lizard_mail_backend::ImapAccountSyncStatus::Stopped
    );
}

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn applies_server_mutations_and_records_flag_conflicts() {
    let dovecot = DovecotContainer::start().await;
    let mut fixture_session = dovecot.login().await;
    fixture_session.create("Archive").await.unwrap();
    for subject in ["Flags", "Copy", "Move", "Trash", "Delete", "Conflict"] {
        fixture_session
            .append("INBOX", None, None, message(subject))
            .await
            .unwrap();
    }

    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot mutations".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:account-engine".into()),
            imap: Some(ImapSettings {
                host: "localhost".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();
    let engine = backend
        .imap_account_engine(
            Arc::new(FixtureCredentials),
            ImapAccountEngineConfig {
                use_webpki_roots: false,
                additional_root_certificates_der: vec![dovecot.certificate_der.clone()],
                ..ImapAccountEngineConfig::default()
            },
        )
        .unwrap();
    engine.sync_once(account.id).await.unwrap();

    let folders = backend.folders().list(Some(account.id)).await.unwrap();
    let inbox = folders
        .iter()
        .find(|folder| folder.remote_name.as_deref() == Some("INBOX"))
        .unwrap();
    let archive = folders
        .iter()
        .find(|folder| folder.remote_name.as_deref() == Some("Archive"))
        .unwrap();
    let trash = folders
        .iter()
        .find(|folder| folder.remote_name.as_deref() == Some("Trash"))
        .unwrap();
    let summaries = backend
        .messages()
        .list(MessageFilter::default())
        .await
        .unwrap()
        .items;
    let id_for = |subject: &str| {
        summaries
            .iter()
            .find(|summary| summary.subject.as_deref() == Some(subject))
            .unwrap()
            .id
    };
    let flags_id = id_for("Flags");
    let copy_id = id_for("Copy");
    let move_id = id_for("Move");
    let trash_id = id_for("Trash");
    let delete_id = id_for("Delete");
    let conflict_id = id_for("Conflict");
    let mutations = backend.imap_mutations();

    let flag_mutation = mutations.set_read(flags_id, inbox.id, true).await.unwrap();
    assert_eq!(flag_mutation.status, ImapMutationStatus::Pending);
    assert!(
        backend
            .messages()
            .get(flags_id)
            .await
            .unwrap()
            .summary
            .is_read
    );
    let copy_mutation = mutations.copy(copy_id, inbox.id, archive.id).await.unwrap();
    let move_mutation = mutations
        .move_to(move_id, inbox.id, archive.id)
        .await
        .unwrap();
    let trash_mutation = mutations.trash(trash_id, inbox.id).await.unwrap();
    let delete_mutation = mutations.delete(delete_id, inbox.id).await.unwrap();

    let report = engine.sync_once(account.id).await.unwrap();
    assert_eq!(report.mutations.attempted, 5);
    assert_eq!(report.mutations.applied, 5);
    assert_eq!(report.mutations.conflicts, 0);
    for mutation in [
        flag_mutation.id,
        copy_mutation.id,
        move_mutation.id,
        trash_mutation.id,
        delete_mutation.id,
    ] {
        assert_eq!(
            mutations.get(mutation).await.unwrap().status,
            ImapMutationStatus::Applied
        );
    }
    let copied = backend.messages().get(copy_id).await.unwrap();
    assert!(copied
        .instances
        .iter()
        .any(|instance| instance.folder_id == inbox.id));
    assert!(copied
        .instances
        .iter()
        .any(|instance| instance.folder_id == archive.id));
    let moved = backend.messages().get(move_id).await.unwrap();
    assert!(!moved
        .instances
        .iter()
        .any(|instance| instance.folder_id == inbox.id));
    assert!(moved
        .instances
        .iter()
        .any(|instance| instance.folder_id == archive.id));
    let trashed = backend.messages().get(trash_id).await.unwrap();
    assert!(!trashed
        .instances
        .iter()
        .any(|instance| instance.folder_id == inbox.id));
    assert!(trashed
        .instances
        .iter()
        .any(|instance| instance.folder_id == trash.id));
    assert!(backend.messages().get(delete_id).await.is_err());

    let conflict_mutation = mutations
        .set_starred(conflict_id, inbox.id, true)
        .await
        .unwrap();
    fixture_session.select("INBOX").await.unwrap();
    let conflict_uid = backend
        .messages()
        .get(conflict_id)
        .await
        .unwrap()
        .instances
        .into_iter()
        .find(|instance| instance.folder_id == inbox.id)
        .unwrap()
        .uid;
    fixture_session
        .uid_store(conflict_uid.to_string(), "+FLAGS.SILENT (\\Answered)")
        .await
        .unwrap()
        .try_collect::<Vec<_>>()
        .await
        .unwrap();
    let report = engine.sync_once(account.id).await.unwrap();
    assert_eq!(report.mutations.conflicts, 1);
    assert_eq!(
        mutations.get(conflict_mutation.id).await.unwrap().status,
        ImapMutationStatus::Conflict
    );
    let conflicts = mutations
        .conflicts(Some(conflict_mutation.id))
        .await
        .unwrap();
    assert_eq!(conflicts.len(), 1);
    assert_eq!(
        conflicts[0].kind,
        ImapMutationConflictKind::ServerStateChanged
    );
    let reconciled = backend.messages().get(conflict_id).await.unwrap();
    assert!(!reconciled.summary.is_starred);
    assert!(reconciled.instances.iter().any(|instance| {
        instance.folder_id == inbox.id
            && instance
                .flags
                .iter()
                .any(|flag| flag.eq_ignore_ascii_case("\\Answered"))
    }));
}
