mod support;

use futures_util::future::BoxFuture;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, CredentialProvider, FolderKind, ImapAccountEngineConfig,
    ImapCredential, ImapFetchedHeaders, ImapSecurity, ImapSettings, ImapSyncIsolationConfig,
    MessageContentAvailability, MessageFilter, NewAccount, NewFolder, SecretValue,
};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use support::dovecot::DovecotContainer;

struct FixtureCredentials;

impl CredentialProvider for FixtureCredentials {
    fn resolve<'a>(
        &'a self,
        reference: &'a str,
    ) -> BoxFuture<'a, lizard_mail_backend::Result<ImapCredential>> {
        Box::pin(async move {
            assert_eq!(reference, "test-only:isolated-worker");
            Ok(ImapCredential::Password(SecretValue::new("password")))
        })
    }
}

fn sandbox_available() -> bool {
    let profile = tempfile::tempdir().unwrap();
    std::process::Command::new(worker_path())
        .arg("--sandbox-self-test")
        .arg(profile.path())
        .status()
        .is_ok_and(|status| status.success())
}

fn message() -> Vec<u8> {
    concat!(
        "From: Sender <sender@example.test>\r\n",
        "To: Reader <reader@example.test>\r\n",
        "Date: Mon, 16 Nov 2026 10:00:00 +0000\r\n",
        "Message-ID: <isolated-worker@example.test>\r\n",
        "Subject: Isolated synchronization\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "process boundary fixture\r\n"
    )
    .as_bytes()
    .to_vec()
}

fn worker_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_lizard-mail-sync-worker"))
}

#[test]
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn worker_seccomp_kills_x32_syscall_numbers() {
    use std::os::unix::process::ExitStatusExt;

    let status = std::process::Command::new(worker_path())
        .arg("--seccomp-x32-self-test")
        .status()
        .unwrap();
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "x32-numbered syscall was not killed by seccomp: {status}"
    );
}

#[test]
#[cfg(target_os = "linux")]
fn worker_sandbox_is_fail_closed() {
    let profile = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(worker_path())
        .arg("--sandbox-self-test")
        .arg(profile.path())
        .output()
        .unwrap();
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Landlock sandbox was not fully enforced")
                && (stderr.contains("NotImplemented") || stderr.contains("NotEnabled")),
            "sandbox failed for an unexpected reason: {stderr}"
        );
        return;
    }
    let evidence: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for field in [
        "profile_write_allowed",
        "credential_read_denied",
        "unrelated_profile_write_denied",
        "outside_read_denied",
        "outside_write_denied",
        "execute_denied",
        "udp_socket_denied",
        "unlisted_tcp_port_denied",
    ] {
        assert_eq!(evidence[field], true, "failed sandbox property {field}");
    }
}

#[tokio::test]
async fn worker_crash_is_an_account_error_not_a_backend_crash() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Crash containment".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:isolated-worker".into()),
            imap: Some(ImapSettings {
                host: "127.0.0.1".into(),
                port: 9,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let worker = if cfg!(windows) {
        PathBuf::from("C:\\Windows\\System32\\where.exe")
    } else {
        PathBuf::from("/bin/false")
    };
    let engine = backend
        .isolated_imap_account_engine(
            Arc::new(FixtureCredentials),
            ImapAccountEngineConfig::default(),
            ImapSyncIsolationConfig {
                worker_path: worker,
                operation_timeout: Duration::from_secs(5),
                ..ImapSyncIsolationConfig::default()
            },
        )
        .unwrap();

    let error = engine.sync_once(account.id).await.unwrap_err();
    assert!(error.to_string().contains("worker"));
    let state = engine.state(account.id).await.unwrap();
    assert_eq!(
        state.status,
        lizard_mail_backend::ImapAccountSyncStatus::Error
    );
    assert!(state.last_error.unwrap().contains("worker"));

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
    let projected = backend
        .sync()
        .ingest_imap_header_batch(
            account.id,
            folder.id,
            42,
            vec![ImapFetchedHeaders {
                uid: 7,
                mod_sequence: None,
                flags: Vec::new(),
                internal_date: None,
                size_bytes: 1_024,
                has_attachment: false,
                headers: message(),
            }],
        )
        .await
        .unwrap();
    let message_id = projected.message_ids[0];
    let error = engine.fetch_message_content(message_id).await.unwrap_err();
    assert!(error.to_string().contains("worker"));
    let content = backend.messages().content_status(message_id).await.unwrap();
    assert_eq!(content.availability, MessageContentAvailability::Failed);
    assert!(content.last_error.unwrap().contains("worker"));

    // The live backend and its exclusive search writer remain usable after
    // the disposable child dies before returning a frame.
    assert_eq!(
        backend.accounts().get(account.id).await.unwrap().id,
        account.id
    );
    backend
        .search()
        .search(lizard_mail_backend::SearchRequest {
            query: "from:nonexistent.invalid".into(),
            page_size: 10,
            cursor: None,
        })
        .await
        .unwrap();
}

#[tokio::test]
#[ignore = "requires Docker, the pinned Dovecot image, and a kernel with Landlock ABI 6"]
async fn sandboxed_worker_syncs_and_publishes_search_after_exit() {
    if !sandbox_available() {
        eprintln!("Landlock ABI 6 is unavailable; worker correctly failed closed");
        return;
    }
    let dovecot = DovecotContainer::start().await;
    let mut fixture = dovecot.login().await;
    fixture
        .append("INBOX", None, None, message())
        .await
        .unwrap();

    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Isolated Dovecot".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:isolated-worker".into()),
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
        .isolated_imap_account_engine(
            Arc::new(FixtureCredentials),
            ImapAccountEngineConfig {
                use_webpki_roots: false,
                additional_root_certificates_der: vec![dovecot.certificate_der.clone()],
                ..ImapAccountEngineConfig::default()
            },
            ImapSyncIsolationConfig {
                worker_path: worker_path(),
                ..ImapSyncIsolationConfig::default()
            },
        )
        .unwrap();

    let report = engine.sync_once(account.id).await.unwrap();
    assert_eq!(
        report
            .folders
            .iter()
            .map(|folder| folder.fetched_messages)
            .sum::<usize>(),
        1
    );
    let messages = backend
        .messages()
        .list(MessageFilter::default())
        .await
        .unwrap();
    assert_eq!(messages.items.len(), 1);
    let status = engine
        .fetch_message_content(messages.items[0].id)
        .await
        .unwrap();
    assert_eq!(status.availability, MessageContentAvailability::Complete);
    let search = backend
        .search()
        .search(lizard_mail_backend::SearchRequest {
            query: "subject:isolated".into(),
            page_size: 10,
            cursor: None,
        })
        .await
        .unwrap();
    assert_eq!(search.items.len(), 1);

    fixture.logout().await.unwrap();
}
