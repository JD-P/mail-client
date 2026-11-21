use chrono::Utc;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, FolderKind, ImapSecurity, ImapSettings, IngestMessage,
    NewAccount, NewFolder, RemoteMessageIdentity, WorkflowView,
};
use lizard_mail_tui::app::{AppCommand, MailApp, Screen};
use lizard_mail_tui::{HtmlRenderIsolationConfig, IsolatedHtmlRenderer, Limits};
use ratatui::backend::TestBackend;
use ratatui::Terminal;
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroizing;

#[tokio::test]
async fn empty_profile_opens_account_connection_onboarding() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let mut app = MailApp::open(backend).await.unwrap();
    assert_eq!(app.screen, Screen::AccountEdit);
    assert!(app.account_editor.as_ref().unwrap().account_id.is_none());

    let backend = TestBackend::new(100, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let rendered = terminal.backend().buffer().content().to_vec();
    let text = rendered
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("ACCOUNT / IMAP CONNECTION"));
    assert!(text.contains("Connect an IMAP account"));
    assert!(text.contains("Email / username"));
    assert!(text.contains("TLS from connection start"));

    app.dispatch(AppCommand::EditPaste(Zeroizing::new(
        "reader@example.test".into(),
    )))
    .await
    .unwrap();
    app.dispatch(AppCommand::EditNextField).await.unwrap();
    app.dispatch(AppCommand::EditPaste(Zeroizing::new("127.0.0.1".into())))
        .await
        .unwrap();
    for _ in 0..4 {
        app.dispatch(AppCommand::EditNextField).await.unwrap();
    }
    app.dispatch(AppCommand::EditPaste(Zeroizing::new(
        "test-app-password".into(),
    )))
    .await
    .unwrap();
    app.dispatch(AppCommand::AccountSave).await.unwrap();

    assert_eq!(app.screen, Screen::Accounts);
    assert_eq!(app.accounts.len(), 1);
    assert_eq!(app.accounts[0].name, "Personal");
    assert_eq!(app.accounts[0].imap.as_ref().unwrap().host, "127.0.0.1");
    assert!(app.accounts[0]
        .credential_ref
        .as_deref()
        .unwrap()
        .starts_with("lizard-credential:v1:"));
}

#[tokio::test]
async fn accounts_menu_edits_syncs_and_confirms_destructive_removal() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add_with_credential(
            NewAccount {
                name: "Personal".into(),
                kind: AccountKind::Imap,
                credential_ref: None,
                imap: Some(ImapSettings {
                    host: "127.0.0.1".into(),
                    port: 993,
                    username: "reader@example.test".into(),
                    security: ImapSecurity::ImplicitTls,
                }),
            },
            lizard_mail_backend::ImapCredential::Password(lizard_mail_backend::SecretValue::new(
                "password",
            )),
        )
        .await
        .unwrap();

    let mut app = MailApp::open(backend.clone()).await.unwrap();
    app.dispatch(AppCommand::Accounts).await.unwrap();
    assert_eq!(app.screen, Screen::Accounts);
    assert_eq!(app.accounts.len(), 1);

    app.dispatch(AppCommand::AccountEdit).await.unwrap();
    assert_eq!(app.screen, Screen::AccountEdit);
    assert_eq!(
        app.account_editor.as_ref().unwrap().secret_label(),
        "unchanged"
    );
    app.dispatch(AppCommand::Back).await.unwrap();

    app.dispatch(AppCommand::AccountDelete).await.unwrap();
    assert_eq!(app.screen, Screen::AccountDeleteConfirm);
    app.dispatch(AppCommand::AccountCancelDelete).await.unwrap();
    assert_eq!(app.screen, Screen::Accounts);
    assert_eq!(backend.accounts().list().await.unwrap().len(), 1);

    app.dispatch(AppCommand::AccountDelete).await.unwrap();
    app.dispatch(AppCommand::AccountConfirmDelete)
        .await
        .unwrap();
    assert_eq!(app.screen, Screen::AccountEdit);
    assert!(backend.accounts().list().await.unwrap().is_empty());
}

#[tokio::test]
async fn cold_reader_keeps_identity_context_and_persistent_explanations() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .ingest(IngestMessage::local(
            concat!(
                "From: Chase Support <support@chase.com.evil.wtf>\r\n",
                "Reply-To: payments@different.example\r\n",
                "To: reader@example.test\r\n",
                "Message-ID: <cold-identity@example.test>\r\n",
                "Subject: Account notice\r\n\r\n",
                "Do not trust this message.\r\n"
            )
            .as_bytes(),
        ))
        .await
        .unwrap();

    let mut app = MailApp::open(backend).await.unwrap();
    app.dispatch(AppCommand::Cold).await.unwrap();
    app.dispatch(AppCommand::Open).await.unwrap();
    assert_eq!(app.screen, Screen::Reader);
    assert!(app.reader_is_blocked());
    app.dispatch(AppCommand::RestrictedOpen).await.unwrap();

    let backend = TestBackend::new(120, 40);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();

    assert!(text.contains("COLD / CONVERSATION"));
    assert!(text.contains("support@chase.com.evil.wtf"));
    assert!(text.contains("controlled by evil.wtf, not chase.com"));
    assert!(text.contains("reply would be sent somewhere other"));
    assert!(text.contains("RESTRICTED VIEW"));
}

#[tokio::test]
async fn first_account_opens_address_first_contact_onboarding() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Personal".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test:personal".into()),
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
    let mut message = IngestMessage::local(
        b"From: Friendly Name <friend@example.test>\r\nTo: reader@example.test\r\nMessage-ID: <friend-one@example.test>\r\nSubject: Hello\r\n\r\nHello.\r\n"
            .to_vec(),
    );
    message.received_at = Some(Utc::now().timestamp());
    message.remote = Some(RemoteMessageIdentity {
        account_id: account.id,
        folder_id: folder.id,
        uid_validity: 1,
        uid: 1,
        mod_sequence: None,
        flags: Vec::new(),
    });
    backend.ingest(message).await.unwrap();

    let mut app = MailApp::open(backend).await.unwrap();
    assert_eq!(app.screen, Screen::Onboarding);
    assert_eq!(app.suggestions.len(), 1);

    let backend = TestBackend::new(120, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("friend@example.test claims to be Friendly Name"));

    app.dispatch(AppCommand::OnboardingAccept).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmAction));
    assert_eq!(app.threads.len(), 1);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn html_worker_failure_uses_safe_plain_text_in_the_reader() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Personal".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test:personal".into()),
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
    let mut message = IngestMessage::local(
        b"From: Friendly Name <friend@example.test>\r\nTo: reader@example.test\r\nMessage-ID: <html-one@example.test>\r\nSubject: HTML mail\r\nMIME-Version: 1.0\r\nContent-Type: multipart/alternative; boundary=part\r\n\r\n--part\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSAFE PLAIN FALLBACK\r\n--part\r\nContent-Type: text/html; charset=utf-8\r\n\r\n<h1>UNTRUSTED HTML VIEW</h1>\r\n--part--\r\n"
            .to_vec(),
    );
    message.received_at = Some(Utc::now().timestamp());
    message.remote = Some(RemoteMessageIdentity {
        account_id: account.id,
        folder_id: folder.id,
        uid_validity: 1,
        uid: 1,
        mod_sequence: None,
        flags: Vec::new(),
    });
    backend.ingest(message).await.unwrap();

    let mut app = MailApp::open(backend).await.unwrap();
    app.dispatch(AppCommand::OnboardingAccept).await.unwrap();
    app.dispatch(AppCommand::Open).await.unwrap();
    assert_eq!(app.screen, Screen::Reader);
    if app.reader_is_blocked() {
        app.dispatch(AppCommand::RestrictedOpen).await.unwrap();
    }
    app.set_html_renderer(IsolatedHtmlRenderer::new(
        Limits::default(),
        HtmlRenderIsolationConfig {
            worker_path: PathBuf::from("/bin/false"),
            wall_timeout: Duration::from_secs(1),
        },
    ));
    app.prepare_reader_html(118).await;
    assert!(app.reader_html().is_none());
    assert!(app.reader_html_error().is_some());

    let backend = TestBackend::new(120, 28);
    let mut terminal = Terminal::new(backend).unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let text = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(text.contains("safe plain-text fallback"));
    assert!(text.contains("SAFE PLAIN FALLBACK"));
    assert!(!text.contains("UNTRUSTED HTML VIEW"));
}

#[tokio::test]
async fn automatic_sync_ignores_local_only_profiles() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Local".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    let mut app = MailApp::open(backend).await.unwrap();
    assert!(!app.auto_sync_enabled());
    app.enable_auto_sync();
    app.poll_background_tasks().await.unwrap();
    assert!(app.queued_sync_accounts().is_empty());
    assert!(!app.account_syncing(account.id));
}
