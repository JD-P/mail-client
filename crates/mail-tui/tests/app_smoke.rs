use chrono::Utc;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, FolderKind, ImapSecurity, ImapSettings, IngestMessage,
    NewAccount, NewFolder, RemoteMessageIdentity, WorkflowView,
};
use lizard_mail_tui::app::{AppCommand, MailApp, Screen};
use ratatui::backend::TestBackend;
use ratatui::Terminal;

#[tokio::test]
async fn empty_profile_opens_to_warm_action_and_renders_inbox_zero() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let mut app = MailApp::open(backend).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmAction));

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
    assert!(text.contains("WARM / ACTION"));
    assert!(text.contains("Warm inbox zero"));

    app.dispatch(AppCommand::Cold).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::ColdReview));
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
