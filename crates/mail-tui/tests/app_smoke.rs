use chrono::Utc;
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ContactAddress, FolderKind, ImapSecurity, ImapSettings,
    IngestMessage, NewAccount, NewContact, NewFolder, RemoteMessageIdentity, SmtpAuthMethod,
    SmtpSecurity, SmtpSettings, ThreadWorkStatus, WarmRoute, WorkflowView,
};
use lizard_mail_tui::app::{AppCommand, MailApp, Screen};
use lizard_mail_tui::{HtmlRenderIsolationConfig, IsolatedHtmlRenderer, Limits};
use ratatui::backend::TestBackend;
use ratatui::style::Color;
use ratatui::Terminal;
use std::{path::PathBuf, time::Duration};
use zeroize::Zeroizing;

async fn wait_for_reader_metadata(app: &mut MailApp) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.current_thread.is_none() {
            app.poll_background_tasks().await.unwrap();
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("reader metadata should load without blocking the UI");
}

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
    assert!(text.contains("ACCOUNT / MAIL CONNECTIONS"));
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
async fn reader_creates_and_saves_a_threaded_reply_with_visible_recipients() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add_with_credential(
            NewAccount {
                name: "Personal".into(),
                kind: AccountKind::Imap,
                credential_ref: None,
                imap: Some(ImapSettings {
                    host: "imap.example.test".into(),
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
    backend
        .sending()
        .configure_smtp(
            account.id,
            SmtpSettings {
                host: "127.0.0.1".into(),
                port: 9,
                username: "reader@example.test".into(),
                security: SmtpSecurity::ImplicitTls,
                auth: SmtpAuthMethod::Password,
            },
            account.credential_ref.clone().unwrap(),
        )
        .await
        .unwrap();
    backend
        .contacts()
        .add(NewContact {
            display_name: "Friendly Name".into(),
            addresses: vec![ContactAddress {
                address: "friend@example.test".into(),
                accepted_name: Some("Friendly Name".into()),
            }],
        })
        .await
        .unwrap();
    let mut message = IngestMessage::local(
        concat!(
            "From: Friendly Name <friend@example.test>\r\n",
            "To: reader@example.test\r\n",
            "Cc: colleague@example.test\r\n",
            "Message-ID: <reply-source@example.test>\r\n",
            "Subject: Project update\r\n\r\n",
            "Can you review this?\r\n"
        )
        .as_bytes(),
    );
    message.remote = Some(RemoteMessageIdentity {
        account_id: account.id,
        folder_id: folder.id,
        uid_validity: 1,
        uid: 1,
        mod_sequence: None,
        flags: Vec::new(),
    });
    backend.ingest(message).await.unwrap();

    let mut app = MailApp::open(backend.clone()).await.unwrap();
    app.dispatch(AppCommand::Open).await.unwrap();
    wait_for_reader_metadata(&mut app).await;
    if app.reader_is_blocked() {
        app.dispatch(AppCommand::RestrictedOpen).await.unwrap();
    }
    app.dispatch(AppCommand::ReplyAll).await.unwrap();
    assert_eq!(app.screen, Screen::Compose);
    let editor = app.compose_editor.as_mut().unwrap();
    assert_eq!(editor.to, "friend@example.test");
    assert_eq!(editor.cc, "colleague@example.test");
    assert_eq!(editor.subject, "Re: Project update");
    editor.body = "Yes — I will review it today.\n".into();
    let draft_id = editor.draft.id;
    app.dispatch(AppCommand::ComposeSave).await.unwrap();

    let draft = backend.drafts().get(draft_id).await.unwrap();
    assert_eq!(draft.content.to_addresses, ["friend@example.test"]);
    assert_eq!(draft.content.cc_addresses, ["colleague@example.test"]);
    assert_eq!(draft.content.body_text, "Yes — I will review it today.\n");
    assert_eq!(
        draft.content.in_reply_to.as_deref(),
        Some("reply-source@example.test")
    );
    app.dispatch(AppCommand::Back).await.unwrap();
    assert_eq!(app.screen, Screen::Reader);
    app.dispatch(AppCommand::Reply).await.unwrap();
    assert_eq!(app.screen, Screen::Compose);
    assert_eq!(app.compose_editor.as_ref().unwrap().draft.id, draft_id);
    assert_eq!(
        app.compose_editor.as_ref().unwrap().body,
        "Yes — I will review it today.\n"
    );

    let terminal_backend = TestBackend::new(120, 32);
    let mut terminal = Terminal::new(terminal_backend).unwrap();
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
    assert!(text.contains("WARM / REPLY"));
    assert!(text.contains("verify this address before sending"));
    assert!(text.contains("friend@example.test"));
    assert!(text.contains("Ctrl-D send"));

    app.dispatch(AppCommand::ComposeSend).await.unwrap();
    assert_eq!(app.screen, Screen::Reader);
    assert_eq!(backend.outbox().list().await.unwrap().len(), 1);
}

#[tokio::test]
async fn slash_search_opens_the_exact_matching_message_in_a_conversation() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add(NewAccount {
            name: "Local".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    backend
        .contacts()
        .add(NewContact {
            display_name: "Friendly Name".into(),
            addresses: vec![ContactAddress {
                address: "friend@example.test".into(),
                accepted_name: Some("Friendly Name".into()),
            }],
        })
        .await
        .unwrap();
    let matched = backend
        .ingest(IngestMessage::local(
            concat!(
                "From: Friendly Name <friend@example.test>\r\n",
                "To: reader@example.test\r\n",
                "Message-ID: <search-old@example.test>\r\n",
                "Subject: Cobalt migration details\r\n\r\n",
                "The unique needleword appears only in this older message.\r\n"
            )
            .as_bytes(),
        ))
        .await
        .unwrap();
    backend
        .ingest(IngestMessage::local(
            concat!(
                "From: Friendly Name <friend@example.test>\r\n",
                "To: reader@example.test\r\n",
                "Message-ID: <search-new@example.test>\r\n",
                "In-Reply-To: <search-old@example.test>\r\n",
                "References: <search-old@example.test>\r\n",
                "Subject: Re: Cobalt migration details\r\n\r\n",
                "This newest reply deliberately omits the unique term.\r\n"
            )
            .as_bytes(),
        ))
        .await
        .unwrap();

    let mut app = MailApp::open(backend).await.unwrap();
    app.dispatch(AppCommand::SearchStart).await.unwrap();
    assert_eq!(app.screen, Screen::SearchInput);
    let terminal_backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(terminal_backend).unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let help = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(help.contains("has:attachment"));
    assert!(help.contains("newer_than:/older_than:"));
    assert!(help.contains("message-id: or rfc822msgid:"));
    app.dispatch(AppCommand::EditPaste(Zeroizing::new("needleword".into())))
        .await
        .unwrap();
    app.dispatch(AppCommand::SearchSubmit).await.unwrap();
    assert_eq!(app.screen, Screen::SearchResults);
    assert_eq!(app.search_results.len(), 1);
    assert_eq!(app.search_results[0].id, matched);
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let result_row = terminal
        .backend()
        .buffer()
        .content()
        .chunks(120)
        .find(|row| {
            row.iter()
                .map(|cell| cell.symbol())
                .collect::<String>()
                .contains("[WARM] Cobalt migration details")
        })
        .expect("search result should retain an explicit Warm identity");
    assert!(result_row
        .iter()
        .any(|cell| cell.fg == Color::Rgb(198, 48, 67)));

    app.dispatch(AppCommand::Open).await.unwrap();
    wait_for_reader_metadata(&mut app).await;
    assert_eq!(
        app.current_thread
            .as_ref()
            .unwrap()
            .messages
            .last()
            .unwrap()
            .summary
            .id,
        matched,
        "opening search must show the matching message, not merely the newest message in its thread"
    );
    app.dispatch(AppCommand::Back).await.unwrap();
    assert_eq!(app.screen, Screen::SearchResults);
}

#[tokio::test]
async fn reader_tabs_through_browser_links_but_never_in_restricted_view() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add(NewAccount {
            name: "Local".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    backend
        .ingest(IngestMessage::local(
            concat!(
                "From: Links <links@example.test>\r\n",
                "To: reader@example.test\r\n",
                "Message-ID: <link-focus@example.test>\r\n",
                "Subject: Useful links\r\n",
                "MIME-Version: 1.0\r\n",
                "Content-Type: text/html; charset=utf-8\r\n\r\n",
                "<a href=\"https://first.example/path\">First</a>",
                "<a href=\"mailto:person@example.test\">Mail</a>",
                "<a href=\"https://second.example/next\">Second</a>\r\n"
            )
            .as_bytes(),
        ))
        .await
        .unwrap();

    let mut app = MailApp::open(backend).await.unwrap();
    app.dispatch(AppCommand::Cold).await.unwrap();
    app.dispatch(AppCommand::Open).await.unwrap();
    wait_for_reader_metadata(&mut app).await;
    app.current_thread
        .as_mut()
        .unwrap()
        .messages
        .last_mut()
        .unwrap()
        .findings
        .clear();

    app.dispatch(AppCommand::ReaderNextLink).await.unwrap();
    assert_eq!(app.reader_selected_link(), Some(0));
    app.dispatch(AppCommand::ReaderOpenLink).await.unwrap();
    assert_eq!(
        app.take_external_url_request().as_deref(),
        Some("https://first.example/path")
    );
    app.dispatch(AppCommand::ReaderNextLink).await.unwrap();
    assert_eq!(app.reader_selected_link(), Some(1));
    app.dispatch(AppCommand::ReaderOpenLink).await.unwrap();
    assert_eq!(
        app.take_external_url_request().as_deref(),
        Some("https://second.example/next")
    );
    app.dispatch(AppCommand::ReaderPreviousLink).await.unwrap();
    assert_eq!(app.reader_selected_link(), Some(0));

    let terminal_backend = TestBackend::new(120, 36);
    let mut terminal = Terminal::new(terminal_backend).unwrap();
    terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    assert!(terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .any(|cell| cell.fg == Color::Black && cell.bg == Color::Cyan));

    app.dispatch(AppCommand::RestrictedOpen).await.unwrap();
    assert_eq!(app.reader_selected_link(), None);
    app.dispatch(AppCommand::ReaderNextLink).await.unwrap();
    app.dispatch(AppCommand::ReaderOpenLink).await.unwrap();
    assert_eq!(app.reader_selected_link(), None);
    assert!(app.take_external_url_request().is_none());
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
async fn account_editor_configures_encrypted_smtp_for_replies() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
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
    app.dispatch(AppCommand::AccountEdit).await.unwrap();
    let editor = app.account_editor.as_mut().unwrap();
    editor.smtp_host = "smtp.example.test".into();
    editor.smtp_port = "587".into();
    editor.smtp_security = SmtpSecurity::StartTls;
    app.dispatch(AppCommand::AccountSave).await.unwrap();

    let smtp = backend.sending().smtp_account(account.id).await.unwrap();
    assert_eq!(smtp.settings.host, "smtp.example.test");
    assert_eq!(smtp.settings.port, 587);
    assert_eq!(smtp.settings.security, SmtpSecurity::StartTls);
    assert_eq!(smtp.settings.username, "reader@example.test");
    assert_eq!(smtp.credential_ref, account.credential_ref.unwrap());
}

#[tokio::test]
async fn contacts_list_edits_identity_addresses_and_obligation_policy() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add(NewAccount {
            name: "Local".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    let contact = backend
        .contacts()
        .add(NewContact {
            display_name: "Northwind".into(),
            addresses: vec![ContactAddress {
                address: "hello@northwind.example".into(),
                accepted_name: Some("Northwind".into()),
            }],
        })
        .await
        .unwrap();
    let mut app = MailApp::open(backend.clone()).await.unwrap();
    app.dispatch(AppCommand::Contacts).await.unwrap();
    app.dispatch(AppCommand::ContactEdit).await.unwrap();
    assert_eq!(app.screen, Screen::ContactEdit);
    let editor = app.contact_editor.as_mut().unwrap();
    editor.display_name = "Northwind Studio".into();
    editor.addresses = "hello@northwind.example, billing@northwind.example".into();
    app.dispatch(AppCommand::EditNextField).await.unwrap();
    app.dispatch(AppCommand::EditNextField).await.unwrap();
    app.dispatch(AppCommand::EditNextField).await.unwrap();
    app.dispatch(AppCommand::EditToggleChoice).await.unwrap();
    app.dispatch(AppCommand::ContactSave).await.unwrap();

    let saved = backend.contacts().get(contact.id).await.unwrap();
    assert_eq!(saved.display_name, "Northwind Studio");
    assert_eq!(saved.addresses.len(), 2);
    let relationship = backend.contacts().relationship(contact.id).await.unwrap();
    assert_eq!(relationship.warm_route, WarmRoute::Fyi);
    assert!(!relationship.may_create_obligations);
    assert_eq!(app.screen, Screen::Contacts);

    let terminal_backend = TestBackend::new(120, 28);
    let mut terminal = Terminal::new(terminal_backend).unwrap();
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
    assert!(text.contains("Northwind Studio"));
    assert!(text.contains("FYI · does not create obligations"));
}

#[tokio::test]
async fn done_and_manual_routing_advance_without_leaving_the_source_inbox() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add(NewAccount {
            name: "Local".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    backend
        .contacts()
        .add(NewContact {
            display_name: "Northwind".into(),
            addresses: vec![ContactAddress {
                address: "hello@northwind.example".into(),
                accepted_name: Some("Northwind".into()),
            }],
        })
        .await
        .unwrap();
    for index in 0..3 {
        let mut message = IngestMessage::local(
            format!(
                "From: Northwind <hello@northwind.example>\r\nTo: reader@example.test\r\nMessage-ID: <workflow-{index}@example.test>\r\nSubject: Separate task {index}\r\n\r\nTask number {index}.\r\n"
            )
            .into_bytes(),
        );
        message.received_at = Some(1_700_000_000 + index);
        backend.ingest(message).await.unwrap();
    }

    let mut app = MailApp::open(backend.clone()).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmAction));
    assert_eq!(app.threads.len(), 3);
    let original = app
        .threads
        .iter()
        .map(|thread| thread.id)
        .collect::<Vec<_>>();

    app.dispatch(AppCommand::MoveToAction).await.unwrap();
    assert_eq!(
        backend
            .threads()
            .work_state(original[0])
            .await
            .unwrap()
            .route_override,
        None,
        "moving Action mail to Action must be a no-op"
    );

    app.dispatch(AppCommand::Open).await.unwrap();
    wait_for_reader_metadata(&mut app).await;
    assert_eq!(app.current_thread.as_ref().unwrap().summary.id, original[0]);

    app.dispatch(AppCommand::MarkDone).await.unwrap();
    assert_eq!(app.screen, Screen::Reader);
    assert_eq!(app.previous_screen, Screen::Queue(WorkflowView::WarmAction));
    wait_for_reader_metadata(&mut app).await;
    assert_eq!(app.current_thread.as_ref().unwrap().summary.id, original[1]);
    assert_eq!(
        backend
            .threads()
            .work_state(original[0])
            .await
            .unwrap()
            .status,
        ThreadWorkStatus::Done
    );

    app.dispatch(AppCommand::MoveToFyi).await.unwrap();
    assert_eq!(app.screen, Screen::Reader);
    assert_eq!(app.previous_screen, Screen::Queue(WorkflowView::WarmAction));
    wait_for_reader_metadata(&mut app).await;
    assert_eq!(app.current_thread.as_ref().unwrap().summary.id, original[2]);
    assert_eq!(
        backend
            .threads()
            .work_state(original[1])
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Fyi)
    );

    app.dispatch(AppCommand::MoveToFyi).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmAction));
    assert!(app.threads.is_empty());

    app.dispatch(AppCommand::WarmFyi).await.unwrap();
    assert_eq!(app.threads.len(), 2);
    let fyi_id = app.threads[0].id;
    app.dispatch(AppCommand::MoveToFyi).await.unwrap();
    assert_eq!(
        backend
            .threads()
            .work_state(fyi_id)
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Fyi),
        "moving FYI mail to FYI must be a no-op"
    );
    app.dispatch(AppCommand::MoveToAction).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmFyi));
    assert_eq!(app.threads.len(), 1);
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
                "Date: Tue, 14 Nov 2023 22:13:20 +0000\r\n",
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
    assert!(app.current_thread.is_none());
    assert_eq!(app.reader_load_status(), Some("Opening conversation…"));
    wait_for_reader_metadata(&mut app).await;
    assert!(app.reader_is_blocked());
    app.dispatch(AppCommand::ReaderNextLink).await.unwrap();
    app.dispatch(AppCommand::ReaderOpenLink).await.unwrap();
    assert_eq!(app.reader_selected_link(), None);
    assert!(app.take_external_url_request().is_none());

    let compact_backend = TestBackend::new(100, 12);
    let mut compact_terminal = Terminal::new(compact_backend).unwrap();
    compact_terminal
        .draw(|frame| lizard_mail_tui::ui::draw(frame, &app))
        .unwrap();
    let compact_text = compact_terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .map(|cell| cell.symbol())
        .collect::<String>();
    assert!(compact_text.contains("O] Read restricted"));
    assert!(compact_text.contains("Choose how to continue"));

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
    assert!(text.contains("Visible From: support@chase.com.evil.wtf"));
    assert!(text.contains("Replies go to: payments@different.example"));
    assert!(text.contains("Received:"));
    assert!(text.contains("Message claims sent:"));
    assert!(text.contains("RESTRICTED VIEW"));
    assert!(text.contains('╱'));
    let caution_cells = terminal
        .backend()
        .buffer()
        .content()
        .iter()
        .filter(|cell| {
            matches!(
                (cell.fg, cell.bg),
                (Color::Black, Color::Yellow) | (Color::Yellow, Color::Black)
            )
        })
        .count();
    assert!(
        caution_cells >= 120,
        "restricted mode should have a conspicuous yellow/black perimeter"
    );
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

#[tokio::test]
async fn similar_fyi_rule_requires_a_visible_preview_before_moving_mail() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .accounts()
        .add(NewAccount {
            name: "Local".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();
    backend
        .contacts()
        .add(NewContact {
            display_name: "Northwind News".into(),
            addresses: vec![ContactAddress {
                address: "news@northwind.example".into(),
                accepted_name: Some("Northwind News".into()),
            }],
        })
        .await
        .unwrap();
    let seed = backend
        .ingest(IngestMessage::local(
            b"From: Northwind News <news@northwind.example>\r\nTo: reader@example.test\r\nMessage-ID: <news-one@example.test>\r\nSubject: January blue widget offers\r\n\r\nWeekly product newsletter. Save twenty percent on blue widgets. Browse featured products and seasonal offers.\r\n"
                .to_vec(),
        ))
        .await
        .unwrap();
    backend
        .ingest(IngestMessage::local(
            b"From: Northwind News <news@northwind.example>\r\nTo: reader@example.test\r\nMessage-ID: <news-two@example.test>\r\nSubject: January blue widget offers\r\n\r\nWeekly product newsletter. Save twenty percent on blue widgets. Browse featured products and seasonal offers.\r\n"
                .to_vec(),
        ))
        .await
        .unwrap();
    let seed_thread = backend
        .messages()
        .get(seed)
        .await
        .unwrap()
        .summary
        .thread_id;
    let mut app = MailApp::open(backend.clone()).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmAction));

    app.dispatch(AppCommand::PreviewSimilarFyi).await.unwrap();
    assert_eq!(app.screen, Screen::SimilarityPreview);
    assert!(app
        .similarity_preview
        .as_ref()
        .is_some_and(|preview| preview.matches.len() >= 2));
    assert_eq!(
        backend
            .threads()
            .work_state(seed_thread)
            .await
            .unwrap()
            .route_override,
        None,
        "opening the preview must not move mail"
    );

    let terminal_backend = TestBackend::new(120, 34);
    let mut terminal = Terminal::new(terminal_backend).unwrap();
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
    assert!(text.contains("Confirm sender-scoped similar-mail rule"));
    assert!(text.contains("January blue widget offers"));
    assert!(text.contains("Weekly product newsletter"));

    app.dispatch(AppCommand::SimilarityConfirm).await.unwrap();
    assert_eq!(app.screen, Screen::Queue(WorkflowView::WarmFyi));
    assert_eq!(backend.similarity_rules().list().await.unwrap().len(), 1);
    assert_eq!(
        backend
            .threads()
            .work_state(seed_thread)
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Fyi)
    );
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
    wait_for_reader_metadata(&mut app).await;
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
    assert!(app.reader_html_error().is_none());
    tokio::time::timeout(Duration::from_secs(2), async {
        while app.reader_html_error().is_none() {
            app.prepare_reader_html(118).await;
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HTML worker failure should be collected in the background");

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
