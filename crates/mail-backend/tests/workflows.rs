use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ContactAddress, ContactRelationship, FolderKind,
    ImapSecurity, ImapSettings, IngestMessage, NewAccount, NewContact, NewContactRelationship,
    NewFolder, RelationshipKind, RemoteContentPolicy, RemoteMessageIdentity, ThreadFilter,
    ThreadWorkStatus, WarmRoute, WorkflowView,
};

fn message(from_name: &str, from: &str, id: &str, subject: &str) -> Vec<u8> {
    format!(
        "From: {from_name} <{from}>\r\nTo: reader@example.test\r\nMessage-ID: <{id}>\r\nSubject: {subject}\r\n\r\nHello from {from_name}.\r\n"
    )
    .into_bytes()
}

#[tokio::test]
async fn onboarding_seeds_relationships_and_workflow_views_remain_independent() {
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

    let mut request = IngestMessage::local(message(
        "Maya Chen",
        "maya@example.test",
        "maya-1@example.test",
        "Review request",
    ));
    request.received_at = Some(1_800_000_000);
    request.remote = Some(RemoteMessageIdentity {
        account_id: account.id,
        folder_id: folder.id,
        uid_validity: 7,
        uid: 1,
        mod_sequence: None,
        flags: Vec::new(),
    });
    let maya_message = backend.ingest(request).await.unwrap();
    let maya_thread = backend
        .messages()
        .get(maya_message)
        .await
        .unwrap()
        .summary
        .thread_id;

    let mut outgoing = IngestMessage::local(
        b"From: Reader <reader@example.test>\r\nTo: Jo <jo@example.test>\r\nMessage-ID: <reader-to-jo@example.test>\r\nSubject: Checking in\r\n\r\nHello Jo.\r\n"
            .to_vec(),
    );
    outgoing.received_at = Some(1_800_000_001);
    outgoing.remote = Some(RemoteMessageIdentity {
        account_id: account.id,
        folder_id: folder.id,
        uid_validity: 7,
        uid: 2,
        mod_sequence: None,
        flags: Vec::new(),
    });
    backend.ingest(outgoing).await.unwrap();

    let cold = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::ColdReview),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(cold.items.len(), 1);

    let suggestions = backend
        .onboarding()
        .contact_suggestions(account.id, 1_700_000_000, 20)
        .await
        .unwrap();
    assert_eq!(suggestions.len(), 2);
    assert_eq!(suggestions[0].address, "jo@example.test");
    assert_eq!(suggestions[1].address, "maya@example.test");
    assert_eq!(suggestions[1].suggested_warm_route, WarmRoute::Action);

    let contact = backend
        .onboarding()
        .accept_contact(
            account.id,
            "maya@example.test",
            NewContact {
                display_name: "Maya Chen".into(),
                addresses: vec![ContactAddress {
                    address: "maya@example.test".into(),
                    accepted_name: Some("Maya Chen".into()),
                }],
            },
            NewContactRelationship::default(),
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .onboarding()
            .contact_suggestions(account.id, 1_700_000_000, 20)
            .await
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        backend
            .threads()
            .list(ThreadFilter {
                workflow: Some(WorkflowView::WarmAction),
                ..ThreadFilter::default()
            })
            .await
            .unwrap()
            .items
            .len(),
        1
    );

    backend
        .contacts()
        .set_relationship(
            contact.id,
            ContactRelationship {
                contact_id: contact.id,
                kind: RelationshipKind::Person,
                warm_route: WarmRoute::Fyi,
                may_create_obligations: false,
                notify: false,
                remote_content: RemoteContentPolicy::Ask,
                updated_at: 0,
            },
        )
        .await
        .unwrap();
    assert_eq!(
        backend
            .threads()
            .list(ThreadFilter {
                workflow: Some(WorkflowView::WarmFyi),
                ..ThreadFilter::default()
            })
            .await
            .unwrap()
            .items
            .len(),
        1
    );

    backend
        .threads()
        .set_work_state(maya_thread, ThreadWorkStatus::Done, None)
        .await
        .unwrap();
    let done = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::Done),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(done.items.len(), 1);

    let mallory = backend
        .ingest(IngestMessage::local(message(
            "Mallory",
            "mallory@example.test",
            "mallory-1@example.test",
            "One-off request",
        )))
        .await
        .unwrap();
    let mallory_thread = backend
        .messages()
        .get(mallory)
        .await
        .unwrap()
        .summary
        .thread_id;
    backend
        .threads()
        .set_actionable_once(mallory_thread, true)
        .await
        .unwrap();
    let action = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::WarmAction),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(action.items.len(), 1);
    assert_eq!(action.items[0].id, mallory_thread);
    assert!(action.items[0].work_state.actionable_once);
}
