use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ContactAddress, ContactRelationship, FolderKind,
    ImapSecurity, ImapSettings, IngestMessage, NewAccount, NewContact, NewContactRelationship,
    NewFolder, RelationshipKind, RemoteContentPolicy, RemoteMessageIdentity, RouteOverrideSource,
    ThreadFilter, ThreadWorkStatus, UserClassification, WarmRoute, WorkflowView,
    DEFAULT_SIMILARITY_CUTOFF_MILLIS,
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

    let manual_action = backend
        .threads()
        .set_route_override(maya_thread, Some(WarmRoute::Action))
        .await
        .unwrap();
    assert_eq!(manual_action.route_override, Some(WarmRoute::Action));
    assert_eq!(
        manual_action.route_override_source,
        Some(RouteOverrideSource::Manual)
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
    let manual_fyi = backend
        .threads()
        .set_route_override(maya_thread, Some(WarmRoute::Fyi))
        .await
        .unwrap();
    assert_eq!(manual_fyi.route_override, Some(WarmRoute::Fyi));
    assert_eq!(
        manual_fyi.route_override_source,
        Some(RouteOverrideSource::Manual)
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
    let fyi_after_done = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::WarmFyi),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(fyi_after_done.items.len(), 1);
    assert_eq!(fyi_after_done.items[0].id, maya_thread);
    assert_eq!(
        fyi_after_done.items[0].work_state.status,
        ThreadWorkStatus::Done
    );

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
    let fyi_error = backend
        .threads()
        .set_route_override(mallory_thread, Some(WarmRoute::Fyi))
        .await
        .unwrap_err();
    assert!(fyi_error
        .to_string()
        .contains("FYI routing requires a known contact"));
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

#[tokio::test]
async fn warm_workflows_page_active_before_done_then_sort_each_tier_by_date() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let contact = backend
        .contacts()
        .add(NewContact {
            display_name: "Ada".into(),
            addresses: vec![ContactAddress {
                address: "ada@example.test".into(),
                accepted_name: Some("Ada".into()),
            }],
        })
        .await
        .unwrap();
    backend
        .contacts()
        .set_relationship(
            contact.id,
            ContactRelationship {
                contact_id: contact.id,
                kind: RelationshipKind::Person,
                warm_route: WarmRoute::Action,
                may_create_obligations: true,
                notify: true,
                remote_content: RemoteContentPolicy::Ask,
                updated_at: 0,
            },
        )
        .await
        .unwrap();

    let mut threads = Vec::new();
    for (index, received_at) in [1_700_000_001, 1_700_000_002, 1_700_000_003]
        .into_iter()
        .enumerate()
    {
        let mut request = IngestMessage::local(message(
            "Ada",
            "ada@example.test",
            &format!("tier-{index}@example.test"),
            &format!("Independent task {index}"),
        ));
        request.received_at = Some(received_at);
        request.user_classification = Some(UserClassification::NotSpam);
        let message_id = backend.ingest(request).await.unwrap();
        let summary = backend.messages().get(message_id).await.unwrap().summary;
        assert_eq!(summary.inbox_class, lizard_mail_backend::InboxClass::Warm);
        threads.push(summary.thread_id);
    }
    backend
        .threads()
        .set_work_state(threads[2], ThreadWorkStatus::Done, None)
        .await
        .unwrap();

    let all_threads = backend
        .threads()
        .list(ThreadFilter::default())
        .await
        .unwrap();
    let warm_threads = backend
        .threads()
        .list(ThreadFilter {
            inbox_class: Some(lizard_mail_backend::InboxClass::Warm),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert_eq!(all_threads.items.len(), 3, "all={all_threads:?}");
    assert_eq!(warm_threads.items.len(), 3, "warm={warm_threads:?}");

    let mut cursor = None;
    let mut observed = Vec::new();
    loop {
        let page = backend
            .threads()
            .list(ThreadFilter {
                workflow: Some(WorkflowView::WarmAction),
                page_size: 1,
                cursor,
                ..ThreadFilter::default()
            })
            .await
            .unwrap();
        observed.extend(
            page.items
                .into_iter()
                .map(|item| (item.id, item.latest_received_at, item.work_state.status)),
        );
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(
        observed,
        vec![
            (threads[1], 1_700_000_002, ThreadWorkStatus::Active),
            (threads[0], 1_700_000_001, ThreadWorkStatus::Active),
            (threads[2], 1_700_000_003, ThreadWorkStatus::Done),
        ]
    );
}

#[tokio::test]
async fn similar_mail_preview_is_sender_scoped_and_manual_corrections_win() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
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
    backend
        .contacts()
        .add(NewContact {
            display_name: "Unrelated News".into(),
            addresses: vec![ContactAddress {
                address: "news@unrelated.example".into(),
                accepted_name: Some("Unrelated News".into()),
            }],
        })
        .await
        .unwrap();

    async fn ingest_news(
        backend: &Backend,
        sender: &str,
        id: &str,
        subject: &str,
        body: &str,
    ) -> lizard_mail_backend::MessageId {
        backend
            .ingest(IngestMessage::local(
                format!(
                    "From: News <{sender}>\r\nTo: reader@example.test\r\nMessage-ID: <{id}>\r\nSubject: {subject}\r\n\r\n{body}\r\n"
                )
                .into_bytes(),
            ))
            .await
            .unwrap()
    }

    let template = "Weekly product newsletter. Save twenty percent on blue widgets. Browse featured products and seasonal offers.";
    let seed = ingest_news(
        &backend,
        "news@northwind.example",
        "northwind-january@example.test",
        "January blue widget offers",
        template,
    )
    .await;
    let similar = ingest_news(
        &backend,
        "news@northwind.example",
        "northwind-february@example.test",
        "February blue widget offers",
        "Weekly product newsletter. Save thirty percent on blue widgets. Browse featured products and seasonal offers.",
    )
    .await;
    let unrelated = ingest_news(
        &backend,
        "news@northwind.example",
        "northwind-invoice@example.test",
        "Invoice 9281 requires approval",
        "Your invoice is due Friday. Review the attached accounting statement and approve payment in the official portal.",
    )
    .await;
    let other_sender = ingest_news(
        &backend,
        "news@unrelated.example",
        "unrelated-january@example.test",
        "January blue widget offers",
        template,
    )
    .await;

    let preview = backend
        .similarity_rules()
        .preview(seed, WarmRoute::Fyi, DEFAULT_SIMILARITY_CUTOFF_MILLIS, 50)
        .await
        .unwrap();
    let preview_ids = preview
        .matches
        .iter()
        .map(|matched| matched.message.id)
        .collect::<std::collections::HashSet<_>>();
    assert!(preview_ids.contains(&seed));
    assert!(preview_ids.contains(&similar));
    assert!(!preview_ids.contains(&unrelated));
    assert!(!preview_ids.contains(&other_sender));
    assert!(preview.matches.iter().all(|matched| matched.would_move));

    let late_match = ingest_news(
        &backend,
        "news@northwind.example",
        "northwind-preview-race@example.test",
        "Preview-race blue widget offers",
        "Weekly product newsletter. Save forty percent on blue widgets. Browse featured products and seasonal offers.",
    )
    .await;
    let changed_error = backend
        .similarity_rules()
        .create_from_preview(&preview)
        .await
        .unwrap_err();
    assert!(changed_error
        .to_string()
        .contains("match set changed after preview"));
    assert_eq!(
        backend
            .threads()
            .work_state(
                backend
                    .messages()
                    .get(late_match)
                    .await
                    .unwrap()
                    .summary
                    .thread_id
            )
            .await
            .unwrap()
            .route_override,
        None
    );
    let refreshed_preview = backend
        .similarity_rules()
        .preview(seed, WarmRoute::Fyi, DEFAULT_SIMILARITY_CUTOFF_MILLIS, 50)
        .await
        .unwrap();
    let application = backend
        .similarity_rules()
        .create_from_preview(&refreshed_preview)
        .await
        .unwrap();
    assert_eq!(
        application.matching_messages,
        refreshed_preview.matching_messages
    );
    assert!(application.matching_messages >= 1);
    let seed_thread = backend
        .messages()
        .get(seed)
        .await
        .unwrap()
        .summary
        .thread_id;
    assert_eq!(
        backend
            .threads()
            .work_state(seed_thread)
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Fyi)
    );
    let fyi = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::WarmFyi),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert!(fyi.items.iter().any(|item| item.id == seed_thread));

    backend
        .threads()
        .set_route_override(seed_thread, Some(WarmRoute::Action))
        .await
        .unwrap();
    let future = ingest_news(
        &backend,
        "news@northwind.example",
        "northwind-march@example.test",
        "March blue widget offers",
        "Weekly product newsletter. Save twenty five percent on blue widgets. Browse featured products and seasonal offers.",
    )
    .await;
    let future_thread = backend
        .messages()
        .get(future)
        .await
        .unwrap()
        .summary
        .thread_id;
    assert_eq!(
        backend
            .threads()
            .work_state(future_thread)
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Fyi)
    );
    assert_eq!(
        backend
            .threads()
            .work_state(seed_thread)
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Action)
    );
    let action = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::WarmAction),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert!(action.items.iter().any(|item| item.id == seed_thread));
    let fyi = backend
        .threads()
        .list(ThreadFilter {
            workflow: Some(WorkflowView::WarmFyi),
            ..ThreadFilter::default()
        })
        .await
        .unwrap();
    assert!(fyi.items.iter().all(|item| item.id != seed_thread));

    backend
        .similarity_rules()
        .remove(application.rule.id)
        .await
        .unwrap();
    assert_eq!(
        backend
            .threads()
            .work_state(future_thread)
            .await
            .unwrap()
            .route_override,
        None
    );
    assert_eq!(
        backend
            .threads()
            .work_state(seed_thread)
            .await
            .unwrap()
            .route_override,
        Some(WarmRoute::Action)
    );
}
