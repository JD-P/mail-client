use lizard_mail_backend::{
    Backend, BackendConfig, FilterAction, FilterCondition, FindingPresentation, FindingSeverity,
    FolderKind, HeuristicSourceKind, IngestMessage, NewFilterRule, NewFolder, NewHeuristic,
};

fn fixture() -> Vec<u8> {
    concat!(
        "From: Billing <receipts@example.com>\r\n",
        "To: Reader <reader@example.net>\r\n",
        "Date: Mon, 16 Nov 2026 12:30:00 +0000\r\n",
        "Message-ID: <automation-1@example.com>\r\n",
        "Subject: November invoice\r\n",
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=automation-boundary\r\n",
        "\r\n",
        "--automation-boundary\r\n",
        "Content-Type: text/plain; charset=utf-8\r\n",
        "\r\n",
        "The cobalt invoice is attached. Review https://login.example.org/reset\r\n",
        "--automation-boundary\r\n",
        "Content-Type: application/pdf; name=invoice.pdf\r\n",
        "Content-Disposition: attachment; filename=invoice.pdf\r\n",
        "Content-Transfer-Encoding: base64\r\n",
        "\r\n",
        "JVBERi0xLjQK\r\n",
        "--automation-boundary--\r\n"
    )
    .as_bytes()
    .to_vec()
}

#[tokio::test]
async fn filters_and_python_shaped_heuristics_execute_during_ingest() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let receipts = backend
        .folders()
        .add(NewFolder {
            account_id: None,
            name: "Receipts".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();
    let later = backend
        .folders()
        .add(NewFolder {
            account_id: None,
            name: "Should not run".into(),
            kind: FolderKind::Local,
            remote_name: None,
        })
        .await
        .unwrap();

    let first_rule = backend
        .filter_rules()
        .add(NewFilterRule {
            name: "PDF receipts".into(),
            priority: 10,
            enabled: true,
            conditions: vec![
                FilterCondition::SenderAddressEquals {
                    value: "receipts@example.com".into(),
                },
                FilterCondition::SubjectContains {
                    value: "invoice".into(),
                },
                FilterCondition::AttachmentDeclaredType {
                    value: "application/pdf".into(),
                },
            ],
            actions: vec![
                FilterAction::MoveToLocalFolder {
                    folder_id: receipts.id,
                },
                FilterAction::Stop,
            ],
        })
        .await
        .unwrap();
    backend
        .filter_rules()
        .add(NewFilterRule {
            name: "Blocked by Stop".into(),
            priority: 20,
            enabled: true,
            conditions: vec![FilterCondition::HasAttachment { value: true }],
            actions: vec![FilterAction::MoveToLocalFolder {
                folder_id: later.id,
            }],
        })
        .await
        .unwrap();

    let heuristic = backend
        .heuristics()
        .add(NewHeuristic {
            name: "PDF annotation".into(),
            source_kind: HeuristicSourceKind::User,
            enabled: true,
            source: r#"
@heuristic
def detect(message):
    if message.sender.domain != "example.com":
        return
    for attachment in message.attachments:
        if attachment.declared_type == "application/pdf":
            yield Finding(
                code="pdf_attachment",
                presentation=AttachmentInterstitial,
                severity=Warning,
                target=attachment.id,
                text="This PDF matched your local heuristic.",
                evidence={"name": attachment.name},
            )
    for link in message.links:
        if link.registrable_domain != message.sender.registrable_domain:
            yield Finding(
                code="cross_domain_link",
                presentation=LinkInterstitial,
                severity=Danger,
                target=link.id,
                evidence={"destination": link.destination},
            )
"#
            .into(),
        })
        .await
        .unwrap();
    assert_eq!(
        heuristic.required_features,
        vec!["attachments", "headers", "links"]
    );

    let message_id = backend
        .messages()
        .ingest(IngestMessage::local(fixture()))
        .await
        .unwrap();
    let message = backend.messages().get(message_id).await.unwrap();
    assert_eq!(message.local_folder_ids, vec![receipts.id]);
    assert_eq!(message.links.len(), 1);
    assert_eq!(message.links[0].id, "link:0");
    assert_eq!(
        message.links[0].registrable_domain.as_deref(),
        Some("example.org")
    );
    assert_eq!(
        message
            .findings
            .iter()
            .filter(|finding| finding.heuristic_id == heuristic.id)
            .count(),
        2
    );
    let finding = message
        .findings
        .iter()
        .find(|finding| finding.code == "pdf_attachment")
        .unwrap();
    assert_eq!(finding.code, "pdf_attachment");
    assert_eq!(
        finding.presentation,
        FindingPresentation::AttachmentInterstitial
    );
    assert_eq!(finding.severity, FindingSeverity::Warning);
    assert_eq!(finding.target_id.as_deref(), Some("attachment:0"));
    assert_eq!(finding.evidence["name"], "invoice.pdf");

    let applications = backend
        .filter_rules()
        .applications(message_id)
        .await
        .unwrap();
    assert_eq!(applications.len(), 1);
    assert_eq!(applications[0].rule_id, first_rule.id);
    assert!(backend
        .filter_rules()
        .evaluate_message(message_id)
        .await
        .unwrap()
        .is_empty());

    let replacement = backend
        .heuristics()
        .evaluate_message(message_id)
        .await
        .unwrap();
    assert_eq!(
        replacement
            .iter()
            .filter(|finding| finding.heuristic_id == heuristic.id)
            .count(),
        2
    );
    let replacement_id = replacement
        .iter()
        .find(|finding| finding.code == "pdf_attachment")
        .unwrap()
        .id;
    assert_eq!(replacement_id, finding.id);
    backend
        .heuristics()
        .dismiss_finding(replacement_id)
        .await
        .unwrap();
    backend
        .heuristics()
        .evaluate_message(message_id)
        .await
        .unwrap();
    let message = backend.messages().get(message_id).await.unwrap();
    assert!(message
        .findings
        .iter()
        .find(|finding| finding.id == replacement_id)
        .unwrap()
        .dismissed_at
        .is_some());

    drop(backend);
    let reopened = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let message = reopened.messages().get(message_id).await.unwrap();
    assert_eq!(message.local_folder_ids, vec![receipts.id]);
    assert_eq!(
        message
            .findings
            .iter()
            .filter(|finding| finding.heuristic_id == heuristic.id)
            .count(),
        2
    );
    assert!(message
        .findings
        .iter()
        .find(|finding| finding.id == replacement_id)
        .unwrap()
        .dismissed_at
        .is_some());
    assert_eq!(
        reopened
            .heuristics()
            .evaluations(message_id)
            .await
            .unwrap()
            .iter()
            .filter(|evaluation| evaluation.heuristic_id == heuristic.id)
            .count(),
        1
    );
}

#[tokio::test]
async fn invalid_rule_authority_is_rejected_before_activation() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let error = backend
        .heuristics()
        .add(NewHeuristic {
            name: "Not allowed".into(),
            source_kind: HeuristicSourceKind::User,
            enabled: true,
            source: r#"
@heuristic
def detect(message):
    open("/tmp/stolen", "w")
"#
            .into(),
        })
        .await
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("standalone expressions are forbidden"));
    assert!(backend
        .heuristics()
        .list()
        .await
        .unwrap()
        .iter()
        .all(|heuristic| heuristic.source_kind == HeuristicSourceKind::BuiltIn));
}

#[tokio::test]
async fn empty_conditions_and_stop_only_form_a_catch_all_barrier() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let barrier = backend
        .filter_rules()
        .add(NewFilterRule {
            name: "Do not run later filters".into(),
            priority: 0,
            enabled: true,
            conditions: Vec::new(),
            actions: vec![FilterAction::Stop],
        })
        .await
        .unwrap();

    let message_id = backend
        .messages()
        .ingest(IngestMessage::local(fixture()))
        .await
        .unwrap();
    let applications = backend
        .filter_rules()
        .applications(message_id)
        .await
        .unwrap();
    assert_eq!(applications.len(), 1);
    assert_eq!(applications[0].rule_id, barrier.id);
    assert_eq!(applications[0].actions, vec![FilterAction::Stop]);
}
