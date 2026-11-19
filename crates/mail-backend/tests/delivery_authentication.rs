use lizard_mail_backend::{
    AccountKind, AuthenticationMethodKind, AuthenticationMethodResult,
    AuthenticationResultsHeaderKind, AuthenticationResultsTrust, Backend, BackendConfig,
    BackendError, DkimAuthenticationStatus, FolderKind, HeuristicSourceKind, ImapFetchedHeaders,
    ImapSecurity, ImapSettings, IngestMessage, MessageContentAvailability, NewAccount, NewFolder,
    NewHeuristic, RemoteMessageIdentity,
};

fn authentication_headers() -> &'static str {
    concat!(
        "Authentication-Results: mx.provider.example;\r\n",
        " dkim=pass header.d=example.com header.s=mail;\r\n",
        " dmarc=pass header.from=example.com;\r\n",
        " spf=pass smtp.mailfrom=return@example.com; arc=pass\r\n",
        "Authentication-Results: attacker.invalid; dkim=pass header.d=evil.example\r\n",
        "Authentication-Results: mx.provider.example; dkim=fail header.d=example.com\r\n",
        "ARC-Authentication-Results: i=1; forwarder.example; dkim=pass header.d=example.com\r\n",
    )
}

fn complete_message() -> Vec<u8> {
    format!(
        concat!(
            "From: Example Service <notices@example.com>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Date: Mon, 16 Nov 2026 10:01:00 +0000\r\n",
            "Message-ID: <delivery-auth@example.com>\r\n",
            "Subject: Delivery authentication\r\n",
            "{}",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "The message itself deliberately has no DKIM-Signature.\r\n",
        ),
        authentication_headers()
    )
    .into_bytes()
}

fn projected_headers() -> Vec<u8> {
    format!(
        concat!(
            "From: Example Service <notices@example.com>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Date: Mon, 16 Nov 2026 10:01:00 +0000\r\n",
            "Message-ID: <delivery-auth-headers@example.com>\r\n",
            "Subject: Header-only delivery authentication\r\n",
            "{}",
            "MIME-Version: 1.0\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
        ),
        authentication_headers()
    )
    .into_bytes()
}

#[tokio::test]
async fn provider_results_are_account_scoped_and_never_replace_independent_dkim() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Provider fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:delivery-auth".into()),
            imap: Some(ImapSettings {
                host: "mail.example.test".into(),
                port: 993,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    let account = backend
        .accounts()
        .set_trusted_authserv_ids(account.id, vec!["MX.Provider.Example.".into()])
        .await
        .unwrap();
    assert_eq!(account.trusted_authserv_ids, ["mx.provider.example"]);
    assert!(matches!(
        backend
            .accounts()
            .set_trusted_authserv_ids(account.id, vec!["mx.example; dkim=pass".into()])
            .await,
        Err(BackendError::InvalidInput(_))
    ));

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
    let id = backend
        .messages()
        .ingest(IngestMessage {
            raw: complete_message(),
            remote: Some(RemoteMessageIdentity {
                account_id: account.id,
                folder_id: folder.id,
                uid_validity: 7,
                uid: 12,
                mod_sequence: None,
                flags: Vec::new(),
            }),
            received_at: Some(1_795_000_000),
            user_classification: None,
        })
        .await
        .unwrap();

    let message = backend.messages().get(id).await.unwrap();
    assert_eq!(message.dkim.status, DkimAuthenticationStatus::Unsigned);
    let headers = &message.delivery_authentication.observations[0].headers;
    assert_eq!(headers.len(), 4);
    assert_eq!(headers[0].trust, AuthenticationResultsTrust::Trusted);
    assert_eq!(
        headers[0]
            .methods
            .iter()
            .map(|method| (method.kind, method.result))
            .collect::<Vec<_>>(),
        vec![
            (
                AuthenticationMethodKind::Dkim,
                AuthenticationMethodResult::Pass
            ),
            (
                AuthenticationMethodKind::Dmarc,
                AuthenticationMethodResult::Pass
            ),
            (
                AuthenticationMethodKind::Spf,
                AuthenticationMethodResult::Pass
            ),
            (
                AuthenticationMethodKind::Arc,
                AuthenticationMethodResult::Pass
            ),
        ]
    );
    assert_eq!(
        headers[1].trust,
        AuthenticationResultsTrust::AuthservIdNotTrusted
    );
    assert_eq!(
        headers[2].trust,
        AuthenticationResultsTrust::DuplicateTrustedAuthservId
    );
    assert_eq!(
        headers[3].kind,
        AuthenticationResultsHeaderKind::ArcAuthenticationResults
    );
    assert_eq!(headers[3].arc_instance, Some(1));
    assert_eq!(
        headers[3].trust,
        AuthenticationResultsTrust::ArcChainUnverified
    );
    assert!(message
        .findings
        .iter()
        .all(|finding| !finding.code.to_ascii_lowercase().contains("spf")));

    let delivery_rule = NewHeuristic {
        name: "Trusted DMARC pass".into(),
        source_kind: HeuristicSourceKind::User,
        enabled: true,
        source: r#"
@heuristic
def detect(message):
    if message.authentication.delivery.dmarc.status == "pass":
        yield Finding(
            code="trusted_dmarc_pass",
            presentation=MessageAnnotation,
            severity=Information,
        )
"#
        .into(),
    };
    let preview = backend
        .heuristics()
        .preview(&delivery_rule, &[id])
        .await
        .unwrap();
    assert_eq!(preview.affected_messages, 1);
    assert_eq!(preview.samples[0].findings[0].code, "trusted_dmarc_pass");
    let delivery_rule = backend.heuristics().add(delivery_rule).await.unwrap();
    backend.heuristics().evaluate_message(id).await.unwrap();
    let before_revision = backend
        .heuristics()
        .evaluations(id)
        .await
        .unwrap()
        .into_iter()
        .find(|evaluation| evaluation.heuristic_id == delivery_rule.id)
        .unwrap()
        .evidence_revision;

    backend
        .accounts()
        .set_trusted_authserv_ids(account.id, vec!["different.provider.example".into()])
        .await
        .unwrap();
    backend.heuristics().evaluate_message(id).await.unwrap();
    let message = backend.messages().get(id).await.unwrap();
    assert_eq!(
        message.delivery_authentication.observations[0].headers[0].trust,
        AuthenticationResultsTrust::AuthservIdNotTrusted
    );
    assert!(message
        .findings
        .iter()
        .all(|finding| finding.code != "trusted_dmarc_pass"));
    let after_revision = backend
        .heuristics()
        .evaluations(id)
        .await
        .unwrap()
        .into_iter()
        .find(|evaluation| evaluation.heuristic_id == delivery_rule.id)
        .unwrap()
        .evidence_revision;
    assert_ne!(before_revision, after_revision);
}

#[tokio::test]
async fn header_first_sync_captures_delivery_evidence_and_local_imports_do_not_trust_it() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Header fixture".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:headers".into()),
            imap: Some(ImapSettings {
                host: "mail.example.test".into(),
                port: 993,
                username: "reader@example.test".into(),
                security: ImapSecurity::ImplicitTls,
            }),
        })
        .await
        .unwrap();
    backend
        .accounts()
        .set_trusted_authserv_ids(account.id, vec!["mx.provider.example".into()])
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
    let result = backend
        .sync()
        .ingest_imap_header_batch(
            account.id,
            folder.id,
            9,
            vec![ImapFetchedHeaders {
                uid: 19,
                mod_sequence: None,
                flags: Vec::new(),
                internal_date: Some(1_795_000_000),
                size_bytes: 8_192,
                has_attachment: false,
                headers: projected_headers(),
            }],
        )
        .await
        .unwrap();
    let message = backend.messages().get(result.message_ids[0]).await.unwrap();
    assert_eq!(
        message.summary.content_availability,
        MessageContentAvailability::HeadersOnly
    );
    assert_eq!(message.dkim.status, DkimAuthenticationStatus::NotEvaluated);
    assert_eq!(
        message.delivery_authentication.observations[0].headers[0].trust,
        AuthenticationResultsTrust::Trusted
    );

    let local_id = backend
        .messages()
        .ingest(IngestMessage::local(complete_message()))
        .await
        .unwrap();
    let local = backend.messages().get(local_id).await.unwrap();
    assert_eq!(
        local.delivery_authentication.observations[0].headers[0].trust,
        AuthenticationResultsTrust::NoReceivingAccount
    );
}
