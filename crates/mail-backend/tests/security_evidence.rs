use base64::Engine;
use lizard_mail_backend::{
    ArchiveInspectionState, ArchiveLimits, Backend, BackendConfig, ContactAddress, IngestMessage,
    NewContact,
};
use std::collections::BTreeSet;
use std::io::{Cursor, Write};
use zip::write::SimpleFileOptions;

fn message(
    from: &str,
    subject: &str,
    extra_headers: &str,
    content_type: &str,
    body: &str,
) -> Vec<u8> {
    format!(
        concat!(
            "From: {from}\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Date: Mon, 16 Nov 2026 12:00:00 +0000\r\n",
            "Message-ID: <{message_id}@fixture.test>\r\n",
            "Subject: {subject}\r\n",
            "{extra_headers}",
            "MIME-Version: 1.0\r\n",
            "Content-Type: {content_type}\r\n",
            "\r\n",
            "{body}\r\n"
        ),
        from = from,
        message_id = uuid::Uuid::new_v4(),
        subject = subject,
        extra_headers = extra_headers,
        content_type = content_type,
        body = body,
    )
    .into_bytes()
}

fn codes(message: &lizard_mail_backend::Message) -> BTreeSet<&str> {
    message
        .findings
        .iter()
        .map(|finding| finding.code.as_str())
        .collect()
}

fn assert_codes(message: &lizard_mail_backend::Message, expected: &[&str]) {
    let actual = codes(message);
    for expected in expected {
        assert!(
            actual.contains(expected),
            "missing {expected:?}; actual findings were {actual:?}"
        );
    }
}

fn zip(entries: &[(&str, &[u8])], method: zip::CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(method);
    for (name, bytes) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(bytes).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn attachment_part(boundary: &str, name: &str, media_type: &str, bytes: &[u8]) -> String {
    format!(
        concat!(
            "--{boundary}\r\n",
            "Content-Type: {media_type}; name=\"{name}\"\r\n",
            "Content-Disposition: attachment; filename=\"{name}\"\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "{encoded}\r\n"
        ),
        boundary = boundary,
        media_type = media_type,
        name = name,
        encoded = base64::engine::general_purpose::STANDARD.encode(bytes),
    )
}

#[tokio::test]
async fn native_identity_evidence_uses_contacts_and_separates_sender_fields() {
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
                accepted_name: Some("Franklin".into()),
            }],
        })
        .await
        .unwrap();

    let known_id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "Chase Bank <frank@example.test>",
            "Account notice",
            concat!(
                "Sender: dispatcher@third-party.example\r\n",
                "Reply-To: Payments <payments@unrelated.example>\r\n"
            ),
            "text/plain; charset=utf-8",
            "Please read this notice.",
        )))
        .await
        .unwrap();
    let known = backend.messages().get(known_id).await.unwrap();
    assert_eq!(
        known.sender_addresses,
        vec!["dispatcher@third-party.example"]
    );
    assert_codes(
        &known,
        &[
            "warm_sender_name_mismatch",
            "sender_from_mismatch",
            "reply_to_mismatch",
        ],
    );

    let cold_id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "Frank <stranger@unrelated.example>",
            "Hello",
            "",
            "text/plain; charset=utf-8",
            "Hello from Frank.",
        )))
        .await
        .unwrap();
    assert_codes(
        &backend.messages().get(cold_id).await.unwrap(),
        &["cold_contact_name_collision"],
    );

    let root_id = backend
        .messages()
        .ingest(IngestMessage::local(
            concat!(
                "From: Frank <frank@example.test>\r\n",
                "To: Reader <reader@example.test>\r\n",
                "Date: Mon, 16 Nov 2026 12:01:00 +0000\r\n",
                "Message-ID: <established-thread@example.test>\r\n",
                "Subject: Private conversation\r\n\r\n",
                "The established message.\r\n"
            )
            .as_bytes(),
        ))
        .await
        .unwrap();
    assert!(backend.messages().get(root_id).await.is_ok());
    let injection_id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "Attacker <attacker@unrelated.example>",
            "Re: Private conversation",
            concat!(
                "In-Reply-To: <established-thread@example.test>\r\n",
                "References: <established-thread@example.test>\r\n"
            ),
            "text/plain; charset=utf-8",
            "I claim to belong in the trusted conversation.",
        )))
        .await
        .unwrap();
    assert_codes(
        &backend.messages().get(injection_id).await.unwrap(),
        &["conversation_injection"],
    );

    let builtin = backend
        .heuristics()
        .list()
        .await
        .unwrap()
        .into_iter()
        .find(|heuristic| heuristic.source == "native:security-evidence")
        .unwrap();
    assert!(builtin.enabled);
    assert!(backend.heuristics().remove(builtin.id).await.is_err());
}

#[tokio::test]
async fn native_navigation_evidence_parses_html_without_loading_or_executing_it() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let body = concat!(
        "<style>body{background:url(https://tracker.example/open-css)}</style>",
        "<a href=\"https://accounts.example.com@evil.example:8443/login?next=https%3A%2F%2Faccounts.example.com\">accounts.example.com</a>",
        "<a href=\"http://192.0.2.10/login\">Sign in</a>",
        "<a href=\"javascript:document.location='https://evil.example'\">Continue</a>",
        "<a href=\"https://раypal.com/login\">paypal.com</a>",
        "<a href=\"https://paypaI.com/login\">paypal.com</a>",
        "<a href=\"https://paypal.com\u{202e}.evil.example/login\">paypal.com</a>",
        "<form action=\"https://evil.example/collect\"><input name=password type=password></form>",
        "<img src=\"https://tracker.example/open.gif?recipient=reader\">"
    );
    let id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "Accounts <accounts@example.com>",
            "Reset your account password",
            "",
            "text/html; charset=utf-8",
            body,
        )))
        .await
        .unwrap();
    let stored = backend.messages().get(id).await.unwrap();
    assert_codes(
        &stored,
        &[
            "misleading_link_text",
            "misleading_userinfo",
            "raw_ip_destination",
            "unusual_port",
            "dangerous_scheme",
            "nested_redirect",
            "unicode_confusable_domain",
            "ascii_confusable_domain",
            "invisible_or_bidi_domain",
            "cross_domain_account_action",
            "remote_tracking_resource",
            "interactive_credential_form",
        ],
    );
    let form = stored
        .findings
        .iter()
        .find(|finding| finding.code == "interactive_credential_form")
        .unwrap();
    assert_eq!(form.evidence["forms"][0]["password_input"], true);
    let resources = stored
        .findings
        .iter()
        .find(|finding| finding.code == "remote_tracking_resource")
        .unwrap();
    assert_eq!(resources.evidence["resources"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn archive_security_reads_directory_metadata_but_never_inflates_entries() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let executable_zip = zip(
        &[("documents/invoice.pdf.exe", b"not actually executed")],
        zip::CompressionMethod::Stored,
    );
    let zeros = vec![0; 2 * 1024 * 1024];
    let bomb_zip = zip(
        &[("large-document.txt", zeros.as_slice())],
        zip::CompressionMethod::Deflated,
    );
    let malformed_zip = b"PK\x03\x04deliberately truncated central directory";
    let boundary = "security-attachment-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nSee attachments.\r\n"
    );
    body.push_str(&attachment_part(
        boundary,
        "invoice.pdf",
        "application/pdf",
        b"MZ\0\0a harmless test marker",
    ));
    body.push_str(&attachment_part(
        boundary,
        "contains-program.zip",
        "application/zip",
        &executable_zip,
    ));
    body.push_str(&attachment_part(
        boundary,
        "high-ratio.zip",
        "application/zip",
        &bomb_zip,
    ));
    body.push_str(&attachment_part(
        boundary,
        "malformed.zip",
        "application/zip",
        malformed_zip,
    ));
    body.push_str(&format!("--{boundary}--\r\n"));
    let id = backend
        .messages()
        .ingest(IngestMessage::local(message(
            "Archive <archive@example.com>",
            "Attachment evidence",
            "",
            &format!("multipart/mixed; boundary={boundary}"),
            &body,
        )))
        .await
        .unwrap();
    let stored = backend.messages().get(id).await.unwrap();
    assert_codes(
        &stored,
        &[
            "attachment_type_mismatch",
            "executable_attachment",
            "executable_in_archive",
            "uninspectable_archive",
        ],
    );
    for finding in stored
        .findings
        .iter()
        .filter(|finding| finding.code == "uninspectable_archive")
    {
        assert_eq!(
            finding.evidence["inspection"],
            "zip_directory_metadata_only"
        );
        assert_eq!(finding.evidence["entries_decompressed"], 0);
    }

    let high_ratio = stored
        .attachments
        .iter()
        .find(|attachment| attachment.name.as_deref() == Some("high-ratio.zip"))
        .unwrap();
    let limits = ArchiveLimits {
        max_archive_bytes: 8 * 1024 * 1024,
        max_entries: 256,
        max_entry_bytes: 32 * 1024 * 1024,
        max_total_uncompressed_bytes: 64 * 1024 * 1024,
        max_compression_ratio: 100,
    };
    let inspection = backend
        .mime()
        .inspect_archive(id, &high_ratio.id, limits.clone())
        .await
        .unwrap();
    assert_eq!(inspection.state, ArchiveInspectionState::Limited);
    assert_eq!(inspection.entries[0].uncompressed_size, zeros.len() as u64);
    assert!(backend
        .mime()
        .read_archive_entry(id, &high_ratio.id, 0, limits)
        .await
        .is_err());
}
