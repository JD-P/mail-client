use base64::{engine::general_purpose::STANDARD, Engine};
use futures_util::future::BoxFuture;
use lizard_mail_backend::{
    ArchiveInspectionState, ArchiveIsolationConfig, ArchiveLimits, Backend, BackendConfig,
    BackendError, DocumentExtractionLimits, DocumentExtractionRequest, DocumentExtractionResult,
    IngestMessage, MimeDecodeState, MimeParseState, MimePartKind, SandboxedDocumentExtractor,
};
use std::io::{Cursor, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn archive_isolation() -> ArchiveIsolationConfig {
    ArchiveIsolationConfig {
        worker_path: PathBuf::from(env!("CARGO_BIN_EXE_lizard-mail-archive-worker")),
        wall_timeout: Duration::from_secs(10),
    }
}

fn archive_sandbox_available() -> bool {
    Command::new(env!("CARGO_BIN_EXE_lizard-mail-archive-worker"))
        .arg("--sandbox-self-test")
        .output()
        .is_ok_and(|output| output.status.success())
}

struct FixtureExtractor;

impl SandboxedDocumentExtractor for FixtureExtractor {
    fn extract<'a>(
        &'a self,
        request: DocumentExtractionRequest,
    ) -> BoxFuture<'a, lizard_mail_backend::Result<DocumentExtractionResult>> {
        Box::pin(async move {
            assert_eq!(
                request.declared_media_type.as_deref(),
                Some("application/octet-stream")
            );
            assert_eq!(
                request.detected_media_type.as_deref(),
                Some("application/zip")
            );
            assert_eq!(request.name.as_deref(), Some("bundle.zip"));
            assert!(request.bytes.starts_with(b"PK"));
            Ok(DocumentExtractionResult {
                text: "sandbox result".into(),
                truncated: false,
            })
        })
    }
}

fn zip_fixture(path: &str, contents: &[u8]) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    writer
        .start_file(
            path,
            zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Deflated),
        )
        .unwrap();
    writer.write_all(contents).unwrap();
    writer.finish().unwrap().into_inner()
}

fn message(zip: &[u8]) -> Vec<u8> {
    format!(
        concat!(
            "From: Sender <sender@example.test>\r\n",
            "To: Reader <reader@example.test>\r\n",
            "Message-ID: <mime-api@example.test>\r\n",
            "Subject: MIME API\r\n",
            "MIME-Version: 1.0\r\n",
            "Content-Type: multipart/mixed; boundary=outer\r\n",
            "\r\n",
            "--outer\r\n",
            "Content-Type: multipart/related; boundary=related\r\n",
            "\r\n",
            "--related\r\n",
            "Content-Type: multipart/alternative; boundary=alternative\r\n",
            "\r\n",
            "--alternative\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "\r\n",
            "plain body\r\n",
            "--alternative\r\n",
            "Content-Type: text/html; charset=utf-8\r\n",
            "\r\n",
            "<p>html body<img src=\"cid:hero@example.test\"></p>\r\n",
            "--alternative--\r\n",
            "--related\r\n",
            "Content-Type: image/png\r\n",
            "Content-ID: <hero@example.test>\r\n",
            "Content-Disposition: inline; filename=hero.png\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "{}\r\n",
            "--related--\r\n",
            "--outer\r\n",
            "Content-Type: application/octet-stream; name=bundle.zip\r\n",
            "Content-Disposition: attachment; filename=bundle.zip\r\n",
            "Content-Transfer-Encoding: base64\r\n",
            "\r\n",
            "{}\r\n",
            "--outer--\r\n"
        ),
        STANDARD.encode(b"\x89PNG\r\n\x1a\nfixture"),
        STANDARD.encode(zip),
    )
    .into_bytes()
}

#[tokio::test]
async fn materializes_mime_tree_and_streams_decoded_resources() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let zip = zip_fixture("folder/note.txt", b"archive payload");
    let id = backend
        .messages()
        .ingest(IngestMessage::local(message(&zip)))
        .await
        .unwrap();

    let structure = backend.mime().structure(id).await.unwrap();
    assert_eq!(structure.state, MimeParseState::Complete);
    assert_eq!(
        structure.parts[structure.root_part_id as usize].kind,
        MimePartKind::Multipart
    );
    assert_eq!(structure.plain_body_part_ids.len(), 1);
    assert_eq!(structure.html_body_part_ids.len(), 1);
    assert!(structure.parts.iter().any(|part| {
        part.content_id.as_deref() == Some("hero@example.test")
            && part.decode_state == MimeDecodeState::Complete
    }));

    let stored = backend.messages().get(id).await.unwrap();
    let archive = stored
        .attachments
        .iter()
        .find(|attachment| attachment.name.as_deref() == Some("bundle.zip"))
        .unwrap();
    assert_eq!(
        archive.declared_media_type.as_deref(),
        Some("application/octet-stream")
    );
    assert_eq!(
        archive.detected_media_type.as_deref(),
        Some("application/zip")
    );

    let mut inline = Vec::new();
    assert!(backend
        .mime()
        .stream_content_id(id, "cid:hero@example.test", &mut inline, 1_024)
        .await
        .unwrap());
    assert_eq!(inline, b"\x89PNG\r\n\x1a\nfixture");
    let mut absent = Vec::new();
    assert!(!backend
        .mime()
        .stream_content_id(id, "missing@example.test", &mut absent, 1_024)
        .await
        .unwrap());

    let mut attachment = Vec::new();
    backend
        .mime()
        .stream_attachment(id, &archive.id, &mut attachment, 1_024 * 1_024)
        .await
        .unwrap();
    assert_eq!(attachment, zip);
    assert!(matches!(
        backend
            .mime()
            .stream_attachment(id, &archive.id, &mut Vec::new(), 2)
            .await,
        Err(BackendError::MessageTooLarge { .. })
    ));

    let export = profile.path().join("exported.zip");
    backend
        .mime()
        .export_attachment(id, &archive.id, &export, 1_024 * 1_024)
        .await
        .unwrap();
    assert_eq!(tokio::fs::read(&export).await.unwrap(), zip);
    assert!(backend
        .mime()
        .export_attachment(id, &archive.id, &export, 1_024 * 1_024)
        .await
        .is_err());

    if archive_sandbox_available() {
        let inspection = backend
            .mime()
            .inspect_archive_with_isolation(
                id,
                &archive.id,
                ArchiveLimits::default(),
                archive_isolation(),
            )
            .await
            .unwrap();
        assert_eq!(inspection.state, ArchiveInspectionState::Complete);
        assert_eq!(inspection.entries[0].path, "folder/note.txt");
        assert_eq!(
            backend
                .mime()
                .read_archive_entry_with_isolation(
                    id,
                    &archive.id,
                    0,
                    ArchiveLimits::default(),
                    archive_isolation(),
                )
                .await
                .unwrap(),
            b"archive payload"
        );
        let limited = backend
            .mime()
            .inspect_archive_with_isolation(
                id,
                &archive.id,
                ArchiveLimits {
                    max_total_uncompressed_bytes: 2,
                    ..ArchiveLimits::default()
                },
                archive_isolation(),
            )
            .await
            .unwrap();
        assert_eq!(limited.state, ArchiveInspectionState::Limited);
    } else {
        let error = backend
            .mime()
            .inspect_archive_with_isolation(
                id,
                &archive.id,
                ArchiveLimits::default(),
                archive_isolation(),
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("archive worker boundary"));
    }

    let extracted = backend
        .mime()
        .extract_document_text(
            id,
            &archive.id,
            DocumentExtractionLimits::default(),
            &FixtureExtractor,
        )
        .await
        .unwrap();
    assert_eq!(extracted.text, "sandbox result");
}

#[tokio::test]
async fn exposes_mime_limit_state_instead_of_silently_claiming_completeness() {
    let profile = tempfile::tempdir().unwrap();
    let mut config = BackendConfig::new(profile.path());
    config.limits.max_mime_parts = 3;
    let backend = Backend::open(config).await.unwrap();
    let zip = zip_fixture("note.txt", b"payload");
    let id = backend
        .messages()
        .ingest(IngestMessage::local(message(&zip)))
        .await
        .unwrap();
    let structure = backend.mime().structure(id).await.unwrap();
    assert_eq!(structure.state, MimeParseState::Limited);
    assert!(structure.detail.is_some());
    assert!(structure
        .parts
        .iter()
        .any(|part| part.decode_state == MimeDecodeState::Limited));
}

#[tokio::test]
async fn archive_paths_are_never_treated_as_export_paths() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let zip = zip_fixture("../escape.txt", b"nope");
    let id = backend
        .messages()
        .ingest(IngestMessage::local(message(&zip)))
        .await
        .unwrap();
    let archive = backend.messages().get(id).await.unwrap().attachments[1].clone();
    if !archive_sandbox_available() {
        assert!(backend
            .mime()
            .inspect_archive_with_isolation(
                id,
                &archive.id,
                ArchiveLimits::default(),
                archive_isolation(),
            )
            .await
            .is_err());
        return;
    }
    let inspection = backend
        .mime()
        .inspect_archive_with_isolation(
            id,
            &archive.id,
            ArchiveLimits::default(),
            archive_isolation(),
        )
        .await
        .unwrap();
    assert_eq!(inspection.state, ArchiveInspectionState::Limited);
    assert_eq!(inspection.entries[0].path, "[unsafe path omitted]");
    assert!(backend
        .mime()
        .read_archive_entry_with_isolation(
            id,
            &archive.id,
            0,
            ArchiveLimits::default(),
            archive_isolation(),
        )
        .await
        .is_err());
}

#[tokio::test]
async fn keeps_unparseable_bytes_with_an_explicit_failed_projection() {
    let profile = tempfile::tempdir().unwrap();
    let backend = Backend::open(BackendConfig::new(profile.path()))
        .await
        .unwrap();
    let raw = b"this has neither an RFC header nor a blank-line separator".to_vec();
    let id = backend
        .messages()
        .ingest(IngestMessage::local(raw.clone()))
        .await
        .unwrap();
    assert_eq!(backend.messages().raw(id).await.unwrap(), raw);
    let structure = backend.mime().structure(id).await.unwrap();
    assert_eq!(structure.state, MimeParseState::Failed);
    assert_eq!(structure.parts.len(), 1);
    assert_eq!(structure.parts[0].decode_state, MimeDecodeState::Failed);
    assert!(structure.parts[0]
        .parse_flags
        .iter()
        .any(|flag| flag == "parse_failed"));
}
