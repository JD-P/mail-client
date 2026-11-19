use crate::backend::{enqueue_search_on, insert_event, not_found};
use crate::{
    AccountId, Attachment, Backend, BackendError, DraftId, MessageId, OpenPgpBindingState,
    OpenPgpCertificate, OpenPgpCertificateBinding, OpenPgpCertificateSource,
    OpenPgpDecryptedMessage, OpenPgpDraftMode, OpenPgpDraftSecurity, OpenPgpEncryptionStatus,
    OpenPgpMessageSecurity, OpenPgpSearchPolicy, OpenPgpSearchStatus, OpenPgpSecretKeyProvider,
    OpenPgpSecretKeyProviderKind, OpenPgpSignatureEvidence, OpenPgpSignatureStatus, Result,
    SecretValue,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use lizard_verified_kernel::{bounded_read_window, charge_usize};
use mail_parser::MessageParser;
use pgp::{
    composed::{
        Deserializable, DetachedSignature, EncryptionCaps, KeyType, Message, MessageBuilder,
        SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::{
        aead::{AeadAlgorithm, ChunkSize},
        hash::HashAlgorithm,
        sym::SymmetricKeyAlgorithm,
    },
    packet::SignatureType,
    ser::Serialize,
    types::{KeyDetails, KeyVersion, Password},
};
use rand::thread_rng;
use serde_json::json;
use std::{
    collections::HashSet,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    sync::Arc,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_CERTIFICATE_BYTES: usize = 4 * 1024 * 1024;
const MAX_SECRET_KEY_BYTES: usize = 4 * 1024 * 1024;
const MAX_SIGNATURES: usize = 16;
const MAX_GPG_DIAGNOSTIC_BYTES: usize = 1024 * 1024;
const MAX_DECRYPTED_BYTES: usize = 64 * 1024 * 1024;
const MAX_COMPRESSION_DEPTH: usize = 16;
const OPENPGP_READ_CHUNK: usize = 64 * 1024;
const OPENPGP_INLINE_PLAINTEXT: usize = 1024 * 1024;

#[derive(Clone)]
pub struct OpenPgp(Backend);

pub(crate) struct ProtectedMimeEntity {
    pub(crate) bytes: Vec<u8>,
}

#[derive(Clone)]
struct StoredCertificate {
    summary: OpenPgpCertificate,
    bytes: Vec<u8>,
}

#[derive(Clone)]
struct RecipientCertificate {
    certificate: SignedPublicKey,
    fingerprint: String,
    anonymous: bool,
}

impl OpenPgp {
    pub(crate) fn new(backend: Backend) -> Self {
        Self(backend)
    }

    pub async fn search_status(&self) -> Result<OpenPgpSearchStatus> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT encrypted_search_policy FROM openpgp_settings WHERE singleton = 1",
                (),
            )
            .await?;
        let policy = parse_search_policy(
            &rows
                .next()
                .await?
                .ok_or_else(|| BackendError::OpenPgp("missing OpenPGP settings row".into()))?
                .get::<String>(0)?,
        )?;
        drop(rows);
        let mut rows = connection
            .query(
                r#"SELECT
                    (SELECT COUNT(*) FROM openpgp_message_evidence
                     WHERE json_extract(evidence_json, '$.encryption') != 'not_encrypted'),
                    (SELECT COUNT(*) FROM openpgp_decrypted_messages)"#,
                (),
            )
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| BackendError::OpenPgp("could not count encrypted messages".into()))?;
        Ok(OpenPgpSearchStatus {
            policy,
            encrypted_messages: row.get::<i64>(0)? as u64,
            indexed_messages: row.get::<i64>(1)? as u64,
        })
    }

    /// Record the explicit setup choice. Disabling search synchronously removes
    /// all persistent decrypted MIME blobs and rebuilds affected Tantivy rows.
    pub async fn set_encrypted_search(&self, enabled: bool) -> Result<OpenPgpSearchStatus> {
        let _blob_guard = self.0.inner.blob_references.write().await;
        let _search_guard = self.0.inner.search_sync.write().await;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "UPDATE openpgp_settings SET encrypted_search_policy = ?1, updated_at = ?2 WHERE singleton = 1",
                (if enabled { "enabled" } else { "disabled" }, now),
            )
            .await?;
        let mut removed_hashes = Vec::new();
        if !enabled {
            let mut rows = transaction
                .query(
                    "SELECT message_id, decrypted_blob_hash FROM openpgp_decrypted_messages",
                    (),
                )
                .await?;
            let mut message_ids = Vec::new();
            while let Some(row) = rows.next().await? {
                message_ids.push(parse_message_id(row.get(0)?)?);
                removed_hashes.push(row.get::<String>(1)?);
            }
            drop(rows);
            transaction
                .execute("DELETE FROM openpgp_decrypted_messages", ())
                .await?;
            for message_id in message_ids {
                enqueue_search_on(&transaction, message_id).await?;
                if let Some(mut evidence) = load_evidence_on(&transaction, message_id).await? {
                    evidence.decrypted_derivative_stored = false;
                    store_evidence_on(&transaction, message_id, &evidence, now).await?;
                }
            }
        }
        let event = insert_event(
            &transaction,
            now,
            "openpgp_search_policy_changed",
            "openpgp".to_owned(),
            json!({"enabled": enabled}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        self.0.flush_search_projection().await?;
        let index_cleanup = if enabled {
            Ok(())
        } else {
            let search_index = Arc::clone(&self.0.inner.search_index);
            tokio::task::spawn_blocking(move || search_index.expunge_deleted_documents())
                .await
                .map_err(|error| {
                    BackendError::SearchIndex(format!(
                        "encrypted-search index cleanup task failed: {error}"
                    ))
                })?
        };
        let _ = self.0.inner.events.send(event);
        let mut removed_any = false;
        for hash in removed_hashes {
            if !self.0.blob_is_referenced(&hash).await? {
                removed_any |= self.0.inner.blobs.remove_unreferenced(&hash).await?;
            }
        }
        if removed_any {
            // Keep quota accounting honest after securely removing decrypted
            // derivatives at the user's request.
            self.0.inner.storage.measure().await?;
        }
        index_cleanup?;
        drop(_search_guard);
        self.search_status().await
    }

    pub async fn import_public_certificate(
        &self,
        bytes: &[u8],
        source: OpenPgpCertificateSource,
    ) -> Result<OpenPgpCertificate> {
        let parsed = parse_public_certificate(bytes)?;
        self.store_public_certificate(parsed, source).await
    }

    pub async fn export_public_certificate(&self, fingerprint: &str) -> Result<Vec<u8>> {
        Ok(self.load_certificate(fingerprint).await?.bytes)
    }

    pub async fn certificate(&self, fingerprint: &str) -> Result<OpenPgpCertificate> {
        Ok(self.load_certificate(fingerprint).await?.summary)
    }

    pub async fn certificates_for_address(&self, address: &str) -> Result<Vec<OpenPgpCertificate>> {
        let address = normalize_address(address)?;
        let fingerprints = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT fingerprint FROM openpgp_certificate_bindings WHERE address = ?1 COLLATE NOCASE ORDER BY CASE state WHEN 'accepted' THEN 0 WHEN 'candidate' THEN 1 WHEN 'retired' THEN 2 ELSE 3 END, fingerprint",
                    (address,),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push(row.get::<String>(0)?);
            }
            values
        };
        let mut certificates = Vec::with_capacity(fingerprints.len());
        for fingerprint in fingerprints {
            certificates.push(self.load_certificate(&fingerprint).await?.summary);
        }
        Ok(certificates)
    }

    /// Add or update exactly one address/certificate association. Accepting a
    /// new certificate never retires or replaces another accepted certificate.
    pub async fn set_binding(
        &self,
        address: &str,
        fingerprint: &str,
        state: OpenPgpBindingState,
        source: OpenPgpCertificateSource,
    ) -> Result<OpenPgpCertificateBinding> {
        let address = normalize_address(address)?;
        let fingerprint = normalize_fingerprint(fingerprint)?;
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let mut rows = transaction
            .query(
                "SELECT 1 FROM openpgp_certificates WHERE fingerprint = ?1",
                (fingerprint.clone(),),
            )
            .await?;
        if rows.next().await?.is_none() {
            drop(rows);
            transaction.rollback().await?;
            return Err(not_found("OpenPGP certificate", fingerprint));
        }
        drop(rows);
        transaction
            .execute(
                r#"INSERT INTO openpgp_certificate_bindings(
                    address, fingerprint, state, source, created_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                ON CONFLICT(address, fingerprint) DO UPDATE SET
                    state = excluded.state,
                    source = excluded.source,
                    updated_at = excluded.updated_at"#,
                (
                    address.clone(),
                    fingerprint.clone(),
                    binding_state_text(state),
                    source_text(source),
                    now,
                ),
            )
            .await?;
        let event = insert_event(
            &transaction,
            now,
            "openpgp_binding_changed",
            fingerprint.clone(),
            json!({"address": address, "fingerprint": fingerprint, "state": state}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        Ok(OpenPgpCertificateBinding {
            address,
            fingerprint,
            state,
            source,
            created_at: now,
            updated_at: now,
        })
    }

    /// Generate a modern RFC 9580 Ed25519/X25519 certificate. The secret key
    /// is stored only in the managed credential vault and is made the default
    /// signing/decryption provider for this account.
    pub async fn generate_software_key(
        &self,
        account_id: AccountId,
        user_id: &str,
    ) -> Result<OpenPgpSecretKeyProvider> {
        if user_id.trim().is_empty() || user_id.len() > 512 || user_id.chars().any(char::is_control)
        {
            return Err(BackendError::InvalidInput(
                "OpenPGP user ID must contain 1 to 512 printable bytes".into(),
            ));
        }
        let params = SecretKeyParamsBuilder::default()
            .version(KeyVersion::V6)
            .key_type(KeyType::Ed25519)
            .can_certify(true)
            .can_sign(true)
            .primary_user_id(user_id.to_owned())
            .passphrase(None)
            .subkey(
                SubkeyParamsBuilder::default()
                    .version(KeyVersion::V6)
                    .key_type(KeyType::X25519)
                    .can_encrypt(EncryptionCaps::All)
                    .passphrase(None)
                    .build()
                    .map_err(openpgp_error)?,
            )
            .build()
            .map_err(openpgp_error)?;
        let secret = params.generate(thread_rng()).map_err(openpgp_error)?;
        let mut bytes = Vec::new();
        secret.to_writer(&mut bytes).map_err(openpgp_error)?;
        self.store_software_secret(account_id, Zeroizing::new(bytes), SecretValue::new(""))
            .await
    }

    pub async fn import_software_secret_key(
        &self,
        account_id: AccountId,
        bytes: Vec<u8>,
        passphrase: SecretValue,
    ) -> Result<OpenPgpSecretKeyProvider> {
        if bytes.is_empty() || bytes.len() > MAX_SECRET_KEY_BYTES {
            return Err(BackendError::InvalidInput(format!(
                "OpenPGP secret key must contain 1 to {MAX_SECRET_KEY_BYTES} bytes"
            )));
        }
        self.store_software_secret(account_id, Zeroizing::new(bytes), passphrase)
            .await
    }

    /// Register an existing GnuPG-owned key without copying its private key.
    pub async fn register_gnupg_key(
        &self,
        account_id: AccountId,
        fingerprint: &str,
        gnu_pg_home: Option<PathBuf>,
    ) -> Result<OpenPgpSecretKeyProvider> {
        self.register_external_provider(
            account_id,
            fingerprint,
            gnu_pg_home,
            None,
            OpenPgpSecretKeyProviderKind::GnuPg,
        )
        .await
    }

    /// Register a YubiKey OpenPGP Card key. GnuPG's secret-key listing must
    /// report a card token/stub; private operations are delegated to
    /// gpg-agent/scdaemon so Lizard never receives or caches the PIN.
    pub async fn register_yubikey(
        &self,
        account_id: AccountId,
        fingerprint: &str,
        card_serial: &str,
        gnu_pg_home: Option<PathBuf>,
    ) -> Result<OpenPgpSecretKeyProvider> {
        if card_serial.trim().is_empty()
            || card_serial.len() > 128
            || card_serial.chars().any(char::is_control)
        {
            return Err(BackendError::InvalidInput(
                "YubiKey OpenPGP card serial is invalid".into(),
            ));
        }
        self.register_external_provider(
            account_id,
            fingerprint,
            gnu_pg_home,
            Some(card_serial.to_owned()),
            OpenPgpSecretKeyProviderKind::YubiKey,
        )
        .await
    }

    pub async fn providers(&self, account_id: AccountId) -> Result<Vec<OpenPgpSecretKeyProvider>> {
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT fingerprint, kind, gnu_pg_home, card_serial, is_default, created_at FROM openpgp_secret_key_providers WHERE account_id = ?1 ORDER BY is_default DESC, created_at DESC, fingerprint",
                (account_id.to_string(),),
            )
            .await?;
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(OpenPgpSecretKeyProvider {
                account_id,
                fingerprint: row.get(0)?,
                kind: parse_provider_kind(&row.get::<String>(1)?)?,
                gnu_pg_home: row.get::<Option<String>>(2)?.map(PathBuf::from),
                card_serial: row.get(3)?,
                is_default: row.get(4)?,
                created_at: row.get(5)?,
            });
        }
        Ok(values)
    }

    pub async fn set_default_provider(
        &self,
        account_id: AccountId,
        fingerprint: &str,
    ) -> Result<OpenPgpSecretKeyProvider> {
        let fingerprint = normalize_fingerprint(fingerprint)?;
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        let changed = transaction
            .execute(
                "UPDATE openpgp_secret_key_providers SET is_default = CASE WHEN fingerprint = ?1 THEN 1 ELSE 0 END WHERE account_id = ?2",
                (fingerprint.clone(), account_id.to_string()),
            )
            .await?;
        if changed == 0 {
            transaction.rollback().await?;
            return Err(not_found("OpenPGP key provider", fingerprint));
        }
        let mut rows = transaction
            .query(
                "SELECT EXISTS(SELECT 1 FROM openpgp_secret_key_providers WHERE account_id = ?1 AND fingerprint = ?2 AND is_default = 1)",
                (account_id.to_string(), fingerprint.clone()),
            )
            .await?;
        if !rows
            .next()
            .await?
            .is_some_and(|row| row.get::<bool>(0).unwrap_or(false))
        {
            drop(rows);
            transaction.rollback().await?;
            return Err(not_found("OpenPGP key provider", fingerprint));
        }
        drop(rows);
        transaction.commit().await?;
        self.default_provider(account_id).await
    }

    pub async fn remove_provider(&self, account_id: AccountId, fingerprint: &str) -> Result<()> {
        let fingerprint = normalize_fingerprint(fingerprint)?;
        let was_default = {
            let mut connection = self.0.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            let mut rows = transaction
                .query(
                    "SELECT credential_ref, is_default FROM openpgp_secret_key_providers WHERE account_id = ?1 AND fingerprint = ?2",
                    (account_id.to_string(), fingerprint.clone()),
                )
                .await?;
            let row = rows.next().await?.ok_or_else(|| {
                not_found(
                    "OpenPGP key provider",
                    format!("{account_id}:{fingerprint}"),
                )
            })?;
            let credential_ref = row.get::<Option<String>>(0)?;
            let was_default = row.get::<bool>(1)?;
            drop(rows);
            if let Some(reference) = credential_ref.as_deref() {
                self.0
                    .queue_managed_credential_cleanup_on(
                        &transaction,
                        reference,
                        Utc::now().timestamp(),
                    )
                    .await?;
            }
            transaction
                .execute(
                    "DELETE FROM openpgp_secret_key_providers WHERE account_id = ?1 AND fingerprint = ?2",
                    (account_id.to_string(), fingerprint.clone()),
                )
                .await?;
            if was_default {
                transaction
                    .execute(
                        "UPDATE openpgp_secret_key_providers SET is_default = 1 WHERE account_id = ?1 AND fingerprint = (SELECT fingerprint FROM openpgp_secret_key_providers WHERE account_id = ?1 ORDER BY created_at DESC, fingerprint LIMIT 1)",
                        (account_id.to_string(),),
                    )
                    .await?;
            }
            transaction.commit().await?;
            was_default
        };
        self.0.drain_credential_cleanup(16).await?;
        let _ = was_default;
        Ok(())
    }

    pub async fn message_security(&self, message_id: MessageId) -> Result<OpenPgpMessageSecurity> {
        let connection = self.0.inner.connection.lock().await;
        if let Some(evidence) = load_evidence_on(&connection, message_id).await? {
            return Ok(evidence);
        }
        let mut rows = connection
            .query(
                "SELECT 1 FROM messages WHERE id = ?1",
                (message_id.to_string(),),
            )
            .await?;
        if rows.next().await?.is_some() {
            Ok(OpenPgpMessageSecurity::default())
        } else {
            Err(not_found("message", message_id))
        }
    }

    /// Verify the OpenPGP/MIME envelope again using the current certificate
    /// set. This never decrypts or prompts for a software key/PIN.
    pub async fn refresh_message(&self, message_id: MessageId) -> Result<OpenPgpMessageSecurity> {
        let evidence = self.refresh_message_evidence(message_id).await?;
        self.0.heuristics().evaluate_message(message_id).await?;
        Ok(evidence)
    }

    pub(crate) async fn refresh_message_evidence(
        &self,
        message_id: MessageId,
    ) -> Result<OpenPgpMessageSecurity> {
        let raw = self.0.messages().raw(message_id).await?;
        let from_address = self
            .0
            .messages()
            .get(message_id)
            .await?
            .summary
            .from_address;
        let certificates = self.load_all_certificates().await?;
        let now = Utc::now().timestamp();
        let mut evidence = inspect_openpgp_mime(
            &raw,
            from_address.as_deref(),
            &certificates,
            &self.0.inner.config.limits,
        );
        evidence.evaluated_at = Some(now);
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        store_evidence_on(&transaction, message_id, &evidence, now).await?;
        if evidence.encryption != OpenPgpEncryptionStatus::NotEncrypted {
            transaction
                .execute(
                    "UPDATE threads SET openpgp_encryption_required = 1 WHERE id = (SELECT thread_id FROM messages WHERE id = ?1)",
                    (message_id.to_string(),),
                )
                .await?;
        }
        transaction.commit().await?;
        Ok(evidence)
    }

    pub(crate) async fn refresh_messages(&self, message_ids: &[MessageId]) -> Result<()> {
        let mut seen = HashSet::new();
        for message_id in message_ids {
            if seen.insert(*message_id) {
                self.refresh_message_evidence(*message_id).await?;
            }
        }
        Ok(())
    }

    /// Decrypt and fully authenticate a message before returning any plaintext.
    /// HTML and remote resources are deliberately absent from the result.
    pub async fn decrypt_message(&self, message_id: MessageId) -> Result<OpenPgpDecryptedMessage> {
        if let Some(cached) = self.load_cached_decrypted(message_id).await? {
            return Ok(cached);
        }
        let (outer, protected_entity, signatures, decrypting_fingerprint) =
            self.decrypt_authenticated_entity(message_id).await?;
        let parsed =
            parse_decrypted_entity(&protected_entity, &outer, &self.0.inner.config.limits)?;
        let policy = self.search_status().await?.policy;
        let persist = policy == OpenPgpSearchPolicy::Enabled;
        let now = Utc::now().timestamp();
        let mut security = OpenPgpMessageSecurity {
            encryption: OpenPgpEncryptionStatus::Decrypted,
            signatures,
            encrypted_to_fingerprint: Some(decrypting_fingerprint),
            protected_headers: parsed.protected_headers,
            protected_header_mismatch: parsed.protected_header_mismatch,
            decrypted_derivative_stored: persist,
            evaluated_at: Some(now),
            detail: None,
        };
        if security.protected_header_mismatch {
            security.detail = Some(
                "outer and integrity-protected OpenPGP headers disagree; protected values win"
                    .into(),
            );
        }

        if persist {
            let _blob_guard = self.0.inner.blob_references.read().await;
            let _search_guard = self.0.inner.search_sync.write().await;
            let hash = self.0.inner.blobs.put(&protected_entity).await?;
            let attachment_names = parsed
                .attachments
                .iter()
                .filter_map(|attachment| attachment.name.as_deref())
                .collect::<Vec<_>>()
                .join(" ");
            let mut connection = self.0.inner.connection.lock().await;
            let transaction = connection.transaction().await?;
            transaction
                .execute(
                    r#"INSERT INTO openpgp_decrypted_messages(
                        message_id, decrypted_blob_hash, decrypted_size_bytes, body_text,
                        subject, from_address, to_addresses_json, cc_addresses_json,
                        attachments_json, attachment_names, has_attachment, created_at
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
                    ON CONFLICT(message_id) DO UPDATE SET
                        decrypted_blob_hash = excluded.decrypted_blob_hash,
                        decrypted_size_bytes = excluded.decrypted_size_bytes,
                        body_text = excluded.body_text,
                        subject = excluded.subject,
                        from_address = excluded.from_address,
                        to_addresses_json = excluded.to_addresses_json,
                        cc_addresses_json = excluded.cc_addresses_json,
                        attachments_json = excluded.attachments_json,
                        attachment_names = excluded.attachment_names,
                        has_attachment = excluded.has_attachment,
                        created_at = excluded.created_at"#,
                    turso::params![
                        message_id.to_string(),
                        hash,
                        protected_entity.len() as i64,
                        parsed.body_text.clone(),
                        parsed.subject.clone(),
                        parsed.from_address.clone(),
                        serde_json::to_string(&parsed.to_addresses)?,
                        serde_json::to_string(&parsed.cc_addresses)?,
                        serde_json::to_string(&parsed.attachments)?,
                        attachment_names,
                        !parsed.attachments.is_empty(),
                        now,
                    ],
                )
                .await?;
            store_evidence_on(&transaction, message_id, &security, now).await?;
            enqueue_search_on(&transaction, message_id).await?;
            transaction.commit().await?;
            drop(connection);
            self.0.flush_search_projection().await?;
            drop(_search_guard);
        } else {
            let connection = self.0.inner.connection.lock().await;
            store_evidence_on(&connection, message_id, &security, now).await?;
        }

        let decrypted = OpenPgpDecryptedMessage {
            message_id,
            body_text: parsed.body_text,
            subject: parsed.subject,
            from_address: parsed.from_address,
            to_addresses: parsed.to_addresses,
            cc_addresses: parsed.cc_addresses,
            attachments: parsed.attachments,
            security,
            persisted_for_search: persist,
        };
        self.0
            .heuristics()
            .evaluate_message_with_decrypted(message_id, &decrypted)
            .await?;
        Ok(decrypted)
    }

    /// Stream one attachment from an encrypted message. The complete OpenPGP
    /// container is authenticated before the first byte reaches `writer`.
    pub async fn stream_decrypted_attachment<W: tokio::io::AsyncWrite + Unpin>(
        &self,
        message_id: MessageId,
        attachment_id: &str,
        writer: &mut W,
        maximum_bytes: u64,
    ) -> Result<u64> {
        let ordinal = attachment_id
            .strip_prefix("attachment:")
            .and_then(|value| value.parse::<u32>().ok())
            .ok_or_else(|| BackendError::InvalidInput("invalid attachment ID".into()))?;
        let (_outer, entity, _signatures, _decrypting_fingerprint) =
            self.decrypt_authenticated_entity(message_id).await?;
        let (parse_bytes, _) = decrypted_rfc_bytes(&entity, &self.0.inner.config.limits)?;
        let parsed = crate::mime::parse(&parse_bytes, &self.0.inner.config.limits)?;
        let attachment = parsed
            .attachments
            .iter()
            .find(|value| value.metadata.ordinal == ordinal)
            .ok_or_else(|| not_found("decrypted attachment", attachment_id))?;
        if attachment.metadata.decode_state != crate::MimeDecodeState::Complete {
            return Err(BackendError::OpenPgp(
                "decrypted attachment has MIME decoding problems".into(),
            ));
        }
        let resource = parsed
            .resources
            .iter()
            .find(|value| value.part_id == attachment.metadata.mime_part_id)
            .ok_or_else(|| {
                BackendError::OpenPgp("decrypted attachment bytes are unavailable".into())
            })?;
        let size = u64::try_from(resource.bytes.len()).unwrap_or(u64::MAX);
        if size > maximum_bytes {
            return Err(BackendError::MessageTooLarge {
                actual: resource.bytes.len(),
                limit: usize::try_from(maximum_bytes).unwrap_or(usize::MAX),
            });
        }
        tokio::io::AsyncWriteExt::write_all(writer, &resource.bytes)
            .await
            .map_err(|source| {
                BackendError::OpenPgp(format!("attachment write failed: {source}"))
            })?;
        Ok(size)
    }

    pub async fn set_draft_mode(
        &self,
        draft_id: DraftId,
        mode: OpenPgpDraftMode,
    ) -> Result<OpenPgpDraftSecurity> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        let changed = connection
            .execute(
                r#"INSERT INTO openpgp_draft_security(draft_id, requested_mode, updated_at)
                SELECT id, ?1, ?2 FROM drafts WHERE id = ?3 AND status = 'editing'
                ON CONFLICT(draft_id) DO UPDATE SET
                    requested_mode = excluded.requested_mode,
                    updated_at = excluded.updated_at"#,
                (draft_mode_text(mode), now, draft_id.to_string()),
            )
            .await?;
        if changed == 0 {
            return Err(BackendError::Conflict(
                "OpenPGP mode can only be changed on an editing draft".into(),
            ));
        }
        drop(connection);
        self.draft_security(draft_id).await
    }

    pub async fn draft_security(&self, draft_id: DraftId) -> Result<OpenPgpDraftSecurity> {
        let (account_id, preferred_sender, recipients, requested, required) = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    r#"SELECT d.account_id, i.openpgp_fingerprint,
                        d.to_addresses, d.cc_addresses,
                        d.bcc_addresses, COALESCE(s.requested_mode, 'automatic'),
                        COALESCE(t.openpgp_encryption_required, 0)
                    FROM drafts d
                    LEFT JOIN account_identities i ON i.id = d.identity_id
                    LEFT JOIN openpgp_draft_security s ON s.draft_id = d.id
                    LEFT JOIN threads t ON t.id = d.thread_id
                    WHERE d.id = ?1"#,
                    (draft_id.to_string(),),
                )
                .await?;
            let row = rows
                .next()
                .await?
                .ok_or_else(|| not_found("draft", draft_id))?;
            let mut recipients = serde_json::from_str::<Vec<String>>(&row.get::<String>(2)?)?;
            recipients.extend(serde_json::from_str::<Vec<String>>(&row.get::<String>(3)?)?);
            recipients.extend(serde_json::from_str::<Vec<String>>(&row.get::<String>(4)?)?);
            (
                row.get::<String>(0)?.parse::<AccountId>().map_err(|_| {
                    BackendError::OpenPgp("database contains invalid account identifier".into())
                })?,
                row.get::<Option<String>>(1)?,
                recipients,
                parse_draft_mode(&row.get::<String>(5)?)?,
                row.get::<bool>(6)?,
            )
        };
        let effective = match (requested, required) {
            (OpenPgpDraftMode::Automatic, true) => OpenPgpDraftMode::EncryptAndSign,
            (OpenPgpDraftMode::Automatic, false) => OpenPgpDraftMode::Plaintext,
            (mode, _) => mode,
        };
        let mut recipient_fingerprints = Vec::new();
        let mut missing = Vec::new();
        let sender_fingerprint = if matches!(
            effective,
            OpenPgpDraftMode::SignOnly | OpenPgpDraftMode::EncryptAndSign
        ) {
            Some(
                self.sender_provider(account_id, preferred_sender.as_deref())
                    .await?
                    .fingerprint,
            )
        } else {
            preferred_sender
        };
        if effective == OpenPgpDraftMode::EncryptAndSign {
            let (certificates, missing_addresses) = self
                .recipient_certificates(&recipients, &[], account_id, sender_fingerprint.as_deref())
                .await?;
            recipient_fingerprints.extend(certificates.into_iter().map(|value| value.fingerprint));
            missing = missing_addresses;
        }
        recipient_fingerprints.sort_unstable();
        recipient_fingerprints.dedup();
        Ok(OpenPgpDraftSecurity {
            draft_id,
            requested,
            effective,
            recipient_fingerprints,
            missing_recipient_addresses: missing,
            sender_fingerprint,
            conversation_requires_encryption: required,
        })
    }

    pub(crate) async fn protect_mime_entity(
        &self,
        account_id: AccountId,
        sender_fingerprint: Option<&str>,
        visible_recipients: &[String],
        bcc_recipients: &[String],
        entity: &[u8],
        mode: OpenPgpDraftMode,
    ) -> Result<ProtectedMimeEntity> {
        let provider = self.sender_provider(account_id, sender_fingerprint).await?;
        let signed = self.sign_entity(&provider, entity).await?;
        if mode == OpenPgpDraftMode::SignOnly {
            return Ok(ProtectedMimeEntity { bytes: signed });
        }
        if mode != OpenPgpDraftMode::EncryptAndSign {
            return Err(BackendError::InvalidInput(
                "OpenPGP MIME protection requires sign_only or encrypt_and_sign".into(),
            ));
        }
        let (recipients, missing) = self
            .recipient_certificates(
                visible_recipients,
                bcc_recipients,
                account_id,
                Some(&provider.fingerprint),
            )
            .await?;
        if !missing.is_empty() {
            return Err(BackendError::Conflict(format!(
                "OpenPGP encryption is missing accepted keys for: {}",
                missing.join(", ")
            )));
        }
        let encrypted = encrypt_for_recipients(&signed, &recipients)?;
        Ok(ProtectedMimeEntity {
            bytes: wrap_encrypted_entity(&encrypted),
        })
    }

    async fn store_public_certificate(
        &self,
        parsed: SignedPublicKey,
        source: OpenPgpCertificateSource,
    ) -> Result<OpenPgpCertificate> {
        parsed.verify_bindings().map_err(openpgp_error)?;
        let mut bytes = Vec::new();
        parsed.to_writer(&mut bytes).map_err(openpgp_error)?;
        if bytes.len() > MAX_CERTIFICATE_BYTES {
            return Err(BackendError::InvalidInput(format!(
                "OpenPGP certificate exceeds {MAX_CERTIFICATE_BYTES} bytes"
            )));
        }
        let fingerprint = fingerprint(&parsed);
        let user_ids = parsed
            .details
            .users
            .iter()
            .map(|user| user.id.to_string())
            .collect::<Vec<_>>();
        let signing_capable = parsed.primary_key.algorithm().can_sign()
            || parsed
                .public_subkeys
                .iter()
                .any(|subkey| subkey.algorithm().can_sign() && !subkey_revoked(subkey));
        let encryption_capable = parsed.primary_key.algorithm().can_encrypt()
            || parsed
                .public_subkeys
                .iter()
                .any(|subkey| subkey.algorithm().can_encrypt() && !subkey_revoked(subkey));
        let revoked = !parsed.details.revocation_signatures.is_empty();
        let key_created_at = i64::from(parsed.created_at().as_secs());
        let key_expires_at = certificate_expires_at(&parsed);
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                r#"INSERT INTO openpgp_certificates(
                    fingerprint, certificate_bytes, user_ids_json, signing_capable,
                    encryption_capable, revoked, key_created_at, key_expires_at,
                    source, imported_at, updated_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    certificate_bytes = excluded.certificate_bytes,
                    user_ids_json = excluded.user_ids_json,
                    signing_capable = excluded.signing_capable,
                    encryption_capable = excluded.encryption_capable,
                    revoked = excluded.revoked,
                    key_created_at = excluded.key_created_at,
                    key_expires_at = excluded.key_expires_at,
                    updated_at = excluded.updated_at"#,
                turso::params![
                    fingerprint.clone(),
                    bytes,
                    serde_json::to_string(&user_ids)?,
                    signing_capable,
                    encryption_capable,
                    revoked,
                    key_created_at,
                    key_expires_at,
                    source_text(source),
                    now,
                ],
            )
            .await?;
        for user_id in &user_ids {
            if let Some(address) = address_from_user_id(user_id) {
                transaction
                    .execute(
                        r#"INSERT OR IGNORE INTO openpgp_certificate_bindings(
                            address, fingerprint, state, source, created_at, updated_at
                        ) VALUES (?1, ?2, 'candidate', ?3, ?4, ?4)"#,
                        (address, fingerprint.clone(), source_text(source), now),
                    )
                    .await?;
            }
        }
        let event = insert_event(
            &transaction,
            now,
            "openpgp_certificate_imported",
            fingerprint.clone(),
            json!({"fingerprint": fingerprint, "source": source}),
        )
        .await?;
        transaction.commit().await?;
        drop(connection);
        let _ = self.0.inner.events.send(event);
        self.certificate(&fingerprint).await
    }

    async fn store_software_secret(
        &self,
        account_id: AccountId,
        bytes: Zeroizing<Vec<u8>>,
        passphrase: SecretValue,
    ) -> Result<OpenPgpSecretKeyProvider> {
        let secret = parse_secret_key(bytes.as_ref())?;
        secret.verify_bindings().map_err(openpgp_error)?;
        let public = SignedPublicKey::from(secret);
        let summary = self
            .store_public_certificate(public, OpenPgpCertificateSource::Manual)
            .await?;
        let reference = self
            .0
            .inner
            .credentials
            .store_openpgp_secret(bytes, passphrase)
            .await?;
        if let Err(error) = self
            .insert_provider(
                account_id,
                &summary.fingerprint,
                OpenPgpSecretKeyProviderKind::Software,
                Some(reference.clone()),
                None,
                None,
            )
            .await
        {
            let _ = self.0.inner.credentials.delete_if_managed(&reference).await;
            return Err(error);
        }
        self.default_provider(account_id).await
    }

    async fn register_external_provider(
        &self,
        account_id: AccountId,
        fingerprint_value: &str,
        home: Option<PathBuf>,
        card_serial: Option<String>,
        kind: OpenPgpSecretKeyProviderKind,
    ) -> Result<OpenPgpSecretKeyProvider> {
        let fingerprint_value = normalize_fingerprint(fingerprint_value)?;
        let provider = OpenPgpSecretKeyProvider {
            account_id,
            fingerprint: fingerprint_value.clone(),
            kind,
            gnu_pg_home: home.clone(),
            card_serial: card_serial.clone(),
            is_default: true,
            created_at: Utc::now().timestamp(),
        };
        let listing = run_gpg(
            &provider,
            &[
                "--with-colons",
                "--with-keygrip",
                "--list-secret-keys",
                &fingerprint_value,
            ],
            &[],
            4 * 1024 * 1024,
        )
        .await?;
        let listing_text = String::from_utf8_lossy(&listing.stdout);
        if !listing_text.contains(&fingerprint_value) {
            return Err(BackendError::OpenPgp(
                "GnuPG does not own the requested secret key".into(),
            ));
        }
        if kind == OpenPgpSecretKeyProviderKind::YubiKey
            && !gnupg_listing_has_card(&listing_text, card_serial.as_deref())
        {
            return Err(BackendError::OpenPgp(
                "GnuPG did not report this key as an OpenPGP card/YubiKey key".into(),
            ));
        }
        if kind == OpenPgpSecretKeyProviderKind::YubiKey {
            let status = run_gpg(
                &provider,
                &["--with-colons", "--card-status"],
                &[],
                1024 * 1024,
            )
            .await?;
            if !gnupg_card_status_has_serial(
                &String::from_utf8_lossy(&status.stdout),
                card_serial
                    .as_deref()
                    .expect("YubiKey provider has a serial"),
            ) {
                return Err(BackendError::OpenPgp(
                    "the connected OpenPGP card does not match the requested YubiKey serial".into(),
                ));
            }
        }
        let exported = run_gpg(
            &provider,
            &["--export", &fingerprint_value],
            &[],
            MAX_CERTIFICATE_BYTES,
        )
        .await?;
        if exported.stdout.is_empty() {
            return Err(BackendError::OpenPgp(
                "GnuPG exported no public certificate".into(),
            ));
        }
        self.import_public_certificate(
            &exported.stdout,
            if kind == OpenPgpSecretKeyProviderKind::YubiKey {
                OpenPgpCertificateSource::YubiKey
            } else {
                OpenPgpCertificateSource::GnuPg
            },
        )
        .await?;
        self.insert_provider(
            account_id,
            &fingerprint_value,
            kind,
            None,
            home,
            card_serial,
        )
        .await?;
        self.default_provider(account_id).await
    }

    async fn insert_provider(
        &self,
        account_id: AccountId,
        fingerprint: &str,
        kind: OpenPgpSecretKeyProviderKind,
        credential_ref: Option<String>,
        home: Option<PathBuf>,
        card_serial: Option<String>,
    ) -> Result<()> {
        let now = Utc::now().timestamp();
        let mut connection = self.0.inner.connection.lock().await;
        let transaction = connection.transaction().await?;
        transaction
            .execute(
                "UPDATE openpgp_secret_key_providers SET is_default = 0 WHERE account_id = ?1",
                (account_id.to_string(),),
            )
            .await?;
        transaction
            .execute(
                r#"INSERT INTO openpgp_secret_key_providers(
                    account_id, fingerprint, kind, credential_ref, gnu_pg_home,
                    card_serial, is_default, created_at
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, ?7)
                ON CONFLICT(account_id, fingerprint) DO UPDATE SET
                    kind = excluded.kind,
                    credential_ref = excluded.credential_ref,
                    gnu_pg_home = excluded.gnu_pg_home,
                    card_serial = excluded.card_serial,
                    is_default = 1"#,
                turso::params![
                    account_id.to_string(),
                    fingerprint,
                    provider_kind_text(kind),
                    credential_ref,
                    home.map(|value| value.to_string_lossy().into_owned()),
                    card_serial,
                    now,
                ],
            )
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn default_provider(&self, account_id: AccountId) -> Result<OpenPgpSecretKeyProvider> {
        self.providers(account_id)
            .await?
            .into_iter()
            .find(|provider| provider.is_default)
            .ok_or_else(|| not_found("default OpenPGP key provider", account_id))
    }

    async fn sender_provider(
        &self,
        account_id: AccountId,
        fingerprint: Option<&str>,
    ) -> Result<OpenPgpSecretKeyProvider> {
        let Some(fingerprint) = fingerprint else {
            return self.default_provider(account_id).await;
        };
        let fingerprint = normalize_fingerprint(fingerprint)?;
        self.providers(account_id)
            .await?
            .into_iter()
            .find(|provider| provider.fingerprint == fingerprint)
            .ok_or_else(|| not_found("OpenPGP key provider", fingerprint))
    }

    async fn load_certificate(&self, fingerprint_value: &str) -> Result<StoredCertificate> {
        let fingerprint_value = normalize_fingerprint(fingerprint_value)?;
        let connection = self.0.inner.connection.lock().await;
        let mut rows = connection
            .query(
                "SELECT certificate_bytes, user_ids_json, signing_capable, encryption_capable, revoked, key_created_at, key_expires_at, imported_at, source FROM openpgp_certificates WHERE fingerprint = ?1",
                (fingerprint_value.clone(),),
            )
            .await?;
        let row = rows
            .next()
            .await?
            .ok_or_else(|| not_found("OpenPGP certificate", &fingerprint_value))?;
        let bytes = row.get::<Vec<u8>>(0)?;
        let user_ids = serde_json::from_str(&row.get::<String>(1)?)?;
        let signing_capable = row.get(2)?;
        let encryption_capable = row.get(3)?;
        let revoked = row.get(4)?;
        let created_at = row.get(5)?;
        let expires_at = row.get(6)?;
        let imported_at = row.get(7)?;
        let source = parse_source(&row.get::<String>(8)?)?;
        drop(rows);
        let mut rows = connection
            .query(
                "SELECT address, state, source, created_at, updated_at FROM openpgp_certificate_bindings WHERE fingerprint = ?1 ORDER BY address",
                (fingerprint_value.clone(),),
            )
            .await?;
        let mut bindings = Vec::new();
        while let Some(row) = rows.next().await? {
            bindings.push(OpenPgpCertificateBinding {
                address: row.get(0)?,
                fingerprint: fingerprint_value.clone(),
                state: parse_binding_state(&row.get::<String>(1)?)?,
                source: parse_source(&row.get::<String>(2)?)?,
                created_at: row.get(3)?,
                updated_at: row.get(4)?,
            });
        }
        Ok(StoredCertificate {
            summary: OpenPgpCertificate {
                fingerprint: fingerprint_value,
                user_ids,
                signing_capable,
                encryption_capable,
                revoked,
                expires_at,
                created_at,
                imported_at,
                source,
                bindings,
            },
            bytes,
        })
    }

    async fn load_all_certificates(&self) -> Result<Vec<(OpenPgpCertificate, SignedPublicKey)>> {
        let fingerprints = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT fingerprint FROM openpgp_certificates ORDER BY fingerprint LIMIT 4096",
                    (),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push(row.get::<String>(0)?);
            }
            values
        };
        let mut output = Vec::with_capacity(fingerprints.len());
        for fingerprint in fingerprints {
            let stored = self.load_certificate(&fingerprint).await?;
            output.push((stored.summary, parse_public_certificate(&stored.bytes)?));
        }
        Ok(output)
    }

    async fn providers_for_message(
        &self,
        message_id: MessageId,
    ) -> Result<Vec<OpenPgpSecretKeyProvider>> {
        let account_ids = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT DISTINCT account_id FROM message_instances WHERE message_id = ?1 ORDER BY account_id",
                    (message_id.to_string(),),
                )
                .await?;
            let mut values = Vec::new();
            while let Some(row) = rows.next().await? {
                values.push(row.get::<String>(0)?.parse::<AccountId>().map_err(|_| {
                    BackendError::OpenPgp("database contains invalid account identifier".into())
                })?);
            }
            values
        };
        let mut output = Vec::new();
        if account_ids.is_empty() {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT DISTINCT account_id FROM openpgp_secret_key_providers ORDER BY is_default DESC, account_id",
                    (),
                )
                .await?;
            let mut all = Vec::new();
            while let Some(row) = rows.next().await? {
                all.push(row.get::<String>(0)?.parse::<AccountId>().map_err(|_| {
                    BackendError::OpenPgp("database contains invalid account identifier".into())
                })?);
            }
            drop(rows);
            drop(connection);
            for account_id in all {
                output.extend(self.providers(account_id).await?);
            }
        } else {
            for account_id in account_ids {
                output.extend(self.providers(account_id).await?);
            }
        }
        output.sort_by_key(|provider| !provider.is_default);
        Ok(output)
    }

    async fn decrypt_authenticated_entity(
        &self,
        message_id: MessageId,
    ) -> Result<(
        crate::Message,
        Vec<u8>,
        Vec<OpenPgpSignatureEvidence>,
        String,
    )> {
        let outer = self.0.messages().get(message_id).await?;
        let raw = self.0.messages().raw(message_id).await?;
        let encrypted = encrypted_payload(&raw)?.ok_or_else(|| {
            BackendError::InvalidInput("message is not OpenPGP/MIME encrypted".into())
        })?;
        let providers = self.providers_for_message(message_id).await?;
        if providers.is_empty() {
            let evidence = self
                .store_decryption_failure(
                    message_id,
                    OpenPgpEncryptionStatus::MissingSecretKey,
                    "no local secret-key provider can decrypt this message",
                )
                .await?;
            return Err(BackendError::OpenPgp(
                evidence
                    .detail
                    .unwrap_or_else(|| "missing secret key".into()),
            ));
        }

        let mut plaintext = None;
        let mut failures = Vec::new();
        for provider in providers {
            match self.decrypt_with_provider(&provider, &encrypted).await {
                Ok(value) => {
                    plaintext = Some((value, provider.fingerprint));
                    break;
                }
                Err(error @ BackendError::MessageTooLarge { .. }) => {
                    self.store_decryption_failure(
                        message_id,
                        OpenPgpEncryptionStatus::Unsupported,
                        "decrypted OpenPGP entity exceeds the configured message limit",
                    )
                    .await?;
                    return Err(error);
                }
                Err(error) => failures.push(error.to_string()),
            }
        }
        let Some((plaintext, decrypting_fingerprint)) = plaintext else {
            let detail = failures.join("; ");
            let status = if integrity_failure(&detail) {
                OpenPgpEncryptionStatus::FailedIntegrity
            } else if provider_interaction_failure(&detail) {
                OpenPgpEncryptionStatus::InteractionRequired
            } else {
                OpenPgpEncryptionStatus::MissingSecretKey
            };
            self.store_decryption_failure(message_id, status, &detail)
                .await?;
            return Err(BackendError::OpenPgp(detail));
        };
        if plaintext.len() > self.0.inner.config.limits.max_message_bytes
            || plaintext.len() > MAX_DECRYPTED_BYTES
        {
            self.store_decryption_failure(
                message_id,
                OpenPgpEncryptionStatus::Unsupported,
                "decrypted OpenPGP entity exceeds the configured message limit",
            )
            .await?;
            return Err(BackendError::MessageTooLarge {
                actual: plaintext.len(),
                limit: self
                    .0
                    .inner
                    .config
                    .limits
                    .max_message_bytes
                    .min(MAX_DECRYPTED_BYTES),
            });
        }

        let certificates = self.load_all_certificates().await?;
        match unwrap_signed_entity(
            &plaintext,
            outer.summary.from_address.as_deref(),
            &certificates,
        ) {
            Ok((entity, signatures)) => Ok((outer, entity, signatures, decrypting_fingerprint)),
            Err(error) => {
                self.store_decryption_failure(
                    message_id,
                    OpenPgpEncryptionStatus::Malformed,
                    &error.to_string(),
                )
                .await?;
                Err(error)
            }
        }
    }

    async fn decrypt_with_provider(
        &self,
        provider: &OpenPgpSecretKeyProvider,
        encrypted: &[u8],
    ) -> Result<Vec<u8>> {
        match provider.kind {
            OpenPgpSecretKeyProviderKind::Software => {
                let reference = {
                    let connection = self.0.inner.connection.lock().await;
                    let mut rows = connection
                        .query(
                            "SELECT credential_ref FROM openpgp_secret_key_providers WHERE account_id = ?1 AND fingerprint = ?2",
                            (provider.account_id.to_string(), provider.fingerprint.clone()),
                        )
                        .await?;
                    rows.next()
                        .await?
                        .ok_or_else(|| not_found("OpenPGP key provider", &provider.fingerprint))?
                        .get::<Option<String>>(0)?
                        .ok_or_else(|| {
                            BackendError::OpenPgp("software key has no credential reference".into())
                        })?
                };
                let stored = self
                    .0
                    .inner
                    .credentials
                    .resolve_openpgp_secret(&reference)
                    .await?;
                let secret = parse_secret_key(stored.key.as_ref())?;
                let password = Password::from(stored.passphrase.expose());
                let decrypt = || {
                    let message = Message::from_bytes(encrypted).map_err(openpgp_error)?;
                    let mut decrypted =
                        message.decrypt(&password, &secret).map_err(openpgp_error)?;
                    let mut compression_depth = 0;
                    while decrypted.is_compressed() {
                        if compression_depth == MAX_COMPRESSION_DEPTH {
                            return Err(BackendError::OpenPgp(format!(
                                "OpenPGP compression nesting exceeds the supported depth of {MAX_COMPRESSION_DEPTH}"
                            )));
                        }
                        decrypted = decrypted.decompress().map_err(openpgp_error)?;
                        compression_depth += 1;
                    }
                    Ok::<_, BackendError>(decrypted)
                };
                let limit = self
                    .0
                    .inner
                    .config
                    .limits
                    .max_message_bytes
                    .min(MAX_DECRYPTED_BYTES);
                let mut authenticated = decrypt()?;
                match inspect_openpgp_plaintext(&mut authenticated, limit)? {
                    InspectedPlaintext::Buffered(plaintext) => Ok(plaintext),
                    InspectedPlaintext::Length(length) => {
                        let mut authenticated = decrypt()?;
                        read_openpgp_plaintext_exact(&mut authenticated, length)
                    }
                }
            }
            OpenPgpSecretKeyProviderKind::GnuPg | OpenPgpSecretKeyProviderKind::YubiKey => {
                let result = run_gpg(
                    provider,
                    &["--decrypt"],
                    encrypted,
                    self.0
                        .inner
                        .config
                        .limits
                        .max_message_bytes
                        .min(MAX_DECRYPTED_BYTES),
                )
                .await?;
                let status = String::from_utf8_lossy(&result.stderr);
                if !status.contains("DECRYPTION_OKAY") {
                    return Err(BackendError::OpenPgp(format!(
                        "GnuPG did not authenticate decrypted data: {}",
                        sanitize_gpg_diagnostic(&status)
                    )));
                }
                Ok(result.stdout)
            }
        }
    }

    async fn sign_entity(
        &self,
        provider: &OpenPgpSecretKeyProvider,
        entity: &[u8],
    ) -> Result<Vec<u8>> {
        let provider_certificate = self.load_certificate(&provider.fingerprint).await?;
        if provider_certificate.summary.revoked {
            return Err(BackendError::OpenPgp(
                "the selected OpenPGP signing certificate is revoked".into(),
            ));
        }
        if certificate_expired(&provider_certificate.summary) {
            return Err(BackendError::OpenPgp(
                "the selected OpenPGP signing certificate is expired".into(),
            ));
        }
        let canonical = canonicalize_mime_entity(entity);
        let signature = match provider.kind {
            OpenPgpSecretKeyProviderKind::Software => {
                let reference = {
                    let connection = self.0.inner.connection.lock().await;
                    let mut rows = connection
                        .query(
                            "SELECT credential_ref FROM openpgp_secret_key_providers WHERE account_id = ?1 AND fingerprint = ?2",
                            (provider.account_id.to_string(), provider.fingerprint.clone()),
                        )
                        .await?;
                    rows.next()
                        .await?
                        .ok_or_else(|| not_found("OpenPGP key provider", &provider.fingerprint))?
                        .get::<Option<String>>(0)?
                        .ok_or_else(|| {
                            BackendError::OpenPgp("software key has no credential reference".into())
                        })?
                };
                let stored = self
                    .0
                    .inner
                    .credentials
                    .resolve_openpgp_secret(&reference)
                    .await?;
                let secret = parse_secret_key(stored.key.as_ref())?;
                let password = Password::from(stored.passphrase.expose());
                let detached = if secret.primary_key.algorithm().can_sign() {
                    DetachedSignature::sign_binary_data(
                        thread_rng(),
                        &secret.primary_key,
                        &password,
                        HashAlgorithm::Sha256,
                        canonical.as_slice(),
                    )
                    .map_err(openpgp_error)?
                } else {
                    let subkey = secret
                        .secret_subkeys
                        .iter()
                        .find(|subkey| subkey.algorithm().can_sign())
                        .ok_or_else(|| {
                            BackendError::OpenPgp(
                                "secret key has no signing-capable component".into(),
                            )
                        })?;
                    DetachedSignature::sign_binary_data(
                        thread_rng(),
                        &subkey.key,
                        &password,
                        HashAlgorithm::Sha256,
                        canonical.as_slice(),
                    )
                    .map_err(openpgp_error)?
                };
                let mut bytes = Vec::new();
                detached.to_writer(&mut bytes).map_err(openpgp_error)?;
                bytes
            }
            OpenPgpSecretKeyProviderKind::GnuPg | OpenPgpSecretKeyProviderKind::YubiKey => {
                run_gpg(
                    provider,
                    &[
                        "--local-user",
                        &provider.fingerprint,
                        "--digest-algo",
                        "SHA256",
                        "--detach-sign",
                    ],
                    &canonical,
                    8 * 1024 * 1024,
                )
                .await?
                .stdout
            }
        };
        Ok(wrap_signed_entity(&canonical, &signature))
    }

    async fn recipient_certificates(
        &self,
        visible: &[String],
        bcc: &[String],
        account_id: AccountId,
        own_fingerprint: Option<&str>,
    ) -> Result<(Vec<RecipientCertificate>, Vec<String>)> {
        let visible_set = visible
            .iter()
            .map(|address| normalize_address(address))
            .collect::<Result<HashSet<_>>>()?;
        let bcc_set = bcc
            .iter()
            .map(|address| normalize_address(address))
            .collect::<Result<HashSet<_>>>()?;
        let mut recipients = Vec::new();
        let mut missing = Vec::new();
        let mut seen = HashSet::new();
        for address in visible_set.iter().chain(bcc_set.iter()) {
            let certificates = self.certificates_for_address(address).await?;
            let accepted = certificates
                .into_iter()
                .filter(|certificate| {
                    !certificate.revoked
                        && !certificate_expired(certificate)
                        && certificate.encryption_capable
                        && certificate.bindings.iter().any(|binding| {
                            binding.address.eq_ignore_ascii_case(address)
                                && binding.state == OpenPgpBindingState::Accepted
                        })
                })
                .collect::<Vec<_>>();
            let mut has_usable_certificate = false;
            for certificate in accepted {
                let stored = self.load_certificate(&certificate.fingerprint).await?;
                let parsed = parse_public_certificate(&stored.bytes)?;
                if encryption_subkey(&parsed).is_none()
                    && !parsed.primary_key.algorithm().can_encrypt()
                {
                    continue;
                }
                has_usable_certificate = true;
                if seen.insert(certificate.fingerprint.clone()) {
                    recipients.push(RecipientCertificate {
                        certificate: parsed,
                        fingerprint: certificate.fingerprint,
                        anonymous: bcc_set.contains(address) && !visible_set.contains(address),
                    });
                }
            }
            if !has_usable_certificate {
                missing.push(address.clone());
            }
        }
        let own = self.sender_provider(account_id, own_fingerprint).await?;
        if seen.insert(own.fingerprint.clone()) {
            let stored = self.load_certificate(&own.fingerprint).await?;
            recipients.push(RecipientCertificate {
                certificate: parse_public_certificate(&stored.bytes)?,
                fingerprint: own.fingerprint,
                anonymous: false,
            });
        }
        missing.sort_unstable();
        missing.dedup();
        Ok((recipients, missing))
    }

    pub(crate) async fn load_cached_decrypted(
        &self,
        message_id: MessageId,
    ) -> Result<Option<OpenPgpDecryptedMessage>> {
        let row = {
            let connection = self.0.inner.connection.lock().await;
            let mut rows = connection
                .query(
                    "SELECT decrypted_blob_hash, body_text, subject, from_address, to_addresses_json, cc_addresses_json, attachments_json FROM openpgp_decrypted_messages WHERE message_id = ?1",
                    (message_id.to_string(),),
                )
                .await?;
            rows.next().await?.map(|row| {
                Ok::<_, BackendError>((
                    row.get::<String>(0)?,
                    row.get::<String>(1)?,
                    row.get::<Option<String>>(2)?,
                    row.get::<Option<String>>(3)?,
                    serde_json::from_str::<Vec<String>>(&row.get::<String>(4)?)?,
                    serde_json::from_str::<Vec<String>>(&row.get::<String>(5)?)?,
                    serde_json::from_str::<Vec<Attachment>>(&row.get::<String>(6)?)?,
                ))
            })
        };
        let Some((hash, body_text, subject, from_address, to_addresses, cc_addresses, attachments)) =
            row.transpose()?
        else {
            return Ok(None);
        };
        // Reading the blob verifies its SHA-256 content address before the
        // cached projection is released.
        let _ = self.0.inner.blobs.get(&hash).await?;
        let security = self.message_security(message_id).await?;
        Ok(Some(OpenPgpDecryptedMessage {
            message_id,
            body_text,
            subject,
            from_address,
            to_addresses,
            cc_addresses,
            attachments,
            security,
            persisted_for_search: true,
        }))
    }

    async fn store_decryption_failure(
        &self,
        message_id: MessageId,
        status: OpenPgpEncryptionStatus,
        detail: &str,
    ) -> Result<OpenPgpMessageSecurity> {
        let now = Utc::now().timestamp();
        let connection = self.0.inner.connection.lock().await;
        let mut evidence = load_evidence_on(&connection, message_id)
            .await?
            .unwrap_or_default();
        evidence.encryption = status;
        evidence.detail = Some(detail.chars().take(2048).collect());
        evidence.evaluated_at = Some(now);
        store_evidence_on(&connection, message_id, &evidence, now).await?;
        Ok(evidence)
    }
}

struct DecryptedProjection {
    body_text: String,
    subject: Option<String>,
    from_address: Option<String>,
    to_addresses: Vec<String>,
    cc_addresses: Vec<String>,
    attachments: Vec<Attachment>,
    protected_headers: bool,
    protected_header_mismatch: bool,
}

fn parse_public_certificate(bytes: &[u8]) -> Result<SignedPublicKey> {
    if bytes.is_empty() || bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(BackendError::InvalidInput(format!(
            "OpenPGP certificate must contain 1 to {MAX_CERTIFICATE_BYTES} bytes"
        )));
    }
    let (certificate, _) = SignedPublicKey::from_reader_single(bytes).map_err(openpgp_error)?;
    certificate.verify_bindings().map_err(openpgp_error)?;
    Ok(certificate)
}

fn parse_secret_key(bytes: &[u8]) -> Result<SignedSecretKey> {
    let (secret, _) = SignedSecretKey::from_reader_single(bytes).map_err(openpgp_error)?;
    secret.verify_bindings().map_err(openpgp_error)?;
    Ok(secret)
}

fn fingerprint(key: &impl KeyDetails) -> String {
    format!("{:X}", key.fingerprint())
}

fn subkey_revoked(key: &pgp::composed::SignedPublicSubKey) -> bool {
    key.signatures
        .iter()
        .any(|signature| signature.typ() == Some(SignatureType::SubkeyRevocation))
}

fn certificate_expires_at(key: &SignedPublicKey) -> Option<i64> {
    if let Some(days) = key.legacy_v3_expiration_days() {
        return i64::from(key.created_at().as_secs())
            .checked_add(i64::from(days).checked_mul(24 * 60 * 60)?);
    }
    expiration_from_signatures(
        key.created_at().as_secs(),
        key.details
            .direct_signatures
            .iter()
            .chain(key.details.users.iter().flat_map(|user| &user.signatures)),
    )
}

fn subkey_expires_at(key: &pgp::composed::SignedPublicSubKey) -> Option<i64> {
    expiration_from_signatures(key.created_at().as_secs(), key.signatures.iter())
}

fn expiration_from_signatures<'a>(
    created_at: u32,
    signatures: impl Iterator<Item = &'a pgp::packet::Signature>,
) -> Option<i64> {
    let latest = signatures.max_by_key(|signature| {
        signature
            .created()
            .map(|value| value.as_secs())
            .unwrap_or_default()
    })?;
    let duration = latest.key_expiration_time()?;
    if duration.as_secs() == 0 {
        return None;
    }
    i64::from(created_at).checked_add(i64::from(duration.as_secs()))
}

fn certificate_expired(certificate: &OpenPgpCertificate) -> bool {
    certificate
        .expires_at
        .is_some_and(|expires_at| expires_at <= Utc::now().timestamp())
}

fn certificate_supports_aead(key: &SignedPublicKey) -> bool {
    key.details
        .users
        .iter()
        .flat_map(|user| &user.signatures)
        .any(|signature| {
            signature
                .features()
                .is_some_and(|features| features.seipd_v2())
        })
        || key.details.direct_signatures.iter().any(|signature| {
            signature
                .features()
                .is_some_and(|features| features.seipd_v2())
        })
}

fn encryption_subkey(key: &SignedPublicKey) -> Option<&pgp::composed::SignedPublicSubKey> {
    key.public_subkeys
        .iter()
        .filter(|subkey| {
            subkey.algorithm().can_encrypt()
                && !subkey_revoked(subkey)
                && !subkey_expires_at(subkey)
                    .is_some_and(|expires_at| expires_at <= Utc::now().timestamp())
        })
        .max_by_key(|subkey| subkey.created_at().as_secs())
}

fn encrypt_for_recipients(entity: &[u8], recipients: &[RecipientCertificate]) -> Result<Vec<u8>> {
    if recipients.is_empty() {
        return Err(BackendError::OpenPgp(
            "OpenPGP encryption requires at least one recipient certificate".into(),
        ));
    }
    let use_aead = recipients
        .iter()
        .all(|recipient| certificate_supports_aead(&recipient.certificate));
    let mut rng = thread_rng();
    if use_aead {
        let mut builder = MessageBuilder::from_bytes("", entity.to_vec()).seipd_v2(
            &mut rng,
            SymmetricKeyAlgorithm::AES256,
            AeadAlgorithm::Ocb,
            ChunkSize::default(),
        );
        for recipient in recipients {
            if let Some(key) = encryption_subkey(&recipient.certificate) {
                if recipient.anonymous {
                    builder
                        .encrypt_to_key_anonymous(&mut rng, key)
                        .map_err(openpgp_error)?;
                } else {
                    builder
                        .encrypt_to_key(&mut rng, key)
                        .map_err(openpgp_error)?;
                }
            } else if recipient.certificate.primary_key.algorithm().can_encrypt() {
                if recipient.anonymous {
                    builder
                        .encrypt_to_key_anonymous(&mut rng, &recipient.certificate)
                        .map_err(openpgp_error)?;
                } else {
                    builder
                        .encrypt_to_key(&mut rng, &recipient.certificate)
                        .map_err(openpgp_error)?;
                }
            } else {
                return Err(BackendError::OpenPgp(format!(
                    "certificate {} has no active encryption-capable key",
                    recipient.fingerprint
                )));
            }
        }
        builder.to_vec(&mut rng).map_err(openpgp_error)
    } else {
        let mut builder = MessageBuilder::from_bytes("", entity.to_vec())
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for recipient in recipients {
            if let Some(key) = encryption_subkey(&recipient.certificate) {
                if recipient.anonymous {
                    builder
                        .encrypt_to_key_anonymous(&mut rng, key)
                        .map_err(openpgp_error)?;
                } else {
                    builder
                        .encrypt_to_key(&mut rng, key)
                        .map_err(openpgp_error)?;
                }
            } else if recipient.certificate.primary_key.algorithm().can_encrypt() {
                if recipient.anonymous {
                    builder
                        .encrypt_to_key_anonymous(&mut rng, &recipient.certificate)
                        .map_err(openpgp_error)?;
                } else {
                    builder
                        .encrypt_to_key(&mut rng, &recipient.certificate)
                        .map_err(openpgp_error)?;
                }
            } else {
                return Err(BackendError::OpenPgp(format!(
                    "certificate {} has no active encryption-capable key",
                    recipient.fingerprint
                )));
            }
        }
        builder.to_vec(&mut rng).map_err(openpgp_error)
    }
}

fn inspect_openpgp_mime(
    raw: &[u8],
    from_address: Option<&str>,
    certificates: &[(OpenPgpCertificate, SignedPublicKey)],
    _limits: &crate::IngestLimits,
) -> OpenPgpMessageSecurity {
    match signed_entity(raw) {
        Ok(Some((entity, signature))) => OpenPgpMessageSecurity {
            signatures: verify_detached_signatures(
                &signature,
                &canonicalize_mime_entity(&entity),
                from_address,
                certificates,
            ),
            evaluated_at: Some(Utc::now().timestamp()),
            ..OpenPgpMessageSecurity::default()
        },
        Err(error) => OpenPgpMessageSecurity {
            signatures: vec![OpenPgpSignatureEvidence {
                status: OpenPgpSignatureStatus::Unsupported,
                certificate_fingerprint: None,
                signing_key_fingerprint: None,
                binding_state: None,
                certificate_revoked: false,
                certificate_expired: false,
                created_at: None,
                detail: Some(error.to_string()),
            }],
            evaluated_at: Some(Utc::now().timestamp()),
            detail: Some(error.to_string()),
            ..OpenPgpMessageSecurity::default()
        },
        Ok(None) => match encrypted_payload(raw) {
            Ok(Some(_)) => OpenPgpMessageSecurity {
                encryption: OpenPgpEncryptionStatus::Encrypted,
                evaluated_at: Some(Utc::now().timestamp()),
                ..OpenPgpMessageSecurity::default()
            },
            Err(error) => OpenPgpMessageSecurity {
                encryption: OpenPgpEncryptionStatus::Malformed,
                evaluated_at: Some(Utc::now().timestamp()),
                detail: Some(error.to_string()),
                ..OpenPgpMessageSecurity::default()
            },
            Ok(None) => OpenPgpMessageSecurity {
                evaluated_at: Some(Utc::now().timestamp()),
                ..OpenPgpMessageSecurity::default()
            },
        },
    }
}

fn signed_entity(raw: &[u8]) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
    let Some(message) = MessageParser::new().parse(raw) else {
        return Ok(None);
    };
    let root = message.root_part();
    let Some(content_type) = root.content_type() else {
        return Ok(None);
    };
    if !content_type.ctype().eq_ignore_ascii_case("multipart")
        || !content_type
            .subtype()
            .is_some_and(|value| value.eq_ignore_ascii_case("signed"))
    {
        return Ok(None);
    }
    if !content_type
        .attribute("protocol")
        .is_some_and(|value| value.eq_ignore_ascii_case("application/pgp-signature"))
    {
        return Ok(None);
    }
    let children = root.children().collect::<Vec<_>>();
    if children.len() != 2 {
        return Err(BackendError::OpenPgp(
            "OpenPGP multipart/signed must contain exactly two parts".into(),
        ));
    }
    let (decoded, problems) = children[1].decoded_checked();
    if !problems.is_empty() || decoded.len() > 8 * 1024 * 1024 {
        return Err(BackendError::OpenPgp(
            "OpenPGP signature part is malformed or oversized".into(),
        ));
    }
    Ok(Some((children[0].raw().to_vec(), decoded.into_owned())))
}

fn encrypted_payload(raw: &[u8]) -> Result<Option<Vec<u8>>> {
    let Some(message) = MessageParser::new().parse(raw) else {
        return Ok(None);
    };
    let root = message.root_part();
    let Some(content_type) = root.content_type() else {
        return Ok(None);
    };
    if !content_type.ctype().eq_ignore_ascii_case("multipart")
        || !content_type
            .subtype()
            .is_some_and(|value| value.eq_ignore_ascii_case("encrypted"))
    {
        return Ok(None);
    }
    if !content_type
        .attribute("protocol")
        .is_some_and(|value| value.eq_ignore_ascii_case("application/pgp-encrypted"))
    {
        return Err(BackendError::OpenPgp(
            "multipart/encrypted does not declare application/pgp-encrypted".into(),
        ));
    }
    let children = root.children().collect::<Vec<_>>();
    if children.len() != 2 {
        return Err(BackendError::OpenPgp(
            "OpenPGP multipart/encrypted must contain exactly two parts".into(),
        ));
    }
    let (version, version_problems) = children[0].decoded_checked();
    if !version_problems.is_empty()
        || !String::from_utf8_lossy(&version)
            .lines()
            .any(|line| line.trim() == "Version: 1")
    {
        return Err(BackendError::OpenPgp(
            "OpenPGP/MIME version part is missing Version: 1".into(),
        ));
    }
    let (decoded, problems) = children[1].decoded_checked();
    if !problems.is_empty() || decoded.is_empty() {
        return Err(BackendError::OpenPgp(
            "OpenPGP encrypted data part is malformed".into(),
        ));
    }
    Ok(Some(decoded.into_owned()))
}

fn verify_detached_signatures(
    bytes: &[u8],
    entity: &[u8],
    from_address: Option<&str>,
    certificates: &[(OpenPgpCertificate, SignedPublicKey)],
) -> Vec<OpenPgpSignatureEvidence> {
    let Ok((signatures, _)) = DetachedSignature::from_reader_many(bytes) else {
        return vec![OpenPgpSignatureEvidence {
            status: OpenPgpSignatureStatus::Unsupported,
            certificate_fingerprint: None,
            signing_key_fingerprint: None,
            binding_state: None,
            certificate_revoked: false,
            certificate_expired: false,
            created_at: None,
            detail: Some("OpenPGP detached signature packets could not be parsed".into()),
        }];
    };
    let mut output = Vec::new();
    for parsed in signatures.take(MAX_SIGNATURES) {
        let Ok(signature) = parsed else {
            output.push(OpenPgpSignatureEvidence {
                status: OpenPgpSignatureStatus::Unsupported,
                certificate_fingerprint: None,
                signing_key_fingerprint: None,
                binding_state: None,
                certificate_revoked: false,
                certificate_expired: false,
                created_at: None,
                detail: Some("OpenPGP signature packet is malformed".into()),
            });
            continue;
        };
        let claimed = signature
            .signature
            .issuer_fingerprint()
            .first()
            .map(|value| format!("{value:X}"));
        let created_at = signature
            .signature
            .created()
            .map(|value| i64::from(value.as_secs()));
        let mut matched = None;
        let mut known_issuer = false;
        for (summary, certificate) in certificates {
            let primary_fingerprint = fingerprint(certificate);
            if claimed
                .as_ref()
                .is_some_and(|value| value == &primary_fingerprint)
            {
                known_issuer = true;
            }
            if signature.verify(&certificate.primary_key, entity).is_ok() {
                matched = Some((summary, primary_fingerprint));
                break;
            }
            for subkey in &certificate.public_subkeys {
                let subkey_fingerprint = fingerprint(subkey);
                if claimed
                    .as_ref()
                    .is_some_and(|value| value == &subkey_fingerprint)
                {
                    known_issuer = true;
                }
                if signature.verify(&subkey.key, entity).is_ok() {
                    matched = Some((summary, subkey_fingerprint));
                    break;
                }
            }
            if matched.is_some() {
                break;
            }
        }
        if let Some((summary, signing_fingerprint)) = matched {
            let binding_state = from_address.and_then(|address| {
                summary
                    .bindings
                    .iter()
                    .find(|binding| binding.address.eq_ignore_ascii_case(address))
                    .map(|binding| binding.state)
            });
            output.push(OpenPgpSignatureEvidence {
                status: OpenPgpSignatureStatus::Valid,
                certificate_fingerprint: Some(summary.fingerprint.clone()),
                signing_key_fingerprint: Some(signing_fingerprint),
                binding_state,
                certificate_revoked: summary.revoked,
                certificate_expired: certificate_expired(summary),
                created_at,
                detail: None,
            });
        } else {
            output.push(OpenPgpSignatureEvidence {
                status: if known_issuer {
                    OpenPgpSignatureStatus::Invalid
                } else {
                    OpenPgpSignatureStatus::MissingCertificate
                },
                certificate_fingerprint: claimed.clone(),
                signing_key_fingerprint: claimed,
                binding_state: None,
                certificate_revoked: false,
                certificate_expired: false,
                created_at,
                detail: Some(
                    if known_issuer {
                        "signature did not verify against the claimed local certificate"
                    } else {
                        "the signing certificate is not available locally"
                    }
                    .into(),
                ),
            });
        }
    }
    if output.is_empty() {
        output.push(OpenPgpSignatureEvidence {
            status: OpenPgpSignatureStatus::Unsupported,
            certificate_fingerprint: None,
            signing_key_fingerprint: None,
            binding_state: None,
            certificate_revoked: false,
            certificate_expired: false,
            created_at: None,
            detail: Some("OpenPGP signature part contained no signatures".into()),
        });
    }
    output
}

fn unwrap_signed_entity(
    bytes: &[u8],
    from_address: Option<&str>,
    certificates: &[(OpenPgpCertificate, SignedPublicKey)],
) -> Result<(Vec<u8>, Vec<OpenPgpSignatureEvidence>)> {
    match signed_entity(bytes)? {
        Some((entity, signature)) => {
            let canonical = canonicalize_mime_entity(&entity);
            let evidence =
                verify_detached_signatures(&signature, &canonical, from_address, certificates);
            if evidence
                .iter()
                .any(|value| value.status == OpenPgpSignatureStatus::Invalid)
            {
                return Err(BackendError::OpenPgp(
                    "decrypted content contains an invalid OpenPGP signature".into(),
                ));
            }
            Ok((entity, evidence))
        }
        None => Ok((bytes.to_vec(), Vec::new())),
    }
}

fn parse_decrypted_entity(
    entity: &[u8],
    outer: &crate::Message,
    limits: &crate::IngestLimits,
) -> Result<DecryptedProjection> {
    let (parse_bytes, protected_headers) = decrypted_rfc_bytes(entity, limits)?;
    let parsed = crate::mime::parse(&parse_bytes, limits)?;
    let mut body_text = parsed.body_text;
    if body_text.is_empty() {
        if let Some(html) = parsed.body_html.as_deref() {
            body_text = mail_parser::decoders::html::html_to_text(html);
            body_text.truncate(limits.max_text_bytes);
        }
    }
    let outer_uses_encrypted_placeholder =
        outer.summary.subject.as_deref() == Some("Encrypted message");
    let mismatch = protected_headers
        && ((!outer_uses_encrypted_placeholder && outer.summary.subject != parsed.subject)
            || outer.summary.from_address != parsed.from_address);
    Ok(DecryptedProjection {
        body_text,
        subject: parsed.subject,
        from_address: parsed.from_address,
        to_addresses: parsed.to_addresses,
        cc_addresses: parsed.cc_addresses,
        attachments: parsed
            .attachments
            .into_iter()
            .map(|attachment| attachment.metadata)
            .collect(),
        protected_headers,
        protected_header_mismatch: mismatch,
    })
}

fn decrypted_rfc_bytes(entity: &[u8], limits: &crate::IngestLimits) -> Result<(Vec<u8>, bool)> {
    let Some(message) = MessageParser::new()
        .max_depth(limits.max_mime_depth as usize)
        .max_parts(limits.max_mime_parts)
        .max_encoded_nesting(4)
        .parse(entity)
    else {
        return Err(BackendError::OpenPgp(
            "decrypted OpenPGP payload is not a valid MIME entity".into(),
        ));
    };
    let root = message.root_part();
    let protected_headers = root.content_type().is_some_and(|content_type| {
        content_type
            .attribute("protected-headers")
            .is_some_and(|value| value.eq_ignore_ascii_case("v1"))
    });

    let parse_bytes = if protected_headers {
        let children = root.children().collect::<Vec<_>>();
        if children.len() != 2
            || !children[0].content_type().is_some_and(|value| {
                value.ctype().eq_ignore_ascii_case("text")
                    && value
                        .subtype()
                        .is_some_and(|subtype| subtype.eq_ignore_ascii_case("rfc822-headers"))
            })
        {
            return Err(BackendError::OpenPgp(
                "protected OpenPGP headers require one text/rfc822-headers part and one body part"
                    .into(),
            ));
        }
        let (headers, problems) = children[0].decoded_checked();
        if !problems.is_empty() || headers.len() > 128 * 1024 {
            return Err(BackendError::OpenPgp(
                "protected OpenPGP headers are malformed or oversized".into(),
            ));
        }
        let mut message = canonicalize_mime_entity(&headers);
        message.extend_from_slice(b"MIME-Version: 1.0\r\n");
        message.extend_from_slice(children[1].raw());
        message
    } else {
        entity.to_vec()
    };
    Ok((parse_bytes, protected_headers))
}

fn wrap_signed_entity(entity: &[u8], signature: &[u8]) -> Vec<u8> {
    let boundary = format!("lizard-openpgp-signed-{}", uuid::Uuid::new_v4());
    let mut output = format!(
        "Content-Type: multipart/signed; protocol=\"application/pgp-signature\"; micalg=pgp-sha256; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\n"
    )
    .into_bytes();
    output.extend_from_slice(entity);
    if !output.ends_with(b"\r\n") {
        output.extend_from_slice(b"\r\n");
    }
    output.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Type: application/pgp-signature; name=\"signature.asc\"\r\nContent-Disposition: attachment; filename=\"signature.asc\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
        )
        .as_bytes(),
    );
    write_base64(&mut output, signature);
    output.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    output
}

fn wrap_encrypted_entity(encrypted: &[u8]) -> Vec<u8> {
    let boundary = format!("lizard-openpgp-encrypted-{}", uuid::Uuid::new_v4());
    let mut output = format!(
        "Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--{boundary}\r\nContent-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Disposition: inline; filename=\"encrypted.asc\"\r\nContent-Transfer-Encoding: base64\r\n\r\n"
    )
    .into_bytes();
    write_base64(&mut output, encrypted);
    output.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    output
}

fn write_base64(output: &mut Vec<u8>, bytes: &[u8]) {
    let encoded = STANDARD.encode(bytes);
    for chunk in encoded.as_bytes().chunks(76) {
        output.extend_from_slice(chunk);
        output.extend_from_slice(b"\r\n");
    }
}

fn canonicalize_mime_entity(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() + 2);
    let mut index = 0;
    while index < input.len() {
        match input[index] {
            b'\r' => {
                output.extend_from_slice(b"\r\n");
                index += usize::from(input.get(index + 1) == Some(&b'\n')) + 1;
            }
            b'\n' => {
                output.extend_from_slice(b"\r\n");
                index += 1;
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    if !output.ends_with(b"\r\n") {
        output.extend_from_slice(b"\r\n");
    }
    output
}

struct GpgOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

async fn run_gpg(
    provider: &OpenPgpSecretKeyProvider,
    args: &[&str],
    input: &[u8],
    maximum_output: usize,
) -> Result<GpgOutput> {
    let provider = provider.clone();
    let args = args
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let input = input.to_vec();
    tokio::task::spawn_blocking(move || run_gpg_blocking(&provider, &args, &input, maximum_output))
        .await
        .map_err(|error| BackendError::OpenPgp(format!("GnuPG task failed: {error}")))?
}

fn run_gpg_blocking(
    provider: &OpenPgpSecretKeyProvider,
    args: &[String],
    input: &[u8],
    maximum_output: usize,
) -> Result<GpgOutput> {
    let mut command = Command::new("gpg");
    command
        .arg("--batch")
        .arg("--yes")
        .arg("--no-tty")
        .arg("--status-fd")
        .arg("2");
    if let Some(home) = provider.gnu_pg_home.as_deref() {
        command.arg("--homedir").arg(home);
    }
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| BackendError::OpenPgp(format!("could not start GnuPG: {error}")))?;
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| BackendError::OpenPgp("GnuPG standard input pipe is unavailable".into()))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| BackendError::OpenPgp("GnuPG standard output pipe is unavailable".into()))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| BackendError::OpenPgp("GnuPG status pipe is unavailable".into()))?;
    let stdout_reader = thread::spawn(move || read_bounded_and_drain(stdout, maximum_output));
    let stderr_reader =
        thread::spawn(move || read_bounded_and_drain(stderr, MAX_GPG_DIAGNOSTIC_BYTES));
    let input = input.to_vec();
    let stdin_writer = thread::spawn(move || {
        stdin
            .write_all(&input)
            .map_err(|error| BackendError::OpenPgp(format!("could not write to GnuPG: {error}")))
    });
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| BackendError::OpenPgp(format!("could not wait for GnuPG: {error}")))?
        {
            break status;
        }
        if started.elapsed() >= Duration::from_secs(10 * 60) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(BackendError::OpenPgp(
                "GnuPG operation timed out while waiting for its key provider".into(),
            ));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = stdout_reader
        .join()
        .map_err(|_| BackendError::OpenPgp("GnuPG output reader panicked".into()))??;
    let stderr = stderr_reader
        .join()
        .map_err(|_| BackendError::OpenPgp("GnuPG status reader panicked".into()))??;
    stdin_writer
        .join()
        .map_err(|_| BackendError::OpenPgp("GnuPG input writer panicked".into()))??;
    if !status.success() {
        return Err(BackendError::OpenPgp(format!(
            "GnuPG failed: {}",
            sanitize_gpg_diagnostic(&String::from_utf8_lossy(&stderr))
        )));
    }
    Ok(GpgOutput { stdout, stderr })
}

fn read_bounded_and_drain(mut reader: impl Read, maximum: usize) -> Result<Vec<u8>> {
    let mut kept = Vec::new();
    let mut buffer = [0u8; 16 * 1024];
    let mut oversized = false;
    loop {
        let count = reader.read(&mut buffer).map_err(|error| {
            BackendError::OpenPgp(format!("could not read GnuPG output: {error}"))
        })?;
        if count == 0 {
            break;
        }
        let remaining = maximum.saturating_sub(kept.len());
        kept.extend_from_slice(&buffer[..count.min(remaining)]);
        oversized |= count > remaining;
    }
    if oversized {
        return Err(BackendError::OpenPgp(format!(
            "GnuPG output exceeds the {maximum}-byte limit"
        )));
    }
    Ok(kept)
}

fn sanitize_gpg_diagnostic(value: &str) -> String {
    value
        .lines()
        .filter(|line| !line.trim().is_empty())
        .take(12)
        .map(|line| line.chars().take(512).collect::<String>())
        .collect::<Vec<_>>()
        .join(" | ")
}

fn gnupg_listing_has_card(listing: &str, serial: Option<&str>) -> bool {
    listing.lines().any(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        if !matches!(fields.first(), Some(&"sec") | Some(&"ssb")) {
            return false;
        }
        let capability_marks_card = fields.get(11).is_some_and(|value| value.contains('>'));
        let serial_match = serial.is_some_and(|wanted| {
            let wanted = wanted.replace(' ', "");
            fields.iter().skip(14).any(|value| {
                !value.is_empty() && value.replace(' ', "").eq_ignore_ascii_case(&wanted)
            })
        });
        capability_marks_card || serial_match
    })
}

fn gnupg_card_status_has_serial(status: &str, wanted: &str) -> bool {
    let wanted = wanted.replace(' ', "");
    status.lines().any(|line| {
        let fields = line.split(':').collect::<Vec<_>>();
        (fields.first() == Some(&"serialno")
            && fields
                .iter()
                .skip(1)
                .any(|value| value.replace(' ', "").eq_ignore_ascii_case(&wanted)))
            || (line.to_ascii_lowercase().contains("serial number")
                && line
                    .replace(' ', "")
                    .to_ascii_uppercase()
                    .contains(&wanted.to_ascii_uppercase()))
    })
}

pub(crate) async fn load_evidence_on(
    connection: &turso::Connection,
    message_id: MessageId,
) -> Result<Option<OpenPgpMessageSecurity>> {
    let mut rows = connection
        .query(
            "SELECT evidence_json FROM openpgp_message_evidence WHERE message_id = ?1",
            (message_id.to_string(),),
        )
        .await?;
    rows.next()
        .await?
        .map(|row| serde_json::from_str(&row.get::<String>(0)?).map_err(Into::into))
        .transpose()
}

async fn store_evidence_on(
    connection: &turso::Connection,
    message_id: MessageId,
    evidence: &OpenPgpMessageSecurity,
    now: i64,
) -> Result<()> {
    connection
        .execute(
            r#"INSERT INTO openpgp_message_evidence(message_id, evidence_json, evaluated_at)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(message_id) DO UPDATE SET
                evidence_json = excluded.evidence_json,
                evaluated_at = excluded.evaluated_at"#,
            (
                message_id.to_string(),
                serde_json::to_string(evidence)?,
                now,
            ),
        )
        .await?;
    Ok(())
}

fn normalize_fingerprint(value: &str) -> Result<String> {
    let value = value
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>()
        .to_ascii_uppercase();
    if !matches!(value.len(), 40 | 64) || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(BackendError::InvalidInput(
            "OpenPGP fingerprint must be 40 or 64 hexadecimal digits".into(),
        ));
    }
    Ok(value)
}

fn normalize_address(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    let Some((local, domain)) = value.rsplit_once('@') else {
        return Err(BackendError::InvalidInput("invalid email address".into()));
    };
    if local.is_empty()
        || domain.is_empty()
        || value.len() > 320
        || value.chars().any(char::is_whitespace)
    {
        return Err(BackendError::InvalidInput("invalid email address".into()));
    }
    Ok(value)
}

fn address_from_user_id(value: &str) -> Option<String> {
    let candidate = value
        .rsplit_once('<')
        .and_then(|(_, tail)| tail.split_once('>'))
        .map(|(address, _)| address)
        .unwrap_or(value)
        .trim();
    normalize_address(candidate).ok()
}

fn openpgp_error(error: impl std::fmt::Display) -> BackendError {
    BackendError::OpenPgp(error.to_string())
}

#[derive(Debug)]
enum InspectedPlaintext {
    Buffered(Vec<u8>),
    Length(usize),
}

/// Authenticate and count OpenPGP plaintext without retaining a large packet
/// on the heap. Small messages stay buffered; a larger accepted message is
/// decrypted a second time into an exactly sized allocation. Reading to EOF
/// is intentional because rPGP completes MDC/AEAD authentication while it is
/// being read. Oversized plaintext is never returned to a caller.
fn inspect_openpgp_plaintext(reader: &mut impl Read, limit: usize) -> Result<InspectedPlaintext> {
    let sentinel = charge_usize(limit, 1, usize::MAX)
        .ok_or_else(|| BackendError::InvalidInput("OpenPGP plaintext limit is too large".into()))?;
    let mut buffered = Some(Vec::with_capacity(limit.min(OPENPGP_INLINE_PLAINTEXT)));
    let mut total = 0_usize;
    let mut buffer = vec![0_u8; OPENPGP_READ_CHUNK.min(sentinel).max(1)];

    loop {
        let read_limit = bounded_read_window(total, sentinel, buffer.len()).ok_or_else(|| {
            BackendError::OpenPgp("OpenPGP plaintext accounting invariant failed".into())
        })?;
        let count = reader
            .read(&mut buffer[..read_limit])
            .map_err(openpgp_error)?;
        if count == 0 {
            return Ok(match buffered {
                Some(plaintext) => InspectedPlaintext::Buffered(plaintext),
                None => InspectedPlaintext::Length(total),
            });
        }

        let observed = charge_usize(total, count, sentinel).ok_or_else(|| {
            BackendError::OpenPgp("OpenPGP reader exceeded its requested slice".into())
        })?;
        if observed > limit {
            return Err(BackendError::MessageTooLarge {
                actual: observed,
                limit,
            });
        }
        total = observed;
        if let Some(output) = buffered.as_mut() {
            if total <= OPENPGP_INLINE_PLAINTEXT {
                output.extend_from_slice(&buffer[..count]);
            } else {
                buffered = None;
            }
        }
    }
}

fn read_openpgp_plaintext_exact(reader: &mut impl Read, expected: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(expected);
    let mut buffer = vec![0_u8; OPENPGP_READ_CHUNK.min(expected.max(1))];
    loop {
        let count = reader.read(&mut buffer).map_err(openpgp_error)?;
        if count == 0 {
            if output.len() == expected {
                return Ok(output);
            }
            return Err(BackendError::OpenPgp(format!(
                "OpenPGP plaintext length changed while authenticating: expected {expected}, received {}",
                output.len()
            )));
        }
        let Some(observed) = charge_usize(output.len(), count, expected) else {
            return Err(BackendError::OpenPgp(format!(
                "OpenPGP plaintext length changed while authenticating: expected {expected}, received more than expected"
            )));
        };
        debug_assert_eq!(observed, output.len() + count);
        output.extend_from_slice(&buffer[..count]);
    }
}

fn parse_message_id(value: String) -> Result<MessageId> {
    value
        .parse()
        .map_err(|_| BackendError::OpenPgp("database contains invalid message identifier".into()))
}

fn integrity_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("mdc")
        || detail.contains("integrity")
        || detail.contains("aead")
        || detail.contains("bad signature")
        || detail.contains("checksum mismatch")
}

fn provider_interaction_failure(detail: &str) -> bool {
    let detail = detail.to_ascii_lowercase();
    detail.contains("pinentry")
        || detail.contains("card not present")
        || detail.contains("no smartcard")
        || detail.contains("touch")
        || detail.contains("cancelled")
        || detail.contains("canceled")
}

fn source_text(value: OpenPgpCertificateSource) -> &'static str {
    match value {
        OpenPgpCertificateSource::Manual => "manual",
        OpenPgpCertificateSource::AttachedKey => "attached_key",
        OpenPgpCertificateSource::Autocrypt => "autocrypt",
        OpenPgpCertificateSource::Wkd => "wkd",
        OpenPgpCertificateSource::SignedMessage => "signed_message",
        OpenPgpCertificateSource::GnuPg => "gnu_pg",
        OpenPgpCertificateSource::YubiKey => "yubi_key",
    }
}

fn parse_source(value: &str) -> Result<OpenPgpCertificateSource> {
    match value {
        "manual" => Ok(OpenPgpCertificateSource::Manual),
        "attached_key" => Ok(OpenPgpCertificateSource::AttachedKey),
        "autocrypt" => Ok(OpenPgpCertificateSource::Autocrypt),
        "wkd" => Ok(OpenPgpCertificateSource::Wkd),
        "signed_message" => Ok(OpenPgpCertificateSource::SignedMessage),
        "gnu_pg" => Ok(OpenPgpCertificateSource::GnuPg),
        "yubi_key" => Ok(OpenPgpCertificateSource::YubiKey),
        _ => Err(BackendError::OpenPgp(
            "database contains invalid certificate source".into(),
        )),
    }
}

fn binding_state_text(value: OpenPgpBindingState) -> &'static str {
    match value {
        OpenPgpBindingState::Candidate => "candidate",
        OpenPgpBindingState::Accepted => "accepted",
        OpenPgpBindingState::Retired => "retired",
        OpenPgpBindingState::Rejected => "rejected",
    }
}

fn parse_binding_state(value: &str) -> Result<OpenPgpBindingState> {
    match value {
        "candidate" => Ok(OpenPgpBindingState::Candidate),
        "accepted" => Ok(OpenPgpBindingState::Accepted),
        "retired" => Ok(OpenPgpBindingState::Retired),
        "rejected" => Ok(OpenPgpBindingState::Rejected),
        _ => Err(BackendError::OpenPgp(
            "database contains invalid certificate binding state".into(),
        )),
    }
}

fn provider_kind_text(value: OpenPgpSecretKeyProviderKind) -> &'static str {
    match value {
        OpenPgpSecretKeyProviderKind::Software => "software",
        OpenPgpSecretKeyProviderKind::GnuPg => "gnu_pg",
        OpenPgpSecretKeyProviderKind::YubiKey => "yubi_key",
    }
}

fn parse_provider_kind(value: &str) -> Result<OpenPgpSecretKeyProviderKind> {
    match value {
        "software" => Ok(OpenPgpSecretKeyProviderKind::Software),
        "gnu_pg" => Ok(OpenPgpSecretKeyProviderKind::GnuPg),
        "yubi_key" => Ok(OpenPgpSecretKeyProviderKind::YubiKey),
        _ => Err(BackendError::OpenPgp(
            "database contains invalid secret-key provider".into(),
        )),
    }
}

fn parse_search_policy(value: &str) -> Result<OpenPgpSearchPolicy> {
    match value {
        "unset" => Ok(OpenPgpSearchPolicy::Unset),
        "enabled" => Ok(OpenPgpSearchPolicy::Enabled),
        "disabled" => Ok(OpenPgpSearchPolicy::Disabled),
        _ => Err(BackendError::OpenPgp(
            "database contains invalid encrypted-search policy".into(),
        )),
    }
}

fn draft_mode_text(value: OpenPgpDraftMode) -> &'static str {
    match value {
        OpenPgpDraftMode::Automatic => "automatic",
        OpenPgpDraftMode::SignOnly => "sign_only",
        OpenPgpDraftMode::EncryptAndSign => "encrypt_and_sign",
        OpenPgpDraftMode::Plaintext => "plaintext",
    }
}

fn parse_draft_mode(value: &str) -> Result<OpenPgpDraftMode> {
    match value {
        "automatic" => Ok(OpenPgpDraftMode::Automatic),
        "sign_only" => Ok(OpenPgpDraftMode::SignOnly),
        "encrypt_and_sign" => Ok(OpenPgpDraftMode::EncryptAndSign),
        "plaintext" => Ok(OpenPgpDraftMode::Plaintext),
        _ => Err(BackendError::OpenPgp(
            "database contains invalid OpenPGP draft mode".into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AccountKind, BackendConfig, CredentialStoragePolicy, NewAccount};

    struct RepeatedByteReader {
        remaining: usize,
        consumed: usize,
    }

    impl Read for RepeatedByteReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.remaining.min(buffer.len());
            buffer[..count].fill(b'x');
            self.remaining -= count;
            self.consumed += count;
            Ok(count)
        }
    }

    #[test]
    fn bounded_openpgp_inspection_accepts_plaintext_at_the_limit() {
        let mut reader = RepeatedByteReader {
            remaining: 128 * 1024,
            consumed: 0,
        };
        let inspected = inspect_openpgp_plaintext(&mut reader, 128 * 1024).unwrap();
        assert!(matches!(
            inspected,
            InspectedPlaintext::Buffered(plaintext) if plaintext.len() == 128 * 1024
        ));
        assert_eq!(reader.consumed, 128 * 1024);
    }

    #[test]
    fn bounded_openpgp_inspection_stops_after_the_first_excess_byte() {
        let limit = 128 * 1024;
        let mut reader = RepeatedByteReader {
            remaining: 16 * 1024 * 1024,
            consumed: 0,
        };
        let error = inspect_openpgp_plaintext(&mut reader, limit).unwrap_err();
        assert!(matches!(
            error,
            BackendError::MessageTooLarge {
                actual,
                limit: actual_limit
            } if actual == limit + 1 && actual_limit == limit
        ));
        assert_eq!(reader.consumed, limit + 1);
    }

    #[test]
    fn large_openpgp_inspection_retains_only_the_length() {
        let length = OPENPGP_INLINE_PLAINTEXT + 1;
        let mut reader = RepeatedByteReader {
            remaining: length,
            consumed: 0,
        };
        let inspected = inspect_openpgp_plaintext(&mut reader, length).unwrap();
        assert!(matches!(inspected, InspectedPlaintext::Length(value) if value == length));
        assert_eq!(reader.consumed, length);
    }

    #[test]
    fn canonicalizes_mime_without_double_crlf() {
        assert_eq!(
            canonicalize_mime_entity(b"Content-Type: text/plain\n\nhello\n"),
            b"Content-Type: text/plain\r\n\r\nhello\r\n"
        );
        assert_eq!(canonicalize_mime_entity(b"hello\r\n"), b"hello\r\n");
    }

    #[test]
    fn recognizes_gnupg_card_stubs() {
        assert!(gnupg_listing_has_card(
            "sec:u:255:22:ABC:0:0:::::scSC:::+:D2760001240103040006123456780000:\n",
            Some("D2760001240103040006123456780000")
        ));
    }

    #[test]
    fn wraps_and_recovers_openpgp_mime_payload() {
        let bytes = b"OpenPGP ciphertext bytes";
        let wrapped = wrap_encrypted_entity(bytes);
        assert_eq!(encrypted_payload(&wrapped).unwrap().unwrap(), bytes);
    }

    #[tokio::test]
    async fn encrypts_to_every_accepted_recipient_certificate() {
        let profile = tempfile::tempdir().unwrap();
        let mut config = BackendConfig::new(profile.path());
        config.credential_storage = CredentialStoragePolicy::ProfileOnly;
        let backend = Backend::open(config).await.unwrap();
        let sender = backend
            .accounts()
            .add(NewAccount {
                name: "Sender".into(),
                kind: AccountKind::Local,
                credential_ref: None,
                imap: None,
            })
            .await
            .unwrap();
        let recipient = backend
            .accounts()
            .add(NewAccount {
                name: "Recipient".into(),
                kind: AccountKind::Local,
                credential_ref: None,
                imap: None,
            })
            .await
            .unwrap();
        let openpgp = backend.openpgp();
        let sender_key = openpgp
            .generate_software_key(sender.id, "Sender <sender@example.test>")
            .await
            .unwrap();
        openpgp
            .set_binding(
                "sender@example.test",
                &sender_key.fingerprint,
                OpenPgpBindingState::Accepted,
                OpenPgpCertificateSource::Manual,
            )
            .await
            .unwrap();
        let first = openpgp
            .generate_software_key(recipient.id, "Recipient One <reader@example.test>")
            .await
            .unwrap();
        let second = openpgp
            .generate_software_key(recipient.id, "Recipient Two <reader@example.test>")
            .await
            .unwrap();
        for provider in [&first, &second] {
            openpgp
                .set_binding(
                    "reader@example.test",
                    &provider.fingerprint,
                    OpenPgpBindingState::Accepted,
                    OpenPgpCertificateSource::Manual,
                )
                .await
                .unwrap();
        }

        let entity = b"Content-Type: multipart/mixed; boundary=\"test-boundary\"\r\n\r\n--test-boundary\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nsecret searchable body\r\n--test-boundary\r\nContent-Type: application/pdf; name=\"report.pdf\"\r\nContent-Disposition: attachment; filename=\"report.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\nYXR0YWNobWVudA==\r\n--test-boundary--\r\n";
        let protected = openpgp
            .protect_mime_entity(
                sender.id,
                None,
                &["reader@example.test".into()],
                &[],
                entity,
                OpenPgpDraftMode::EncryptAndSign,
            )
            .await
            .unwrap();
        let ciphertext = encrypted_payload(&protected.bytes).unwrap().unwrap();
        let certificates = openpgp.load_all_certificates().await.unwrap();
        for provider in [first, second] {
            let decrypted = openpgp
                .decrypt_with_provider(&provider, &ciphertext)
                .await
                .unwrap();
            let (recovered, signatures) =
                unwrap_signed_entity(&decrypted, Some("sender@example.test"), &certificates)
                    .unwrap();
            assert_eq!(
                canonicalize_mime_entity(&recovered),
                canonicalize_mime_entity(entity)
            );
            assert!(signatures.iter().any(|value| {
                value.status == OpenPgpSignatureStatus::Valid
                    && value.binding_state == Some(OpenPgpBindingState::Accepted)
            }));
        }

        let mut raw = b"From: sender@example.test\r\nTo: reader@example.test\r\nSubject: Encrypted message\r\nMIME-Version: 1.0\r\n"
            .to_vec();
        raw.extend_from_slice(&protected.bytes);
        let message_id = backend
            .messages()
            .ingest(crate::IngestMessage::local(raw))
            .await
            .unwrap();
        openpgp.set_encrypted_search(true).await.unwrap();
        let decrypted = openpgp.decrypt_message(message_id).await.unwrap();
        assert_eq!(decrypted.attachments.len(), 1);
        assert!(decrypted.body_text.contains("secret searchable body"));
        for query in ["searchable", "filename:report.pdf"] {
            let results = backend
                .search()
                .search(crate::SearchRequest {
                    query: query.into(),
                    page_size: 10,
                    cursor: None,
                })
                .await
                .unwrap();
            assert_eq!(results.items.len(), 1, "query {query:?}");
        }
        let (mut writer, mut reader) = tokio::io::duplex(64);
        let size = openpgp
            .stream_decrypted_attachment(message_id, "attachment:0", &mut writer, 64)
            .await
            .unwrap();
        drop(writer);
        let mut attachment = Vec::new();
        tokio::io::AsyncReadExt::read_to_end(&mut reader, &mut attachment)
            .await
            .unwrap();
        assert_eq!(size, 10);
        assert_eq!(attachment, b"attachment");

        openpgp.set_encrypted_search(false).await.unwrap();
        let results = backend
            .search()
            .search(crate::SearchRequest {
                query: "searchable".into(),
                page_size: 10,
                cursor: None,
            })
            .await
            .unwrap();
        assert!(results.items.is_empty());
        assert!(!results.content_results_complete);
    }

    #[tokio::test]
    async fn encrypted_search_requires_an_explicit_choice() {
        let profile = tempfile::tempdir().unwrap();
        let mut config = BackendConfig::new(profile.path());
        config.credential_storage = CredentialStoragePolicy::ProfileOnly;
        let backend = Backend::open(config).await.unwrap();
        assert_eq!(
            backend.openpgp().search_status().await.unwrap().policy,
            OpenPgpSearchPolicy::Unset
        );
        assert_eq!(
            backend
                .openpgp()
                .set_encrypted_search(true)
                .await
                .unwrap()
                .policy,
            OpenPgpSearchPolicy::Enabled
        );
        assert_eq!(
            backend
                .openpgp()
                .set_encrypted_search(false)
                .await
                .unwrap()
                .policy,
            OpenPgpSearchPolicy::Disabled
        );
    }
}
