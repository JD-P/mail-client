use crate::imap_engine::{CredentialProvider, ImapCredential, SecretValue};
use crate::{BackendError, CredentialStoragePolicy, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use futures_util::future::BoxFuture;
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const REFERENCE_PREFIX: &str = "lizard-credential:v1";
const KEYRING_SERVICE: &str = "net.extropian.lizard-mail";
// A transferable OpenPGP secret key is base64-encoded inside the typed
// credential payload. Keep this above the public API's 4 MiB binary-key cap,
// while still bounding hostile/corrupt native-store responses.
const MAX_CREDENTIAL_BYTES: usize = 6 * 1024 * 1024;
const MAX_FALLBACK_FILE_BYTES: u64 = 8 * 1024 * 1024;
const FALLBACK_KEY_BYTES: usize = 32;
const FALLBACK_NONCE_BYTES: usize = 24;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStorageKind {
    Native,
    ProfileFallback,
}

#[derive(Clone)]
pub struct Credentials {
    manager: Arc<CredentialManager>,
}

impl Credentials {
    pub(crate) fn new(manager: Arc<CredentialManager>) -> Self {
        Self { manager }
    }

    /// Save an account password and return an opaque reference suitable for
    /// `NewAccount::credential_ref` or `Sending::configure_smtp`.
    pub async fn store_password(&self, password: SecretValue) -> Result<String> {
        self.manager
            .store(CredentialToStore::Password(password))
            .await
    }

    pub async fn store(&self, credential: ImapCredential) -> Result<String> {
        match credential {
            ImapCredential::Password(value) => self.store_password(value).await,
            ImapCredential::OAuth2 { access_token } => {
                self.store_oauth2_access_token(access_token).await
            }
        }
    }

    /// Save an OAuth access token. Refresh-token exchange remains the
    /// responsibility of the OAuth broker supplying credentials to the mail
    /// engines.
    pub async fn store_oauth2_access_token(&self, token: SecretValue) -> Result<String> {
        self.manager
            .store(CredentialToStore::OAuth2AccessToken(token))
            .await
    }

    pub async fn resolve(&self, reference: &str) -> Result<ImapCredential> {
        self.manager.resolve(reference).await
    }

    /// Delete a Lizard-managed credential. External provider references are
    /// rejected so this API can never erase another application's state.
    pub async fn delete(&self, reference: &str) -> Result<()> {
        if !self.manager.delete_if_managed(reference).await? {
            return Err(BackendError::InvalidInput(
                "credential reference is not managed by Lizard".into(),
            ));
        }
        Ok(())
    }

    pub fn storage_kind(&self, reference: &str) -> Option<CredentialStorageKind> {
        parse_reference(reference)
            .ok()
            .flatten()
            .map(|value| value.0)
    }
}

impl CredentialProvider for Credentials {
    fn resolve<'a>(&'a self, reference: &'a str) -> BoxFuture<'a, Result<ImapCredential>> {
        Box::pin(async move { self.manager.resolve(reference).await })
    }
}

pub(crate) struct CredentialManager {
    policy: CredentialStoragePolicy,
    fallback_dir: PathBuf,
    fallback_lock: Mutex<()>,
}

impl CredentialManager {
    pub(crate) fn new(profile_dir: &Path, policy: CredentialStoragePolicy) -> Arc<Self> {
        Arc::new(Self {
            policy,
            fallback_dir: profile_dir.join("credentials"),
            fallback_lock: Mutex::new(()),
        })
    }

    pub(crate) fn manages(&self, reference: &str) -> Result<bool> {
        Ok(parse_reference(reference)?.is_some())
    }

    pub(crate) async fn store_openpgp_secret(
        &self,
        key: Zeroizing<Vec<u8>>,
        passphrase: SecretValue,
    ) -> Result<String> {
        self.store(CredentialToStore::OpenPgpSecretKey { key, passphrase })
            .await
    }

    pub(crate) async fn resolve_openpgp_secret(
        &self,
        reference: &str,
    ) -> Result<OpenPgpStoredSecret> {
        let (kind, id) = parse_reference(reference)?.ok_or_else(|| {
            BackendError::CredentialStore(
                "OpenPGP secret key reference belongs to an external provider".into(),
            )
        })?;
        let payload = Zeroizing::new(match kind {
            CredentialStorageKind::Native => load_native(id).await?,
            CredentialStorageKind::ProfileFallback => self.load_fallback(&id, reference).await?,
        });
        if payload.len() > MAX_CREDENTIAL_BYTES {
            return Err(BackendError::CredentialStore(
                "stored OpenPGP key exceeds the configured size limit".into(),
            ));
        }
        let mut decoded: StoredCredential =
            serde_json::from_slice(payload.as_ref()).map_err(|_| {
                BackendError::CredentialStore("stored OpenPGP key has an invalid format".into())
            })?;
        decoded.take_openpgp_secret()
    }

    async fn store(&self, credential: CredentialToStore) -> Result<String> {
        let payload = serialize_credential(&credential)?;
        let id = Uuid::new_v4().to_string();
        if self.policy == CredentialStoragePolicy::Automatic {
            let reference = format!("{REFERENCE_PREFIX}:native:{id}");
            let native_payload = Zeroizing::new(payload.to_vec());
            match store_native(id.clone(), native_payload).await {
                Ok(()) => return Ok(reference),
                Err(_) => {
                    // A platform API can fail after an ambiguous write. Make a
                    // best-effort deletion before selecting the fallback so a
                    // credential with no durable reference is not left behind.
                    let _ = delete_native(id.clone()).await;
                }
            }
        }
        let reference = format!("{REFERENCE_PREFIX}:profile:{id}");
        self.store_fallback(&id, &reference, &payload).await?;
        Ok(reference)
    }

    async fn resolve(&self, reference: &str) -> Result<ImapCredential> {
        let (kind, id) = parse_reference(reference)?.ok_or_else(|| {
            BackendError::CredentialStore(
                "credential reference belongs to an external provider".into(),
            )
        })?;
        let payload = Zeroizing::new(match kind {
            CredentialStorageKind::Native => load_native(id).await?,
            CredentialStorageKind::ProfileFallback => self.load_fallback(&id, reference).await?,
        });
        if payload.len() > MAX_CREDENTIAL_BYTES {
            return Err(BackendError::CredentialStore(
                "stored credential exceeds the configured size limit".into(),
            ));
        }
        let mut decoded: StoredCredential =
            serde_json::from_slice(payload.as_ref()).map_err(|_| {
                BackendError::CredentialStore("stored credential has an invalid format".into())
            })?;
        decoded.take()
    }

    pub(crate) async fn delete_if_managed(&self, reference: &str) -> Result<bool> {
        let Some((kind, id)) = parse_reference(reference)? else {
            return Ok(false);
        };
        match kind {
            CredentialStorageKind::Native => delete_native(id).await?,
            CredentialStorageKind::ProfileFallback => self.delete_fallback(&id).await?,
        }
        Ok(true)
    }

    async fn store_fallback(&self, id: &str, reference: &str, plaintext: &[u8]) -> Result<()> {
        let _guard = self.fallback_lock.lock().await;
        let directory = self.fallback_dir.clone();
        let id = id.to_owned();
        let reference = reference.to_owned();
        let plaintext = Zeroizing::new(plaintext.to_vec());
        tokio::task::spawn_blocking(move || {
            ensure_private_directory(&directory)?;
            let key = load_or_create_fallback_key(&directory)?;
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| {
                BackendError::CredentialStore("could not initialize credential cipher".into())
            })?;
            let mut nonce = [0u8; FALLBACK_NONCE_BYTES];
            getrandom::fill(&mut nonce).map_err(|_| {
                BackendError::CredentialStore("operating-system randomness is unavailable".into())
            })?;
            let nonce_value = XNonce::from(nonce);
            let ciphertext = cipher
                .encrypt(
                    &nonce_value,
                    Payload {
                        msg: plaintext.as_ref(),
                        aad: reference.as_bytes(),
                    },
                )
                .map_err(|_| {
                    BackendError::CredentialStore("could not encrypt credential".into())
                })?;
            let envelope = FallbackEnvelope {
                version: 1,
                nonce: URL_SAFE_NO_PAD.encode(nonce),
                ciphertext: URL_SAFE_NO_PAD.encode(ciphertext),
            };
            let encoded = serde_json::to_vec(&envelope)?;
            write_private_atomic(&credential_path(&directory, &id), &encoded)
        })
        .await
        .map_err(task_error)??;
        Ok(())
    }

    async fn load_fallback(&self, id: &str, reference: &str) -> Result<Vec<u8>> {
        let _guard = self.fallback_lock.lock().await;
        let directory = self.fallback_dir.clone();
        let id = id.to_owned();
        let reference = reference.to_owned();
        tokio::task::spawn_blocking(move || {
            let key = load_existing_fallback_key(&directory)?;
            let path = credential_path(&directory, &id);
            let metadata = fs::metadata(&path).map_err(|source| BackendError::Io {
                path: path.clone(),
                source,
            })?;
            if !metadata.is_file() || metadata.len() > MAX_FALLBACK_FILE_BYTES {
                return Err(BackendError::CredentialStore(
                    "profile credential file is not a bounded regular file".into(),
                ));
            }
            let encoded = fs::read(&path).map_err(|source| BackendError::Io {
                path: path.clone(),
                source,
            })?;
            let envelope: FallbackEnvelope = serde_json::from_slice(&encoded).map_err(|_| {
                BackendError::CredentialStore("profile credential is corrupted".into())
            })?;
            if envelope.version != 1 {
                return Err(BackendError::CredentialStore(
                    "profile credential uses an unsupported format".into(),
                ));
            }
            let nonce = URL_SAFE_NO_PAD.decode(envelope.nonce).map_err(|_| {
                BackendError::CredentialStore("profile credential nonce is corrupted".into())
            })?;
            if nonce.len() != FALLBACK_NONCE_BYTES {
                return Err(BackendError::CredentialStore(
                    "profile credential nonce has an invalid length".into(),
                ));
            }
            let nonce_value = XNonce::try_from(nonce.as_slice()).map_err(|_| {
                BackendError::CredentialStore(
                    "profile credential nonce has an invalid length".into(),
                )
            })?;
            let ciphertext = URL_SAFE_NO_PAD.decode(envelope.ciphertext).map_err(|_| {
                BackendError::CredentialStore("profile credential ciphertext is corrupted".into())
            })?;
            let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| {
                BackendError::CredentialStore("could not initialize credential cipher".into())
            })?;
            cipher
                .decrypt(
                    &nonce_value,
                    Payload {
                        msg: &ciphertext,
                        aad: reference.as_bytes(),
                    },
                )
                .map_err(|_| {
                    BackendError::CredentialStore(
                        "profile credential failed its integrity check".into(),
                    )
                })
        })
        .await
        .map_err(task_error)?
    }

    async fn delete_fallback(&self, id: &str) -> Result<()> {
        let _guard = self.fallback_lock.lock().await;
        let directory = self.fallback_dir.clone();
        let path = credential_path(&directory, id);
        tokio::task::spawn_blocking(move || match fs::remove_file(&path) {
            Ok(()) => sync_directory(&directory),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(BackendError::Io { path, source }),
        })
        .await
        .map_err(task_error)??;
        Ok(())
    }
}

enum CredentialToStore {
    Password(SecretValue),
    OAuth2AccessToken(SecretValue),
    OpenPgpSecretKey {
        key: Zeroizing<Vec<u8>>,
        passphrase: SecretValue,
    },
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CredentialBorrowed<'a> {
    Password { value: &'a str },
    OAuth2AccessToken { value: &'a str },
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StoredCredential {
    Password { value: String },
    OAuth2AccessToken { value: String },
    OpenPgpSecretKey { key: String, passphrase: String },
}

pub(crate) struct OpenPgpStoredSecret {
    pub(crate) key: Zeroizing<Vec<u8>>,
    pub(crate) passphrase: SecretValue,
}

impl StoredCredential {
    fn take(&mut self) -> Result<ImapCredential> {
        match self {
            Self::Password { value } => Ok(ImapCredential::Password(SecretValue::new(
                std::mem::take(value),
            ))),
            Self::OAuth2AccessToken { value } => Ok(ImapCredential::OAuth2 {
                access_token: SecretValue::new(std::mem::take(value)),
            }),
            Self::OpenPgpSecretKey { .. } => Err(BackendError::CredentialStore(
                "credential reference contains an OpenPGP key, not an account credential".into(),
            )),
        }
    }

    fn take_openpgp_secret(&mut self) -> Result<OpenPgpStoredSecret> {
        let Self::OpenPgpSecretKey { key, passphrase } = self else {
            return Err(BackendError::CredentialStore(
                "credential reference does not contain an OpenPGP secret key".into(),
            ));
        };
        let encoded = std::mem::take(key);
        let decoded = URL_SAFE_NO_PAD
            .decode(encoded.as_bytes())
            .map_err(|_| BackendError::CredentialStore("stored OpenPGP key is corrupted".into()))?;
        Ok(OpenPgpStoredSecret {
            key: Zeroizing::new(decoded),
            passphrase: SecretValue::new(std::mem::take(passphrase)),
        })
    }
}

impl Drop for StoredCredential {
    fn drop(&mut self) {
        match self {
            Self::Password { value } | Self::OAuth2AccessToken { value } => value.zeroize(),
            Self::OpenPgpSecretKey { key, passphrase } => {
                key.zeroize();
                passphrase.zeroize();
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct FallbackEnvelope {
    version: u8,
    nonce: String,
    ciphertext: String,
}

fn serialize_credential(credential: &CredentialToStore) -> Result<Zeroizing<Vec<u8>>> {
    let encoded = match credential {
        CredentialToStore::Password(value) => serde_json::to_vec(&CredentialBorrowed::Password {
            value: value.expose(),
        })?,
        CredentialToStore::OAuth2AccessToken(value) => {
            serde_json::to_vec(&CredentialBorrowed::OAuth2AccessToken {
                value: value.expose(),
            })?
        }
        CredentialToStore::OpenPgpSecretKey { key, passphrase } => {
            #[derive(Serialize)]
            struct OpenPgpSecretBorrowed<'a> {
                kind: &'static str,
                key: &'a str,
                passphrase: &'a str,
            }
            let key = Zeroizing::new(URL_SAFE_NO_PAD.encode(key.as_slice()));
            serde_json::to_vec(&OpenPgpSecretBorrowed {
                kind: "open_pgp_secret_key",
                key: key.as_str(),
                passphrase: passphrase.expose(),
            })?
        }
    };
    let encoded = Zeroizing::new(encoded);
    if encoded.len() > MAX_CREDENTIAL_BYTES {
        return Err(BackendError::InvalidInput(format!(
            "credential exceeds the {MAX_CREDENTIAL_BYTES}-byte limit"
        )));
    }
    Ok(encoded)
}

fn parse_reference(reference: &str) -> Result<Option<(CredentialStorageKind, String)>> {
    if !reference.starts_with("lizard-credential:") {
        return Ok(None);
    }
    let mut parts = reference.split(':');
    if parts.next() != Some("lizard-credential") || parts.next() != Some("v1") {
        return Err(invalid_reference());
    }
    let kind = match parts.next() {
        Some("native") => CredentialStorageKind::Native,
        Some("profile") => CredentialStorageKind::ProfileFallback,
        _ => return Err(invalid_reference()),
    };
    let Some(id) = parts.next() else {
        return Err(invalid_reference());
    };
    if parts.next().is_some() || Uuid::parse_str(id).is_err() {
        return Err(invalid_reference());
    }
    Ok(Some((kind, id.to_owned())))
}

fn invalid_reference() -> BackendError {
    BackendError::CredentialStore("managed credential reference is malformed".into())
}

async fn store_native(id: String, payload: Zeroizing<Vec<u8>>) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &id).map_err(keyring_error)?;
        entry.set_secret(payload.as_ref()).map_err(keyring_error)
    })
    .await
    .map_err(task_error)?
}

async fn load_native(id: String) -> Result<Vec<u8>> {
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &id).map_err(keyring_error)?;
        entry.get_secret().map_err(keyring_error)
    })
    .await
    .map_err(task_error)?
}

async fn delete_native(id: String) -> Result<()> {
    tokio::task::spawn_blocking(move || {
        let entry = keyring::Entry::new(KEYRING_SERVICE, &id).map_err(keyring_error)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(keyring_error(error)),
        }
    })
    .await
    .map_err(task_error)?
}

fn keyring_error(error: keyring::Error) -> BackendError {
    BackendError::CredentialStore(format!("operating-system credential store: {error}"))
}

fn task_error(error: tokio::task::JoinError) -> BackendError {
    BackendError::CredentialStore(format!("credential worker failed: {error}"))
}

fn credential_path(directory: &Path, id: &str) -> PathBuf {
    directory.join(format!("{id}.credential"))
}

fn fallback_key_path(directory: &Path) -> PathBuf {
    directory.join("profile-key-v1")
}

fn ensure_private_directory(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory).map_err(|source| BackendError::Io {
        path: directory.to_owned(),
        source,
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).map_err(|source| {
            BackendError::Io {
                path: directory.to_owned(),
                source,
            }
        })?;
    }
    Ok(())
}

fn load_or_create_fallback_key(directory: &Path) -> Result<Zeroizing<[u8; FALLBACK_KEY_BYTES]>> {
    let path = fallback_key_path(directory);
    match load_key(&path) {
        Ok(key) => Ok(key),
        Err(BackendError::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            let mut key = Zeroizing::new([0u8; FALLBACK_KEY_BYTES]);
            getrandom::fill(key.as_mut()).map_err(|_| {
                BackendError::CredentialStore("operating-system randomness is unavailable".into())
            })?;
            match write_private_new(&path, key.as_ref()) {
                Ok(()) => {
                    sync_directory(directory)?;
                    Ok(key)
                }
                Err(BackendError::Io { source, .. })
                    if source.kind() == std::io::ErrorKind::AlreadyExists =>
                {
                    load_key(&path)
                }
                Err(error) => Err(error),
            }
        }
        Err(error) => Err(error),
    }
}

fn load_existing_fallback_key(directory: &Path) -> Result<Zeroizing<[u8; FALLBACK_KEY_BYTES]>> {
    load_key(&fallback_key_path(directory)).map_err(|error| match error {
        BackendError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound => {
            BackendError::CredentialStore("profile credential key is missing".into())
        }
        other => other,
    })
}

fn load_key(path: &Path) -> Result<Zeroizing<[u8; FALLBACK_KEY_BYTES]>> {
    let mut file = File::open(path).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })?;
    let mut key = Zeroizing::new([0u8; FALLBACK_KEY_BYTES]);
    file.read_exact(key.as_mut())
        .map_err(|source| BackendError::Io {
            path: path.to_owned(),
            source,
        })?;
    let mut extra = [0u8; 1];
    if file.read(&mut extra).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })? != 0
    {
        return Err(BackendError::CredentialStore(
            "profile credential key has an invalid length".into(),
        ));
    }
    Ok(key)
}

fn write_private_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })?;
    file.write_all(bytes).map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })?;
    file.sync_all().map_err(|source| BackendError::Io {
        path: path.to_owned(),
        source,
    })
}

fn write_private_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        BackendError::CredentialStore("credential path has no parent directory".into())
    })?;
    let temporary = parent.join(format!(".credential-{}.tmp", Uuid::new_v4()));
    write_private_new(&temporary, bytes)?;
    if let Err(source) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(BackendError::Io {
            path: path.to_owned(),
            source,
        });
    }
    sync_directory(parent)
}

fn sync_directory(directory: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|source| BackendError::Io {
                path: directory.to_owned(),
                source,
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AccountKind, Backend, BackendConfig, ImapSecurity, ImapSettings, NewAccount,
        SmtpAuthMethod, SmtpSecurity, SmtpSettings,
    };

    #[test]
    fn managed_references_are_strict_and_typed() {
        let id = Uuid::new_v4();
        assert_eq!(
            parse_reference(&format!("{REFERENCE_PREFIX}:native:{id}"))
                .unwrap()
                .unwrap()
                .0,
            CredentialStorageKind::Native
        );
        assert_eq!(
            parse_reference(&format!("{REFERENCE_PREFIX}:profile:{id}"))
                .unwrap()
                .unwrap()
                .0,
            CredentialStorageKind::ProfileFallback
        );
        assert!(parse_reference("external:key").unwrap().is_none());
        assert!(parse_reference("lizard-credential:v1:profile:not-a-uuid").is_err());
    }

    #[tokio::test]
    async fn profile_fallback_roundtrips_without_persisting_plaintext_and_is_cleaned_up() {
        let profile = tempfile::tempdir().unwrap();
        let mut config = BackendConfig::new(profile.path());
        config.credential_storage = CredentialStoragePolicy::ProfileOnly;
        let backend = Backend::open(config.clone()).await.unwrap();
        let first_secret = "cobalt-password-that-must-not-reach-disk";
        let account = backend
            .accounts()
            .add_with_credential(
                NewAccount {
                    name: "Credential test".into(),
                    kind: AccountKind::Imap,
                    credential_ref: None,
                    imap: Some(ImapSettings {
                        host: "imap.example.test".into(),
                        port: 993,
                        username: "reader@example.test".into(),
                        security: ImapSecurity::ImplicitTls,
                    }),
                },
                ImapCredential::Password(SecretValue::new(first_secret)),
            )
            .await
            .unwrap();
        let first_reference = account.credential_ref.clone().unwrap();
        assert_eq!(
            backend.credentials().storage_kind(&first_reference),
            Some(CredentialStorageKind::ProfileFallback)
        );
        assert_password(
            backend
                .credentials()
                .resolve(&first_reference)
                .await
                .unwrap(),
            first_secret,
        );
        assert!(!directory_contains(profile.path(), first_secret.as_bytes()));

        drop(backend);
        let backend = Backend::open(config).await.unwrap();
        assert_password(
            backend
                .credentials()
                .resolve(&first_reference)
                .await
                .unwrap(),
            first_secret,
        );

        let second_secret = "replacement-password-also-never-plaintext";
        let account = backend
            .accounts()
            .set_credential(
                account.id,
                ImapCredential::Password(SecretValue::new(second_secret)),
            )
            .await
            .unwrap();
        let second_reference = account.credential_ref.clone().unwrap();
        assert!(backend
            .credentials()
            .resolve(&first_reference)
            .await
            .is_err());
        assert_password(
            backend
                .credentials()
                .resolve(&second_reference)
                .await
                .unwrap(),
            second_secret,
        );

        backend
            .sending()
            .configure_smtp(
                account.id,
                SmtpSettings {
                    host: "smtp.example.test".into(),
                    port: 465,
                    username: "reader@example.test".into(),
                    security: SmtpSecurity::ImplicitTls,
                    auth: SmtpAuthMethod::Password,
                },
                second_reference.clone(),
            )
            .await
            .unwrap();
        backend.sending().remove_smtp(account.id).await.unwrap();
        assert_password(
            backend
                .credentials()
                .resolve(&second_reference)
                .await
                .unwrap(),
            second_secret,
        );

        backend.accounts().remove(account.id).await.unwrap();
        assert!(backend
            .credentials()
            .resolve(&second_reference)
            .await
            .is_err());
        assert!(!directory_contains(
            profile.path(),
            second_secret.as_bytes()
        ));
    }

    #[tokio::test]
    async fn profile_fallback_rejects_ciphertext_tampering() {
        let profile = tempfile::tempdir().unwrap();
        let manager = CredentialManager::new(profile.path(), CredentialStoragePolicy::ProfileOnly);
        let credentials = Credentials::new(manager);
        let reference = credentials
            .store_password(SecretValue::new("integrity-test-secret"))
            .await
            .unwrap();
        let (_, id) = parse_reference(&reference).unwrap().unwrap();
        let path = credential_path(&profile.path().join("credentials"), &id);
        let mut envelope: FallbackEnvelope =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        let replacement = if envelope.ciphertext.starts_with('A') {
            "B"
        } else {
            "A"
        };
        envelope.ciphertext.replace_range(..1, replacement);
        fs::write(&path, serde_json::to_vec(&envelope).unwrap()).unwrap();
        assert!(credentials.resolve(&reference).await.is_err());
    }

    #[tokio::test]
    async fn profile_fallback_preserves_oauth_credential_kind() {
        let profile = tempfile::tempdir().unwrap();
        let credentials = Credentials::new(CredentialManager::new(
            profile.path(),
            CredentialStoragePolicy::ProfileOnly,
        ));
        let reference = credentials
            .store_oauth2_access_token(SecretValue::new("oauth-access-token"))
            .await
            .unwrap();
        match credentials.resolve(&reference).await.unwrap() {
            ImapCredential::OAuth2 { access_token } => {
                assert_eq!(access_token.expose(), "oauth-access-token")
            }
            ImapCredential::Password(_) => panic!("expected OAuth credential"),
        }
        credentials.delete(&reference).await.unwrap();
        assert!(credentials.resolve(&reference).await.is_err());
    }

    #[tokio::test]
    async fn account_removal_durably_retries_credential_cleanup_failures() {
        let profile = tempfile::tempdir().unwrap();
        let mut config = BackendConfig::new(profile.path());
        config.credential_storage = CredentialStoragePolicy::ProfileOnly;
        let backend = Backend::open(config).await.unwrap();
        let account = backend
            .accounts()
            .add_with_credential(
                NewAccount {
                    name: "Cleanup retry".into(),
                    kind: AccountKind::Imap,
                    credential_ref: None,
                    imap: Some(ImapSettings {
                        host: "imap.example.test".into(),
                        port: 993,
                        username: "reader@example.test".into(),
                        security: ImapSecurity::ImplicitTls,
                    }),
                },
                ImapCredential::Password(SecretValue::new("cleanup-retry-secret")),
            )
            .await
            .unwrap();
        let reference = account.credential_ref.clone().unwrap();
        let (_, id) = parse_reference(&reference).unwrap().unwrap();
        let path = credential_path(&profile.path().join("credentials"), &id);
        let saved = path.with_extension("saved-for-test");
        fs::rename(&path, &saved).unwrap();
        fs::create_dir(&path).unwrap();

        backend.accounts().remove(account.id).await.unwrap();
        assert!(backend.accounts().get(account.id).await.is_err());
        assert_eq!(cleanup_queue_count(&backend).await, 1);

        fs::remove_dir(&path).unwrap();
        fs::rename(&saved, &path).unwrap();
        assert_eq!(backend.drain_credential_cleanup(16).await.unwrap(), 0);
        assert!(!path.exists());
        assert_eq!(cleanup_queue_count(&backend).await, 0);
    }

    fn assert_password(credential: ImapCredential, expected: &str) {
        match credential {
            ImapCredential::Password(value) => assert_eq!(value.expose(), expected),
            ImapCredential::OAuth2 { .. } => panic!("expected password credential"),
        }
    }

    fn directory_contains(path: &Path, needle: &[u8]) -> bool {
        let Ok(entries) = fs::read_dir(path) else {
            return false;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if directory_contains(&path, needle) {
                    return true;
                }
            } else if fs::read(path)
                .is_ok_and(|bytes| bytes.windows(needle.len()).any(|window| window == needle))
            {
                return true;
            }
        }
        false
    }

    async fn cleanup_queue_count(backend: &Backend) -> i64 {
        let connection = backend.inner.connection.lock().await;
        let mut rows = connection
            .query("SELECT count(*) FROM credential_cleanup_queue", ())
            .await
            .unwrap();
        rows.next().await.unwrap().unwrap().get(0).unwrap()
    }
}
