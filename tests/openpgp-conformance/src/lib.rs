use std::{
    env, fs,
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};

use anyhow::{bail, ensure, Context, Result};
use pgp::{
    composed::{
        Deserializable, DetachedSignature, MessageBuilder, SignedPublicKey, SignedSecretKey,
        SubpacketConfig,
    },
    crypto::{
        hash::HashAlgorithm,
        sym::{StreamEncryptor, SymmetricKeyAlgorithm},
    },
    packet::{Subpacket, SubpacketData},
    ser::Serialize,
    types::{KeyDetails, Password, StringToKey, Timestamp},
};
use rand::{CryptoRng, RngCore};
use tempfile::{tempdir, TempDir};

const REQUIRED_GPG_VERSION: &str = "gpg (GnuPG) 2.4.7";
const TEST_UID: &str = "Lizard OpenPGP conformance <openpgp-conformance.invalid>";
const KEY_TIME: u32 = 1_700_000_000;
const SIGNATURE_TIME_BASE: u32 = 1_700_100_000;
const PASSWORD: &[u8] = b"differential-test-password";
const MAX_PAYLOAD: usize = 8 * 1024;
const S2K_DECODED_COUNT: &str = "65011712";

#[derive(Debug, Clone, Copy)]
pub enum DifferentialOperation {
    RsaSignature,
    RsaSessionKey,
    Aes256Seipdv1,
}

impl DifferentialOperation {
    pub fn from_selector(selector: u8) -> Self {
        match selector % 3 {
            0 => Self::RsaSignature,
            1 => Self::RsaSessionKey,
            _ => Self::Aes256Seipdv1,
        }
    }
}

#[derive(Debug)]
pub struct DifferentialInput<'a> {
    pub operation: DifferentialOperation,
    pub random_start: u8,
    pub payload: &'a [u8],
}

impl<'a> DifferentialInput<'a> {
    pub fn from_fuzz_bytes(input: &'a [u8]) -> Option<Self> {
        let (&selector, rest) = input.split_first()?;
        let (&random_start, payload) = rest.split_first()?;
        Some(Self {
            operation: DifferentialOperation::from_selector(selector),
            random_start,
            payload: &payload[..payload.len().min(MAX_PAYLOAD)],
        })
    }
}

#[derive(Debug)]
struct CounterRng(u64);

impl RngCore for CounterRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = (self.0 & 0xff) as u8;
            self.0 += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for CounterRng {}

#[derive(Debug)]
struct NonzeroCounterRng(u64);

impl RngCore for NonzeroCounterRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for byte in dest {
            *byte = ((self.0 % 255) + 1) as u8;
            self.0 += 1;
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for NonzeroCounterRng {}

pub struct Harness {
    _root: TempDir,
    gpg: PathBuf,
    gpg_home: PathBuf,
    hook: PathBuf,
    fingerprint: String,
    secret: SignedSecretKey,
}

impl Harness {
    pub fn new() -> Result<Self> {
        ensure!(
            cfg!(target_os = "linux"),
            "the GnuPG entropy hook is Linux-only"
        );

        let gpg =
            PathBuf::from(env::var_os("OPENPGP_CONFORMANCE_GPG").unwrap_or_else(|| "gpg".into()));
        require_gpg_version(&gpg)?;

        let root = tempdir().context("create conformance working directory")?;
        let gpg_home = root.path().join("gnupg");
        fs::create_dir(&gpg_home).context("create disposable GnuPG home")?;
        fs::set_permissions(&gpg_home, fs::Permissions::from_mode(0o700))
            .context("secure disposable GnuPG home")?;

        let hook = root.path().join("liblizard_gpg_test_rng.so");
        compile_hook(&hook)?;
        verify_hook_guard(&gpg, &hook)?;

        generate_rsa_key(&gpg, &gpg_home)?;
        let fingerprint = primary_fingerprint(&gpg, &gpg_home)?;
        add_encryption_subkey(&gpg, &gpg_home, &fingerprint)?;
        let secret = export_secret_key(&gpg, &gpg_home, &fingerprint)?;

        ensure!(
            SignedPublicKey::from(secret.clone()).public_subkeys.len() == 1,
            "fixture must contain exactly one encryption subkey"
        );

        Ok(Self {
            _root: root,
            gpg,
            gpg_home,
            hook,
            fingerprint,
            secret,
        })
    }

    pub fn compare(&self, input: DifferentialInput<'_>) -> Result<()> {
        ensure!(
            input.payload.len() <= MAX_PAYLOAD,
            "payload exceeds {MAX_PAYLOAD}-byte harness limit"
        );
        match input.operation {
            DifferentialOperation::RsaSignature => {
                self.compare_rsa_signature(input.payload, input.random_start)
            }
            DifferentialOperation::RsaSessionKey => {
                self.compare_rsa_session_key(input.payload, input.random_start)
            }
            DifferentialOperation::Aes256Seipdv1 => {
                self.compare_aes256_seipdv1(input.payload, input.random_start)
            }
        }
    }

    fn compare_rsa_signature(&self, payload: &[u8], selector: u8) -> Result<()> {
        let timestamp = SIGNATURE_TIME_BASE + u32::from(selector);
        let case = tempdir().context("create RSA signature case directory")?;
        let input = case.path().join("input.bin");
        let gpg_output = case.path().join("gpg.sig");
        fs::write(&input, payload).context("write RSA signature input")?;

        let mut command = self.gpg_command();
        command
            .arg("--local-user")
            .arg(&self.fingerprint)
            .arg("--digest-algo")
            .arg("SHA256")
            .arg("--faked-system-time")
            .arg(format!("{timestamp}!"))
            .arg("--no-emit-version")
            .arg("--no-comments")
            .arg("--output")
            .arg(&gpg_output)
            .arg("--detach-sign")
            .arg(&input);
        run(&mut command, "GnuPG RSA signature")?;

        let gpg_bytes = fs::read(&gpg_output).context("read GnuPG RSA signature")?;
        let rpgp_bytes = rpgp_rsa_signature(&self.secret, payload, timestamp)?;
        let gpg_body = packet_body_by_tag(&gpg_bytes, 2)?;
        let rpgp_body = packet_body_by_tag(&rpgp_bytes, 2)?;
        equal_bytes(
            "RSA-3072/SHA-256 signature packet body",
            gpg_body,
            rpgp_body,
        )
    }

    fn compare_rsa_session_key(&self, payload: &[u8], random_start: u8) -> Result<()> {
        let literal = literal_packet(payload);
        let case = tempdir().context("create RSA encryption case directory")?;
        let input = case.path().join("literal.pgp");
        let gpg_output = case.path().join("gpg.pgp");
        fs::write(&input, &literal).context("write RSA encryption input")?;

        let mut command = self.gpg_command();
        self.add_rng_hook(&mut command, random_start, true);
        command
            .arg("--trust-model")
            .arg("always")
            .arg("--recipient")
            .arg(&self.fingerprint)
            .arg("--cipher-algo")
            .arg("AES256")
            .arg("--compress-algo")
            .arg("none")
            .arg("--no-literal")
            .arg("--output")
            .arg(&gpg_output)
            .arg("--encrypt")
            .arg(&input);
        run(&mut command, "GnuPG RSA session-key encryption")?;

        let gpg_bytes = fs::read(&gpg_output).context("read GnuPG RSA encryption")?;
        let rpgp_bytes = rpgp_rsa_encryption(&self.secret, &literal, random_start)?;
        let gpg_body = packet_body_by_tag(&gpg_bytes, 1)?;
        let rpgp_body = packet_body_by_tag(&rpgp_bytes, 1)?;
        equal_bytes("RSA-3072 PKESK packet body", gpg_body, rpgp_body)
    }

    fn compare_aes256_seipdv1(&self, payload: &[u8], random_start: u8) -> Result<()> {
        let literal = literal_packet(payload);
        let case = tempdir().context("create AES encryption case directory")?;
        let input = case.path().join("literal.pgp");
        let gpg_output = case.path().join("gpg.pgp");
        fs::write(&input, &literal).context("write AES encryption input")?;

        let mut command = self.gpg_command();
        self.add_rng_hook(&mut command, random_start, false);
        command
            .arg("--pinentry-mode")
            .arg("loopback")
            .arg("--passphrase")
            .arg(std::str::from_utf8(PASSWORD).expect("ASCII test password"))
            .arg("--cipher-algo")
            .arg("AES256")
            .arg("--s2k-mode")
            .arg("3")
            .arg("--s2k-digest-algo")
            .arg("SHA256")
            .arg("--s2k-count")
            .arg(S2K_DECODED_COUNT)
            .arg("--compress-algo")
            .arg("none")
            .arg("--no-literal")
            .arg("--output")
            .arg(&gpg_output)
            .arg("--symmetric")
            .arg(&input);
        run(&mut command, "GnuPG AES-256 SEIPDv1 encryption")?;

        let gpg_bytes = fs::read(&gpg_output).context("read GnuPG AES encryption")?;
        let gpg_packet = packet_body_by_tag(&gpg_bytes, 18)?;
        ensure!(gpg_packet.first() == Some(&1), "GnuPG did not emit SEIPDv1");
        let rpgp_body = rpgp_seipdv1_body(&literal, random_start)?;
        equal_bytes(
            "AES-256 SEIPDv1 encrypted body",
            &gpg_packet[1..],
            &rpgp_body,
        )
    }

    fn gpg_command(&self) -> Command {
        let mut command = Command::new(&self.gpg);
        command
            .arg("--batch")
            .arg("--yes")
            .arg("--no-tty")
            .arg("--no-options")
            .arg("--no-random-seed-file")
            .arg("--homedir")
            .arg(&self.gpg_home);
        command
    }

    fn add_rng_hook(&self, command: &mut Command, start: u8, nonzero: bool) {
        command
            .env("LD_PRELOAD", &self.hook)
            .env("LIZARD_GPG_TEST_RNG", "INSECURE_DIFFERENTIAL_TEST_ONLY")
            .env("LIZARD_GPG_TEST_RNG_START", start.to_string());
        if nonzero {
            command.env("LIZARD_GPG_TEST_RNG_NONZERO", "1");
        } else {
            command.env_remove("LIZARD_GPG_TEST_RNG_NONZERO");
        }
    }
}

fn require_gpg_version(gpg: &Path) -> Result<()> {
    let output = Command::new(gpg)
        .arg("--version")
        .output()
        .with_context(|| format!("execute {}", gpg.display()))?;
    ensure!(output.status.success(), "GnuPG --version failed");
    let stdout = String::from_utf8(output.stdout).context("GnuPG version is not UTF-8")?;
    let first = stdout.lines().next().unwrap_or_default();
    ensure!(
        first == REQUIRED_GPG_VERSION,
        "exact differential oracle requires {REQUIRED_GPG_VERSION}, found {first}"
    );
    Ok(())
}

fn compile_hook(output: &Path) -> Result<()> {
    let cc = env::var_os("CC").unwrap_or_else(|| "cc".into());
    let source = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("native")
        .join("deterministic_rng_hook.c");
    let result = Command::new(&cc)
        .arg("-std=c11")
        .arg("-O2")
        .arg("-fPIC")
        .arg("-shared")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg(&source)
        .arg("-ldl")
        .arg("-o")
        .arg(output)
        .output()
        .with_context(|| format!("execute C compiler {:?}", cc))?;
    ensure!(
        result.status.success(),
        "failed to compile deterministic RNG hook:\n{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

fn verify_hook_guard(gpg: &Path, hook: &Path) -> Result<()> {
    let result = Command::new(gpg)
        .arg("--version")
        .env("LD_PRELOAD", hook)
        .env_remove("LIZARD_GPG_TEST_RNG")
        .env_remove("LIZARD_GPG_TEST_RNG_START")
        .env_remove("LIZARD_GPG_TEST_RNG_NONZERO")
        .output()
        .context("exercise deterministic RNG hook guard")?;
    ensure!(
        result.status.code() == Some(99),
        "deterministic RNG hook did not fail closed without its opt-in"
    );
    Ok(())
}

fn base_setup_command(gpg: &Path, home: &Path) -> Command {
    let mut command = Command::new(gpg);
    command
        .arg("--batch")
        .arg("--yes")
        .arg("--no-tty")
        .arg("--no-options")
        .arg("--no-random-seed-file")
        .arg("--homedir")
        .arg(home)
        .arg("--pinentry-mode")
        .arg("loopback")
        .arg("--passphrase")
        .arg("");
    command
}

fn generate_rsa_key(gpg: &Path, home: &Path) -> Result<()> {
    let mut command = base_setup_command(gpg, home);
    command
        .arg("--faked-system-time")
        .arg(format!("{KEY_TIME}!"))
        .arg("--quick-generate-key")
        .arg(TEST_UID)
        .arg("rsa3072")
        .arg("sign")
        .arg("0");
    run(&mut command, "generate disposable RSA signing key")?;
    Ok(())
}

fn primary_fingerprint(gpg: &Path, home: &Path) -> Result<String> {
    let mut command = base_setup_command(gpg, home);
    command
        .arg("--with-colons")
        .arg("--list-secret-keys")
        .arg(TEST_UID);
    let output = run(&mut command, "list disposable RSA key")?;
    let listing = String::from_utf8(output.stdout).context("GnuPG key listing is not UTF-8")?;
    listing
        .lines()
        .filter_map(|line| {
            let fields: Vec<_> = line.split(':').collect();
            (fields.first() == Some(&"fpr"))
                .then(|| fields.get(9).copied())
                .flatten()
        })
        .next()
        .map(str::to_owned)
        .context("GnuPG did not report the primary fingerprint")
}

fn add_encryption_subkey(gpg: &Path, home: &Path, fingerprint: &str) -> Result<()> {
    let mut command = base_setup_command(gpg, home);
    command
        .arg("--faked-system-time")
        .arg(format!("{}!", KEY_TIME + 1))
        .arg("--quick-add-key")
        .arg(fingerprint)
        .arg("rsa3072")
        .arg("encr")
        .arg("0");
    run(&mut command, "add disposable RSA encryption subkey")?;
    Ok(())
}

fn export_secret_key(gpg: &Path, home: &Path, fingerprint: &str) -> Result<SignedSecretKey> {
    let mut command = base_setup_command(gpg, home);
    command
        .arg("--armor")
        .arg("--export-options")
        .arg("export-minimal")
        .arg("--export-secret-keys")
        .arg(fingerprint);
    let output = run(&mut command, "export disposable RSA key")?;
    let armored = String::from_utf8(output.stdout).context("secret key armor is not UTF-8")?;
    SignedSecretKey::from_string(&armored)
        .map(|(key, _)| key)
        .context("rPGP could not parse the GnuPG-generated secret key")
}

fn run(command: &mut Command, description: &str) -> Result<Output> {
    let output = command
        .output()
        .with_context(|| format!("execute {description}"))?;
    ensure!(
        output.status.success(),
        "{description} failed with {}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn rpgp_rsa_signature(key: &SignedSecretKey, data: &[u8], timestamp: u32) -> Result<Vec<u8>> {
    let hashed = vec![
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            key.primary_key.fingerprint(),
        ))?,
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::from_secs(
            timestamp,
        )))?,
    ];
    let unhashed = vec![Subpacket::regular(SubpacketData::IssuerKeyId(
        key.primary_key.legacy_key_id(),
    ))?];
    let signature = DetachedSignature::sign_binary_data_with_subpackets(
        CounterRng(0),
        &key.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        data,
        SubpacketConfig::UserDefined { hashed, unhashed },
    )?;
    let mut output = Vec::new();
    signature.to_writer(&mut output)?;
    Ok(output)
}

fn rpgp_rsa_encryption(
    secret: &SignedSecretKey,
    literal: &[u8],
    random_start: u8,
) -> Result<Vec<u8>> {
    let public = SignedPublicKey::from(secret.clone());
    let recipient = &public
        .public_subkeys
        .first()
        .context("missing RSA encryption subkey")?
        .key;
    let mut rng = NonzeroCounterRng(u64::from(random_start));
    let mut builder = MessageBuilder::from_bytes("", literal.to_vec())
        .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
    builder.encrypt_to_key(&mut rng, recipient)?;
    let mut output = Vec::new();
    builder.to_writer(&mut rng, &mut output)?;
    Ok(output)
}

fn rpgp_seipdv1_body(literal: &[u8], random_start: u8) -> Result<Vec<u8>> {
    let mut salt = [0u8; 8];
    for (index, byte) in salt.iter_mut().enumerate() {
        *byte = random_start.wrapping_add(index as u8);
    }
    let s2k = StringToKey::IteratedAndSalted {
        hash_alg: HashAlgorithm::Sha256,
        salt,
        count: 255,
    };
    let key = s2k.derive_key(PASSWORD, 32)?;
    let mut encryptor = StreamEncryptor::new(
        CounterRng(u64::from(random_start) + 8),
        SymmetricKeyAlgorithm::AES256,
        key.as_ref(),
        literal,
    )?;
    let mut output = Vec::new();
    encryptor.read_to_end(&mut output)?;
    Ok(output)
}

pub fn literal_packet(payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(payload.len() + 6);
    body.push(b'b');
    body.push(0);
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(payload);

    let mut packet = vec![0xc0 | 11];
    write_new_length(body.len(), &mut packet);
    packet.extend_from_slice(&body);
    packet
}

fn write_new_length(length: usize, output: &mut Vec<u8>) {
    if length < 192 {
        output.push(length as u8);
    } else if length <= 8_383 {
        let adjusted = length - 192;
        output.push(((adjusted >> 8) + 192) as u8);
        output.push((adjusted & 0xff) as u8);
    } else {
        output.push(255);
        output.extend_from_slice(&(length as u32).to_be_bytes());
    }
}

pub fn packet_body_by_tag(bytes: &[u8], wanted_tag: u8) -> Result<&[u8]> {
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (tag, body_start, body_end) = packet_at(bytes, cursor)?;
        if tag == wanted_tag {
            return Ok(&bytes[body_start..body_end]);
        }
        cursor = body_end;
    }
    bail!("packet tag {wanted_tag} not found")
}

fn packet_at(bytes: &[u8], offset: usize) -> Result<(u8, usize, usize)> {
    let ctb = *bytes.get(offset).context("truncated packet header")?;
    ensure!(ctb & 0x80 != 0, "invalid packet header at offset {offset}");
    let mut cursor = offset + 1;
    let (tag, length) = if ctb & 0x40 != 0 {
        let tag = ctb & 0x3f;
        let first = take_u8(bytes, &mut cursor)?;
        let length = match first {
            0..=191 => usize::from(first),
            192..=223 => {
                ((usize::from(first) - 192) << 8) + usize::from(take_u8(bytes, &mut cursor)?) + 192
            }
            255 => take_u32(bytes, &mut cursor)? as usize,
            _ => bail!("partial packet lengths are outside the harness profile"),
        };
        (tag, length)
    } else {
        let tag = (ctb >> 2) & 0x0f;
        let length = match ctb & 0x03 {
            0 => usize::from(take_u8(bytes, &mut cursor)?),
            1 => usize::from(take_u16(bytes, &mut cursor)?),
            2 => take_u32(bytes, &mut cursor)? as usize,
            _ => bail!("indeterminate old-format packet length is outside the harness profile"),
        };
        (tag, length)
    };
    let end = cursor
        .checked_add(length)
        .context("packet length overflow")?;
    ensure!(end <= bytes.len(), "truncated packet body for tag {tag}");
    Ok((tag, cursor, end))
}

fn take_u8(bytes: &[u8], cursor: &mut usize) -> Result<u8> {
    let byte = *bytes.get(*cursor).context("truncated packet length")?;
    *cursor += 1;
    Ok(byte)
}

fn take_u16(bytes: &[u8], cursor: &mut usize) -> Result<u16> {
    let end = cursor.checked_add(2).context("packet length overflow")?;
    let raw: [u8; 2] = bytes
        .get(*cursor..end)
        .context("truncated packet length")?
        .try_into()
        .expect("two-byte slice");
    *cursor = end;
    Ok(u16::from_be_bytes(raw))
}

fn take_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32> {
    let end = cursor.checked_add(4).context("packet length overflow")?;
    let raw: [u8; 4] = bytes
        .get(*cursor..end)
        .context("truncated packet length")?
        .try_into()
        .expect("four-byte slice");
    *cursor = end;
    Ok(u32::from_be_bytes(raw))
}

fn equal_bytes(label: &str, left: &[u8], right: &[u8]) -> Result<()> {
    if left == right {
        return Ok(());
    }
    let first = left
        .iter()
        .zip(right)
        .position(|(a, b)| a != b)
        .unwrap_or_else(|| left.len().min(right.len()));
    let left_byte = left.get(first).copied();
    let right_byte = right.get(first).copied();
    bail!(
        "{label} mismatch at byte {first}: GnuPG={left_byte:02x?}, rPGP={right_byte:02x?}; lengths {} vs {}",
        left.len(),
        right.len()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_packet_has_expected_body() {
        let packet = literal_packet(b"hello");
        assert_eq!(
            packet_body_by_tag(&packet, 11).unwrap(),
            b"b\0\0\0\0\0hello"
        );
    }

    #[test]
    fn packet_parser_accepts_old_and_new_fixed_headers() {
        assert_eq!(packet_body_by_tag(&[0x88, 1, 0xaa], 2).unwrap(), &[0xaa]);
        assert_eq!(packet_body_by_tag(&[0xc2, 1, 0xbb], 2).unwrap(), &[0xbb]);
    }
}
