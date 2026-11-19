# Pass 1 — OpenPGP decompression and terminal identity presentation

- **Date:** 2026-11-19
- **Subject:** clean commit
  `4d04393b2fcd9f8cee25029279cc2fe3bd4a3b5c`, equal to `origin/main`
  before this pass created `adversarial/`.
- **Harnesses:**
  `adversarial/p1/openpgp-compression-bomb/` and
  `adversarial/p1/tui-bidi-queue/`; retained output is in
  `adversarial/p1/results_openpgp.txt` and
  `adversarial/p1/results_tui_bidi.txt`. Post-fix output is retained in
  `adversarial/p1/results_remediation.txt`.
- **Method:** mapped attacker-controlled mail through ingestion, MIME and
  archive parsing, authentication evidence, OpenPGP, threading, search,
  terminal presentation and the sandboxed Gecko-subset worker. Prioritized
  pre-limit allocations and places where attacker-controlled identity text
  crosses into trusted UI grammar. All exploit work was local; product source
  was not modified.
- **Disposition:** **P1-A and P1-B confirmed at the reviewed commit and
  remediated by `562aea7d3b29ec64c6e65851137caf557b01750b`.**

---

## 1. Executive summary

| # | Finding | Intended boundary | Observed behavior | Class |
|---|---|---|---|---|
| **P1-A** | The software OpenPGP provider fully inflates attacker-controlled compressed plaintext into a `Vec<u8>` before applying the 64 MiB decrypted-message limit. | Encrypted mail should be rejected once decrypted output crosses `max_message_bytes`/`MAX_DECRYPTED_BYTES`, without materializing output beyond that boundary. | A 179,279-byte valid OpenPGP/MIME message inflated to 128 MiB, peaked at 213,264 KiB RSS, and was rejected only afterward. Under a 180,000 KiB address-space ceiling, the same ordinary-size message aborted the process on a 32 MiB allocation. | **high denial of service**; remote mail sender, expected OpenPGP use, read/decrypt interaction |
| **P1-B** | Attacker-supplied queue text should be inert, matching the reader and HTML renderer's explicit bidi sanitization. | No message text should emit Unicode bidi formatting controls into the terminal stream. | A subject containing U+202E survives ingestion and is emitted byte-for-byte by the real Ratatui/Crossterm queue path. On bidi-capable terminals it can reorder the sender/subject/state row. | **low integrity violation**; terminal-dependent phishing/presentation defect, limited by Cold coloring and sanitized reader |

---

## 2. P1-A — the OpenPGP size check occurs after decompression

### 2.1 The software-key path has no output-limiting reader

`decrypt_authenticated_entity` asks a provider for a complete plaintext
`Vec<u8>` and checks its length only after the provider returns:

```rust
// crates/mail-backend/src/openpgp.rs:1320-1343
match self.decrypt_with_provider(&provider, &encrypted).await {
    Ok(value) => plaintext = Some((value, provider.fingerprint)),
    ...
}

if plaintext.len() > self.0.inner.config.limits.max_message_bytes
    || plaintext.len() > MAX_DECRYPTED_BYTES
{
    ...
}
```

The software provider decrypts, recursively unwraps every compressed message,
then calls rPGP's unbounded `as_data_vec()`:

```rust
// crates/mail-backend/src/openpgp.rs:1411-1417
let message = Message::from_bytes(encrypted)?;
let mut decrypted = message.decrypt(&password, &secret)?;
while decrypted.is_compressed() {
    decrypted = decrypted.decompress()?;
}
decrypted.as_data_vec()
```

rPGP exposes the decompressed literal as a reader internally, but
`as_data_vec()` reads it to completion. The configured default is 64 MiB
(`types.rs:78-82`), so the check does not constrain the allocation that is
supposed to enforce it.

The external-provider branch is a useful control: GnuPG/YubiKey decryption
uses `run_gpg(..., MAX_DECRYPTED_BYTES)` (`openpgp.rs:1419-1422`), whose
subprocess output reader is bounded while data is arriving. The defect is the
in-process software provider's missing equivalent.

### 2.2 End-to-end received-message reproduction

The retained harness:

1. Generates an RFC 9580 Ed25519/X25519 software key through the same rPGP
   version used by the backend and imports it through the public backend API.
2. Creates a valid encrypted, integrity-protected OpenPGP packet containing a
   ZLIB-compressed MIME entity.
3. Wraps that packet in `multipart/encrypted`, ingests the exact RFC 5322
   bytes through `Messages::ingest`, closes the generator, reopens the profile
   in a fresh process and calls `OpenPgp::decrypt_message`.

The one-MiB control and 128-MiB candidate measured:

| Fixture | Outer email | Decrypted literal | Decrypt result | Peak RSS |
|---|---:|---:|---|---:|
| control | 2,161 bytes | 1,048,576 bytes | success | 83,664 KiB |
| candidate | 179,279 bytes | 134,217,728 bytes | rejected as over 67,108,864 bytes | 213,264 KiB |

The candidate is roughly **749 times larger after decompression than the
received email**. Its RSS delta over the control is about 126.6 MiB, closely
tracking the materialized plaintext. This is not merely a false-positive size
error: with `RLIMIT_AS=180000 KiB`, the candidate prints
`memory allocation of 33554432 bytes failed` and exits via `SIGABRT` before a
size error can be returned.

The chosen 128 MiB literal keeps the retained test inexpensive. An attacker
who has the recipient's public key controls the compressed plaintext length;
the 64 MiB configured value supplies no upper bound before allocation.

### 2.3 Reachability, impact and severity

- **Primary family:** `denial_of_service`.
- **Impact tier:** high. A remote sender can deliver the fixture as an
  ordinary small encrypted email using only the recipient's public key. When
  a software-key user reads/decrypts it, the main backend process—not the
  disposable HTML renderer—performs the expansion. Output can be selected to
  exhaust the process or machine, and the retained message can retrigger the
  failure on another open. User interaction and the OpenPGP/software-provider
  precondition limit population-wide reach, but both are ordinary intended
  use rather than privileged or abnormal configuration.
- **Unintended behavior count:** 1. A post-decompression length check is used
  as if it bounded decompression output.
- **Remediation component count:** 1. The software provider needs a bounded
  streaming plaintext sink shared with the configured message limit. A
  separate small nesting counter should be enforced in the same component so
  nested compression cannot exchange memory amplification for unbounded
  decompression stages.

### 2.4 Remediation and regression boundary

Implemented in `562aea7d3b29ec64c6e65851137caf557b01750b`:

1. Software-provider plaintext is authenticated and counted through a 64 KiB
   streaming buffer. At most one MiB is retained during this first pass, and
   the reader stops on the first byte beyond
   `min(max_message_bytes, MAX_DECRYPTED_BYTES)`.
2. Messages larger than the one-MiB inline buffer are decrypted a second time
   into an exactly sized allocation only after the first pass reaches EOF and
   completes rPGP's MDC/AEAD authentication. This avoids writing decrypted
   mail to a temporary file while ensuring an oversized message is never
   materialized.
3. Compression nesting is capped at 16. GnuPG/YubiKey subprocess output now
   uses the same configured limit as the software provider.
4. Unit regressions cover exact-limit acceptance, the single sentinel byte,
   and length-only handling of larger plaintext. The unchanged end-to-end
   fixture now returns `MessageTooLarge` under the original 180,000 KiB
   address-space ceiling with a 77,544 KiB peak RSS instead of aborting.

---

## 3. P1-B — the queue emits bidi controls that other views neutralize

### 3.1 The queue is the unsanitized presentation path

The queue puts stored participant and subject strings directly into Ratatui
spans:

```rust
// crates/mail-tui/src/ui.rs:88-109
let sender = thread.participants.first()...;
let subject = thread.subject.as_deref().unwrap_or("(no subject)");
...
format!("{sender:<28.28}")
Span::raw(format!("  {subject}{state}"))
```

The same module already defines `safe_text`, which replaces U+202A–U+202E and
U+2066–U+2069 (`ui.rs:478-495`), and uses it in the message reader. The HTML
renderer makes the policy even more explicit by rendering visible `⟦RLO⟧`,
`⟦LRI⟧`, and related tokens (`render.rs:1520-1535`). The queue simply does not
call either sanitizer.

Ratatui removes C0 controls such as ESC and BEL, but Unicode bidi formatting
characters are not C0 controls. The retained end-to-end harness ingests:

```text
Subject: Invoice <U+202E>moc.live@troppus
```

and captures the actual Crossterm writer. The terminal stream contains the
exact UTF-8 bytes `E2 80 AE`; `terminal_contains_rlo=true`. A terminal that
implements the Unicode bidi algorithm may visually reverse subsequent text,
including neighboring queue-row content. This undermines the client's rule
that attacker-supplied identity metadata must not speak in the application's
own voice.

### 3.2 Reachability, impact and severity

- **Primary family:** `integrity_violation`.
- **Impact tier:** low. Any message sender controls the subject, and inbound
  address text can reach the participant column. The result is a phishing and
  UI-integrity primitive on bidi-capable terminals, not code execution or a
  trust-state mutation. Cold mail remains blue, and opening the message moves
  to a reader that neutralizes the controls. Terminals without bidi support
  display no reordering.
- **Unintended behavior count:** 1. The queue bypasses the shared inert-text
  rule applied to the other attacker-controlled display paths.
- **Remediation component count:** 1. Apply one presentation sanitizer before
  width/truncation to every attacker-controlled queue field.

### 3.3 Remediation and regression boundary

Implemented in `562aea7d3b29ec64c6e65851137caf557b01750b`:

1. A single-line terminal sanitizer replaces C0 controls and all bidi
   embeddings, overrides and isolates before queue width/truncation.
2. The same boundary now covers queue participants and subjects, onboarding
   identities, contact rows, DKIM labels and dynamic footer status text.
3. A unit regression covers ESC, RLO, LRI, newline and tab. The unchanged
   Crossterm capture now reports `terminal_contains_rlo=false` and contains
   the UTF-8 replacement marker at the original RLO position.

---

## 4. Negative observations and remaining risk

Retained details are in `adversarial/p1/negative-results.txt`.

- A real queue subject containing OSC 52 did **not** produce an OSC sequence
  at the Crossterm writer; Ratatui discarded ESC and BEL. P1-B is not a claim
  of arbitrary terminal command injection.
- CalDAV DTD/entity input is rejected by roxmltree as `DtdDetected`, so the
  tested XML expansion/XXE theory was rejected. CalDAV also enforces HTTPS,
  same-origin discovered URLs and final-response origin checks.
- MIME parsing has raw-message, header, depth, part, decoded-text, HTML-node
  and link limits. ZIP inspection reads metadata first and requires a complete
  within-budget inspection before bounded entry expansion. No archive bomb
  was retained.
- SMTP lines/responses and individual IMAP responses have byte/count and time
  limits. Some IMAP reconciliation paths still aggregate server-selected
  response sets into `Vec`/`HashSet` before applying mailbox cardinality
  checks. That deserves a dedicated malicious-server resource pass, but this
  review did not retain it as a confirmed finding.
- The Gecko-subset renderer runs in a disposable worker with an eight-second
  host deadline, a 512 MiB address-space limit, a CPU limit, closed
  descriptors and seccomp. No sandbox escape or host-side frame-length trust
  error was found in this pass.

These negative results are scoped observations, not proof that the remaining
surfaces are vulnerability-free.
