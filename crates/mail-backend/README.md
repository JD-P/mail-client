# Lizard mail backend

This crate is the renderer-independent, local-first backend for the mail
client. Open a profile with `Backend::open`, then use its typed service handles:

```rust,no_run
use lizard_mail_backend::{Backend, BackendConfig, IngestMessage};

# async fn example() -> lizard_mail_backend::Result<()> {
let backend = Backend::open(BackendConfig::new("mail-profile")).await?;
let id = backend
    .messages()
    .ingest(IngestMessage::local(b"From: a@example.com\r\n\r\nHello".to_vec()))
    .await?;
let message = backend.messages().get(id).await?;
# Ok(())
# }
```

Current invariants:

- raw RFC 5322 bytes are immutable, content-addressed, and hash-checked on read;
- on Unix, the profile directory is forced to owner-only permissions;
- normalized metadata/search text is rebuildable local Turso state;
- MIME parsing and decoded body extraction have explicit byte/depth/part limits;
- every physical DKIM signature is verified from the stored bytes under parser,
  signature, DNS-query and wall-clock budgets, then persisted as typed evidence;
- the default DKIM resolver uses Quad9 DNS-over-TLS with local DNSSEC
  validation; system DNS is an explicit configuration policy;
- a remote identity is `(folder, UIDVALIDITY, UID)`, never RFC `Message-ID`;
- contacts are the single source of truth for Warm versus Cold, while explicit
  Spam wins over contact state;
- remote mailbox instances and local folder memberships are durable state;
- filter conditions are pure implicit-AND checks and filter authority is limited
  to local placement of the message being evaluated;
- heuristic source is compiled from a restricted Python-shaped subset into a
  bounded serialized IR; no Python runtime, imports or arbitrary calls execute;
- typed findings and separate dismissal state are durable Turso data returned
  with message reads, never programmable client presentation;
- search and mailbox scrolling use stable keyset cursors rather than offsets;
- Turso is authoritative while native Tantivy is a rebuildable search
  projection maintained through a revisioned, crash-replayable database outbox;
- missing, incompatible or count-inconsistent Tantivy indexes rebuild from
  Turso, and replay uses delete-plus-add upserts so a crash cannot duplicate hits;
- changes commit with the state they describe and can be replayed by sequence;
- bulk ingestion publishes at most 1,000 messages or 64 MiB of staged data per
  atomic Turso chunk, then commits the corresponding Tantivy batch before the
  API call returns;
- IMAP configuration permits TLS or STARTTLS, not plaintext, and stores only an
  opaque credential reference.

`imap_fetch_message` converts complete `async-imap` `FETCH` results into the
transport-neutral batch type. The caller must request `UID FLAGS INTERNALDATE
BODY.PEEK[]`; `MODSEQ` is retained when available, and missing UID or complete
body data is rejected.
`ingest_imap_batch` routes complete fetch batches through the same bounded
set-based path exposed as `Backend::ingest_batch` and
`Messages::ingest_batch`. `Sync::pull_imap_folder` accepts an authenticated
session, performs incremental UID-based fetching, and advances its durable
cursor only after ingestion succeeds.

The initial search grammar supports bare terms, quoted phrases, parentheses,
`AND`, `OR`, unary `-`, `from:`, `to:`, `cc:`, `bcc:`, `subject:`,
`deliveredto:`, `after:`, `before:`, `older:`, `newer:`, `older_than:`,
`newer_than:`, `in:`, `label:`, `account:`, `is:`, `has:attachment`,
`filename:`, `list:`, `size:`, `larger:`, `smaller:` and exact `rfc822msgid:` or
`message-id:`. Invalid operators and malformed values return source-spanned
query errors. Query size, token count and parenthesis depth are bounded. Exact
newest-first pages are evaluated entirely by native Tantivy, including Boolean
text, state, folder/account, address, date and size predicates. Fast timestamp
and message-ID fields provide exact two-column ordering and stable keyset cursor
semantics; Turso hydrates the bounded result-ID page into message summaries.

Run its focused checks with:

```sh
cargo test -p lizard-mail-backend
cargo clippy -p lizard-mail-backend --all-targets --no-deps -- -D warnings
```

A deterministic synthetic scaling probe is available as:

```sh
cargo run --release -p lizard-mail-backend --example search_benchmark -- 8,16,32,64,128
```

The embedded-versus-native decision can be reproduced independently with:

```sh
cargo run --release -p lizard-mail-backend --example fts_comparison -- native-tantivy 128,256,512,1024
cargo run --release -p lizard-mail-backend --example fts_comparison -- turso-fts 128,256,512,1024
```

Its generated corpus is useful for regression and scaling measurements, not as
a substitute for the representative mixed corpus specified in
`../../spec/mail-backend.md`.

The crate now includes incremental IMAP pulling, structured filter execution,
bounded Python-shaped heuristic programs, and persisted DKIM evidence. Findings
and authentication results are returned with message reads. OpenPGP,
trusted-provider `Authentication-Results`, server-side IMAP mutations and the
broader built-in extractor library remain future work. See
`../../spec/mail-backend.md` for the authority and presentation model.
