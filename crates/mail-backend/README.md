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
- a remote identity is `(folder, UIDVALIDITY, UID)`, never RFC `Message-ID`;
- contacts are the single source of truth for Warm versus Cold, while explicit
  Spam wins over contact state;
- remote mailbox instances and local folder memberships are durable state;
- search and mailbox scrolling use stable keyset cursors rather than offsets;
- changes commit with the state they describe and can be replayed by sequence;
- IMAP configuration permits TLS or STARTTLS, not plaintext, and stores only an
  opaque credential reference.

`imap_fetch_message` converts complete `async-imap` `FETCH` results into the
transport-neutral batch type. The caller must request `UID FLAGS MODSEQ
INTERNALDATE BODY.PEEK[]`; missing UID or complete body data is rejected.

The initial search grammar supports bare terms, quoted phrases, parentheses,
`AND`, `OR`, unary `-`, `from:`, `to:`, `cc:`, `bcc:`, `subject:`,
`deliveredto:`, `after:`, `before:`, `older:`, `newer:`, `older_than:`,
`newer_than:`, `in:`, `label:`, `account:`, `is:`, `has:attachment`,
`filename:`, `list:`, `size:`, `larger:`, `smaller:` and exact `rfc822msgid:` or
`message-id:`. Invalid operators and malformed values return source-spanned
query errors. Query size, token count and parenthesis depth are bounded.

Run its focused checks with:

```sh
cargo test -p lizard-mail-backend
cargo clippy -p lizard-mail-backend --all-targets --no-deps -- -D warnings
```

A deterministic synthetic scaling probe is available as:

```sh
cargo run --release -p lizard-mail-backend --example search_benchmark -- 8,16,32,64,128
```

Its generated corpus is useful for regression and scaling measurements, not as
a substitute for the representative mixed corpus specified in
`../../spec/mail-backend.md`.

The next layers are the actual IMAP session/synchronization driver, rule
execution, authentication evidence and OpenPGP integration. See
`../../spec/mail-backend.md`; this README intentionally does not present those
unimplemented layers as complete.
