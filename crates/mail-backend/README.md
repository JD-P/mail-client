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

- complete RFC 5322 payloads are immutable, content-addressed, and hash-checked
  on read; a header-only projection is separately and explicitly typed until
  the complete payload arrives;
- on Unix, the profile directory is forced to owner-only permissions;
- account passwords and OAuth access tokens never enter Turso: the built-in
  provider first writes to macOS Keychain, Windows Credential Manager or
  freedesktop Secret Service, then falls back to an XChaCha20-Poly1305 profile
  vault when no native write succeeds;
- the fallback key deliberately lives in the same owner-only profile, like
  Thunderbird without a Primary Password: it prevents plaintext storage but
  does not protect a copied profile; mail blobs, Turso and Tantivy likewise
  rely on operating-system full-disk encryption;
- normalized metadata/search text is rebuildable local Turso state;
- MIME parsing and decoded body extraction have explicit byte/depth/part limits;
- the complete MIME tree, selected plain/HTML alternatives, per-part decode
  state and decoded Content-ID resources are materialized once during ingest;
  attachments have bounded streaming reads, create-new safe export, magic-byte
  type evidence and ZIP inspection/expansion budgets;
- hostile document conversion is an optional `SandboxedDocumentExtractor`
  boundary with input, output and wall-clock budgets, never an in-process
  office/PDF parser;
- every physical DKIM signature is verified from the stored bytes under parser,
  signature, DNS-query and wall-clock budgets, then persisted as typed evidence;
- the default DKIM resolver uses Quad9 DNS-over-TLS with local DNSSEC
  validation; system DNS is an explicit configuration policy;
- every physical `Authentication-Results` and `ARC-Authentication-Results`
  field is parsed under fixed work and storage limits; only the first complete
  result from an exact, per-account configured `authserv-id` is trusted, while
  all other copies remain explicitly untrusted evidence;
- trusted delivery-time DKIM and DMARC remain distinct from independent DKIM
  verification, SPF is retained only as low-level evidence, and ARC results
  remain diagnostic until the ARC chain is independently verified;
- a remote identity is `(folder, UIDVALIDITY, UID)`, never RFC `Message-ID`;
- contacts are the single source of truth for Warm versus Cold; explicit user
  Spam/NotSpam corrections are authoritative, while RFC 6154 `\Junk` mailbox
  state and registered `$Junk`/`$NotJunk` keywords are preserved as separate,
  typed provider evidence;
- a bounded Robinson/Fisher Bayesian classifier is initialized from a bundled,
  literally authored CC0 corpus of 1,000 messages: 20 categories with 50
  examples each, evenly divided between spam and legitimate mail; explicit
  user corrections train it reversibly, while provider verdicts and contact
  membership never become training labels;
- every message receives a stable `ThreadId` atomically with ingestion;
  `References`/`In-Reply-To` take precedence, while normalized-subject fallback
  requires an unambiguous recent match from the same sender;
- known-origin threads have a permanent trust boundary, so an unknown sender
  cannot inject a forged reply even when it copies a real `Message-ID`;
  known/self senders may continue an older cold thread without upgrading it;
- remote mailbox instances and local folder memberships are durable state;
- filter conditions are pure implicit-AND checks; actions may change local
  placement or queue exact remote move/trash/delete operations through the
  durable IMAP mutation outbox, but cannot modify contacts or trust, alter raw
  message content, send mail, or affect messages other than the match;
- filter previews report both matches and material changes, explicit replay is
  idempotent across existing mail, and every application captures exact prior
  local placement plus remote mutation IDs for durable undo;
- named saved searches persist validated Gmail-shaped queries; snooze, mute and
  low/normal/high priority are durable message state exposed in summaries and
  mailbox filters;
- contacts support editing and bounded UTF-8 vCard 4.0 import/export with
  manual/import provenance; account and folder records support update/removal,
  while authenticated IMAP sessions create, rename and delete remote mailboxes;
- heuristic source is compiled from a restricted Python-shaped subset into a
  bounded serialized IR; no Python runtime, imports or arbitrary calls execute;
- typed findings and separate dismissal state are durable Turso data returned
  with message reads, never programmable client presentation;
- search and mailbox scrolling use stable keyset cursors rather than offsets;
- Turso is authoritative while native Tantivy is a rebuildable search
  projection maintained through a revisioned, crash-replayable database outbox;
- missing, incompatible or count-inconsistent Tantivy indexes rebuild from
  Turso, and replay uses delete-plus-add upserts so a crash cannot duplicate hits;
- `Storage::audit` checks Turso integrity and foreign keys, every database blob
  reference, optional full SHA-256 content verification, partial-download
  consistency, orphaned/temporary files and Tantivy counts under a bounded
  typed report; warnings remain distinct from data-threatening errors;
- profile usage is reported by database, content blobs, search projection,
  partial downloads, credentials and other files; an optional whole-profile
  quota, a default 64 MiB emergency free-space reserve and durable per-account
  downloaded-message quotas fail with typed errors before message state commits;
- content-addressed writes reserve their growth before writing, serialize only
  equal-hash publication, clean failed temporary files and translate OS,
  Turso, Tantivy and IMAP disk-full evidence into `StorageFull`;
- changes commit with the state they describe and can be replayed by sequence;
- bulk ingestion publishes at most 1,000 messages or 64 MiB of staged data per
  atomic Turso chunk, then commits the corresponding Tantivy batch before the
  API call returns;
- IMAP configuration permits TLS or STARTTLS, not plaintext, and stores only an
  opaque credential reference; replacing or removing account/SMTP
  configuration deletes a Lizard-owned credential after its final reference
  disappears;
- `ImapAccountEngine` owns TLS connection establishment, credential resolution,
  SASL/OAuth authentication, mailbox discovery, capability negotiation,
  UIDVALIDITY/CONDSTORE/QRESYNC reconciliation, IDLE/poll wakeups, cancellation
  and bounded reconnect backoff;
- initial IMAP synchronization fetches bounded header fields and BODYSTRUCTURE,
  making sender, subject, flags, size, threading and attachment presence useful
  without transferring message bodies;
- `MessageContentStatus` durably distinguishes `headers_only`, `downloading`,
  `complete` and `failed`, including expected/downloaded byte counts and the
  last failure; `Messages::raw` and the MIME APIs reject incomplete content;
- on-demand body downloads use bounded `BODY.PEEK[]<offset.count>` requests,
  persist a partial file, resume at its exact durable offset after failure or
  restart, and publish MIME, DKIM, body search and heuristic results only after
  the exact complete payload commits; dropping a download future durably marks
  its synchronized prefix as a resumable cancellation;
- account and mailbox progress, failures, retry time and body completeness are
  durable API state rather than transient log messages;
- server-side removals update Turso and Tantivy together, so expunged mail does
  not survive as a stale search result.
- `ImapMutations` queues offline-safe flag, copy, move, trash and exact-delete
  requests against one UIDVALIDITY/UID identity; queue rows, state transitions,
  conflicts and change events are durable;
- flag edits are optimistic locally, coalesce while pending, use conditional
  STORE when available and are verified afterward; COPY/MOVE require UIDPLUS
  mappings so the destination remains the same logical message;
- interrupted non-idempotent COPY/MOVE operations become blocking ambiguity
  conflicts instead of being retried into duplicate mail. Clients can inspect
  the conflict evidence and explicitly cancel the operation to acknowledge it.
- draft autosaves use optimistic revisions; attachment ingest is streamed into
  the content-addressed store under individual and aggregate limits;
- enqueue freezes protected headers, envelope recipients and exact MIME bytes
  into a durable outbox entry. Bcc is envelope-only and the client never adds a
  DKIM signature;
- `SmtpEngine` supports verified implicit TLS/STARTTLS and credential-provider
  Password, XOAUTH2 or OAUTHBEARER authentication. Definite failures, bounded
  backoff, safe cancellation and post-DATA ambiguous delivery are distinct
  durable states; ambiguous delivery is never retried automatically;
- an accepted submission is ingested as the local Sent message, then a later
  server Sent-folder copy is reconciled by protected Message-ID, account,
  sender identity and `\\Sent` mailbox role without creating a duplicate.

`Backend::threads` lists and reads conversation objects rather than requiring
frontends to group messages themselves. Membership exposes the selected parent,
source (`References`, `In-Reply-To`, normalized subject or root) and immutable
sender-trust partition. `Threads::reply` constructs bounded reply headers and
Reply-All recipients while removing the user's account identities.
`Threads::forward` deliberately creates a new thread with no reply headers and
identifies the exact original message as a `message/rfc822` attachment.

`Backend::imap_account_engine` accepts a `CredentialProvider` implemented by an
OS keychain or OAuth broker. The provider receives only the account's opaque
credential reference and returns a zeroizing, debug-redacted secret. The
engine accepts implicit TLS or verified STARTTLS and never represents plaintext
production transport. `sync_once` is useful for explicit refresh; `run` uses
IDLE when available, polling otherwise, and stops through a cancellation token.

`imap_fetch_message` remains the adapter for importers that already possess a
complete `async-imap` `FETCH` result. The caller must request `UID FLAGS
INTERNALDATE BODY.PEEK[]`; `MODSEQ` is retained when available, and missing UID
or complete body data is rejected.

Ordinary `Sync::pull_imap_folder` instead requests selected header fields,
`RFC822.SIZE` and `BODYSTRUCTURE`, advances the UID cursor after those durable
projections commit, and transfers no body bytes. A front end can call
`ImapAccountEngine::fetch_message_content` or the authenticated-session
`Sync::fetch_imap_message_content` boundary when a message is opened or chosen
for offline caching. `Messages::content_status` exposes progress without
guessing from empty body fields.

Search returns a `SearchPage`. For body terms and `filename:`, its
`content_results_complete` flag is false whenever any message still lacks
complete content, so an empty or partial result is never presented as an
exhaustive answer. Header-only operators remain complete immediately.

`ingest_imap_batch` routes complete fetch batches through the same bounded
set-based path exposed as `Backend::ingest_batch` and
`Messages::ingest_batch`; `ingest_imap_header_batch` is the corresponding
transport-neutral header projection boundary.

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

The crate now includes account-owned IMAP receive and SMTP submission engines,
durable security-partitioned threads, reply/forward and MIME construction,
structured filter execution, bounded Python-shaped heuristic programs,
materialized MIME resources, and persisted DKIM evidence. Findings and
authentication results are returned with message reads. A mandatory native
security-evidence pass covers identity contradictions, DKIM alignment, hostile
navigation, UTS #39 domain confusables, remote resources, credential forms,
attachment magic/filenames and bounded ZIP directory metadata. It performs no
network loads, script execution or archive expansion. OpenPGP and
independent ARC-chain verification remain future work. See
`../../spec/mail-backend.md` for the authority and presentation model.
