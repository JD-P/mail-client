# Local mail backend and API

Status: design plus an implemented first vertical slice in
`crates/mail-backend`. The crate provides a typed asynchronous API, local Turso
schema, immutable content-addressed raw blobs, bounded RFC 5322/MIME ingestion,
accounts and folders, remote IMAP identities, local-folder membership,
contacts, dynamic Warm/Cold/Spam classification, Gmail-shaped search, stable
keyset pagination and a durable/live change stream. Its IMAP boundary accepts
complete fetch results from the hardened vendored client and routes them
through the same idempotent ingestion path as local imports.

The current slice does **not** yet open IMAP network sessions or retrieve
credentials, run DKIM/OpenPGP verification, execute user-authored rules,
extract every security heuristic, synchronize mutations back to a server,
send mail, or expose inter-process transport. Those are tracked here as the
next layers; the presence of their data-model requirements below is not a
claim that they are implemented.

Related frontend requirements: [security-ui.md](security-ui.md).

## Purpose

The backend is the single owner of mail retrieval, normalized message state,
search, stateful organization, contacts, authentication evidence and bounded
feature extraction. GUI, CLI and third-party clients consume one API rather
than separately replaying filters or reparsing hostile messages.

The backend must support offline use and remain useful without any Turso cloud
service. "Turso" in this document means the local, in-process Rust database.

The initial protocol is IMAP. POP3 follows after the storage and synchronization
model is stable. Sending mail is a separate but required workstream and is
listed below.

## Architectural boundaries

Keep the following concepts distinct:

1. **Queries** select and order current messages without changing state.
2. **Rules** apply durable actions such as folder membership, labels, priority
   or structured annotations.
3. **Heuristics** derive bounded evidence such as signature results, parsed
   link domains, attachment type contradictions and semantic features.
4. **Frontend policy** turns evidence into prose, interstitials and visual
   treatment.

Warm, Cold and Spam are canonical product-policy queries over backend facts.
Ordinary folders, remote mailboxes, local labels and rule-produced placement
are backend state.

## Local database

Use local Turso as the provisional authoritative metadata store and search
engine. Its native FTS uses Tantivy while keeping FTS changes in the database
transaction. This avoids a separate SQLite/Tantivy journal and reconciliation
protocol.

The choice remains conditional on crash, corruption, migration, compatibility
and performance tests. As of 2026-11-16, Turso is pre-1.0 and its FTS index
method is documented as experimental. FTS5 syntax is not supported, snippets
and external-content indexes are absent, and FTS writes are not visible to
queries until transaction commit. The application must treat search indexes as
rebuildable and keep independent backups of authoritative state.

Raw RFC 5322 bytes should be immutable and stored separately from normalized
search text, either as bounded blobs or in a content-addressed blob store.
Preserving the original bytes is necessary for signature verification,
forensics and lossless export. Content hashes may deduplicate storage but must
not be used as message identity.

## Core data model

Exact schema is deferred, but the model must represent at least:

- accounts and credential references;
- remote mailboxes and their synchronization cursors/capabilities;
- immutable raw message blobs;
- logical messages with application-stable IDs;
- per-account/per-mailbox message instances, including IMAP UID and
  UIDVALIDITY;
- mailbox and local-folder membership;
- labels, flags, snooze/mute/priority and user classification;
- threads and participant evidence;
- contacts and their exact addresses/accepted display-name aliases;
- OpenPGP public-key associations, fingerprints and locally established trust
  decisions;
- parsed MIME parts, attachments and links;
- signature and receiving-server authentication evidence;
- heuristic findings with rule/source/version provenance;
- saved queries, rules, rule versions and rule-application records; and
- a monotonic change stream for frontends and automation clients.

Do not use RFC `Message-ID` as a primary key: it can be absent, duplicated or
attacker-controlled. Do not assume that an IMAP UID is meaningful outside its
mailbox and UIDVALIDITY epoch.

### Remote mailboxes, local folders and views

Remote mailbox membership and local organization are related but not
identical:

- an IMAP mailbox is synchronized state with server-specific move/copy/delete
  semantics;
- a local folder or label is durable application state and may be populated by
  rules;
- a saved query is a dynamic view and does not imply membership; and
- canonical Warm/Cold/Spam views are frontend product policy over API
  predicates.

A third-party frontend must be able to ask the backend where a message has been
placed without replaying historical rules. Folder/label actions therefore
materialize membership transactionally and record the responsible rule and
version.

## Ingestion pipeline

Each newly fetched or changed message passes through a bounded, cancellable
pipeline:

1. persist the exact original bytes and remote identity;
2. parse RFC 5322 and MIME with depth, size, part-count and expansion limits;
3. extract normalized headers, readable plain text, safe HTML input, links and
   attachment metadata;
4. resolve contact membership and threading candidates;
5. obtain and preserve message-authentication evidence;
6. compute cheap shared features, then more expensive features only when a
   rule or built-in policy requires them;
7. index searchable fields;
8. execute stateful filtering rules and persist their actions/explanations;
9. commit the visible message state; and
10. emit one change-stream transaction to interested clients.

Partial failure must be explicit. For example, a body that is not yet
downloaded can be searchable by headers while the API reports that body search
is incomplete. A parser, attachment inspector or heuristic failure must not
silently turn into a clean verdict.

Bulk synchronization must not publish one FTS statement per message. The
backend prepares bounded chunks of at most 1,000 messages or 64 MiB of
normalized staged data, writes rows to connection-local temporary staging, and
uses one `INSERT ... SELECT` to publish each chunk to the FTS-indexed table.
Message rows, attachment metadata, remote identities and change events commit
in one transaction per chunk. Earlier chunks remain committed if preparing a
later chunk fails, matching resumable IMAP synchronization semantics.

This distinction is material for local Turso 0.9.0-pre.5: FTS flushes a
Tantivy segment at each SQL statement boundary, not each transaction boundary.
Merely wrapping single-row inserts in a transaction still creates one segment
per message. In the synthetic 64 KiB-text corpus, set-based publication raised
1 GiB ingestion from 2.64 MiB/s to 18.35 MiB/s (387.5 seconds to 55.8 seconds).
The same run also crossed Turso FTS's hard-coded 192 MiB retained-segment cache
and exposed a separate search-latency cliff: the common-term p50 rose to 47.6
ms and the oldest rare-term p50 to 392.5 ms. Batching fixes write amplification;
it does not resolve the need to evaluate standalone Tantivy for multi-gigabyte
indexes.

## Search language

Implement a documented Gmail-like grammar because users already know it and
the renderer targets a Gmail-oriented HTML subset. Compatibility means familiar
operators and predictable semantics, not reproducing Gmail bugs or undocumented
thread behavior.

The first supported set should include:

- bare full-text terms and quoted phrases;
- parentheses, `AND`, `OR` and unary `-`;
- `from:`, `to:`, `cc:`, `bcc:`, `subject:` and `deliveredto:`;
- `after:`, `before:`, `older:`, `newer:`, `older_than:` and `newer_than:`;
- `in:`, `label:`, `account:` and `is:` state predicates;
- `has:attachment`, `filename:`, `size:`, `larger:` and `smaller:`;
- `list:` and exact RFC Message-ID lookup; and
- application-specific structured predicates for contact membership,
  signature findings and heuristic tags.

Dates require an explicit account/user timezone and documented inclusive or
exclusive boundaries. The API returns a parsed-query error with source spans;
it must not silently reinterpret malformed security-sensitive searches.

Compile one query AST into:

- ordinary indexed Turso predicates for account, folder, contact, flags, dates,
  sizes and exact addresses;
- Tantivy-backed Turso FTS predicates for subject/body text; and
- a bounded residual predicate only for features that cannot be expressed by
  the database.

Avoid residual filtering where possible because it breaks efficient pagination
and exact counts. Search results use keyset cursors, stable tie-break IDs and a
requested ordering such as relevance or received time. Do not use growing SQL
`OFFSET` values for mailbox scrolling.

Exact result counts may be calculated lazily. The first page and stable
navigation matter more than blocking the UI for a count on every keystroke.
Search requests must support cancellation.

## Search benchmark

The first synthetic 8--128 MiB scaling probe is recorded in
[`../results/mail-backend-turso-benchmark.json`](../results/mail-backend-turso-benchmark.json).
It is a deterministic, text-heavy regression corpus, not the representative
mixed corpus required below. An initial implementation took 75.6 ms p50 for a
term present in every message because SQL sorted the complete posting list.
The current implementation indexes `received_at` as a Tantivy JSON numeric
fast field and searches exact, non-overlapping newest-first time windows. The
windows grow exponentially until a page is full, so the result order and
keyset cursor remain exact rather than approximate.

With that planner, the 128 MiB common-term query took 1.30 ms p50 and 2.61 ms
p99; the same term with a date predicate took 1.28 ms p50 and 1.84 ms p99.
Every measured p50 at that checkpoint was at most 3.72 ms. The rare term near
the oldest end of the corpus requires several expanding windows and had a
4.35 ms p95 plus one 17.31 ms maximum sample reported as p99 by the 31-run
probe. These results fix the small synthetic regression but are not evidence
for a 20 GiB target; the larger representative run remains required.

A second, single-process 128/256/512 MiB run is recorded in
[`../results/mail-backend-turso-scaling-128-512.json`](../results/mail-backend-turso-scaling-128-512.json).
Dense first-page queries remained effectively flat: the common-term p50 values
were 1.51, 2.71 and 2.20 ms, and its p99 values were 3.61, 3.42 and 4.47 ms.
Sparse queries that must expand across much of the time range were noisier but
remained below 16 ms p50 and 20 ms p99. Profile storage was nearly linear at
2.25x, 2.23x and 2.22x the raw corpus. Cumulative ingestion declined from
4.65 to 3.28 MiB/s. RSS rose from 82.7 to 120.9 to 394.2 MiB; the 512 MiB jump
needs cache/segment instrumentation and repeated cold-process measurements
before extrapolating memory use.

Benchmark Turso's Tantivy-backed FTS at normalized corpus targets of:

```text
128 MiB, 256 MiB, 512 MiB, 1 GiB, 2 GiB, 4 GiB
```

Generate each database sequentially and retain compact result JSON rather than
all database copies. Record both raw RFC 5322 bytes and normalized searchable
bytes: a 20 GiB mailbox dominated by attachments is not equivalent to 20 GiB
of indexed prose.

### Corpus construction

Use a deterministic generator so every size is a prefix of the next size. A
reasonable seed is the CMU Enron corpus (roughly 500,000 real messages and a
roughly 423 MiB distribution), mixed with generated modern MIME/HTML messages
and public-domain prose. Do not commit or redistribute the Enron content; it
contains real personal data despite being publicly available for research.

Expanding one corpus by exact duplication would create unrealistic posting
lists. Deterministic expansion must vary IDs, addresses, dates, threads,
vocabulary segments, message sizes and term frequencies. Generate bounded
attachments separately and do not count opaque attachment bytes as indexed
text. A smaller SpamAssassin/Rspamd corpus may supplement malformed, spam and
HTML-shaped messages but is not large enough by itself.

### Query suite

Use fixed queries with known expected results across these classes:

- rare term and exact address;
- common term with many hits;
- two-term intersection and disjunction;
- phrase and prefix;
- subject-only and body-only;
- contact/account/folder/date filters without text;
- full text combined with date/folder/contact predicates;
- attachment filename and size predicates;
- relevance sort and received-time sort;
- first page, deep keyset page and exact count; and
- searches during concurrent incremental ingestion.

Measure index build throughput, incremental commit latency, database/index size,
peak and steady RSS, segment optimization time, and query p50/p95/p99. Measure
warm-cache and process-cold runs separately, before and after index
optimization, and record CPU, memory, filesystem and Turso revision.

Do not fit one latency curve to every query. Inverted-index latency depends on
posting-list cardinality, segment layout, cache residency, sorting and requested
result count, not just corpus bytes. Fit and validate a simple model per query
class, report prediction intervals for 8/16/32 GiB, and treat those values as
estimates until at least one larger point can be measured on representative
hardware.

## Filtering, sorting and stateful rules

### One condition model

Searches, saved views and rule conditions should share the same typed AST where
their semantics overlap. A user should be able to run a search, preview its
matches and choose "create rule from this search" without translating between
languages.

Rule actions are separate from conditions. Initial actions should include:

- add/remove local folder or label;
- request an IMAP move/copy where supported;
- archive, mark read/unread, star, mute or set priority;
- set a user classification;
- add a structured heuristic finding or frontend annotation;
- set retention/expiry policy; and
- stop later ordered actions when explicitly requested.

Actions must be idempotent. Each application records message, rule ID, rule
version, matched condition, actions and timestamp. This supports "why is this
here?", undo, rule debugging and deterministic re-evaluation after a rule is
edited.

### Rule language research direction

[Sieve](https://www.rfc-editor.org/rfc/rfc5228.html) is important precedent: it
was designed specifically for mail filtering, GUI generation and safe
server-side execution, and its base language deliberately has no loops,
functions or shell access. Its final-delivery execution model and extension
history do not directly solve local replay, search, UI annotations or typed
evidence, so adopting Sieve syntax wholesale is not yet recommended.

[CEL](https://github.com/cel-expr/cel-spec) is useful precedent for the
condition core: it is mutation-free, non-Turing-complete, type-checkable and
designed for bounded evaluation of untrusted expressions. Current Rust CEL
implementations should be conformance-, maintenance- and performance-tested
before adoption. A smaller mail-specific language may be easier to optimize,
document and keep stable.

"Compiled" should initially mean:

1. parse and type-check once;
2. resolve field/function references;
3. estimate and reject excessive worst-case cost;
4. lower to a compact immutable decision DAG or bytecode;
5. reorder pure conjunctions by cost/selectivity; and
6. evaluate in-process with no parser startup, I/O, dynamic code loading or
   unbounded allocation.

Native machine-code generation is unnecessary and would add portability,
cache-invalidation and code-execution risk. Evaluation dispatch is unlikely to
dominate MIME parsing, Unicode processing, database I/O or text scanning, but
the benchmark must decide.

The language must have no loops, recursion, mutation, filesystem/network
access, clock access except an injected evaluation time, or user-defined
functions. All strings, collections, regexes and evaluation steps have explicit
budgets. Regex support must use a guaranteed-linear engine.

### Avoid evaluating every rule expensively

At activation time, compile a rule manifest containing referenced fields,
required derived features, cheapest discriminators and maximum cost.

At ingestion time:

- use an activation index keyed by cheap facts such as account, mailbox,
  contact state, sender domain, signature state and attachment presence;
- evaluate cheap pure predicates first and short-circuit;
- parse MIME, links and attachments once and share their results;
- scan all literal keyword predicates for a field in one multi-pattern pass
  rather than rescanning per rule;
- compile and cache regexes;
- calculate expensive Unicode, archive or semantic features only when at least
  one still-viable rule requires them; and
- enforce per-message and per-rule cost budgets with an explicit
  `not_evaluated_budget` result.

Ordered rule actions retain user-visible order even when the pure conditions
inside each rule are optimized.

The first implementation should remain simple enough to benchmark. A
discrimination network shared across rules is a later optimization if ordinary
indexed activation plus short-circuit evaluation is insufficient for realistic
hundreds-of-rules workloads.

### Frontend hooks

Custom rules may emit structured annotations to a finite set of hooks, for
example:

```text
message_annotation
persistent_warning_footer
open_interstitial
link_interstitial
attachment_interstitial
```

The API result includes severity, plain text, responsible rule/origin and
permitted action identifiers. Rules cannot inject HTML, impersonate built-in
chrome or invent arbitrary callbacks. Frontends must distinguish built-in,
user-authored and third-party-authored rules.

Before activation, the API provides parse/type errors, estimated cost, required
features, a sample preview, affected-message count and an explanation trace.
A manual page should document the grammar and include reviewed examples usable
as an LLM prompt, but generated rules receive no authority until the user
previews and activates them.

### Sorting

Common mailbox orderings should be satisfied by composite indexes beginning
with the constrained account/folder and ending with a stable ID, for example
received-time descending plus message ID. Use keyset pagination. Less common
sorts may use bounded database sorting; query plans and latency must be visible
in benchmarks.

Folder membership is stateful, but sort order normally is not. Do not persist
one copy of the same inbox merely to support each sort choice.

## IMAP retrieval and synchronization

The initial IMAP engine must support:

- implicit TLS and STARTTLS with hostname and certificate verification;
- SASL/OAuth mechanisms and credentials referenced from an OS-protected store;
- capability discovery and conservative fallback;
- UIDVALIDITY, UIDNEXT and per-mailbox UID state;
- CONDSTORE/QRESYNC/MODSEQ when available;
- IDLE with reconnect, polling fallback and cancellation;
- bounded streaming fetches and partial-body policy;
- deterministic flag, move, copy and deletion synchronization;
- server/local conflict recording rather than silent last-writer wins;
- backoff, offline operation and resumable synchronization; and
- explicit search-completeness state while bodies remain remote.

The vendored async-imap hardening supplies a starting transport/client library,
not this synchronization model.

POP3 later requires UIDL-based identity, duplicate handling, retention/deletion
policy and clear acknowledgement that POP3 has no server folder model.

## TLS and message authentication

TLS protects the connection to the account server; it does not authenticate a
message author. Certificate exceptions must never be silently persisted.

For DKIM, preserve:

- each signature and exact signing domain/selector;
- pass, fail, temporary failure, absence and unsupported-algorithm results;
- whether a valid signature aligns with the visible From domain;
- which headers/body were covered; and
- verification source and time.

An IMAP client usually learns delivery-time SPF/DKIM/DMARC results through
`Authentication-Results`. That header is attacker-forgeable outside the
receiving provider's trust boundary. The backend must identify trusted
`authserv-id` values per account/provider or mark the result untrusted. Fresh
independent DKIM verification is useful, but later verification can fail after
DNS key rotation and cannot reconstruct delivery-time SPF. Never convert an
unknown result into a failure or a clean verdict.

Signature checks and heuristic extractors produce structured evidence for the
frontend rules in `security-ui.md`; they do not produce application prose.

### OpenPGP

OpenPGP is a backend responsibility. Every frontend and automation client must
observe the same signature result, contact/key binding, encryption state and
trust decision. Frontends must not independently parse or verify cryptographic
message bodies.

The backend should support OpenPGP/MIME signing, verification, encryption and
decryption. Compatibility with legacy inline OpenPGP can follow, but it must
not distort the primary MIME model. Decrypted bytes remain hostile input and
must pass through the same bounded MIME and attachment validation as ordinary
mail, followed by the stricter presentation boundary below.

Decryption has stricter release rules than ordinary MIME ingestion:

- authenticate the encrypted container completely before releasing plaintext
  to MIME parsing, indexing, API clients or logs;
- reject failed AEAD authentication and failed MDC/integrity checks without a
  plaintext click-through path;
- reject obsolete non-integrity-protected encrypted packets rather than
  displaying archival plaintext in the mail application;
- preserve the decrypted MIME entity as a separate origin and never concatenate
  it into attacker-controlled unencrypted sibling HTML;
- expose only bounded plain text to message-reading frontends, deriving text
  from HTML in an isolated no-network parser when no `text/plain` alternative
  exists; and
- never grant remote-resource capabilities or invoke the HTML layout/rendering
  path for OpenPGP-encrypted content.

This is defense in depth even for modern integrity-protected OpenPGP. EFAIL
demonstrated that composing decryption, MIME/HTML interpretation and external
resource loading can turn a mail client into a plaintext exfiltration channel.
Signed-but-unencrypted OpenPGP mail remains on the ordinary MIME/rendering path.

The backend data/API must distinguish:

- a cryptographically valid signature;
- the signing-key fingerprint;
- whether that fingerprint is locally associated with the claimed contact;
- how the key was learned and whether the user verified it;
- expiration, revocation, replacement and conflicting-key state;
- which MIME content and protected headers were signed;
- whether the message was encrypted and to which local identity; and
- a missing key or unsupported message separately from an invalid signature.

OpenPGP validity must not be phrased as human identity unless the user has
locally bound the key to that contact. An Autocrypt header, Web Key Directory
result or attached key may supply a candidate key but must not silently create
that trust binding.

Private keys and passphrases do not belong in ordinary database rows. Define an
OS credential store, hardware token or agent boundary and a cancellable API
challenge for required user presence. Do not log secret material.

#### OpenPGP implementation provider

Do not couple the backend directly to the `gpg` command-line interface.
GnuPG's supported application API is GPGME, but GPGME performs operations by
IPC with separate GnuPG engines; GnuPG intentionally does not expose its
internals as an in-process OpenPGP library. That design offers process and
agent isolation, but adds an external executable/keyring dependency, IPC and
packaging complexity.

Evaluate at least these providers before implementation:

- **Sequoia OpenPGP:** a Rust library implementing RFC 9580 with higher-level
  policy and tooling available; LGPL-2.0-or-later licensing and its selectable
  crypto backend require distribution review.
- **rPGP (`pgp` crate):** a pure-Rust RFC 9580 library under MIT OR Apache-2.0;
  its API is deliberately lower-level and requires the application to supply
  more OpenPGP semantics and safe policy.
- **GPGME adapter:** optional interoperability for users whose existing keys,
  smartcards or agent workflows already live in GnuPG, not the mandatory core
  provider.

Provider acceptance requires RFC 9580 and legacy-message interoperability,
fail-closed integrity behavior, streaming and resource-limit tests,
OpenPGP/MIME fixtures, malformed-input fuzzing, hardware/agent boundary tests,
and differential tests against at least one independent implementation. The
public backend API must expose application-level evidence and remain independent
of provider-specific result types.

Indexing decrypted content is an explicit at-rest privacy decision. If enabled,
the API must say that encrypted mail becomes searchable because plaintext
derivatives are stored locally; disabling it must remove/rebuild those derived
index entries without deleting the encrypted original.

### Spam evidence

Preserve receiving-server spam flags/scores, local classifier results, matching
rules and user corrections as separate evidence with source and version. The
derived Spam workflow must be reversible and explainable. A local classifier
is not part of the first storage/search milestone, but the schema/API must not
force every provider result and future classifier into one unexplained boolean.

## Other required backend capabilities

The original list omits several systems needed for a complete mail client:

### Sending and composition

- SMTP submission (or a provider-native send API), TLS and OAuth;
- drafts, outbox, retry/idempotency and delivery-failure state;
- attachment streaming and size limits;
- Sent-folder reconciliation without creating duplicates; and
- reply/forward header and thread construction.

### Contacts

- a backend-owned address book exposed through the same API and change stream
  as messages;
- local contacts and exact address membership;
- explicit aliases and locally chosen display names;
- associated OpenPGP fingerprints and locally verified key transitions;
- import/export, with CardDAV or other synchronization considered later; and
- provenance for manually created, imported and inferred data.

Contact membership is the source for Warm/Cold views, while signature evidence
remains independent. No frontend may maintain a competing authoritative contact
list: otherwise Warm/Cold membership, sender naming, rule results and key trust
would vary by client.

### MIME and attachments

- robust bounded MIME parsing and character-set conversion;
- plain/HTML alternative selection and quote structure;
- content IDs and explicit renderer resource capabilities;
- attachment type detection, archive budgets and safe export; and
- optional attachment-text extraction in a sandbox, never in the core process.

### Threads

- a documented thread model using normalized subject, References/In-Reply-To
  and local evidence;
- resistance to unknown-sender conversation injection; and
- stable thread IDs and message-level search results without Gmail's ambiguous
  thread-wide negative-query behavior.

### Multi-client API behavior

- stable opaque IDs and schema/API versioning;
- transactions for bulk actions;
- keyset pagination and cancellation;
- a resumable ordered change feed so GUI, CLI and agents stay synchronized;
- optimistic concurrency/revision checks for edits;
- explain/preview endpoints for rules and queries; and
- capability discovery so third-party clients do not guess backend features.

### Data lifecycle and recovery

- migrations with rollback/recovery tests;
- backup and lossless export to standard formats;
- database/index integrity checks and complete search-index rebuild;
- account removal and secure credential deletion;
- cache/body-retention policy; and
- explicit behavior when disk space is exhausted.

### Security and resource control

- OS file permissions and an at-rest encryption decision;
- credential storage outside ordinary database rows;
- strict parser, decompression, image and attachment budgets;
- disposable sandbox workers for hostile codecs and document extraction;
- DNS/network timeouts and cache policy for signature checks; and
- fuzzing, malformed-message corpora and protocol interoperability tests.

## Suggested implementation order

1. Stable IDs, Turso schema, immutable raw storage, MIME parsing and account
   model.
2. Read-only IMAP synchronization with explicit completeness and failure state.
3. Search grammar, FTS indexing and the scaling benchmark.
4. Local folders/labels, stateful rules, explanations and replay.
5. Backend address book plus Warm/Cold query predicates.
6. DKIM/OpenPGP evidence and the bounded heuristic feature pipeline.
7. Change-stream API and official CLI/GUI integration.
8. IMAP mutations, drafts and SMTP submission.
9. POP3 and import/export adapters.

## Research references

- [Turso manual and experimental FTS](https://github.com/tursodatabase/turso/blob/main/docs/manual.md)
- [Turso FTS design and current limitations](https://github.com/tursodatabase/turso/blob/main/docs/fts.md)
- [Turso SQLite compatibility matrix](https://github.com/tursodatabase/turso/blob/main/COMPAT.md)
- [Gmail search operators](https://support.google.com/mail/answer/7190)
- [Gmail API search/filter semantics](https://developers.google.com/workspace/gmail/api/guides/filtering)
- [RFC 5228: Sieve](https://www.rfc-editor.org/rfc/rfc5228.html)
- [Common Expression Language specification](https://github.com/cel-expr/cel-spec)
- [CMU Enron Email Dataset](https://www.cs.cmu.edu/~enron/)
- [RFC 9051: IMAP4rev2](https://www.rfc-editor.org/rfc/rfc9051.html)
- [RFC 7162: CONDSTORE and QRESYNC](https://www.rfc-editor.org/rfc/rfc7162.html)
- [RFC 6376: DKIM](https://www.rfc-editor.org/rfc/rfc6376.html)
- [RFC 8601: Authentication-Results](https://www.rfc-editor.org/rfc/rfc8601.html)
- [RFC 9580: OpenPGP](https://www.rfc-editor.org/rfc/rfc9580.html)
- [RFC 3156: OpenPGP/MIME](https://www.rfc-editor.org/rfc/rfc3156.html)
- [RFC 9788: Header Protection for Cryptographically Protected Email](https://www.rfc-editor.org/rfc/rfc9788.html)
- [EFAIL research and mitigations](https://efail.de/)
- [GnuPG programmatic-use guidance](https://www.gnupg.org/documentation/manuals/gnupg/Programmatic-use-of-GnuPG.html)
- [GPGME engine/IPC model](https://www.gnupg.org/documentation/manuals/gpgme/Protocols-and-Engines.html)
- [Sequoia OpenPGP](https://gitlab.com/sequoia-pgp/sequoia/)
- [rPGP](https://github.com/rpgp/rpgp)
