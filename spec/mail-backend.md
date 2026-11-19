# Local mail backend and API

Status: design plus an implemented first vertical slice in
`crates/mail-backend`. The crate provides a typed asynchronous API, local Turso
schema, immutable content-addressed raw blobs, bounded RFC 5322/MIME ingestion,
accounts and folders, remote IMAP identities, local-folder membership,
contacts, dynamic Warm/Cold/Spam classification, Gmail-shaped search, stable
keyset pagination, durable security-partitioned conversation threads and a
durable/live change stream. It also provides revisioned drafts, protected MIME
construction, a durable SMTP outbox, verified TLS/OAuth submission, Sent-copy
reconciliation, a materialized MIME tree, CID access, bounded attachment
streaming/export and sandboxed extraction hooks. Its account-owned IMAP
engine establishes verified TLS, obtains credentials through an opaque provider
boundary, discovers mailboxes, negotiates capabilities, reconciles UID state
and routes bounded body streams through the same idempotent ingestion path as
local imports.

The current slice runs OpenPGP/MIME signing, verification, encryption and
decryption, but does **not** yet independently verify ARC chains or expose
inter-process transport. It does ingest bounded
provider `Authentication-Results` under an explicit per-account trust policy
and runs a mandatory bounded native security-evidence pass; later requirements
are not a claim that every possible heuristic is implemented.

Related frontend requirements: [security-ui.md](security-ui.md).

## Purpose

The backend is the single owner of mail retrieval, normalized message state,
search, stateful organization, contacts, authentication evidence and bounded
feature extraction. GUI, CLI and third-party clients consume one API rather
than separately replaying filters or reparsing hostile messages.

The backend must support offline use and remain useful without any Turso cloud
service. "Turso" in this document means the local, in-process Rust database.

The initial receive protocol is IMAP. POP3 follows after the storage and
synchronization model is stable. Sending uses a separate SMTP submission
engine over the same account, credential-provider and durable-state model.

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

Use local Turso as the authoritative metadata store and a separate native
Tantivy index as a rebuildable search projection. The projection covers both
text and structured search fields so Boolean queries and chronological
pagination do not need to materialize large FTS result sets back into SQL.

Every search-relevant Turso transaction also enqueues the affected message ID
in a revisioned outbox. After the database commit, the backend performs a
Tantivy delete-plus-add upsert and commits it before returning from the API,
then removes only the exact outbox revision it indexed. A crash before the
index commit leaves the row queued; a crash after the index commit merely
replays an idempotent upsert. A concurrent update increments the revision so an
older flush cannot erase newer work.

Turso stores a per-database search generation. Tantivy stores a matching
versioned manifest. On open, a missing, unreadable, incompatible,
generation-mismatched or document-count-inconsistent index is discarded and
rebuilt from Turso. The search index is never authoritative and is excluded
from backup correctness requirements. Turso's experimental embedded FTS
feature remains compiled temporarily only so version-2 profiles can drop and
migrate their old embedded index.

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

### Conversation threading

Thread membership is backend-owned durable state, not a frontend grouping
guess. Every message receives a stable application `ThreadId` in the same
transaction that inserts the message. The stored evidence includes canonical
`References`, `In-Reply-To`, the selected local parent, normalized subject, the
reason for the match and sender trust at ingest time.

Resolution is conservative and ordered:

1. use the nearest uniquely resolved `References` identifier;
2. otherwise use a uniquely resolved `In-Reply-To` identifier;
3. if neither header exists, use normalized subject only for one recent,
   unambiguous thread containing the same sender; and
4. otherwise create a root thread. Header-derived roots use a deterministic
   UUID namespace so a reply received before its root still converges on the
   same stable thread when the root arrives.

Threads created by a known/self sender have an immutable trust boundary. An
unknown sender copying a real message's identifiers therefore cannot enter that
known-origin conversation. A known/self sender may continue an older cold
thread (important when contacts import after mail, and when the user replies to
a cold message), but this does not silently upgrade the thread boundary. Later
address-book edits can change the Warm/Cold view without rewriting historical
thread identity. Subject fallback has a 30-day window, requires exact
normalized sender continuity, refuses ambiguous matches and never overrides
explicit reply headers.

The thread API returns summaries and complete ordered conversations with
keyset pagination. Reply construction reuses the source `ThreadId`, produces a
bounded `References` chain, honors parsed Reply-To and removes the user's own
account identities from Reply-All. Forward construction creates a new
`ThreadId`, emits no reply headers and carries the immutable source message as
`message/rfc822`. Durable drafts, sending and Sent reconciliation remain a
separate layer.

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

IMAP ingestion has two explicit phases. Initial synchronization persists a
bounded selected-header projection, BODYSTRUCTURE attachment evidence, remote
identity, flags and server size. That is enough for mailbox lists, header
search and trustworthy threading without transferring bodies. Opening a
message or selecting it for offline caching starts the complete-payload phase:

1. stream the exact original bytes with bounded partial IMAP FETCH requests;
2. parse RFC 5322 and MIME with depth, size, part-count and expansion limits;
3. extract normalized headers, readable plain text, safe HTML input, links and
   attachment metadata;
4. resolve contact membership and threading candidates;
5. obtain and preserve message-authentication evidence;
6. compute cheap shared features, then more expensive features only when a
   rule or built-in policy requires them;
7. index searchable fields;
8. execute stateful filtering rules and persist their actions/explanations;
9. atomically replace the header-only projection with visible complete-message
   state; and
10. emit one change-stream transaction to interested clients.

Partial failure must be explicit. For example, a body that is not yet
downloaded can be searchable by headers while the API reports that body search
is incomplete. A parser, attachment inspector or heuristic failure must not
silently turn into a clean verdict.

The backend prepares bounded chunks of at most 1,000 messages or 64 MiB of
normalized staged data, writes rows to connection-local temporary staging, and
uses one `INSERT ... SELECT` to publish each chunk to authoritative Turso
tables. Message rows, attachment metadata, remote identities, the search
outbox and change events commit in one transaction per chunk. The matching
Tantivy batch commits before that chunk's API call completes. Earlier chunks
remain committed if preparing a later chunk fails, matching resumable IMAP
synchronization semantics.

Batching was originally introduced for embedded Turso FTS, where one FTS SQL
statement per message created one Tantivy segment per message. It raised the
old 1 GiB path from 2.64 MiB/s to 18.35 MiB/s, but did not cure the embedded
reader's hard-coded 192 MiB retained-segment cache cliff. The separate native
index retains batching without placing search publication inside Turso's FTS
adapter.

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

Compile the complete query AST to native Tantivy. The projection includes body
and subject text, exact address fields, attachment names, list and RFC
Message-ID values, flags, Warm/Cold/Spam class, folder/account lookup values,
dates, sizes and attachment state. Search results sort by fast `received_at`
and message-ID fields, then Turso hydrates only the bounded result-ID page.

Search results use keyset cursors and stable tie-break IDs. Do not use growing
SQL `OFFSET` values for mailbox scrolling. Search-relevant mutations—contact
addition or removal, classification, remote flag refresh and local-folder
membership—must enqueue and synchronously publish replacement documents before
their API calls return.

Exact result counts may be calculated lazily. The first page and stable
navigation matter more than blocking the UI for a count on every keystroke.
Search requests must support cancellation.

## Search benchmark

The historical embedded-FTS 8--128 MiB scaling probe is recorded in
[`../results/mail-backend-turso-benchmark.json`](../results/mail-backend-turso-benchmark.json).
The later 128/256/512 MiB embedded run is recorded in
[`../results/mail-backend-turso-scaling-128-512.json`](../results/mail-backend-turso-scaling-128-512.json).
Those files remain useful regression history but no longer describe the
production search architecture.

On 2026-11-16, `fts_comparison` measured embedded Turso FTS against a separate
native Tantivy `IndexWriter`. Both variants stored identical normalized rows in
Turso, indexed identical 64 KiB bodies in 1,000-message batches, returned and
materialized the same message-ID pages, and ran in separate processes. At the
1 GiB checkpoint:

| Metric | Native Tantivy | Embedded Turso FTS |
|---|---:|---:|
| Cumulative ingestion | 34.13 MiB/s | 24.24 MiB/s |
| Combined profile size | 1,443 MiB | 1,270 MiB |
| RSS after query suite | 555 MiB | 582 MiB |

The native median was 0.019 ms for the oldest rare term, 0.260 ms for the
all-message common term, 0.141 ms for an intersection, 0.042 ms for a subject
term, 0.038 ms for a sparse sender, 0.599 ms for common-term-plus-date and
0.500 ms for an all-but-missing-subject query. Embedded medians for the same
queries were respectively 530, 56, 114, 250, 528, 58 and 61 ms. The embedded
path crossed its cache cliff between 512 MiB and 1 GiB; native search stayed
below 1 ms median, at the cost of about 14% more disk in this text-heavy
corpus. This result selected the separate native projection.

After integrating the outbox, full structured projection, task handoff and
Turso summary hydration, `search_benchmark` validated the production path at
128/256/512/1,024 MiB. At 1 GiB it ingested 1,024 MiB of raw messages in 41.0
seconds (25.0 MiB/s), versus 55.8 seconds (18.35 MiB/s) for the prior batched
embedded implementation. The seven end-to-end p50 values ranged from 0.276 to
6.56 ms, including 0.276 ms for the oldest rare term and 4.95 ms for the common
term. The profile occupied 2,337 MiB. One RSS sample was 737 MiB and several
p99 samples contained host-scheduling outliers, so memory and tail latency need
repeated cold-process measurements rather than extrapolation from this run.

Continue benchmarking the complete production path at normalized corpus
targets of:

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

### Filters are not searches

Gmail-shaped search is a retrieval language with substring and current-state
semantics. Filter conditions are a separate structured model with exact typed
fields. A filter is an ordered series of pure Boolean checks with an implicit
AND; evaluation stops on the first false check, and an empty series is an
explicit catch-all. A UI may explicitly translate an unambiguous search into a
filter, but the two do not share an AST.

Filter authority is confined to organization or deletion of the message being
evaluated. The implemented action vocabulary supports:

- add/remove a local folder;
- move between local folders;
- move an exact `(folder, UIDVALIDITY, UID)` remote instance;
- move that instance to the account's uniquely advertised `\Trash` mailbox;
- permanently delete that exact instance through UIDPLUS; and
- stop later ordered filters.

Remote actions require a `DeliveryFolder` condition matching their explicit
source mailbox and are inserted into the ordinary IMAP mutation outbox in the
same transaction as the rule application. They therefore inherit UIDVALIDITY,
UIDPLUS, conflict and ambiguous-outcome protections. Filters cannot modify
contacts or trust, train classification, create folders or rules, send mail,
invoke external services, or mutate other messages. Raw message content is
immutable.

Actions must be idempotent. Each application records message, rule ID, rule
version, matched conditions, actions, exact prior local-folder membership,
created remote mutation IDs, timestamp and eventual undo time. Preview compiles
the same typed conditions to bounded SQL and returns both matching and actually
affected counts without changing state. Replay applies one exact revision to
existing messages and can safely resume after an error because the application
key is `(rule, revision, message)`.

Undo restores the captured local-folder set rather than guessing inverse
actions. Pending/conflicted remote mutations are cancelled. A completed move
queues an inverse move from the server-confirmed destination mapping. In-flight
mutations and completed permanent deletions refuse undo because pretending
otherwise would be unsafe.

### Filter representation

Filter conditions and actions are persisted as typed structured values suitable
for GUI construction. "Compiled" means:

1. parse and type-check once;
2. resolve field/function references;
3. estimate and reject excessive worst-case cost;
4. lower to a compact immutable decision plan;
5. reorder pure conjunctions by cost/selectivity; and
6. evaluate in-process with no parser startup, I/O, dynamic code loading or
   unbounded allocation.

The current implementation directly short-circuits the structured checks;
shared activation indexes and decision-plan lowering remain optimization work.

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

## Heuristic programs and findings

Heuristics are not filter predicates. They are bounded evidence-producing
computations over typed backend features. Lizard Rules uses Python-shaped
syntax, parsed by a Python grammar but compiled into a serialized application
IR. No Python runtime executes it.

The accepted subset includes pure `if`, bare `return`, immutable top-level
bindings, bounded `for` over approved message collections, comparisons, Boolean
operators, approved string functions, and `yield Finding(...)`. Imports,
mutation, `while`, recursion, arbitrary calls, reflection, exceptions, async,
filesystem and network access are compile errors. Every program has static and
runtime step limits, collection limits, finding limits and string limits.

Native extractors produce reusable typed features such as MIME attachments,
parsed links and registrable domains. The restricted language also exposes
typed OpenPGP evidence, trusted delivery-time DKIM/DMARC/SPF observations,
provider and local spam assessments, and the durable thread trust boundary.
SPF remains low-level evidence and is not promoted to normal identity UI.
The implemented, non-removable native
pass materializes identity contradictions, DKIM alignment failures, misleading
destinations, remote-resource and credential-form presence, UTS #39 domain
confusables, executable/type/filename evidence and bounded ZIP directory
metadata. It uses a finite finding vocabulary and versioned evidence just like
user rules. Programs consume these features; they do not implement parsers or
cryptography.

The native pass is deliberately passive. Its HTML tokenizer has token, anchor,
form, resource and string budgets and cannot execute script, submit a form,
resolve DNS or fetch a URL. Automatic ZIP analysis accepts at most 8 MiB of
compressed input, reads central-directory metadata with `by_index_raw`, never
inflates an entry, never recurses into a nested archive and has entry-count,
declared-size, ratio and wall-clock budgets. Encrypted, malformed, nested,
oversized or over-budget archives produce `uninspectable_archive`; they never
receive a clean verdict. Expansion remains a separate explicit API that refuses
to run unless metadata inspection completes within caller-supplied limits.

### Finite presentation vocabulary

Heuristics emit structured findings to a finite set of presentation types, for
example:

```text
message_annotation
persistent_warning_footer
open_interstitial
link_interstitial
attachment_interstitial
```

Findings are materialized in Turso with message, heuristic/version, severity,
target, evidence and origin. Message reads return active findings and their
separate dismissal state. Stable finding IDs preserve responses across an
identical re-evaluation. Programs cannot inject HTML, control layout or invent
callbacks. Frontends switch over the finite presentation enum and distinguish
built-in, user-authored and third-party-authored findings.

Before activation, the compile API provides parse/validation errors, estimated
maximum cost and required features. Candidate heuristics can be run without
side effects across the local corpus: the preview reports evaluated and
affected-message counts, finding counts, incomplete/decryption-required counts,
and detailed traces for caller-selected samples. Filter preview provides the
same tri-state behavior plus exact would-change counts and bounded samples.

Persisted evaluations record the heuristic/compiler or filter-rule version, a
SHA-256 revision of only the structured inputs the program depends on, and a
control-flow trace. Traces describe branches, loops, returns and emitted finding
codes, but never copy message field values or plaintext into a second cache.
Evidence changes make evaluations stale and schedule bounded re-evaluation.
The implemented grammar and reviewed examples are documented in
`lizard-rules.md`; generated programs receive no authority until the user
previews and activates them.

Body-dependent automation has two explicit pending states. Header-first mail is
`pending_content` until hydration succeeds. Encrypted mail is
`pending_decryption` unless an authenticated decrypted derivative already
exists in Turso under the user's encrypted-search policy. A user-present
`evaluate_encrypted_automation` pass decrypts each selected message once and
shares that in-memory view with every applicable rule and heuristic. Enabling
search may allow reuse of the verified Turso derivative, but Tantivy is always
disposable and is never a correctness or security oracle for automation.

### Sorting

Common mailbox orderings should be satisfied by composite indexes beginning
with the constrained account/folder and ending with a stable ID, for example
received-time descending plus message ID. Use keyset pagination. Less common
sorts may use bounded database sorting; query plans and latency must be visible
in benchmarks.

Folder membership is stateful, but sort order normally is not. Do not persist
one copy of the same inbox merely to support each sort choice.

## IMAP retrieval and synchronization

The implemented account engine supports:

- implicit TLS and STARTTLS with hostname and certificate verification;
- SASL/OAuth mechanisms and credentials referenced through an opaque provider;
- capability discovery and conservative fallback;
- UIDVALIDITY, UIDNEXT and per-mailbox UID state;
- CONDSTORE/QRESYNC/MODSEQ when available;
- IDLE with reconnect, polling fallback and cancellation;
- header-first synchronization using selected header fields and BODYSTRUCTURE;
- bounded on-demand full-body fetches that resume a durable partial file at its
  exact byte offset;
- remote flag and deletion reconciliation;
- backoff, offline operation and resumable synchronization; and
- explicit per-message `headers_only`/`downloading`/`complete`/`failed` state,
  expected and downloaded byte counts, last failure, and restart recovery.

Header-only messages participate in mailbox lists, header operators, remote
mutations and security-partitioned threading. Empty body fields are never used
as an implicit completeness signal: raw export, MIME structure, attachment
access and DKIM claims reject the message until hydration completes. Body
search, decoded attachments, DKIM verification and body-dependent automation
are republished together after the exact full payload is parsed. A timeout or
disconnect retains the partial prefix and a subsequent request resumes it;
the UIDVALIDITY epoch and RFC822.SIZE must still match before publication.
Search responses explicitly mark content-dependent results incomplete while
any message still lacks full content; header-only operators remain exhaustive.
Dropping a download future records a resumable failure rather than leaving a
permanent in-progress state; startup recovery does the same after a crash and
truncates any uncommitted tail to the last synchronized byte count.

The engine exposes `sync_once` and a cancellable continuous `run` loop. The
continuous path uses IDLE on a discovered selectable INBOX, periodically renews
IDLE, polls when IDLE is absent, reconnects after failures, and persists retry
state. A `CredentialProvider` is the platform boundary for an OS keychain or
OAuth broker; secrets are debug-redacted, zeroized on drop and never written to
the account database. TLS certificate exceptions are not an account setting.

The concrete built-in provider implements the deliberate version-one storage
policy. Each new password or OAuth access token is first written to macOS
Keychain, Windows Credential Manager or the freedesktop Secret Service. If that
write does not succeed, it is stored in a bounded profile-local vault encrypted
with XChaCha20-Poly1305 and authenticated against its opaque reference. The
fallback key is an owner-only file in the same profile. This is intentionally
the Thunderbird-without-a-Primary-Password threat model: secrets are never
plaintext, but copying the complete profile is sufficient to decrypt them.
Existing native references never acquire a weaker duplicate when their OS
store is temporarily inaccessible.

Lizard does not claim application-level encryption for downloaded messages,
Turso metadata or the Tantivy index. Those rely on operating-system account and
full-disk encryption. `ProfileOnly` is available for deterministic tests and
portable profiles; normal configuration selects native storage automatically.
Replacing or removing account/SMTP configuration deletes a Lizard-managed
credential only after its final database reference disappears. External opaque
references remain the responsibility of their provider. Failed native-store
deletions remain in a durable cleanup queue and are retried when the profile is
opened and after later credential changes, so removing an account cannot leave
an untracked secret or make the profile undeletable while a keyring is offline.

Locally requested flag/copy/move/trash/delete mutations are represented by a
durable outbox. Every row captures the exact source UIDVALIDITY epoch, UID,
MODSEQ and flags plus its operation, attempts and terminal state. Flag edits are
optimistic in local state and coalesce while pending, but execution first checks
the server snapshot, uses `UNCHANGEDSINCE` when CONDSTORE is available, and
verifies the resulting flags. Without CONDSTORE it applies only the requested
add/remove delta rather than replacing the full flag set, preserving unrelated
concurrent keywords. A mismatch becomes durable conflict evidence; the backend
never silently chooses local or server last-writer-wins state.

COPY and MOVE require UIDPLUS. Their returned COPYUID mapping is persisted as a
new instance of the existing logical message before ordinary folder
reconciliation, preventing the copied bytes from becoming a duplicate logical
message. MOVE uses the atomic extension when advertised and otherwise uses the
safe UIDPLUS COPY/STORE/UID EXPUNGE sequence. Permanent delete always uses UID
EXPUNGE and never broad EXPUNGE. Trash is a move to the uniquely advertised
`\\Trash` mailbox.

An interrupted flag update or exact delete is recoverable by inspecting the
source UID and desired end state. COPY and MOVE are not generally idempotent: if
their outcome is unknown, or a UIDPLUS server omits the mapping, the account's
folder reconciliation pauses behind an explicit ambiguity conflict. Automatic
retry is forbidden because it could duplicate mail. Cancelling the conflict is
an explicit client acknowledgement that releases synchronization.

POP3 later requires UIDL-based identity, duplicate handling, retention/deletion
policy and clear acknowledgement that POP3 has no server folder model.

## TLS and message authentication

TLS protects the connection to the account server; it does not authenticate a
message author. Certificate exceptions must never be silently persisted.

DKIM verification is implemented at ingestion from the exact stored RFC 5322
bytes. `mail-auth` 0.15.1 is vendored under Apache-2.0 and hardened locally.
The backend preserves:

- each signature and exact signing domain/selector;
- pass, fail, temporary failure, absence and unsupported-algorithm results;
- whether a valid signature aligns with the visible From domain;
- which headers/body were covered; and
- verification source and time.

The verifier rejects duplicate tags, a missing or displaced `v=1`, a missing
`a=`, signatures that omit `From` from `h=`, obsolete RSA-SHA1, all `l=` body
length signatures (including `l=0`), malformed numeric values and unsupported
query methods. Selector records enforce `h=` and `s=` restrictions, reject
multiple TXT answers and RSA keys below 1024 bits. RSA verification uses the
0.10 RustCrypto line rather than the timing-advisory-affected 0.9 line.

Every physical signature header produces an ordered evidence record, even if
it is malformed or above the 16-signature work limit. Verification is bounded
to 16 DNS lookups and 15 seconds; parser header/authentication budgets run
before tag decoding and body-hash allocation. ATPS and RFC 6651 report-address
discovery are off by default so attacker-controlled headers cannot request
extra network traffic. The strong resolver default is Quad9 over DNS-over-TLS
with local DNSSEC validation; `DkimDnsResolver::System` is an explicit option
for private split-DNS deployments.

`Message::dkim` exposes the overall state plus per-signature status, stable
reason code, domain, selector, identity, algorithm, signed headers, alignment,
key size/testing flag, header position and untrusted raw value. Heuristics can
read `message.authentication.dkim.status` and
`message.authentication.dkim.has_aligned_pass`. A schema migration labels
pre-verifier messages `not_evaluated`; it never invents a clean verdict.

An IMAP client usually learns delivery-time SPF/DKIM/DMARC results through
`Authentication-Results`. That header is attacker-forgeable outside the
receiving provider's trust boundary. The backend therefore stores an exact
`authserv-id` allowlist on each receiving account. It preserves every physical
`Authentication-Results` copy, but trusts only the first syntactically complete
copy whose normalized `authserv-id` exactly matches that account's policy.
Later matching copies are marked as duplicates rather than inheriting trust;
nonmatching, malformed, over-budget and locally imported copies carry explicit
untrusted reasons. Changing account policy re-evaluates trust on read without
changing the immutable parsed evidence.

This rule depends on the receiving provider satisfying RFC 8601: it must add
its result above attacker-controlled fields and remove or rename forged copies
of its own `authserv-id`. Raw message text cannot prove that operational fact,
so an account has no trusted delivery evidence until the provider identity is
configured. The parser is bounded by header count, per-header and aggregate
bytes, method/property count, property size and comment nesting.

Trusted delivery-time DKIM and DMARC are exposed as account-scoped evidence;
they do not overwrite `Message::dkim`, which is independently verified from
the stored bytes. Later independent verification can fail after DNS key
rotation, while delivery-time evidence records what the trusted receiver saw.
SPF is retained as low-level diagnostic/policy evidence and must not drive the
normal identity UI. `ARC-Authentication-Results` fields are parsed with their
instance number but remain `arc_chain_unverified`; a trusted receiver's
top-level `arc=...` method is only that receiver's delivery-time assessment,
not independent ARC validation. Never convert an unknown result into a failure
or a clean verdict.

Signature checks and heuristic extractors produce structured evidence for the
frontend rules in `security-ui.md`; they do not produce application prose.

### OpenPGP

OpenPGP is a backend responsibility. Every frontend and automation client must
observe the same signature result, contact/key binding, encryption state and
trust decision. Frontends must not independently parse or verify cryptographic
message bodies.

The backend supports OpenPGP/MIME signing, verification, encryption and
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
Signed-but-unencrypted OpenPGP mail is also exposed as text-only and without
remote-resource capability. A signature does not create an EFAIL
confidentiality boundary, but applying one invariant to all OpenPGP mail avoids
an ambiguous presentation mode and matches the product's deliberately strict
OpenPGP policy.

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

Private keys and passphrases do not belong in ordinary database rows. Generated
or explicitly imported software keys use the typed credential-store boundary:
the OS store when it accepts the payload, otherwise the profile's encrypted
credential vault. Existing GnuPG keys are referenced rather than copied.
YubiKey OpenPGP Card operations are delegated to gpg-agent/scdaemon; the
backend neither receives nor maintains a PIN cache. Do not log secret material.

#### OpenPGP implementation provider

The implemented cryptographic core pins rPGP (`pgp`) 0.21.1 and keeps its types
behind application-level API and evidence records. The repository's
deterministic GnuPG differential harness and fuzz target exercise the supported
RSA and modern elliptic-curve operations against an independent
implementation.

Three secret-key providers share that public API:

- **software:** rPGP operates on an explicitly generated/imported transferable
  key retrieved through the credential boundary;
- **GnuPG:** an optional bounded subprocess adapter references an existing
  GnuPG-owned private key without copying it; and
- **YubiKey:** the same adapter requires a card-backed GnuPG secret-key stub and
  records the OpenPGP Card serial, while gpg-agent/scdaemon owns PIN and touch
  interaction.

External-provider processes run off the asynchronous executor, have bounded
input/output, receive no secret on command-line arguments and are killed after
a bounded provider-interaction window. Lizard never implements a second PIN
cache.

Certificates are many-to-one with email addresses. Discovery and imports create
candidate bindings; accepting one certificate never replaces another accepted
certificate. Encryption targets every accepted active certificate for every
recipient, plus the sender's current key for Sent-mail access. Bcc public-key
session packets use anonymous recipients. A changed or additional key remains
a candidate until a user action accepts, rejects or retires it. No public
keyserver is queried automatically.

OpenPGP/MIME output uses integrity-protected headers. The visible outer Subject
is the fixed `Encrypted message` placeholder; the real From/To/Cc/Subject,
Message-ID and reply headers live in the signed, encrypted protected-headers
entity. Once an encrypted message enters a backend thread, that thread's
durable `openpgp_encryption_required` bit blocks plaintext and sign-only
submissions rather than silently downgrading.

Provider maintenance requires RFC 9580 and legacy-message interoperability,
fail-closed integrity behavior, streaming and resource-limit tests,
OpenPGP/MIME fixtures, malformed-input fuzzing, hardware/agent boundary tests,
and differential tests against at least one independent implementation. The
public backend API must expose application-level evidence and remain independent
of provider-specific result types.

Indexing decrypted content is an explicit at-rest privacy decision. Its initial
state is `unset`; setup asks: “Enable search for encrypted mail? This stores
decrypted copies on disk.” If enabled, authenticated plaintext derivatives feed
Tantivy, including protected subjects and decrypted attachment filenames.
Disabling removes the derivative rows, rebuilds ciphertext-only index entries,
forces a Tantivy segment rewrite and garbage collection, and deletes
unreferenced decrypted blobs without deleting the encrypted original.
Decrypted attachment bytes are available only through a bounded
streaming call which authenticates the complete container before releasing its
first byte.

### Spam evidence

Preserve receiving-server spam flags/scores, local classifier results, matching
rules and user corrections as separate evidence with source and version. The
derived Spam workflow must be reversible and explainable.

Implemented provider evidence uses authenticated account state rather than
untrusted message headers: RFC 6154 `\Junk` mailbox membership plus registered
`$Junk` and `$NotJunk` IMAP keywords. Each observation retains its account,
folder, UIDVALIDITY, UID, source and observation time. Positive and negative
observations together produce an explicit `conflicting` assessment and do not
put the message in Spam. A user `Spam` or `NotSpam` correction takes precedence
without deleting the provider observations. The absence of `$Junk` is not ham
evidence. Proprietary `X-Spam-*` headers are not interpreted globally; a future
provider adapter may ingest one only when it can establish that the trusted
receiving boundary inserted or replaced it.

The local classifier is a bounded Robinson/Fisher Bayesian document-frequency
model. It combines sender-domain, subject, body unigram/bigram, link-domain,
attachment-extension and a small fixed set of structural tokens. Tokenization
is capped per field and per message; scoring uses only the most discriminating
features and returns a numeric score, model version and the strongest token
probabilities. Scores at or above 0.90 enter Spam, scores at or below 0.10 are
local not-spam evidence, and the middle remains explicitly uncertain.

Every new profile installs an original, literally authored synthetic CC0 corpus
of 1,000 static messages. Its 20 categories contain exactly 50 messages each:
500 spam examples covering credential and payment phishing, advance-fee fraud,
cryptocurrency fraud, malicious attachments, parcel scams, support/subscription
scams, business-email compromise, fake jobs and SEO lead generation; and 500
legitimate examples covering personal mail, work, billing, real account-security
notices, shipping/travel, medical/education, marketing, security training,
freelance payments and open-source communities. These are individual records,
not runtime-generated templates. Difficult legitimate counterexamples include
password resets, invoices, PayPal/commission payments, unsubscribe language and
training mail that quotes phishing vocabulary. Reserved example identities are
used throughout. The corpus hash and counts are durable model metadata so a
future corpus update is versioned and reclassifies existing mail.

Only an explicit user Spam/NotSpam action trains the personal model. Repeating
the same action is idempotent; relabeling first subtracts the old document and
clearing the correction untrains it. Exact bounded token snapshots make those
operations reversible even after model or corpus upgrades. Provider evidence,
contacts, rules and the classifier's own output never feed back as labels. A
model change queues every message durably and reclassifies it in bounded idle
batches; the corrected message is rescored synchronously. Header-only messages
are rescored after hydration, including reversible replacement of a user's old
header-only training snapshot.

## Other required backend capabilities

The original list omits several systems needed for a complete mail client:

### Sending and composition

- SMTP submission (or a provider-native send API), TLS and OAuth;
- drafts, outbox, retry/idempotency and delivery-failure state;
- attachment streaming and size limits;
- Sent-folder reconciliation without creating duplicates; and
- persistence of the already-constructed reply/forward intent in drafts and
  the outbox.

Implemented: draft autosave is optimistic and revisioned; enqueue freezes one
exact protected-header/MIME snapshot and envelope (with Bcc excluded from the
message). SMTP supports verified implicit TLS and STARTTLS plus PLAIN, XOAUTH2
and OAUTHBEARER through opaque credential references. Pending, in-flight,
retry-scheduled, failed, ambiguous, cancelled and sent are separate durable
states. A lost response after DATA is ambiguous and is never retried
automatically. DKIM signing is deliberately absent because the submission
server owns it. A local accepted copy is reconciled with later `\\Sent` IMAP
copies using the protected Message-ID, account and sender identity.

Account sending identities are separate from transport credentials. Each
revisioned identity has an address, optional locally chosen display name,
optional Reply-To, default status and optional account-owned OpenPGP secret-key
provider. Drafts persist the selected identity. Reply construction prefers the
identity matching `Delivered-To`, then visible recipients, so an alias receives
and answers mail consistently; SMTP usernames are used only to authenticate.

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

Implemented contacts can be created, edited, removed and exported/imported as
bounded UTF-8 vCard 4.0. Provenance distinguishes manual entries from imports
and retains the optional source label and import time. Import skips a contact
when any of its normalized addresses already belongs to the address book,
rather than silently merging identities. The private
`X-LIZARD-ACCEPTED-NAME` vCard extension makes accepted per-address aliases
round-trip without turning them into standard identity claims.

### Saved views and lifecycle management

Named saved searches persist a validated Gmail-shaped query and execute through
the same Tantivy search API, including cursor and incomplete-content semantics.
Snooze time, mute state and low/normal/high priority live on the backend message
record and are returned in every summary; mailbox listing can filter them
without a frontend-maintained shadow database.

Accounts and folders have typed update/removal APIs with change events and
search-index cleanup. Removing the final owning remote/local placement removes
the logical message and its search document; shared or locally retained mail
survives. Remote mailbox create/rename/delete requires an already authenticated
IMAP session, mutates the server first, and only then updates local state.

### MIME and attachments

- robust bounded MIME parsing and character-set conversion;
- plain/HTML alternative selection and quote structure;
- content IDs and explicit renderer resource capabilities;
- attachment type detection, archive budgets and safe export; and
- optional attachment-text extraction in a sandbox, never in the core process.

Implemented: ingest materializes stable parent/child part IDs, roles, selected
plain/HTML alternatives, parse/decode state and decoded CID resources. Decoded
attachments stream from hash-checked blobs under caller limits and safe export
uses a caller-selected create-new path, never the untrusted filename. ZIP
inspection checks entry, compressed-input, per-entry, total-output, path and
compression-ratio budgets before expansion. The built-in security pass uses
only ZIP directory metadata and never calls the expansion API. Document
extraction is an optional trait boundary with byte, output and timeout budgets;
implementations are required to run disposable sandbox workers.

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
- bounded database/blob/download/search integrity reports, full optional blob
  hash verification and automatic search-index rebuild are implemented;
- account removal with final-reference credential-store cleanup;
- cache/body-retention policy; and
- typed disk-full failures, a configurable emergency free-space reserve,
  whole-profile quota and durable per-account downloaded-mail quotas are
  implemented.

Implemented portability exports and imports exact RFC bytes as EML directories,
Maildir or mboxrd. Bounded streaming imports avoid retaining an entire archive
in memory; Lizard-generated manifests add hashes, timestamps and read/star state
while the mail data remains readable by standard tools. Profile backups are
owner-private, checksum every authoritative file, exclude rebuildable Tantivy
and transient partial downloads, and restore into a no-clobber destination
that is removed on validation failure. Native OS-keychain secrets are
intentionally not exportable and the backup report calls out their surviving
opaque references.

Body-cache policy is per account: on-demand, all messages, a recent-day window,
or selected remote folders. Header-first IMAP sync automatically hydrates a
bounded policy-selected batch. Retention can discard only complete bodies with
a live selectable remote instance; local-folder membership, an explicit pin,
star retention and every owning account's offline requirement are hard stops.
Eviction keeps the header projection and marks MIME, search and DKIM body
evidence incomplete until the resumable downloader restores the exact message.

The profile quota is evaluated against every file in the profile, including
Turso, content blobs, partial downloads, credentials and rebuildable Tantivy
state. Large content writes reserve space before materializing bytes and retain
the configured free-space floor. Per-account quotas intentionally count exact
downloaded RFC message bytes rather than derived MIME/search copies; lowering a
quota below current usage blocks growth but never deletes mail. The integrity
API treats missing, size-mismatched or hash-invalid referenced blobs and Turso
integrity/foreign-key failures as errors. Orphaned blobs, abandoned temporary
files, partial-download mismatches and rebuildable search drift are separately
typed repairable warnings. Report memory is bounded even when damage is broad.

### Security and resource control

- owner-only profile permissions and an explicit decision to rely on OS
  full-disk encryption for mail/profile data;
- native credential storage with an authenticated profile-local fallback,
  outside ordinary database rows;
- strict parser, decompression, image and attachment budgets;
- disposable sandbox workers for hostile codecs and document extraction;
- DNS/network timeouts and cache policy for signature checks; and
- fuzzing, malformed-message corpora and protocol interoperability tests.

## Suggested implementation order

1. Stable IDs, Turso schema, immutable raw storage, MIME parsing and account
   model.
2. Read-only IMAP synchronization with explicit completeness and failure state.
3. Search grammar, native Tantivy projection and the scaling benchmark.
4. Local folders/labels, stateful rules, explanations and replay.
5. Backend address book plus Warm/Cold query predicates.
6. OpenPGP evidence and extensions to the implemented built-in heuristic
   feature pipeline.
7. Change-stream API and official CLI/GUI integration.
8. Broader SMTP interoperability and provider-native send adapters (drafts,
   SMTP submission and IMAP mutations are implemented).
9. POP3 and import/export adapters.

## Research references

- [Turso manual and experimental FTS](https://github.com/tursodatabase/turso/blob/main/docs/manual.md)
- [Turso FTS design and current limitations](https://github.com/tursodatabase/turso/blob/main/docs/fts.md)
- [Turso SQLite compatibility matrix](https://github.com/tursodatabase/turso/blob/main/COMPAT.md)
- [Tantivy documentation](https://docs.rs/tantivy/)
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
