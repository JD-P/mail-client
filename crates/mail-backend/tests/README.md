# Mail-server integration tests

`dovecot_imap.rs` starts the official Dovecot CE image, populates an account
through IMAP `APPEND`, and makes the backend pull that mail through its real
IMAP sync path. It checks that initial sync publishes searchable/threadable
headers without bodies, that raw/MIME access remains unavailable, and that an
on-demand bounded download resumes a durable 700,000-byte prefix before
publishing exact raw bytes, MIME, body search and attachments. It also checks
flags, cursor-based deduplication, `References` threading, and a later
incremental delivery.

The image is pinned by digest. The test is ignored during the ordinary unit
suite because it requires Docker and may need to pull the image. Run it with:

```sh
cargo test -p lizard-mail-backend --test dovecot_imap -- --ignored --nocapture
```

`dovecot_security.rs` delivers the complete hostile-message corpus from
`spec/security-ui.md` through the same real server. It inventories every
warning class, verifies exact RFC bytes survive IMAP, and asserts the structured
identity, link, attachment and heuristic evidence implemented so far:

```sh
cargo test -p lizard-mail-backend --test dovecot_security -- --ignored --nocapture
```

`imap_account_engine.rs` exercises the backend-owned connection path against
the same server: verified STARTTLS and implicit TLS with a private test root,
credential-provider authentication, capability and mailbox discovery,
header-first sync plus engine-owned on-demand body hydration, flag refresh,
QRESYNC/CONDSTORE state, expunge reconciliation, and
an IDLE-driven continuous worker with prompt cancellation. It also exercises
conditional flag edits, UIDPLUS copy/move identity mapping, exact deletion and
durable concurrent-flag conflicts:

```sh
cargo test -p lizard-mail-backend --test imap_account_engine -- --ignored --nocapture
```

`imap_worker.rs` proves that a failed disposable worker becomes an account
error without terminating the parent and that sandbox setup either enforces
its file/network restrictions or fails closed. It also requires an attempted
x32-numbered syscall to terminate the worker with `SIGSYS`, preventing the
alternate ABI from bypassing exact native syscall checks. Its ignored Dovecot
case covers isolated header sync, on-demand body retrieval and parent-side
Tantivy publication on a Linux x86-64 host with Landlock ABI 6:

```sh
cargo test -p lizard-mail-backend --test imap_worker -- --ignored --nocapture
```

The container publishes Dovecot's IMAP and IMAPS ports on random loopback ports,
creates an ephemeral test-only TLS certificate, and is force-removed by the test
guard, including when an assertion unwinds.

The ordinary `threads.rs` integration suite covers deterministic late-root
convergence, `References`/`In-Reply-To`, normalized-subject fallback, stable
IDs across reopen, Reply/Reply-All and forward construction, and the adversarial
case where an unknown sender copies a known conversation's identifiers. That
message must remain in a separate unknown-sender thread.

`storage.rs` covers whole-profile and durable per-account quotas, the emergency
free-space reserve, usage accounting, Turso/foreign-key/search/blob audits,
full content-hash verification, corruption detection, orphan classification
and bounded issue reports which remain unhealthy even when errors are omitted
from the returned detail list.

`sending.rs` runs an in-process ESMTP server with a private test root and a
real STARTTLS upgrade. It covers revisioned autosave, streamed attachment
ingest, protected MIME headers, envelope-only Bcc, definite and temporary SMTP
failures, post-DATA ambiguity, cancellation, retry policy, durable/live events
and decoded attachment recovery. It also proves aliases are independent of the
SMTP login, replies select the receiving alias, and identity-associated OpenPGP
keys override the account default. An internal test additionally covers crash
recovery and Sent-folder reconciliation when the server adds transport headers.

`lifecycle.rs` checks byte-exact EML/Maildir/mboxrd round trips (including mbox
escaping and a missing final newline), bounded multi-batch import, checksummed
profile restore without Tantivy, and safe retention: local, pinned or
policy-required bodies cannot be evicted while a remotely recoverable on-demand
body can.

`mime_api.rs` covers materialized MIME parent/child and alternative-selection
semantics, CID lookup, bounded decoded streams, create-new export, magic-byte
typing, ZIP path/ratio/size budgets, sandbox extraction limits and explicit
complete, limited and failed parsing states.
