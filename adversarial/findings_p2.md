# Pass 2 — malicious mail-server protocol and RCE review

- **Date:** 2026-11-19
- **Subject:** clean commit
  `47eb6b29fde5807dd9204aee2c4049eb7dd0ddb2`, equal to `origin/main`
  before this pass created `adversarial/p2/`.
- **Threat model:** a configured IMAP or SMTP endpoint is malicious or
  compromised, presents a certificate valid for the configured hostname, and
  can return arbitrary protocol data and arbitrary message bytes. No real
  server or public IP was used.
- **Harness:** `adversarial/p2/imap-response-flood/`; retained measurements
  are in `adversarial/p2/results_imap_flood.txt` and negative RCE evidence is
  in `adversarial/p2/negative-results.txt`.
- **Disposition:** **P2-A confirmed at the reviewed commit and remediated by
  `4d1ab6614bfcb103edb2d8cd721f63fdef0e96a4`. No host RCE was
  demonstrated.** The review itself did not modify product source; the later
  remediation is recorded separately.

---

## 1. Executive summary

| # | Finding | Intended boundary | Observed behavior | Class |
|---|---|---|---|---|
| **P2-A** | IMAP command streams bound each response but not the response count or aggregate retained bytes. | One server command must have an aggregate resource budget independent of its timeout and per-response limit. | 1,360,024 bytes of valid `LIST` traffic caused 40,000 responses to be retained at 174,004 KiB peak RSS. The same input aborted under a 150,000 KiB address-space ceiling. Several `FETCH` and `SEARCH` paths had the same missing pre-allocation cardinality boundary. | **high denial of service**, remediated; configured malicious/compromised IMAP server |

The direct answer to the RCE question is **not from anything demonstrated in
this pass**. The confirmed primitive is deterministic process termination in
safe Rust, not memory corruption. The two realistic RCE-capable dependency
boundaries—native HTML/image rendering and the optional system GnuPG
provider—do receive attacker data, but the former is contained in a
resource-capped seccomp worker and the latter has no shell or attacker-selected
arguments. Exploiting either would require a separate parser vulnerability;
none was found here.

## 2. P2-A — unbounded IMAP response aggregation killed the backend

### 2.1 Per-response limits do not compose into a command limit

The vendored async-imap stream rejects an individual server response above
64 MiB and rejects nesting beyond 128. That prevents one literal or recursive
response from growing without bound. It does not bound how many valid
responses may precede the tagged completion for one command.

Mailbox discovery consumes the stream into an unbounded vector:

```rust
// crates/mail-backend/src/imap_engine.rs:1416-1422
session
    .list(None, Some("\"*\""))
    .await?
    .try_collect::<Vec<_>>()
    .await
```

Each returned `Name` owns a `ResponseData`, which in turn owns the parser's
backing `BytesMut`. The stream buffer starts at 4 KiB and transfers that block
to each parsed response so its borrowed strings remain valid
(`vendor/async-imap/src/imap_stream.rs:246-330`). Consequently, even a tiny
valid response generally retains an allocation rounded to 4 KiB.

The command timeout is only a wall-clock boundary. A local server delivered
40,000 responses in about 1.03 seconds, far inside the default 60-second
command timeout, so it does not constrain the allocation.

### 2.2 Retained reproduction

The harness performs a real async-imap greeting, LOGIN and LIST exchange, then
uses the production `try_collect::<Vec<_>>()` pattern. Results scale linearly:

| LIST responses | Wire bytes | Peak RSS |
|---:|---:|---:|
| 1,000 | 34,024 | 6,424 KiB |
| 10,000 | 340,024 | 45,320 KiB |
| 20,000 | 680,024 | 88,216 KiB |
| 40,000 | 1,360,024 | 174,004 KiB |

The largest case retains roughly **128 bytes of resident memory per wire
byte**. Under `RLIMIT_AS=150000 KiB`, it aborts in the allocator with SIGABRT.
The test ceiling limits only the harness child; it does not pressure the
review environment.

Reproduce from the repository root:

```sh
python3 adversarial/p2/imap-response-flood/measure.py 40000
python3 adversarial/p2/imap-response-flood/measure.py 40000 150000
```

TLS is omitted only from the local harness. Production reaches the same
async-imap parser and collector after rustls decrypts the server's bytes, so a
valid certificate neither removes nor changes the defect.

### 2.3 The root cause is shared by other ordinary sync operations

This is not merely an implausibly large mailbox list:

- Flag reconciliation and `CHANGEDSINCE` collect every server-selected
  `FETCH` response (`imap_engine.rs:1663-1688`).
- Bounded body-range helpers request one UID but collect all `FETCH` responses
  before selecting it (`vendor/async-imap/src/client.rs:695-748`).
- Header-first sync streams in groups of 100 requested UIDs, but accepts an
  unlimited number of duplicate matching responses into `metadata` before it
  sorts and deduplicates (`backend.rs:4342-4364`).
- `UID SEARCH ALL` applies the ten-million-UID policy only after async-imap has
  parsed and allocated the returned set (`imap_engine.rs:1701-1713`). Its
  single-response 64 MiB cap limits wire bytes, not parsed collection memory.

These are occurrences of one wrong invariant: a server-command response set
has no aggregate item/byte budget while it is being consumed.

### 2.4 Reachability, severity and remediation boundary

- **Primary family:** `denial_of_service`.
- **Impact tier:** high. A compromised provider or endpoint selected by the
  user can terminate the main backend during automatic mailbox discovery or
  synchronization using a small amount of standards-valid traffic. The
  server needs no message content exploit and can retrigger on reconnect.
  Requiring control of the configured TLS-authenticated endpoint narrows the
  attacker population, but that endpoint is exactly the subject of this pass.
- **Unintended behavior count:** 1. Per-response framing has no command-level
  aggregate resource boundary.
- **Remediation component count:** 1. Add a shared budgeted command-stream
  consumer that counts response items and retained/decoded bytes before
  collection. Use protocol-appropriate item ceilings for LIST/FETCH/SEARCH,
  reject duplicates beyond the requested cardinality, and lower the ordinary
  metadata connection's individual-response limit. Timeouts remain separate.

### 2.5 Remediation

Commit `4d1ab6614bfcb103edb2d8cd721f63fdef0e96a4` places the resource boundary in
the shared async-imap stream, before a parsed response can escape to any
collector. Every tagged command now permits at most 1,024 responses and a
bounded aggregate wire length; the backend additionally caps an individual
response at 8 MiB, command traffic at 64 MiB, and parser nesting at 64.

The application paths were tightened at the same boundary:

- single-UID body size and range fetches stream and reject duplicate target
  responses instead of collecting an attacker-selected vector;
- header sync permits only the requested UID cardinality plus a small bounded
  unsolicited allowance and rejects duplicate requested UIDs;
- flag reconciliation is split into exact 512-UID batches, preserving large
  legitimate mailboxes without an unbounded `UID FETCH 1:*`; and
- a dropped command stream must drain under its original budget before a new
  command can reset the counters.

The original 40,000-response harness is now rejected at about 6.7 MiB peak
RSS. It exits normally under the same `RLIMIT_AS=150000 KiB` ceiling that
previously produced SIGABRT. Unit tests cover count, aggregate-byte, duplicate
UID, cancellation and response-flood behavior; the full backend suite and
real Dovecot synchronization also pass. Exact commands and results are in
`adversarial/p2/results_remediation.txt`.

## 3. RCE analysis

### 3.1 Protocol and MIME parsing

The maintained backend/TUI and vendored async-imap protocol path contain no
unsafe Rust. `imap-proto` is safe Rust; malformed input can at worst expose a
panic/stack/resource defect, with async-imap applying its nesting check before
the recursive parser. One million structured response mutations completed
without a panic or AddressSanitizer finding.

Arbitrary message bytes do reach mail-parser 1.0.1, whose SIMD scanner and
validated UTF-8 conversion contain internal unsafe blocks. Manual inspection
found slice-length guards and validation immediately before the unchecked
conversion. A 250,000-case structured MIME campaign traversed decoded parts,
headers and bodies in both release and AddressSanitizer builds without a
panic or sanitizer finding. This is negative evidence, not a memory-safety
proof.

Mailbox names are quoted with CR/LF rejection before command reuse, UIDs have
a restricted grammar, database uses are parameterized, and server strings do
not become filesystem paths. Attachments are neither launched nor exported to
their MIME filename.

### 3.2 Native renderer

HTML and image decoders are the largest native memory-safety surface. On
Linux x86-64 they execute only after the renderer worker has preloaded fonts,
closed descriptors above 2, installed `no_new_privs` seccomp, and accepted a
512 MiB address-space and CPU limit. Its syscall allowlist has memory,
threading, timing and pipe I/O but no filesystem open, network, `execve`,
`ptrace`, or process creation. Host-side image and trace frame sizes are
independently checked. A renderer memory corruption could execute within the
worker, but this pass found no path from that worker to host authority.

Unsupported platforms refuse sandbox entry rather than silently running the
production worker unconfined.

### 3.3 GnuPG/YubiKey provider

Users selecting the GnuPG or YubiKey provider cause the application to invoke
the literal executable `gpg` and send attacker-controlled OpenPGP packets on
stdin. Arguments are application-selected (`--decrypt` for received mail),
stdout/stderr are bounded, and no shell is involved
(`openpgp.rs:2359-2436`). Thus there is no command-injection primitive.

Unlike the renderer, GnuPG is not sandboxed or given an OS memory/CPU limit;
only a ten-minute wall timeout exists. A memory-safety vulnerability in the
user's installed GnuPG could therefore become same-user code execution. That
is the clearest residual RCE boundary, but it is a dependency exploit
precondition, not a demonstrated vulnerability in this client. The pure-Rust
rPGP path avoids that native subprocess and uses a version beyond its current
RustSec affected range.

### 3.4 Published-advisory check

Against RustSec advisory-db commit
`074ea9a7ed619f511b5b7374c7a97e98d1e98be4`, the locked rustls 0.23.46,
rPGP 0.21.1, zip 9.6.1 and image 0.25.10 are outside published affected
ranges. There were no database entries for async-imap, imap-proto 0.17.0,
mail-parser 1.0.1 or mail-auth. This does not cover unpublished issues or the
system GnuPG installation.

## 4. Conclusion

I found **no demonstrated mail-server-to-host RCE**. At the reviewed commit,
the client did let a malicious configured IMAP server kill the main backend
reliably and cheaply. The later remediation adds the missing shared resource
boundary and retains the provider as untrusted input rather than part of the
availability TCB.

## 5. Subsequent process isolation

Commit `1699f224742e516c176fd5a68827c0256e903762` adds the defense-in-depth
boundary proposed after this review. Managed IMAP synchronization, body fetch
and IDLE now execute in fresh resource-limited workers. On Linux x86-64 the
worker requires fully enforced Landlock ABI 6 plus seccomp; missing support
fails closed. The worker receives one resolved credential, cannot read the
profile credential vault or Tantivy tree, and cannot access other user files,
execute programs, use ptrace, signal the parent, or create UDP/raw/Unix
sockets. The parent remains alive across worker crashes and repairs an
interrupted body download into explicit failed/resumable state.

This is containment, not removal of parser risk. The worker necessarily has
read/write access to the mail database and blobs, and its allowed outbound
ports are not restricted to one destination address. Exact authority,
verification and host limitations are recorded in
`spec/imap-sync-isolation.md` and `adversarial/p2/results_isolation.txt`.
