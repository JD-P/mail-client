# IMAP synchronization isolation

Status: implemented for Linux x86-64 hosts with Landlock ABI 6 or newer.
Unsupported kernels and platforms fail closed; they do not silently run the
isolated API without a sandbox.

## Threat model

An IMAP server controls a large stream of protocol tokens, mailbox names,
headers, MIME bodies and authentication evidence. Rust removes many memory
safety hazards, but it does not prove that every parser dependency is free of
memory corruption, stack exhaustion, panics or resource attacks. A configured
server is therefore an untrusted peer, not part of the backend's trusted
computing base.

The isolation boundary limits what a parser compromise can do. It is not a
claim that messages are harmless, and it does not protect mail belonging to
the account currently being synchronized from a fully compromised worker.

## Process model

`Backend::managed_imap_account_engine` launches
`lizard-mail-sync-worker` for each synchronization, body-download or IMAP IDLE
cycle. The parent retains:

- the frontend API and live event subscribers;
- the only on-disk Tantivy writer;
- the operating-system or profile credential manager; and
- process restart, cancellation and retry policy.

Before launch, the parent resolves the configured IMAP hostname and exactly
one opaque credential reference. It sends a versioned, length-prefixed JSON
request on the child's standard input. The request and response are capped at
2 MiB. Credentials are never placed in arguments, environment variables or
logs; serialized copies and the typed credential are zeroized when dropped.
The child environment is cleared and stderr is discarded so a malicious
message cannot create an unbounded diagnostic channel.

The child opens the same local Turso profile, applies one operation, returns a
bounded result and exits. Its Tantivy index is in memory: durable search-outbox
rows remain for the parent to publish after exit. Change events are replayed
from their durable sequence numbers. A crash, signal, malformed response or
wall-clock timeout becomes an account synchronization error; the parent
backend remains available and retries according to its ordinary backoff.

Continuous synchronization uses separate disposable workers for the sync and
IDLE phases. This gives each phase a fresh CPU, address-space and wall-clock
budget.

## Linux sandbox

The worker installs limits before parsing the request's mail data:

- 1 GiB address space, five CPU minutes, 128 file descriptors, no core dumps,
  and a configurable per-file and wall-clock ceiling by default;
- `PR_SET_DUMPABLE=0`;
- Landlock filesystem, TCP-port, signal and abstract-Unix-socket restrictions;
- `no_new_privs`; and
- an x86-64 seccomp filter.

Filesystem authority is deliberately narrower than the profile directory:

| Path | Worker authority |
|---|---|
| `mail.db`, `mail.db-wal` | read, write and truncate |
| `blobs/`, `downloads/` | mail-data CRUD, without execution, device, pipe, socket or symlink creation |
| profile root | directory listing only |
| `credentials/`, `search-index/`, other profile files | no file read or write |
| selected system resolver/time/randomness paths | read only |
| all other filesystem paths | no file read or write |

The parent measures storage before launch and supplies only that numeric
snapshot, allowing the child to preserve profile quotas without reading the
credential or search-index trees.

Network creation is restricted to IPv4/IPv6 stream sockets. Landlock permits
TCP connects only to the configured IMAP port and TCP 853, which is used by
the DNSSEC-validating Quad9 DNS-over-TLS DKIM resolver. UDP, raw, packet and
Unix sockets, listening sockets and socket pairs are denied. DNS resolution
for the IMAP endpoint occurs in the parent; the TLS server name remains the
configured hostname.

The seccomp layer also denies execution, ptrace and cross-process memory
access, kernel keyring operations, BPF/perf/userfaultfd, mounts, namespaces,
chroot, inbound sockets, and filesystem ownership/mode/xattr mutation. Signal
scoping prevents a compromised worker from signaling the parent. Landlock and
seccomp are additive: sandbox setup must report fully enforced Landlock plus
`no_new_privs`, or the worker terminates before opening the backend.

## Explicit compatibility escape hatch

`Backend::managed_imap_account_engine_in_process` preserves an explicit
in-process option for controlled embedders and unsupported operating systems.
Selecting it is a security-policy decision; the default managed engine never
falls back to it automatically.

## Residual authority

The worker must modify the mail database and downloaded-message storage, so a
successful compromise can corrupt or disclose locally stored mail and state.
Landlock network rules are port-based, not destination-address-based: a worker
may connect to another address on the configured IMAP port or TCP 853. TLS
verification still protects the legitimate protocol connection, but this is
not an anti-exfiltration proof for mail the worker can already read.

The supervisor and worker also share Turso's multi-process database contract.
Database transactions, idempotent remote identities, search-outbox revisions
and durable change sequences provide recovery; they do not make arbitrary
worker writes trustworthy after an actual code-execution compromise. Profile
backup and integrity-audit APIs remain the recovery mechanisms for that case.

## Verification

The worker exposes a test-only sandbox self-check. On a capable kernel it
proves that mail-data writes work while credential reads, unrelated-profile
writes, outside-profile reads/writes, execution, UDP and unlisted TCP ports
are denied. On an incapable kernel the test instead verifies a fail-closed
Landlock error. Integration coverage kills the worker and verifies the parent
database and search API remain usable. A Docker/Dovecot test exercises real
synchronization, on-demand body retrieval and parent-side search publication
when run on a Landlock ABI 6 host.
