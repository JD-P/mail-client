# ZIP archive isolation

Status: implemented for Linux x86-64 hosts with Landlock ABI 6 or newer.
Unsupported kernels and platforms fail closed; the public archive APIs never
silently fall back to in-process ZIP parsing.

## Boundary

`Mime::inspect_archive` and `Mime::read_archive_entry` launch a fresh
`lizard-mail-archive-worker`. The parent reads the hash-checked attachment blob
under the caller's compressed-input limit, then sends a small versioned JSON
header followed by the exact archive bytes over standard input. The child
returns either bounded directory metadata or one bounded expanded entry. It
receives no path, profile handle, credential, network client, display or
terminal.

The parent clears the environment, closes accidentally inherited descriptors
at exec, caps both protocol headers before allocation, enforces a wall timeout,
kills failed workers and independently validates:

- protocol version and operation/result pairing;
- entry count and sequential indices;
- path and diagnostic lengths and absence of terminal controls;
- total uncompressed-size arithmetic;
- compression-ratio and per-entry limits for a `complete` result; and
- the exact expanded byte count.

Inspection reads ZIP central-directory metadata with `by_index_raw` and never
inflates an entry. Expansion is a separate operation and is refused unless a
fresh metadata pass completes within every path, size, count and compression
budget. Only the selected entry is inflated, with a one-byte-over-limit read
guard.

## Linux sandbox

The worker installs its sandbox before reading any archive-controlled byte:

- 1 GiB address space, fifteen CPU seconds, sixteen descriptors, zero-byte
  file creation and no core dumps;
- `PR_SET_DUMPABLE=0`;
- an empty Landlock ABI 6 policy handling all filesystem and network access,
  signal scoping and abstract Unix sockets; and
- an x86-64 seccomp filter denying filesystem opens and mutation, networking,
  process/thread creation, execution, tracing, cross-process access, IPC,
  namespaces, mounts, keyrings, BPF/performance interfaces, io_uring, signals
  and subsequent sandbox/limit changes.

The x32 syscall bit is killed before native-number comparisons. Full Landlock
enforcement and `no_new_privs` are mandatory.

## Existing IMAP worker

Mail received through managed IMAP is already being processed inside the
short-lived IMAP sandbox, whose seccomp profile deliberately forbids nested
execution. Built-in security inspection therefore calls the same bounded ZIP
core inside that existing disposable process. This is not an in-process escape
hatch for ordinary backend callers; it avoids weakening one sandbox merely to
create another.

## Failure behavior and verification

Spawn failure, unavailable Landlock, timeout, crash, malformed or oversized
output, inconsistent metadata and a wrong result type are errors. Built-in
security evidence converts inspection failure into `uninspectable_archive`, so
failure remains visible rather than making the attachment appear safe.

Tests exercise the bounded pure parser, unsafe and overlong paths, seccomp
authority denial, x32 termination, fail-closed Landlock behavior, worker-crash
handling and rejection of an oversized response before allocation. Functional
end-to-end worker parsing runs when the host provides Landlock ABI 6.
