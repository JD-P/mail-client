# Terminal HTML renderer isolation

Sender-authored HTML is adversarial input. The terminal client therefore treats
the HTML parser and layout engine as a disposable service, not as part of its
trusted interactive process.

## Linux boundary

The implemented worker profile currently targets Linux x86-64. A new
`lizard-mail-tui-render-worker` process is launched for each distinct message
body and terminal width. It receives only stdin/stdout pipes; stderr is sent to
`/dev/null`, the environment is cleared, and it never receives a terminal,
profile handle, credential, display connection, or network client.
Immediately before `exec`, the parent marks every descriptor above standard
input/output/error close-on-exec with `close_range`; this prevents an
accidentally inheritable database or profile descriptor from bypassing
Landlock's path checks.

Before reading the request the worker:

- sets 512 MiB address-space, two-second soft/three-second hard CPU, zero-byte
  file, zero-byte core, and sixteen-descriptor limits;
- disables core/ptrace dumping;
- enters an empty Landlock ABI 6 ruleset handling all available filesystem and
  network rights plus signal and abstract-Unix-socket scopes; and
- installs an architecture-checked seccomp filter denying process creation,
  execution, filesystem opens and mutation, sockets, cross-process access,
  inherited/pidfd and System V IPC, namespaces and old/new mount APIs, keyrings,
  filesystem notification APIs, BPF/performance interfaces, signals, io_uring,
  pipes, and later weakening of its own limits or sandbox.

Landlock must report full enforcement. A kernel or container without the
required support does not receive a weaker renderer: the worker exits before it
reads HTML and the client uses plain text.

## Protocol and terminal ownership

Requests and responses are length-prefixed JSON with independent byte caps.
HTML is base64-encoded to keep the protocol unambiguous. The child can return
only semantic lines, a fixed style/color vocabulary, inert link/image metadata,
warnings, and a truncation flag. It never emits terminal escape sequences.

The parent validates the protocol version, collection sizes, total spans,
bytes, terminal cells, line widths, sequential reference numbering, allowed
styles, and all displayed strings. C0/C1 controls and Unicode bidi
embedding/override controls are rejected. Only the parent constructs Ratatui
objects and writes to the user's terminal.

## Failure behavior

The parent kills the worker on a five-second wall timeout. Spawn failure,
sandbox failure, crash, premature exit, malformed/oversized output, render
error, or validation failure all produce the same safe product behavior: show
the backend's bounded plain-text MIME part. The CLI never falls back to parsing
HTML in-process. Serious security findings still replace the reader before a
body is sent to the worker; the explicit restricted-open action is required
first.

The semantic `HtmlRenderer` API remains available for deterministic tests and
controlled embedders. It is not the path used by the hostile-mail CLI reader.

## Residual trust

The Linux kernel's Landlock, seccomp, rlimit and process implementations remain
trusted, as do the parent-side protocol validator and Ratatui. A parser memory
safety flaw may compromise the worker, consume its bounded resources, or forge
a response, but should not grant profile/filesystem/network authority or direct
terminal access. The validator treats even a compromised worker's response as
untrusted.

## Verification

Subprocess tests exercise the seccomp denials without depending on Landlock
availability and require an x32-numbered syscall to terminate the worker with
`SIGSYS`. The full sandbox self-test either demonstrates that filesystem,
network and execution attempts are denied, or demonstrates that an unsupported
Landlock environment fails before rendering. A real end-to-end worker render is
required whenever that full self-test succeeds.
