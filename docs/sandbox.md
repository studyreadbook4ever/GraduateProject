# Linux execution profile

The production executor and diagnostic probe use the same sandbox installation
function. The coordinator checks the running Landlock ABI and refuses to run
below ABI 9. Newer kernels use this same ABI 9 profile.

| Mechanism | Enforcement |
| --- | --- |
| Landlock filesystem | All rights through bit 16, including pathname UNIX socket resolution, are handled; exact regular-file read or write/truncate rules are granted |
| Landlock TCP | TCP bind is denied; connect is allowed only to signed ports |
| Landlock scopes | Abstract UNIX sockets and signals are scoped to the sandbox domain |
| Seccomp | Exec, process creation, ptrace/process-memory access, io_uring, privilege changes and filesystem metadata mutations are denied |
| Socket filter | Only stream IPv4/IPv6/UNIX sockets are permitted; UDP/raw/packet/netlink creation is denied |
| Descriptor cleanup | At exec only a sealed current-call request, result pipe and neutral stdio survive; request FD closes before handler dispatch |
| Memory image | `execveat` of a sealed embedded ELF replaces parent mappings before parsing/dispatch; empty environment, nondumpable helper |
| Process lifetime | Parent-death SIGKILL, child cleanup/reaping, wall/CPU limits and bounded result pipe |

The executor resets its working directory and clears its environment before
running a handler. Standard descriptors 0, 1 and 2 point to freshly opened
`/dev/null`. This is a harmless pre-opened device, not an extra pathname grant.
SQLite's Unix VFS requires database descriptors above 2 and otherwise attempts
to open `/dev/null` itself; denying that lazy open caused the first experiment
to fail. Neutral standard I/O resolves the dependency without widening the
resource policy.

Resource paths are opened using `openat2()` with `RESOLVE_NO_SYMLINKS` and
`RESOLVE_NO_MAGICLINKS`. Both policy and executor reject symlink components and
nonregular files. Landlock rules bind the file opened during sandbox setup.
The signed sandbox must equal the independently derived requirements of the
registered handler; an extra path or port is rejected.

The coordinator forks only a startup stub, which immediately replaces its image
with a sealed embedded executor using `execveat(AT_EMPTY_PATH)`. A sealed
nonexecutable memfd carries the current capability, without TLS keys, tokens or
previous results. No handler runs in the inherited image. The helper has empty
environment and neutral stdio; it closes its request FD and installs the same
Landlock/seccomp profile before dispatch. Executable memfd policy denial fails
closed with no fork-only fallback. The embedded image keeps installed static
and shared library users independent of helper paths or PATH lookup.

For a dynamic SQLite dependency, the coordinator supplies exactly one loader
variable identifying its already loaded library's canonical directory. The
helper clears this variable immediately after exec and before request parsing;
the parent environment is never copied. The helper contains no build-tree
RPATH. Dependency directories containing `:`, `;` or `$` are refused so the
loader cannot reinterpret one directory as several paths or expand tokens.

An exec replaces virtual mappings; it does not promise physical RAM wiping or
erase already returned results from a model's context or the coordinator.
Registered handlers, loader dependencies and the host remain trusted. Running
arbitrary untrusted binaries requires a separately reviewed interface.

Sources: [execve memory semantics](https://man7.org/linux/man-pages/man2/execve.2.html),
[executable memfd policy](https://www.kernel.org/doc/html/v7.0/userspace-api/mfd_noexec.html).
[dynamic-loader search rules](https://man7.org/linux/man-pages/man8/ld.so.8.html).

Landlock does not restrict every system call. TCP rules restrict destination
ports, not hosts or HTTP functions. This implementation therefore combines
kernel enforcement with fixed handlers and exact Provider validation. Its HTTP
handler accepts only registered numeric loopback endpoints, sends one GET,
does not follow redirects and does not use a proxy.

## Data and resource bounds

File output is UTF-8 text; invalid text is an execution/serialization error,
rather than silently changed bytes. JSON strings containing NUL are permitted
as file content but not as paths. Read/write content is bounded to 1 MiB, and
serialized capability and token bounds can reject heavily escaped inputs
earlier. Query results are limited to 1,000 rows and 1 MiB; BLOB output requires
a separate handler. HTTP responses are bounded to 1 MiB.

SQLite resources are immutable rollback-journal-mode snapshots. Active WAL,
shared-memory or journal sidecars are rejected. The worker uses read-only,
immutable URI mode, an authorizer and bound parameters; it never executes
agent-generated SQL. A live server database requires a dedicated, reviewed
handler with database-side function/role restrictions.

Children have a five-second CPU limit, ten-second coordinator wall deadline,
512 MiB address-space limit, four-MiB file limit and disabled core dumps. The
coordinator reaps a child before recording finish. A deadline failure can leave
partial effects, which are reported as failure and are not undone.

Executor image/request memfd preparation checks the coordinator's inherited
RLIMIT_FSIZE before writing. An embedding host with a limit below the image or
request size receives a graceful refusal instead of SIGXFSZ terminating the host.

The registered HTTP handler validates HTTP/1.0 or 1.1 status/header syntax and
Content-Length, rejects conflicting or incomplete/excessive bodies, and rejects
unsupported transfer encodings by header name. Identical combined lengths,
informational responses followed by a final response, and no-body status metadata
are handled explicitly. It requests connection close and bounds response bytes
to 1 MiB and each header block to 64 KiB. A close-delimited response without a
declared length cannot establish whether an origin intended to send more data.

## Diagnostic probe

`saga-worker --sandbox-probe probe.json` accepts a local administrator-supplied
specification. It is not exposed through the Provider tool registry.

```json
{
  "sandbox": {
    "paths": [{"path": "/absolute/test/allowed.txt", "access": "read"}],
    "tcp_ports": [8765]
  },
  "attempts": [
    {"kind": "read", "path": "/absolute/test/allowed.txt"},
    {"kind": "read", "path": "/absolute/test/denied.txt"},
    {"kind": "tcp_connect", "host": "127.0.0.1", "port": 8765},
    {"kind": "unix_connect", "path": "/absolute/test/listening.sock"},
    {"kind": "udp_socket"}
  ]
}
```

The result contains `ok`, `landlock_abi` and an `attempts` array. Each attempt
returns `kind`, `ok` and `errno`. `errno` 1 or 13 demonstrates an actual policy
denial; a refused TCP connection alone does not demonstrate authorization.
Tests create real listening endpoints before testing permitted and denied
connections.

Kernel reference: [Linux Landlock userspace documentation](https://docs.kernel.org/userspace-api/landlock.html).
