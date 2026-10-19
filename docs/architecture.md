# Architecture

SAGA Capability governs **tool execution**, using SAGA's Provider concept as the
starting point. A model proposes a structured call. The Provider authenticates
the caller independently, normalizes the envelope, looks up an administrator's
policy and signs an exact capability. The worker admits it online and runs a
registered handler inside a fresh Linux sandbox.

```mermaid
sequenceDiagram
    participant A as Agent runtime
    participant W as C++ coordinator
    participant P as Provider
    participant D as Durable state
    participant E as Fresh executor
    A->>W: operation ID + task ID + structured tool call
    W->>P: mTLS: state and rotate(expected epoch)
    P->>P: normalize; check registered task policy
    P->>D: transaction: revoke old; publish next epoch
    D-->>P: commit
    P-->>W: signed exact capability
    W->>W: verify pinned signing key and claims
    W->>P: admit(token)
    P->>D: consume once; acquire execution gate
    P-->>W: execution ID + identical capability
    W->>E: sealed current-call input; exec sealed embedded image
    E->>E: close input; apply Landlock + seccomp
    E->>E: execute registered handler
    E-->>W: bounded result; exit
    W->>P: finish(execution ID, outcome, receipt)
    P->>D: persist receipt and release execution gate atomically
    W-->>A: structured result
```

The Provider serializes rights per authenticated agent across all tasks. A token
never accumulates earlier resources. It contains one operation, one registered
resource, the exact arguments and the sandbox description. Permission is
established at a tool boundary; natural-language interpretation never establishes
identity or expands the policy.

This diagram shows a new operation. The SDK assigns a stable `operation_id`
before launching the worker; callers should persist their own ID before an
action. The Provider binds it to the original certificate, task and normalized
call. Retrying it recovers the original ready grant, reports `running`, or
returns the recorded terminal receipt. It never creates a second grant or
replays admission success. A completed response can be recovered even after
resource contents or policy change; it grants no new access. Expired/revoked
IDs remain tombstones. See [the protocol](protocol.md).

## Why a new process for each call

Landlock restrictions are inherited and can only become stricter. A sandbox that
has already been restricted to one file cannot later be widened to a different
file. A fresh executor solves this without retaining previous kernel rights.
The coordinator owns transport and credentials; the executor owns the narrow
operation. Before running a handler, the child replaces its entire image with
an embedded, sealed executor via `execveat()`, without inherited environment variables. Only
the current capability enters through a sealed nonexecutable request memfd;
neutral stdio and a result pipe complete the protocol. Parent heap, mappings,
credentials and previous call outputs are not inherited by that fresh image.
Core dumps are disabled, and the helper resets dumpability after exec. If the
host prohibits executable memfds, execution fails closed. There is no fork-only
fallback and no runtime helper lookup through PATH or a replaceable sidecar.

This is logical address-space separation, not physical RAM erasure. Intended
results still return to the trusted coordinator and model runtime; revocation
cannot erase knowledge already disclosed to those components. Fixed handlers
and the dynamic loader remain trusted code. For dynamic SQLite, startup receives
only the canonical directory of the SQLite library already loaded by the
coordinator, as `LD_LIBRARY_PATH`, then clears it before parsing the request.
No build-tree RPATH is embedded in the helper. This supports installed private
SQLite libraries without copying the parent's environment. Loader separator
characters `:`, `;` and `$` in this dependency directory are refused.

ABI 9 adds pathname UNIX socket resolution control. The worker handles all
filesystem rights through that ABI, TCP bind/connect rights and UNIX/signal
scopes. Supplemental seccomp restrictions cover system calls that Landlock ABI 9
does not govern, including creating UDP sockets. The minimum ABI is checked at
runtime, and an unavailable sandbox causes execution to fail.

## Admission and rotation

An executing grant prevents rotation. A second worker cannot acquire a fresh
grant or replay the current token while the first worker is executing. This is a
Provider-owned admission gate, rather than worker-owned cancellation or rollback.
The transaction commit is the rotation's visibility point. After it, the old
token cannot pass online admission; before it, no new token is exposed.

Explicit `revoke(expected_epoch)` invalidates pending rights without issuing a
new token. It advances the same agent-wide generation and clears the current
grant in one transaction. A race with admission has one winner: if admission
wins, revoke returns `execution_busy`; if revoke wins, old-token admission is
denied. A signature remains mathematically valid, but cannot confer execution
rights without online admission. This is not interruption of running effects.

The workflow does not revoke effects that already happened. A completed file
write remains a completed write. A caller needing a different resource asks at
the next call boundary, after the current executor exits and finish is recorded.

An execution gate deliberately has no automatic timeout. If the coordinator dies
after admission, the Provider retains the gate across restart. Time alone cannot
prove that a process or a remote side effect has stopped. Recovery requires an
operator to verify that the executor is gone. The initial implementation has no
automatic recovery endpoint.

Timeouts do not release this gate. `operation_status(id)` reads the original
operation without executing it. If a side effect occurred but its receipt never
committed, the operation remains uncertain/running rather than being repeated.
Stored receipts contain sensitive tool outputs, are original-certificate scoped,
and commit atomically with finish. Redacted audit streams contain no outputs.
Same-ID retries prevent duplicate admission; exactly-once external effects and
automatic recovery from an unrecorded effect are separate unsolved contracts.

The coordinator retries only safe state reads, definite generation conflicts
and identical idempotent completion requests. A lost admission acknowledgement
is reported as uncertain, not executed or automatically replayed. Failure audit
events commit separately after a rejected action transaction has rolled back;
successful transitions and their audit records still commit together. Request
and call IDs connect redacted server failures, worker receipts and optional SDK
failure logs. Logging storage failures are explicit, with a redacted stderr
fallback, rather than authorization without a transition audit.

Pending grants are checked against the current policy at admission. Changes to
task permissions or resource/query scope after a restart therefore deny old
pending capabilities. Both admission and completion are bound to the original
certificate fingerprint; re-enrolling an ID with a different certificate does
not let it reuse or finish the old certificate's work. Complete running work
before changing enrollment, or retain the closed gate for verified recovery.

## Trusted code and deployment

The trusted components are the Provider, its policy and signing key, the
coordinator, registered handlers, the kernel and the administrator of the host.
Private agent certificates identify runtimes. They must remain outside model
inputs. An operating-system user able to replace these components or steal those
credentials is outside this boundary. A malicious model is inside it: it may
invent names, change arguments, request unauthorized calls and replay responses.

File resources are exact existing regular files. SQLite snapshot access uses
registered read-only queries and bound parameters; live WAL databases are
rejected. The initial HTTP handler contacts a
numeric loopback endpoint registered in policy; it does not implement a general
web browser. TCP Landlock rules govern ports, not IP addresses or HTTP verbs.
The handler and Provider enforce endpoint and function semantics.
