# Capability protocol, version 1

All requests use HTTPS with certificate verification on both ends. The Provider
maps the SHA-256 fingerprint of the actual TLS peer certificate to one registered
agent ID. HTTP headers, tool names, task descriptions and model-supplied names
cannot select that identity. Content type is JSON.
Request bodies are limited to 2 MiB of encoded UTF-8 JSON, except
`/v1/finish`, which accepts up to 5 MiB for completion receipts. Ambiguous JSON,
non-finite numbers, duplicate keys and invalid UTF-8 are rejected.

## Requests

`GET /v1/state` returns the authenticated agent's `agent_id` and `epoch`. A new
agent starts at epoch 0. Generations are global per agent, not per task.

`POST /v1/rotate`:

```json
{
  "task_id": "research",
  "expected_epoch": 0,
  "format": "canonical",
  "call": {"tool": "read_file", "arguments": {"resource": "notes"}}
}
```

The Provider checks the task assignment, adapter, tool schema and exact
tool/resource allow entry. A valid request enters a transaction, checks the
expected epoch and absence of a running execution, revokes the previous grant,
records the new grant and commits. The token is returned only after commit.
There is no externally visible state with two active grants. Rejected requests
do not change the active capability. A failed transaction publishes no token.
The response is `{agent_id, epoch, token}`.

### Durable operation identities

`rotate` also accepts an optional `operation_id`, an application-owned string
of 1 through 128 ASCII characters. The first character is alphanumeric; the
remaining characters can also include `_`, `.`, `:`, and `-`.

```json
{
  "task_id": "research",
  "expected_epoch": 0,
  "operation_id": "read-notes-turn-17",
  "format": "canonical",
  "call": {"tool": "read_file", "arguments": {"resource": "notes"}}
}
```

The first successful issuance commits an operation record together with its
grant and audit transition. Its key is `(authenticated agent_id, operation_id)`;
the original certificate fingerprint, task and canonical normalized
`{tool, arguments}` are immutable bindings. Object key order, adapter syntax and
vendor correlation IDs do not create distinct operations when the normalized
call is identical. Tool arguments themselves are not rewritten to guess
application-specific equivalence. Normalization is snapshotted once, including
when a trusted custom adapter is registered.

Repeating the same key and call looks up the committed operation before the
current epoch comparison or policy checks. It never issues another grant or
advances the generation. Changing the task or normalized call returns
`409 operation_conflict`. A replacement certificate enrolled under the same
agent name cannot recover the original operation or its data.

Responses with an operation ID contain these fields:

```json
{
  "operation_id": "read-notes-turn-17",
  "agent_id": "alice",
  "task_id": "research",
  "epoch": 1,
  "status": "ready",
  "execution_id": null,
  "outcome": null,
  "failure_code": null,
  "receipt": null,
  "created_at": 1791810000,
  "admitted_at": null,
  "finished_at": null,
  "replay": false,
  "token": "signed-capability"
}
```

`replay` is false for the new issuance and true for an existing operation.
Only a `ready` response includes the original token. That token remains
consume-once: concurrent callers can recover the same token, but at most one
admission succeeds. Replaying `admit` never grants a second owner.

| Operation status | Meaning and retry behavior |
| --- | --- |
| `ready` | Original grant is active and unexpired; normal admission checks still apply. |
| `running` | Original admission is unfinished. No token or dispatch permission is returned. |
| `succeeded` or `failed` | Original completion is committed; return its stored receipt when available. |
| `expired` | Grant expired before admission; the same key is never reissued. |
| `revoked` | Grant was revoked before admission; the same key is never reissued. |

`POST /v1/operation` with `{operation_id}` reads the same status record without
returning a token or changing state; it omits `replay`. Missing operations return
`404 unknown_operation` for that authenticated agent. Another agent cannot read
the record. A `running` result does not prove that a local process is still
alive, and an unknown result does not prove that a concurrent request has
finished or could not commit. Status lookup never authorizes execution. An
uncertain caller must retain its original key and reconcile the original
operation; allocating a new key can duplicate effects.

Operation keys are retained with their original grants and results. Token
expiry, elapsed time and Provider restart do not delete them or permit key
reuse. There is no automatic key pruning endpoint. Deleting or restoring an
older state database loses this deduplication history and falls outside the
guarantee. The operator must provision and retain this private state.

Legacy `rotate` requests without `operation_id` and their original response
shape remain accepted. They provide token-level admission limits; separate
legacy calls do not share semantic deduplication. The current Worker generates
an operation ID when one is omitted, but recovery across separate invocations
requires the application to preserve and reuse that ID.

`POST /v1/revoke` with `{expected_epoch}` revokes pending authority without
issuing a replacement token. The transaction checks the current agent-wide
epoch, rejects an unfinished execution, marks any current grant REVOKED,
advances the epoch and clears `current_jti`. Response:
`{agent_id, epoch, revoked: true}`. The old signature still verifies; mandatory
online admission rejects it by epoch, current grant and status. If admission
wins a race, revoke returns `409 execution_busy`, without claiming cancellation.

`POST /v1/admit` with `{token}` checks the signature, authenticated subject and
original certificate fingerprint, exact issued token, expiry, current generation
and ACTIVE status in one
transaction. The token becomes EXECUTING and cannot be admitted again. Response:
`{execution_id, capability}`. The worker verifies that the returned capability
equals the signed capability before executing.

Admission also rebuilds the exact capability against the current registered
policy. A pending token is denied if a restart removed its task permission or
changed its resource/query/sandbox scope. Snapshot safety is checked again. This
recheck does not interrupt an already admitted execution.

`POST /v1/finish` with `{execution_id, outcome}` accepts `succeeded` or `failed`.
It releases only the original certificate's matching execution. Repeating the
same finish is idempotent. Repeating it with another outcome conflicts. This
records completion; it neither revokes earlier effects nor cancels a process.

Failed completion can include optional `failure_code`, one of
`execution_failed`, `sandbox_unavailable`, `sandbox_setup_failed`, `worker_timeout`,
`invalid_worker_output`, `worker_failed` or `completion_uncertain`. It is recorded
with the outcome; arbitrary diagnostic strings and successful outcomes carrying
a failure code are rejected. Legacy finish requests remain accepted.

Completion can also include a `receipt` JSON object. Its boolean `ok` must
match the outcome. If it contains `execution_id` or `operation_id`, those must
match the original admission and operation. The encoded receipt is limited to
4 MiB plus 64 KiB, within the 5 MiB finish-body limit. The outcome, failure code,
receipt and gate release commit in the same transaction. A lost finish response
can therefore be reconciled without rerunning the handler.

A duplicate completion with a different outcome, supplied failure code or
supplied receipt returns `409 completion_conflict`. Omitting optional fields in
a duplicate remains compatible and never removes or overwrites stored values.
A receipt cannot be backfilled after a completion that omitted it; such legacy
operations retain their outcome with `receipt: null`. Completion of an old
execution cannot release a newer execution or attach a result to another key.
An old completed operation remains `succeeded` or `failed` after later grant
rotations.

Receipts may contain private tool output. They are stored in the owner-only
Provider state database and returned only to the originally bound certificate
while it remains enrolled. This sensitive result cache is separate from the
redacted audit streams. Database operators can read it; encryption at rest and
application retention policy remain deployment responsibilities.

`GET /v1/audit?after=0&limit=100` and `GET /v1/failures?after=0&limit=100`
return `{events, next_after}` for the authenticated agent only. `after` is an
event ID and `limit` is between 1 and 500. The first stream contains committed
transitions; the second contains failed requests, persisted after their action
transaction rolls back. Unenrolled peers and handshake failures have no agent
attribution and are available only to the local database operator.

Optional `X-Saga-Call-ID` is 32 lowercase hexadecimal characters and correlates
all phases of one worker call. The Provider generates a distinct request ID in
`X-Saga-Request-ID` and error responses. Neither identifier conveys authority.
Events contain bounded operation/phase/code/status/time and IDs, never a token,
request body, content, SQL, private path or exception text. If a transition audit
cannot commit, its state change rolls back. If failure audit storage is itself
unavailable, the server emits redacted `audit_unavailable` to stderr and returns
503 when the transport permits a response.

| Condition | Result |
| --- | --- |
| Unknown or unenrolled certificate | 403, no execution |
| Malformed or ambiguous input | 400, no state transition |
| Oversized request or serialized capability | 413, no state transition |
| Tool/resource or task denied | 403, no state transition |
| Stale expected generation | 409, caller must observe state again |
| Current execution still running | 409, rotation is refused |
| Revoked, expired or consumed token | 403, admission is refused |
| Completion outcome differs from recorded one | 409 |
| Operation key reused for a different normalized task/call | 409, original operation unchanged |
| Unknown operation key | 404, no dispatch permission |
| Same agent name with a replacement certificate | 403 for the original operation/result |

The worker retries safe state reads, definite rotation `epoch_conflict`, and
identical idempotent finish requests after transport loss, at most three times.
It does not automatically retry a potentially executed operation or a lost
rotate/admit response.
An explicit repeated `perform` with the original operation ID recovers the
original grant or result according to the table above. A running operation
returns `operation_in_progress`, and a cached completion returns a receipt with
`replayed: true` and `executor_started: false` for this invocation. Reconciliation
never reruns a completed or unfinished admission. A successful status-query
receipt means the lookup succeeded; callers must inspect its operation `status`
to distinguish unfinished and terminal work.
Transport failure after admission is an uncertain outcome, so the Provider
gate remains closed unless completion is known and recorded.

## Token

Encoding: unpadded canonical base64url of raw UTF-8 payload, a dot, and canonical
base64url of a 64-byte Ed25519 signature. There is no client-selected algorithm.
The worker pins an Ed25519 public key separately from its TLS CA.

```json
{
  "v": 1,
  "iss": "saga-cap/provider",
  "aud": "saga-cap/worker",
  "sub": "agent-research",
  "certificate_sha256": "sha256-of-enrolled-client-certificate-der",
  "task_id": "research",
  "epoch": 1,
  "jti": "random-grant-id",
  "iat": 1791810000,
  "exp": 1791810060,
  "capability": {
    "tool": "read_file",
    "resource": "notes",
    "operation": "read",
    "arguments": {"resource": "notes"},
    "execution": {"path": "/srv/agent-data/notes.txt"},
    "sandbox": {
      "paths": [{"path": "/srv/agent-data/notes.txt", "access": "read"}],
      "tcp_ports": []
    }
  }
}
```

Tokens are bearer material additionally bound to the mTLS subject. They are
stored only in the private Provider state and held transiently by the worker.
They are not included in execution receipts or audit events. A signature alone
does not authorize execution: online admission is mandatory.

## State invariants

1. At most one ACTIVE or EXECUTING grant exists for each agent.
2. An execution's token is consumed before its handler starts.
3. Rotation cannot commit while that agent has an unfinished execution.
4. The next generation invalidates all preceding generations.
5. The exact certificate identity, task, call arguments and execution scope are
   fixed at issuance.
6. Restart preserves generations, revocations and unfinished executions.
7. The Provider commits audit order for transitions without storing secret
   token values in its audit stream.
8. Explicit revocation advances authority without issuing a new capability;
   it cannot release an unfinished execution gate.
9. A committed operation key always names its original normalized call, grant
   and admission; retries cannot create a second dispatch, including after
   completion, token expiry or restart.
10. Gate release and the original completion receipt are atomic. Duplicate or
    stale completions cannot change another operation's state or cached result.

SQLite partial unique indexes enforce the first two concurrency constraints in
addition to application checks. `BEGIN IMMEDIATE`, foreign keys and FULL
synchronous WAL transactions provide the single-host persistence boundary.
Instances sharing a database must use identical enrollment, policy and signing
keys. Policy changes are applied by stopping the old Provider and restarting it,
rather than concurrently running incompatible configurations.
Running multiple Providers against independent database copies would violate
that boundary and is not a supported replication strategy.
