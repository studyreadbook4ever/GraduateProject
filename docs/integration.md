# Integrating an agent runtime

An agent runtime forwards one structured tool call at a time. It never copies
an identity claim out of a model response. The configured client certificate
identifies the runtime, and the task ID selects an already registered policy.

```python
from agent_backend import WorkerClient

worker = WorkerClient(
    ".runtime/demo/worker.json", binary="build/saga-worker",
    failure_log=".runtime/demo/worker-failures.jsonl",
)
receipt = worker.request_resource(
    task_id="demo",
    tool="read_file",
    resource="notes",
)
if not receipt["ok"]:
    raise RuntimeError(receipt["error"])
print(receipt["result"])

# Invalidate pending authority without issuing another capability.
# An active execution returns execution_busy; it is not reported as cancelled.
revocation = worker.revoke(timeout=10)
```

`execute_many(records)` runs a sequence through one coordinator. Each record
still receives a separate, single-use grant and sandbox. A denied call produces
an error receipt; it does not turn the next call into an authorized one.

The Provider normalizes these individual call dictionaries. Convert a vendor
SDK object to plain JSON data before calling the library (for example,
`model_dump(exclude_none=True)`). An adapter translates syntax; it does not call
the model API, install vendor SDKs, or supply a model API key.

| `format` | Individual call |
| --- | --- |
| `canonical` | `{"tool":"read_file","arguments":{"resource":"notes"}}` |
| `openai` or `openai_chat` | `{"id":"call_1","type":"function","function":{"name":"read_file","arguments":"{\"resource\":\"notes\"}"}}` |
| `openai_responses` | `{"id":"fc_1","call_id":"call_1","type":"function_call","name":"read_file","arguments":"{\"resource\":\"notes\"}","status":"completed"}` |
| `anthropic` | `{"type":"tool_use","id":"toolu_1","name":"read_file","input":{"resource":"notes"}}` |
| `gemini` | `{"functionCall":{"id":"call_1","name":"read_file","args":{"resource":"notes"}}}` |
| `mcp` | `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"resource":"notes"}}}` |

`normalize_call(format, call)` retains the original `{tool, arguments}` API.
It discards correlation fields before authorization. The separate
`normalize_tool_call()` helper preserves an upstream call identifier in a frozen
`ToolCall`; `format_tool_result()` maps a JSON result to one result item/block.
The SDK combines those helpers with execution:

```python
call = {
    "id": "fc_item_1",
    "call_id": "call_upstream_1",
    "type": "function_call",
    "name": "read_file",
    "arguments": '{"resource":"notes"}',
    "status": "completed",
}
reply = worker.execute_tool_call(
    task_id="demo", format="openai_responses", call=call,
    operation_id="read-notes-turn-17", timeout=10,
)
receipt = reply["receipt"]
result_item = reply["tool_result"]
# result_item["type"] == "function_call_output"
# result_item["call_id"] == "call_upstream_1", not "fc_item_1".
# Append result_item to your Responses input after preserving the model turn.
```

The SDK returns both the execution receipt and the model-facing result, so
execution state and retry information remain available to the application.
`execute()` continues to return a receipt. A timeout raises `WorkerError` and
does not manufacture a successful model result. Keep the same application-owned
`operation_id` when reconciling an uncertain execution; a vendor call identifier
only correlates the model conversation and does not authorize or deduplicate an
action.

The mappings follow the official single-call forms for [OpenAI Chat Completions
and Responses](https://developers.openai.com/api/docs/guides/function-calling),
[Anthropic client tool use](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls),
[Gemini GenerateContent FunctionCall/FunctionResponse](https://ai.google.dev/api/generate-content#functioncall),
and [MCP tools/call](https://modelcontextprotocol.io/specification/2025-11-25/server/tools).
OpenAI uses JSON text arguments; Anthropic, Gemini, and MCP use objects.
Gemini `args` and MCP `arguments` may be omitted for an empty object; explicit
`null` is rejected. MCP string and integer IDs, including zero, retain their
types. Result mapping requires call IDs for OpenAI, Anthropic and MCP; a missing
Gemini ID stays absent. OpenAI Responses results use `call_id`, not the output
item's `id`. The result formatter returns one Chat Completions `tool` message,
Responses output item, Anthropic `tool_result` block, Gemini `functionResponse`
part, or MCP JSON-RPC result as appropriate. It does not assemble enclosing
Anthropic user messages or Gemini conversation turns. MCP structured results
also include serialized JSON in a text block, as the specification recommends.

Full response envelopes, batches, streaming fragments, unfinished Responses
calls, vendor-hosted tools, and non-JSON/multimodal results are rejected or
outside this interface. Split individual completed calls explicitly. Each call
receives its own authorization. Preserve the original model turn, thinking
blocks and Gemini `thoughtSignature` in your conversation state; the adapter
accepts an optional Gemini signature but does not rewrite or replay it.
Unknown fields are rejected to prevent ambiguous interpretation. MCP `_meta`
and other correlation metadata never override certificate authentication,
task policy or resource policy. Arguments accept finite UTF-8 JSON up to 1 MiB
after serialization; output formatting has a separate 4 MiB plus 64 KiB limit
to accommodate executor results. NUL in permitted file content is preserved.

Python path entry points accept nonempty UTF-8 strings or string-returning
`PathLike` values. JSON resource policy requires string paths. Null, bytes,
empty paths, embedded NUL (including decoded `\u0000`) and unpaired surrogates
are rejected before filesystem or native API calls. This validation applies to
paths and does not strip characters from file contents.

## C++ embedding

```cpp
#include <saga/worker.hpp>

saga::Worker worker(saga::WorkerConfig::from_json(config_document));
auto receipt = worker.perform(call_record_json);
```

Link the installed CMake target and use the exported header. The coordinator is
used from a single-threaded process because executor startup uses `fork()` and
then immediately `execveat()`s a sealed helper image embedded in the library.
The host must keep the default `SIGCHLD` disposition so children can
be reaped. Use the CLI bridge from a threaded agent host. The installed header
does not expose the private JSON library.

`Worker::revoke()` returns a JSON revocation receipt. The CLI equivalent is
`saga-worker --config worker.json --revoke`. A new logical operation requests
its capability directly from the Provider. Reusing an operation ID reconciles
its existing grant or result; the SDK does not cache resource rights.

## Failures and retries

Receipts carry a random attempt `call_id`, an `operation_id`, `phase`, stable `error_code` on failure,
`executor_started`, `admission_uncertain` and `completion_recorded`. A known
admission also includes its `execution_id`. All requests for one call carry the
same `X-Saga-Call-ID`; Provider replies add `X-Saga-Request-ID` for that request.
These identifiers correlate records and never authorize an operation.

Choose and persist an application-owned `operation_id` **before** submission
when the operation must survive a caller restart. It must start with an ASCII
letter or digit and contain at most 128 ASCII letters, digits, `_`, `.`, `:` or
`-`. `execute()`, `request_resource()` and `execute_tool_call()` accept the ID;
`execute_many()` accepts it per record. The SDK generates a fresh UUID when it
is omitted and exposes the selected IDs on `WorkerError.operation_ids`. A new
SDK invocation with no explicit ID represents a new logical operation.

The Provider durably binds the ID to the authenticated agent, original
certificate, registered task and normalized tool/arguments. Changing the task
or arguments with the same ID returns `operation_conflict`. Equivalent supported
API formats map to the same binding. The ID is a deduplication key, never an
authorization identity. Different agents have separate ID namespaces.

The worker automatically retries read-only state queries, definite
`epoch_conflict` responses, and identical finish requests after transport
failure, at most three attempts. It does not automatically replay a lost
rotate/admit response during that attempt. A later caller can inspect durable
state without executing:

```python
status = worker.operation_status("read-notes-turn-17", timeout=10)
if status["ok"] and status["status"] in {"succeeded", "failed"}:
    original_receipt = status["receipt"]
# Alternatively, submit the same task/call and operation_id to reconcile it.
# A completed operation returns its recorded result and never runs it again.
```

| Durable status | Repeated submission with the same ID and call |
| --- | --- |
| `ready` | Reuses the original pending grant; online admission still checks expiry, current policy and single use. |
| `running` | Returns `operation_in_progress`; creates no second executor. A late finish updates this operation. |
| `succeeded` or `failed` | Returns the immutable recorded receipt, including the original result or failure, without rereading or rewriting the resource. A legacy completion with no stored receipt returns `operation_result_unavailable`. |
| `revoked` or `expired` | Returns a terminal error; never issues replacement authority under that ID. |

Recovered completed receipts have a new attempt `call_id`, `original_call_id`, `cached`,
`replayed`, and `executor_started: false`. `original_executor_started` describes
the original attempt. The result and `execution_id` remain the original ones.
A completed failure remains a failure after the resource is repaired. Use a
fresh operation ID only for an intentionally new action.

`retry_safe` is a conservative statement about an individual attempt. It is
false after observing a grant, during an active execution, or after an operation
conflict. Two callers can both observe the same pending grant before either
admits it: only one admission succeeds, and the rejected attempt also reports
`retry_safe: false`. An `inactive_token` rejection in that race does not mean
the logical action failed. Inspect the operation or resubmit its same ID and
call to obtain its eventual result. Even a locally safe attempt is never a
reason to replace an uncertain logical operation with a fresh ID.

`admission_uncertain: true` means an admission gate may exist even though no
local handler started. `completion_recorded: false` after execution means the
acknowledgement is unknown; it does not prove the Provider failed to commit.
An unknown-operation observation can also race an original request that has
not committed yet. Reconcile or resubmit using the **same** ID and call; never
turn an uncertain attempt into a new ID merely to make it run.

The guarantee is at most one admission for each durable operation ID. If a
coordinator dies after admission and before recording completion, the Provider
keeps the operation `running` and the agent execution gate closed. Time,
token expiry, a retry and revocation do not release it. There is no force-release
API: an operator must establish the executor's termination and reconcile any
external effects before any repair. A server contacted by `http_get` may still
finish work after the local client stops. The library cannot roll back that
work, recreate a result lost before completion, or promise exactly-once effects
for another system. These uncertainties remain visible instead of triggering
a second dispatch.

The CLI writes a sanitized JSON failure event to stderr. Configure `failure_log`
to retain SDK failures, including Provider outages and SDK timeouts, in an
owner-only JSONL file with locked, synchronized appends. Its parent must already
exist. Unsafe permissions, nonregular files and symlinks are rejected before
launch. No token, call body, output content or raw exception is written there.
The host remains responsible for log retention and stderr collection.

An SDK timeout kills the invocation's process group and raises `WorkerError`
with `code="worker_timeout"`, `outcome_uncertain=True`, and any complete receipts
already observed in `receipts` plus submitted `operation_ids`. It does not
release the Provider gate or retry the actions. A log storage failure is an error; no implementation can promise
durable records on unavailable storage.

The SDK collects bytes and decodes individual stdout JSONL records. Invalid
UTF-8 after a complete receipt preserves that prefix; stderr is never decoded
as receipt data. On KeyboardInterrupt/SystemExit, the original exception carries
`receipts`, `code`, `operation_ids`, `outcome_uncertain` and `audit_failed` attributes.
Audit write/open/fsync failures also retain all observed receipts in WorkerError.
A short append is rolled back under the file lock where possible, without
claiming atomicity across a process crash. Audit lock acquisition has a shared
0.5-second budget for the batch. Thus `timeout` controls subprocess handling;
cleanup and audit can add bounded waits, and storage I/O is not a hard real-time
deadline. A blocked audit lock cannot indefinitely withhold known results.

## Adding another format or function

Provider-side `AdapterRegistry.register(name, callable)` adds a structural
normalizer. The normalizer returns the same canonical `{tool, arguments}` shape.
It must not resolve authentication or invent policy grants. Registrations happen
in trusted application setup; there is no remote adapter-registration endpoint.

Adding a function also requires a trusted Provider capability builder and a
corresponding C++ handler with an exact sandbox derivation. A new tool must have
an explicit policy entry and negative tests for unauthorized resources. The
initial distribution includes four handlers; arbitrary commands and model-
generated SQL are outside its execution interface.

File output is UTF-8 text, and SQLite resources are immutable snapshots. See the
[sandbox profile](sandbox.md) for output bounds and handler constraints.

Task policy is configured once by an administrator. The runtime then requests
tokens automatically as structured calls arrive. The library does not invent
new policy or ask the user to interpret authorization prompts during execution.
