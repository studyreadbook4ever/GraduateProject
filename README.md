# SAGA Capability

An execution authorization library for agent runtimes: **one authenticated agent,
one current capability, one exact function and resource per call**.

The Python Provider translates tool calls from different API formats into a
registered policy. The C++ worker automatically obtains a new token, verifies
it, admits it online and executes the approved handler in a fresh Landlock ABI 9
sandbox. A successful replacement invalidates the previous token before the new
one becomes available. An executing action blocks replacement, so the workflow
does not need to cancel or undo earlier work.

Each handler starts through `execveat` of a sealed executor embedded in the
library, without inherited environment variables and with only its current request. Fork-inherited
coordinator memory is replaced before any handler runs. The host must permit
executable memfds; a policy denial refuses execution.

Inspired by [SAGA (NDSS 2026)](https://www.ndss-symposium.org/ndss-paper/saga-a-security-architecture-for-governing-ai-agentic-systems/).
This is an independent function/resource execution protocol; see
[the comparison](docs/saga-comparison.md) for the differences from upstream.

## Build and run

Requirements: Linux with Landlock **ABI 9 or newer**, Python 3.11+, a C++20
compiler, CMake 3.20+, OpenSSL, libcurl and SQLite development packages. Runtime
ABI detection is authoritative; a container uses its host's kernel.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[test]'
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j2
build/saga-worker --probe
.venv/bin/python -m pytest -q
.venv/bin/python -m experiments.run --worker build/saga-worker
```

The experiment downloads a checksum-pinned public Chinook SQLite database and
creates its own certificates, state database and loopback services. It exercises
the original five API formats, authorized file read/write, a registered database query,
network access and kernel denials. Services and temporary credentials are
removed in `finally` cleanup. The receipt is written to
`.artifacts/e2e-receipt.json`. No personal credentials or model API key is needed.

For a reusable local development deployment:

```sh
.venv/bin/saga-cap provision --directory .runtime/demo
.venv/bin/saga-cap serve \
  --config .runtime/demo/provider.json \
  --state .runtime/demo/state.sqlite \
  --signing-key .runtime/demo/provider-signing-key.pem \
  --certificate .runtime/demo/server.pem \
  --key .runtime/demo/server-key.pem \
  --ca .runtime/demo/ca.pem
```

From another terminal, run the generated file-read call:

```sh
build/saga-worker --config .runtime/demo/worker.json --calls .runtime/demo/calls.jsonl
```

The worker also accepts JSON lines on standard input. Each line is independent:

```json
{"task_id":"demo","format":"canonical","call":{"tool":"read_file","arguments":{"resource":"notes"}}}
```

Provisioning requires a new or empty directory. It creates fresh demonstration
keys valid for seven days and never overwrites an existing deployment. Stop the
Provider with Ctrl-C or SIGTERM when finished.

## Library interfaces

Python agent integrations can use `agent_backend.WorkerClient` to invoke the
worker without a shell. C++ applications can include `<saga/worker.hpp>`, create
`saga::Worker` and call `perform()` from a single-threaded coordinator process.
The model runtime can be threaded when using the CLI bridge.

```sh
cmake --install build --prefix "$PWD/.runtime/install"
```

Installed CMake consumers use `find_package(Saga CONFIG REQUIRED)` and link
`Saga::worker`. See [integration examples](docs/integration.md).

```python
from agent_backend import WorkerClient

worker = WorkerClient(".runtime/demo/worker.json", binary="build/saga-worker",
                      failure_log=".runtime/demo/worker-failures.jsonl")
receipt = worker.request_resource(task_id="demo", tool="read_file", resource="notes",
                                  operation_id="demo-read-001")
status = worker.operation_status("demo-read-001")
revocation = worker.revoke()  # Invalidates pending authority; busy if executing.
```

Persist an opaque `operation_id` before submitting an action, and reuse it after
a timeout. The Provider binds it to the normalized call, task and original
certificate. A repeated ready operation receives its original grant; running
operations report their state, and completed operations return the recorded
receipt. None receives a second admission. The SDK generates IDs when omitted
and preserves them in `WorkerError.operation_ids`, even without a receipt.
See [a runnable Python example](examples/client.py).

Failures carry a random call ID, phase and stable error code. Provider request
failures are durable and exposed to their agent at `/v1/failures`; committed
transitions at `/v1/audit` include completion outcome and safe failure reason.
The CLI emits redacted JSON diagnostics on stderr; `failure_log` retains SDK
failures in an owner-only synchronized JSONL file, including Provider outages.
Tokens, call bodies and output contents are excluded from these failure logs.

| Handler | Authorization boundary |
| --- | --- |
| `read_file` | One existing registered file; read access only |
| `write_file` | One existing registered file; exact signed content |
| `query_db` | Immutable SQLite snapshot, registered query and bound parameters |
| `http_get` | Registered numeric loopback HTTP endpoint and TCP port |

Provider adapters accept individual canonical, OpenAI Chat Completions
(`openai`/`openai_chat`), OpenAI Responses (`openai_responses`), Anthropic
tool-use, Gemini function-call and MCP tools/call formats. `execute_tool_call()`
also maps the result back with its original upstream call ID. These are single
completed call adapters; the host owns conversations and streaming. Additional formats
can be registered in trusted Provider setup. New functions require a matching
capability builder, C++ handler and sandbox rule derivation.

## Guarantees and boundaries

Authentication uses the actual mTLS certificate fingerprint. Natural-language
names, HTTP identity hints and model arguments cannot change the authenticated
agent. Policy contains explicit task/tool/resource IDs; the runtime does not
interpret prompts to grant new rights.

Rotation, admission and completion are durable Provider transactions. Tokens
are Ed25519-signed, certificate-bound, short-lived and single-use. Old tokens
cannot start a new execution after rotation, even while their signatures remain
valid. Concurrent admission consumes a token exactly once.

Landlock enforces filesystem rights, TCP ports, UNIX socket resolution and
scopes. Seccomp covers additional prohibited syscall families. The worker
refuses an unavailable sandbox. No shell execution or model-generated SQL is
provided.

The Provider and registered handlers are trusted. State is single-host SQLite;
independent replicas are not supported. An interrupted execution retains its
gate across restart until completion is established. This deliberately favors
preventing overlapping rights over automatic recovery. Completed side effects
are not rolled back. If an effect occurs before its receipt commits, its outcome
can remain unknown; the library does not automatically rerun it or promise
exactly-once external effects. Stored receipts contain tool output and require
the same protection as Provider state. These boundaries are explained in
[architecture](docs/architecture.md) and [SECURITY.md](SECURITY.md).

The [concurrency experiment](docs/concurrency-tradeoffs.ko.md) separates the
agent-wide admission gate from per-call process isolation. It measures fork,
exec, sandbox and full mTLS calls, and demonstrates parallel execution only for
separately enrolled principals under the current policy. Cycling does not
remove that gate. Run `python -m experiments.tradeoffs --help` to reproduce.

## Repository

```text
saga/              Provider, policy, adapters, signing and provisioning
worker/            C++ library, coordinator and Linux sandbox
agent_backend/     Python agent-runtime bridge
user_configs/      Policy and credential configuration guidance
templates/         Provider and worker configuration examples
experiments/       External database and real-kernel experiment
tests/             Independent protocol and kernel tests
docs/              Protocol, decisions and verified project report
```

Read [protocol.md](docs/protocol.md), [sandbox.md](docs/sandbox.md),
[decisions.md](docs/decisions.md) and [verification.md](docs/verification.md).
The implementation uses the Apache-2.0 license. The bundled JSON parser retains
its MIT license.
