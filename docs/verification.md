# Verified implementation: 2026-10-19 KST

## Current operation, format and path verification

The integrated candidate passed **545 Python tests, zero skips**, including the
external Chinook/mTLS experiment, in both GCC Release and Clang UBSan builds.
Both builds passed **2/2 CTest checks**. The commands are:

```sh
SAGA_EXTERNAL_E2E=1 .venv/bin/python -m pytest -q --junitxml=.artifacts/final-release.xml
SAGA_EXTERNAL_E2E=1 SAGA_WORKER_BINARY="$PWD/build-ubsan/saga-worker" \
  .venv/bin/python -m pytest -q --junitxml=.artifacts/final-ubsan.xml
ctest --test-dir build --output-on-failure
ctest --test-dir build-ubsan --output-on-failure
```

New evidence covers durable same-ID issuance/admission races, missing rotate/
admit/finish responses, a real timeout before a late original completion,
restart and six additional before/after-commit process crashes. A retry during
execution receives running status; a completed retry receives the original
output even after the resource changes. Conflicting task/call/certificate,
expiry and revocation cannot revive an ID. Duplicate old completion cannot
release a newer execution. A >3 MiB escaped receipt round-trips through finish,
status and replay. Concurrent ready-grant replays admit exactly once and the
loser no longer reports an unsafe fresh retry as safe.

The new adapter tests cover OpenAI Chat Completions and Responses, Anthropic,
Gemini and MCP single calls and correlated result items, JSON type/size/Unicode
boundaries, omitted versus null arguments, and metadata excluded from authority.
A stateful custom adapter is normalized once, so its operation binding cannot
describe a different call from its issued capability. Path tests reject null,
empty, bytes, NUL and surrogate paths before I/O in policy, SDK, TLS, keys,
provisioning and native config; valid Unicode filenames and NUL file contents
remain supported. Invalid provisioning ports leave the target directory alone.

Independent reviewers reproduced the ready-grant retry flag defect and the
operation-ID grammar mismatch before correction. Tests and reviews establish
these covered behaviors, not absence of all bugs. An effect without a committed
receipt can remain unknown; the retained gate favors safety over availability.
Stored results are sensitive state, not redacted audit events.

Independent packaging checks built wheel/sdist, installed the wheel into a fresh
non-system venv and imported it from outside the repository. All archived source
files matched the working tree; keys, databases, build outputs and runtime
fixtures were absent. Installed static/shared CMake consumers ran actual tool
calls, status and cached-result paths. The default shared CLI initially failed
to locate `libsaga_worker.so`; the shared-only relative install RUNPATH fixes
that defect. A new `tests/check_shared_install.py` reproduces installation,
prefix/build-tree relocation, empty-environment CLI loading, fresh executor
startup and the installed CMake consumer. Default `lib` and custom `lib64`
installed executors loaded successfully with no empty/cwd RUNPATH entries.
CI now builds both static and shared variants and probes the installed CLI.

For deductions, process controls, raw latency samples, source/binary hashes and
cross-run variance, see [the concurrency study](concurrency-tradeoffs.ko.md).
The sections below retain earlier verification snapshots rather than current
test totals.

## Stricter follow-up verification

The final follow-up working tree passed **151 Python tests, zero skips** and
**2 CTest checks** in both the ordinary build and a separate Clang UBSan build.
This included the external Chinook/mTLS experiment. An ASan/UBSan libFuzzer
target compiled from the final native HTTP parser completed **818,234 runs**
without a sanitizer finding. This is a parser-only memory check, not an ASan
proof of the whole sandbox or a guarantee that no bugs remain.

The stronger validation found and fixed defects that the earlier 92 checks
missed: TLS accept-loop blocking, trickled headers/body retaining worker slots,
database-lock contention in rejection logging, broken emergency stderr,
incomplete HTTP bodies reported as success, lost SDK receipts on encoding or
audit failures, indefinite pipe/log-lock waits, and inherited RLIMIT_FSIZE
terminating the coordinator. New tests use actual sockets, subprocesses, OS
signals, exclusive SQLite locks, short writes and closed pipes.

The final data-boundary check also reproduced SQLite infinity becoming JSON
null with a successful receipt. Nonfinite numeric results are now rejected
explicitly; legitimate SQL NULL and finite numbers retain their distinct values.
Positive/negative infinity and the ordinary NULL/finite control are included in
the final 151-test count.

Eight tests kill a real Provider process before and after commit for rotate,
revoke, admit and finish. They reopen the database, check integrity/foreign keys,
assert rollback or committed authority, and verify unfinished gates remain
closed. A fresh reviewer independently reproduced and confirmed closure of
the remaining SDK lock, SQLite initialization-lock and stderr failure paths.

SDK audit-lock waits share a 0.5-second budget across the batch. The subprocess
timeout is not an end-to-end deadline for audit I/O. Log storage unavailable
errors retain observed receipts; optional JSONL logging does not promise
transaction atomicity across a process crash. HTTP without Content-Length is
close-delimited and cannot prove what more its origin intended to send.

## Earlier 2026-10-19 verification

The earlier candidate passed **92 Python tests, zero skips**, including the
external Chinook/mTLS experiment, and **2 CTest checks**. A separate Clang UBSan
build passed the same **92 tests and 2 CTest checks**, without runtime sanitizer
diagnostics. The generated embedded debug image produces a Clang string-literal
length warning; GCC/Clang builds and runtime checks both succeeded.

| Requested change | Current authoritative evidence |
| --- | --- |
| On-demand exact resource requests | `WorkerClient.request_resource`; real TLS worker tests for read/write/query, denied resource, bounded generation-conflict/read retries, no unsafe POST replay, UTF-8/NUL round-trip |
| Effective delegation revocation | Explicit authenticated revoke CAS; still-valid signature denied at online admission; restart, concurrent revoke/admit/rotate, executing gate tests |
| No inherited executor memory | Fresh embedded sealed ELF via execveat; parent secret mmap becomes ENOMEM in repeated children; inherited environment/high FDs and loader variable absent; neutral stdio remains; prohibited memfd fails closed |
| Persistent redacted failure records | Direct and TLS tests for denials, rollback/internal errors, parsing/header timeout/TLS/capacity, owner-scoped pagination, safe completion reason, audit-storage failure, local outages/timeouts and interrupted batch prefix preservation |

The independent initial reproduction found a parent sentinel in a real
sandboxed HTTP executor's memory before the patch. Current production startup
cannot dispatch a handler until exec replaces that image. A signature-only
revocation bypass was not present in the original implementation; the change
adds explicit revoke and stronger regression/operational evidence.

Installed static/shared CMake consumers ran outside the source tree with an
unavailable PATH. `tests/check_private_install.py` additionally passed with
`--shared 0` and `--shared 1`, using a unique private SQLite SONAME, an installed
dependency directory and removal of the original build dependency. The helper
contains no build RPATH and clears its explicit loader variable before request
parsing. Wheel/sdist builds succeeded; installed-wheel imports use the new APIs.

The static SQLite branch was also exercised using an official SQLite 3.50.4
amalgamation built as a PIC archive in temporary storage. Its sqlite3.c SHA3-256
matched the official release value. CTest passed 2/2 and focused kernel/mTLS
resource/query checks passed 2/2. Symbol/dependency inspection confirmed SQLite
was in the main executable, not a DSO; gcov recorded six executions of the
main-image branch and none of the dynamic-library path. Runtime source did not
change for this check.

Reproduce the full test suite after building:

```sh
SAGA_EXTERNAL_E2E=1 .venv/bin/python -m pytest -q
ctest --test-dir build --output-on-failure
```

The private-library check is an explicit installation test and builds its own
disposable project (choose a fresh working directory):

```sh
.venv/bin/python tests/check_private_install.py --source . \
  --sqlite /usr/lib/libsqlite3.so.0 --work /tmp/saga-install-static --shared 0
.venv/bin/python tests/check_private_install.py --source . \
  --sqlite /usr/lib/libsqlite3.so.0 --work /tmp/saga-install-shared --shared 1
```

An initial verification using a very long managed pytest base directory failed
before sandbox execution because its UNIX socket pathname exceeded Linux's
limit. Repeating with pytest's normal short temporary paths passed all checks.
This was a fixture-path constraint, not a kernel-enforcement failure.

Revocation fences new execution, not signatures, completed side effects or
already disclosed model knowledge. Exec removes inherited virtual mappings,
not physical RAM remnants. Unknown admission/completion acknowledgements never
justify automatic side-effect replay or timeout-based gate release. Local SDK
failure persistence requires configuring `failure_log`; stderr collection/log
retention remains an operator responsibility. Arbitrary hostile native programs,
independent multi-host Provider replicas and automatic crash recovery remain
outside the interface.

## Historical verification: 2026-10-13

The final implementation passed **48 Python tests with zero skips**, **2 CTest
checks**, a separate external-database experiment, an installed CMake consumer
and an isolated Python-wheel import. The full Python suite and CTest also passed
with a Clang UndefinedBehaviorSanitizer build. No sanitizer diagnostic occurred.

Environment observed: Linux `7.1.5-arch1-2`, x86_64, Landlock ABI **9**, Python
3.14, GCC 16.1.1, Clang 22.1.8, OpenSSL 3.6.3, libcurl 8.21.0 and SQLite 3.53.4.
ARM execution and hosted GitHub CI were not run locally.

## Requirement to evidence

| Requirement | Direct evidence |
| --- | --- |
| One function/resource per token | Exact signed capability; handler-derived sandbox equality; schema and policy tests |
| Prior token invalid before next grant publication | Durable revoked→issued audit ordering, generation CAS, old-token admission rejection |
| No worker-led cancellation or rollback | Provider executing gate rejects rotation; child is reaped before finish; the initial release had no explicit revoke endpoint |
| Different task cannot reuse prior rights | Global per-agent epoch across two task IDs; old generation denied |
| Rotation cannot race admission into overlapping rights | Concurrent CAS/admission tests, separate Provider instances, repeated rotate/admit race |
| Restart preserves revocation and unfinished work | Persistent SQLite tests; executing gate survives token expiry and restart |
| Model names cannot change authentication | Real mTLS, unregistered/absent certificate denial, forged identity headers and names in content |
| Five Provider-owned envelopes | Canonical/OpenAI/Anthropic/Gemini/MCP unit tests and real C++ execution sequence |
| Exact certificate binding | Other-agent token denial, same-ID re-enrollment denial and original-certificate finish requirement |
| Changed policy cannot admit old pending scope | Restart tests for removed tasks/permissions, changed path/SQL and newly unsafe snapshots |
| Actual ABI 9 enforcement | Allowed/denied file access, listening TCP ports, TCP bind, pathname/abstract UNIX, signals and unsafe syscall probes |
| Reusable library | Installed `Saga::worker` consumer compiles, links and reports ABI 9; wheel imports from isolated site-packages |
| External database and network | Checksum-pinned Chinook SELECT returns `AC/DC`; registered loopback HTTP returns the expected response |
| Exact data handling | 128 KiB signed-content test, escaped-size rejection and real NUL write/read round trip |
| Resource cleanup | Experiment receipt verifies all three service processes reaped and temporary credential/data directory removed |

The standalone experiment submits nine calls: eight authorized operations and
one denied operation. The denied receipt explicitly records
`executor_started: false`. Its five-format authorized batch took 0.095681 seconds
in the recorded loopback run; the complete experiment took 0.405505 seconds.
These are individual observations, not a throughput benchmark or a comparison
with upstream SAGA.

## External data provenance

* Project: [Chinook Database](https://github.com/lerocha/chinook-database).
* Release: v1.4.5; pinned commit `4a944a942426e1f3263fe539155fb7ef92b04b4a`.
* File: `ChinookDatabase/DataSources/Chinook_Sqlite.sqlite`, 1,067,008 bytes.
* SHA-256: `bdf635be69850bd3be09c9a2dbeef7ddfb80036bd3ef3381383cd03b61e4a61a`.
* The fixture is a disposable snapshot copied into a private experiment
  directory, rather than a personal or shared database.

## Reproduction

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j2
ctest --test-dir build --output-on-failure
SAGA_EXTERNAL_E2E=1 .venv/bin/python -m pytest -q \
  --junitxml=.artifacts/pytest-verification.xml
.venv/bin/python -m experiments.run --worker build/saga-worker
```

For the sanitizer run:

```sh
cmake -S . -B .artifacts/build-ubsan -DCMAKE_CXX_COMPILER=clang++ \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS='-fsanitize=undefined -fno-sanitize-recover=all' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=undefined'
cmake --build .artifacts/build-ubsan -j2
SAGA_EXTERNAL_E2E=1 \
  SAGA_WORKER_BINARY="$PWD/.artifacts/build-ubsan/saga-worker" \
  .venv/bin/python -m pytest -q --junitxml=.artifacts/pytest-ubsan.xml
ctest --test-dir .artifacts/build-ubsan --output-on-failure
```

Local receipts are `.artifacts/pytest-verification.xml`,
`.artifacts/pytest-ubsan.xml` and `.artifacts/e2e-receipt.json`. They are excluded
from source control. `.artifacts/e2e-first-attempt.json` records the initial
SQLite/closed-stdio failure and successful service cleanup; the corrected
experiment is the completion evidence.

## Scope of the result

The implementation is a usable local library and execution protocol with the
reported evidence. It does not inherit upstream SAGA's formal proofs. Live model
SDK calls, server-database handlers, clean-exec isolation for hostile binaries,
multi-host Provider consensus and automatic crashed-executor recovery are not
features of this release. Normal operation is autonomous inside registered
policy; these boundaries are recorded in architecture and integration docs.
