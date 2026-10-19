# Design decisions

## D-001 — Who owns the transition

Status: AUTO-DECIDED

A: Let workers invalidate tokens and cancel running operations.
B: Let the Provider serialize admission and rotation at call boundaries.

Chosen: B. The user requested prevention of mid-operation revocation rather than
cancellation and rollback. The Provider's durable gate excludes that situation.
Evidence: rotation/admission concurrency tests and restart tests.
Rollback: replace the protocol and all callers together.
Revisit when: a requirement to interrupt an already executing action is added.

## D-002 — Reusing a sandbox

Status: AUTO-DECIDED

A: Keep one executor and add Landlock rules for later resources.
B: Start a new executor for every admitted capability.

Chosen: B. Landlock cannot relax a restricted domain, and accumulating rights
would contradict the project's purpose.
Evidence: kernel denial probes and repeated workflow integration tests.
Rollback: retain the coordinator API and replace execution isolation.
Revisit when: another isolation mechanism supports safe replacement of domains.

## D-003 — Offline validation

Status: AUTO-DECIDED

A: Trust a valid signature until the token expires.
B: Verify the signature and require online, single-use admission.

Chosen: B. An old signature remains mathematically valid after revocation.
Online generation/status checks supply immediate invalidation.
Evidence: replay and post-rotation admission tests.
Rollback: no safe offline replacement with the same revocation semantics.
Revisit when: a formally defined distributed admission store is introduced.

## D-004 — Semantic policy

Status: AUTO-DECIDED

A: Resolve names and authorization from natural-language instructions.
B: Keep identity in mTLS and normalize only structured calls against a registry.

Chosen: B. Model text is untrusted and must not change authentication.
Evidence: forged identity, names in content and unknown resource tests.
Rollback: adapters may change, while authentication must remain independent.
Revisit when: a user-facing planner is added; it must still use typed policy IDs.

## D-005 — Durable store

Status: AUTO-DECIDED

A: Require a separately installed server database for every deployment.
B: Use dedicated SQLite state and an external database fixture for experiments.

Chosen: B. SQLite transactions supply a concrete single-host serialization
boundary and simplify reproducible deployment. A networked resource is tested
independently. This choice does not claim multi-host consensus.
Evidence: concurrent independent Provider connections and persistence tests.
Rollback: introduce a store interface with equivalent transaction semantics.
Revisit when: multiple Provider hosts or high write throughput are required.

## D-006 — Crash recovery

Status: AUTO-DECIDED

A: Release executing rights when a lease expires.
B: Retain the gate until execution completion is recorded.

Chosen: B. Lease expiry cannot prove that an old action stopped; automatic
release could admit overlapping work. Availability is traded for prevention.
Evidence: restarted Provider retains an EXECUTING gate.
Rollback: a recovery protocol must prove executor fencing before release.
Revisit when: operational recovery is part of the project scope.

## D-007 — Fresh memory before handler dispatch

Chosen: fork only a trusted startup stub, then exec a sealed executor embedded
in the library. Pass only the current capability through a sealed nonexecutable
memfd. No handler can run before image replacement and sandbox installation.
The previous fork-only cleanup retained parent heap/environment bytes; it was
reproduced against a real sandboxed HTTP handler. Regressions check unmapped
parent secret memory, absent parent environment and closed inherited FDs.
No fork-only fallback is allowed if executable memfds are unavailable.
This does not erase physical RAM or data already returned to the model runtime.

## D-008 — Failure evidence survives rollback

Chosen: keep state-transition audit transactional and separately persist failed
requests after rollback. Include fixed error code/phase/status and random
call/request identities, never token/body/content/SQL/exception text. Expose only
the authenticated agent's bounded records. The CLI emits sanitized stderr and
SDK failure_log optionally persists local failures, including Provider outages.
Audit storage failure is explicit; retention belongs to the operator.

## D-009 — Explicit revocation and safe retry boundaries

Chosen: revoke pending authority without replacing it, with the same generation
CAS and unfinished-execution gate as rotation. Cryptographic signature validity
does not authorize execution without online admission. Do not claim cancellation
when the gate is executing. Retry safe state reads, definite CAS conflicts and
identical finish receipts only. Ambiguous admission is not automatically replayed.

## D-010 — Durable logical operation identity

Chosen: bind a caller-persisted operation ID to one normalized call, task,
original certificate and original grant. Keep that key across expiration,
revocation, completion and restarts. Store a bounded receipt in the finish
transaction. Same-ID requests recover status/results, never a new grant or a
second successful admission. SDK-generated keys survive timeout exceptions.
An effect without a committed receipt stays unknown; no lease or automatic
retry converts uncertainty into another side effect.
Evidence: concurrent same-ID callers, lost rotate/admit/finish responses,
late completion, Provider crash before/after commit and actual SDK timeout tests.

## D-011 — Measure cycling and preserve the agent-wide gate

Chosen: retain per-call fork/exec isolation and the existing single execution
per agent. Distinct enrolled agents can run in parallel. A pool alone cannot
change the gate or relax an already restricted executor. Introducing lanes
would require explicit authorization/revocation semantics and is not an
implicit throughput switch. See [measured tradeoffs](concurrency-tradeoffs.ko.md)
for hypotheses, controls, source hashes, raw samples and machine-specific limits.
