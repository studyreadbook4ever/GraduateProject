"""Durable operation identities fence retries across response loss and death."""

import copy
import multiprocessing
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from contextlib import contextmanager
from threading import Barrier, Event

import pytest

from saga.provider import Provider, ProviderError
from saga.provider.core import MAX_RECEIPT_BYTES
from saga.adapters import AdapterRegistry

from conftest import ALICE, BOB, rotate_body


def operation_body(operation_id="operation-1", epoch=0, **kwargs):
    return {**rotate_body(epoch, **kwargs), "operation_id": operation_id}


def code(expected, action):
    with pytest.raises(ProviderError) as error:
        action()
    assert error.value.code == expected


def reopen(env, config=None):
    return Provider(config or env["config"], env["state"], env["key"], clock=lambda: env["now"][0])


def test_replay_preserves_one_grant_before_cas_or_policy_checks(provider_env):
    env = provider_env
    provider = env["provider"]
    body = operation_body()
    first = provider.rotate(ALICE, body)
    assert first["status"] == "ready" and first["replay"] is False
    replay = provider.rotate(ALICE, {**body, "expected_epoch": 54})
    assert replay == {**first, "replay": True}
    changed_policy = copy.deepcopy(env["config"])
    changed_policy["agents"]["alice"]["tasks"] = []
    # Recovery does not require executing the original policy a second time.
    assert reopen(env, changed_policy).rotate(ALICE, body) == replay
    assert provider.state(ALICE)["epoch"] == 1
    assert [event["event"] for event in provider.audit_events(ALICE)] == ["issued"]


@pytest.mark.parametrize("format_name,call", [
    ("openai", {"type": "function", "id": "transport-1", "function": {"name": "read_file", "arguments": '{"resource":"notes"}'}}),
    ("openai_chat", {"type": "function", "id": "transport-1", "function": {"name": "read_file", "arguments": '{"resource":"notes"}'}}),
    ("openai_responses", {"type": "function_call", "call_id": "transport-1", "name": "read_file", "arguments": '{"resource":"notes"}', "status": "completed"}),
    ("anthropic", {"type": "tool_use", "id": "transport-2", "name": "read_file", "input": {"resource": "notes"}}),
    ("gemini", {"functionCall": {"name": "read_file", "args": {"resource": "notes"}, "id": "transport-3"}}),
    ("mcp", {"jsonrpc": "2.0", "id": 73, "method": "tools/call", "params": {"name": "read_file", "arguments": {"resource": "notes"}, "_meta": {"trace": "ignored"}}}),
])
def test_semantic_aliases_recover_same_operation(provider_env, format_name, call):
    provider = provider_env["provider"]
    first = provider.rotate(ALICE, operation_body())
    second = provider.rotate(ALICE, {**operation_body(), "format": format_name, "call": call})
    assert second["token"] == first["token"]
    assert second["epoch"] == 1 and second["replay"] is True


def test_operation_binding_rejects_another_call_task_or_replacement_certificate(provider_env):
    env = provider_env
    provider = env["provider"]
    provider.rotate(ALICE, operation_body())
    code("operation_conflict", lambda: provider.rotate(ALICE, operation_body(resource="output")))
    code("operation_conflict", lambda: provider.rotate(ALICE, {**operation_body(), "task_id": "another-task"}))
    changed = copy.deepcopy(env["config"])
    changed["agents"]["alice"]["certificate_sha256"] = "c" * 64
    replacement = reopen(env, changed)
    code("operation_binding", lambda: replacement.operation("c" * 64, {"operation_id": "operation-1"}))
    code("operation_binding", lambda: replacement.rotate("c" * 64, operation_body()))
    code("unknown_operation", lambda: provider.operation(BOB, {"operation_id": "operation-1"}))


def test_custom_adapter_is_normalized_once_for_binding_and_capability(provider_env):
    env = provider_env
    registry = AdapterRegistry()
    calls = []

    def stateful(_):
        calls.append(None)
        return {"tool": "read_file", "arguments": {"resource": "notes"}} if len(calls) == 1 else {"tool": "write_file", "arguments": {"resource": "output", "content": "unexpected second normalization"}}

    registry.register("stateful", stateful)
    provider = Provider(env["config"], env["state"], env["key"], clock=lambda: env["now"][0], adapters=registry)
    grant = provider.rotate(ALICE, {**operation_body(), "format": "stateful"})
    assert len(calls) == 1
    assert provider.rotate(ALICE, operation_body())["token"] == grant["token"]
    admitted = provider.admit(ALICE, {"token": grant["token"]})
    assert admitted["capability"]["tool"] == "read_file"
    assert admitted["capability"]["resource"] == "notes"


@pytest.mark.parametrize("invalid", [None, False, 1, [], {}, "", ".start", "x" * 129, "with space", "null\x00path", "한글", "\ud800"])
def test_operation_ids_are_strict_and_do_not_change_generation(provider_env, invalid):
    provider = provider_env["provider"]
    code("invalid_operation_id", lambda: provider.rotate(ALICE, operation_body(invalid)))
    code("invalid_operation_id", lambda: provider.operation(ALICE, {"operation_id": invalid}))
    assert provider.state(ALICE)["epoch"] == 0


@pytest.mark.parametrize("path", [None, False, 0, b"bytes.sqlite", "", "null\x00path", "\ud800"])
def test_state_database_path_rejects_null_and_invalid_text(provider_env, path):
    with pytest.raises(ValueError, match="state database path"):
        Provider(provider_env["config"], path, provider_env["key"])


def test_independent_authorities_racing_same_operation_have_one_dispatch_owner(provider_env):
    env = provider_env
    providers = [reopen(env) for _ in range(8)]
    barrier = Barrier(8)

    def issue(index):
        barrier.wait()
        return providers[index].rotate(ALICE, operation_body())

    with ThreadPoolExecutor(max_workers=8) as pool:
        issued = list(pool.map(issue, range(8)))
    assert sum(not grant["replay"] for grant in issued) == 1
    assert len({grant["token"] for grant in issued}) == 1
    barrier = Barrier(8)

    def admit(index):
        barrier.wait()
        try:
            return providers[index].admit(ALICE, {"token": issued[index]["token"]})
        except ProviderError as error:
            return error.code

    with ThreadPoolExecutor(max_workers=8) as pool:
        admitted = list(pool.map(admit, range(8)))
    assert sum(isinstance(value, dict) for value in admitted) == 1
    assert admitted.count("inactive_token") == 7
    with sqlite3.connect(env["state"]) as database:
        assert database.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
        assert database.execute("SELECT count(*) FROM executions").fetchone()[0] == 1


def test_admission_response_loss_and_timeout_never_create_a_second_execution(provider_env):
    env = provider_env
    provider = env["provider"]
    first = provider.rotate(ALICE, operation_body())
    admission = provider.admit(ALICE, {"token": first["token"]})
    # The caller times out without observing the committed admission response.
    env["now"][0] += 86400
    restarted = reopen(env)
    status = restarted.rotate(ALICE, operation_body(epoch=1))
    assert status["status"] == "running" and "token" not in status
    assert status["execution_id"] == admission["execution_id"]
    code("inactive_token", lambda: restarted.admit(ALICE, {"token": first["token"]}))
    code("execution_busy", lambda: restarted.rotate(ALICE, operation_body("operation-2", 1)))
    code("execution_busy", lambda: restarted.revoke(ALICE, {"expected_epoch": 1}))
    receipt = {"ok": True, "result": {"content": "late original result"}, "operation_id": "operation-1", "execution_id": admission["execution_id"]}
    restarted.finish(ALICE, {"execution_id": admission["execution_id"], "outcome": "succeeded", "receipt": receipt})
    recovered = reopen(env).rotate(ALICE, operation_body(epoch=1))
    assert recovered["status"] == "succeeded" and recovered["receipt"] == receipt
    assert "token" not in recovered
    assert len([event for event in restarted.audit_events(ALICE) if event["event"] == "admitted"]) == 1


def test_caller_timeout_races_late_handler_result_without_a_second_side_effect(provider_env):
    env = provider_env
    started, release = Event(), Event()
    marker = env["root"] / "effect.txt"

    def original_call():
        provider = reopen(env)
        grant = provider.rotate(ALICE, operation_body())
        execution = provider.admit(ALICE, {"token": grant["token"]})["execution_id"]
        started.set()
        assert release.wait(timeout=5)
        with marker.open("a") as stream:
            stream.write("effect\n")
        receipt = {"ok": True, "result": "late-result", "execution_id": execution, "operation_id": "operation-1"}
        provider.finish(ALICE, {"execution_id": execution, "outcome": "succeeded", "receipt": receipt})
        return receipt

    with ThreadPoolExecutor(max_workers=1) as pool:
        original = pool.submit(original_call)
        try:
            assert started.wait(timeout=5)
            with pytest.raises(FutureTimeout):
                original.result(timeout=0.01)
            retry = reopen(env).rotate(ALICE, operation_body(epoch=1))
            assert retry["status"] == "running" and "token" not in retry
            assert not marker.exists()
        finally:
            release.set()
        original_receipt = original.result(timeout=5)
    retry = reopen(env).rotate(ALICE, operation_body(epoch=1))
    assert retry["receipt"] == original_receipt and retry["status"] == "succeeded"
    assert marker.read_text() == "effect\n"


def test_failed_operation_publication_rolls_back_binding_and_old_grant(provider_env):
    env = provider_env
    provider = env["provider"]
    first = provider.rotate(ALICE, operation_body())
    with sqlite3.connect(env["state"]) as database:
        database.execute("CREATE TRIGGER no_operation BEFORE INSERT ON operations WHEN NEW.operation_id='operation-2' BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END")
    with pytest.raises(sqlite3.IntegrityError):
        provider.rotate(ALICE, operation_body("operation-2", 1))
    assert provider.state(ALICE)["epoch"] == 1
    code("unknown_operation", lambda: provider.operation(ALICE, {"operation_id": "operation-2"}))
    assert provider.admit(ALICE, {"token": first["token"]})["capability"]["resource"] == "notes"


def test_late_duplicate_finish_cannot_release_or_overwrite_new_operation(provider_env):
    env = provider_env
    provider = env["provider"]
    first = provider.rotate(ALICE, operation_body())
    execution = provider.admit(ALICE, {"token": first["token"]})["execution_id"]
    receipt = {"ok": True, "operation_id": "operation-1", "execution_id": execution, "result": "first"}
    completion = {"execution_id": execution, "outcome": "succeeded", "receipt": receipt}
    provider.finish(ALICE, completion)
    second = provider.rotate(ALICE, operation_body("operation-2", 1))
    later_execution = provider.admit(ALICE, {"token": second["token"]})["execution_id"]
    restarted = reopen(env)
    restarted.finish(ALICE, completion)
    restarted.finish(ALICE, {"execution_id": execution, "outcome": "succeeded"})
    code("completion_conflict", lambda: restarted.finish(ALICE, {**completion, "receipt": {**receipt, "result": "mutated"}}))
    code("completion_conflict", lambda: restarted.finish(ALICE, {"execution_id": execution, "outcome": "failed"}))
    code("execution_busy", lambda: restarted.rotate(ALICE, operation_body("operation-3", 2)))
    assert restarted.operation(ALICE, {"operation_id": "operation-1"})["receipt"] == receipt
    current = restarted.operation(ALICE, {"operation_id": "operation-2"})
    assert current["status"] == "running" and current["execution_id"] == later_execution
    assert current["receipt"] is None


@pytest.mark.parametrize("receipt", [None, [], {}, {"ok": 1}, {"ok": False}, {"ok": True, "execution_id": "different"}, {"ok": True, "operation_id": "different"}, {"ok": True, "result": float("nan")}, {"ok": True, "result": "\ud800"}])
def test_invalid_receipts_preserve_unfinished_gate(provider_env, receipt):
    provider = provider_env["provider"]
    token = provider.rotate(ALICE, operation_body())["token"]
    execution = provider.admit(ALICE, {"token": token})["execution_id"]
    code("invalid_completion", lambda: provider.finish(ALICE, {"execution_id": execution, "outcome": "succeeded", "receipt": receipt}))
    assert provider.operation(ALICE, {"operation_id": "operation-1"})["status"] == "running"


def test_receipt_cap_is_explicit_and_sensitive_data_stays_out_of_audit(provider_env):
    provider = provider_env["provider"]
    token = provider.rotate(ALICE, operation_body())["token"]
    execution = provider.admit(ALICE, {"token": token})["execution_id"]
    receipt = {"ok": True, "result": "x" * MAX_RECEIPT_BYTES}
    code("invalid_completion", lambda: provider.finish(ALICE, {"execution_id": execution, "outcome": "succeeded", "receipt": receipt}))
    secret = "SECRET /private/path SQL sensitive result"
    provider.finish(ALICE, {"execution_id": execution, "outcome": "succeeded", "receipt": {"ok": True, "result": secret}})
    assert secret not in repr(provider.audit_events(ALICE))
    assert secret not in repr(provider.failure_events(ALICE))


def test_expired_and_revoked_operation_ids_are_never_reissued(provider_env):
    env = provider_env
    provider = env["provider"]
    first = provider.rotate(ALICE, operation_body())
    env["now"][0] += 61
    expired = provider.rotate(ALICE, operation_body(epoch=1))
    assert expired["status"] == "expired" and "token" not in expired
    provider.revoke(ALICE, {"expected_epoch": 1})
    revoked = provider.rotate(ALICE, operation_body(epoch=2))
    assert revoked["status"] == "revoked" and "token" not in revoked
    assert provider.state(ALICE)["epoch"] == 2
    code("inactive_token", lambda: provider.admit(ALICE, {"token": first["token"]}))


def interrupted_operation(env, operation, timing, token, execution):
    provider = reopen(env)
    transaction = provider._transaction

    @contextmanager
    def interrupted():
        with transaction() as database:
            yield database
            if timing == "before_commit":
                os._exit(81)
        os._exit(82)

    provider._transaction = interrupted
    if operation == "rotate":
        provider.rotate(ALICE, operation_body())
    elif operation == "admit":
        provider.admit(ALICE, {"token": token})
    else:
        provider.finish(ALICE, {"execution_id": execution, "outcome": "succeeded", "receipt": {"ok": True, "result": "persisted after real death"}})
    os._exit(99)


@pytest.mark.parametrize("operation", ["rotate", "admit", "finish"])
@pytest.mark.parametrize("timing", ["before_commit", "after_commit"])
def test_real_process_death_preserves_operation_and_receipt_atomically(provider_env, operation, timing):
    env = provider_env
    provider = env["provider"]
    token = provider.rotate(ALICE, operation_body())["token"] if operation != "rotate" else None
    execution = provider.admit(ALICE, {"token": token})["execution_id"] if operation == "finish" else None
    process = multiprocessing.get_context("fork").Process(target=interrupted_operation, args=(env, operation, timing, token, execution))
    process.start()
    process.join(timeout=10)
    try:
        assert not process.is_alive()
        assert process.exitcode == (81 if timing == "before_commit" else 82)
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
    restarted = reopen(env)
    if operation == "rotate" and timing == "before_commit":
        code("unknown_operation", lambda: restarted.operation(ALICE, {"operation_id": "operation-1"}))
        assert restarted.state(ALICE)["epoch"] == 0
        restarted.rotate(ALICE, operation_body())
    status = restarted.operation(ALICE, {"operation_id": "operation-1"})
    expected = {("rotate", "before_commit"): "ready", ("rotate", "after_commit"): "ready", ("admit", "before_commit"): "ready", ("admit", "after_commit"): "running", ("finish", "before_commit"): "running", ("finish", "after_commit"): "succeeded"}
    assert status["status"] == expected[operation, timing]
    replay = restarted.rotate(ALICE, operation_body(epoch=1))
    assert replay["epoch"] == 1 and replay["replay"] is True
    if status["status"] == "succeeded":
        assert status["receipt"] == {"ok": True, "result": "persisted after real death"}
        assert "token" not in replay
    elif status["status"] == "running":
        assert "token" not in replay
        env["now"][0] += 86400
        code("execution_busy", lambda: restarted.revoke(ALICE, {"expected_epoch": 1}))
    with sqlite3.connect(env["state"]) as database:
        assert database.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute("SELECT count(*) FROM operations").fetchone()[0] == 1
        assert database.execute("SELECT count(*) FROM grants").fetchone()[0] == 1
        assert database.execute("SELECT count(*) FROM executions").fetchone()[0] <= 1
