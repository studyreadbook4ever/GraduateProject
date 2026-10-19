"""Reconcile actual CLI attempts across lost replies, timeouts and late finish."""

import concurrent.futures
import json
import threading

import pytest

from agent_backend import WorkerClient, WorkerError
from saga.errors import ProviderError

from test_kernel import worker_binary
from test_mtls import tls_provider, tls_server
from test_worker import client_env


def read(client, operation_id):
    return client.request_resource(task_id="research", tool="read_file", resource="notes", operation_id=operation_id)


def admissions(provider, fingerprint):
    return [e for e in provider.audit_events(fingerprint) if e["event"] == "admitted"]


def test_completed_retry_recovers_original_result_after_resource_changes(client_env):
    client, provider, fingerprint, root, _ = client_env
    first = read(client, "read-once")
    assert first["ok"] and first["completion_recorded"]
    (root / "notes.txt").write_text("different contents")
    replay = read(client, "read-once")
    assert replay["ok"] and replay["result"] == first["result"]
    assert replay["execution_id"] == first["execution_id"]
    assert replay["replayed"] and replay["cached"] and not replay["executor_started"]
    assert replay["original_executor_started"]
    assert replay["call_id"] != first["call_id"] and replay["original_call_id"] == first["call_id"]
    status = client.operation_status("read-once")
    assert status["ok"] and status["status"] == "succeeded"
    assert status["receipt"] == first
    assert len(admissions(provider, fingerprint)) == 1


def test_same_id_different_call_fails_before_dispatch(client_env):
    client, provider, fingerprint, _, _ = client_env
    assert read(client, "bound-operation")["ok"]
    conflict = client.request_resource(task_id="research", tool="write_file", resource="output",
                                       content="changed", operation_id="bound-operation")
    assert conflict["error_code"] == "operation_conflict" and not conflict["executor_started"]
    assert len(admissions(provider, fingerprint)) == 1


def test_large_escaped_receipt_survives_finish_status_and_replay(client_env):
    client, _, _, root, _ = client_env
    (root / "notes.txt").write_text("\x01" * 600_000)
    first = read(client, "large-receipt")
    assert first["ok"] and first["completion_recorded"]
    assert len(json.dumps(first)) > 3 * 1024 * 1024
    status = client.operation_status("large-receipt")
    assert status["ok"] and status["receipt"] == first
    replay = read(client, "large-receipt")
    assert replay["ok"] and replay["cached"] and replay["result"] == first["result"]


def test_lost_rotate_reply_reuses_original_grant(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.rotate
    count = []

    def lose_once(certificate, body):
        result = original(certificate, body)
        count.append(1)
        if len(count) == 1:
            raise ConnectionResetError("lost committed rotation")
        return result

    monkeypatch.setattr(provider, "rotate", lose_once)
    first = read(client, "lost-rotate")
    assert not first["ok"] and first["provider_state_uncertain"]
    retry = read(client, "lost-rotate")
    assert retry["ok"] and retry["epoch"] == 1
    assert len(admissions(provider, fingerprint)) == 1
    assert sum(e["event"] == "issued" for e in provider.audit_events(fingerprint)) == 1


def test_running_retry_and_late_finish_share_one_execution(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.finish
    arrived, release = threading.Event(), threading.Event()

    def hold_finish(certificate, body):
        arrived.set()
        assert release.wait(10)
        return original(certificate, body)

    monkeypatch.setattr(provider, "finish", hold_finish)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        first = pool.submit(read, client, "still-running")
        try:
            assert arrived.wait(5)
            retry = read(client, "still-running")
            assert retry["error_code"] == "operation_in_progress"
            assert retry["operation_status"] == "running" and not retry["executor_started"]
            assert client.operation_status("still-running")["status"] == "running"
        finally:
            release.set()
        completed = first.result(timeout=5)
    cached = read(client, "still-running")
    assert cached["ok"] and cached["execution_id"] == completed["execution_id"]
    assert len(admissions(provider, fingerprint)) == 1


def test_simultaneous_ready_replays_admit_only_once_and_never_claim_safe_retry(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.rotate
    both_ready = threading.Barrier(2)

    def simultaneous(certificate, body):
        grant = original(certificate, body)
        both_ready.wait(timeout=5)
        return grant

    monkeypatch.setattr(provider, "rotate", simultaneous)
    with concurrent.futures.ThreadPoolExecutor() as pool:
        results = list(pool.map(lambda _: read(client, "concurrent-same-id"), range(2)))
    assert sum(result["ok"] for result in results) == 1
    denied = next(result for result in results if not result["ok"])
    assert denied["error_code"] == "inactive_token" and not denied["executor_started"]
    assert not denied["retry_safe"]
    assert len(admissions(provider, fingerprint)) == 1


def test_timeout_after_committed_finish_recovers_durable_result(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.finish
    committed, release = threading.Event(), threading.Event()

    def hold_reply(certificate, body):
        result = original(certificate, body)
        committed.set()
        assert release.wait(10)
        return result

    monkeypatch.setattr(provider, "finish", hold_reply)
    try:
        with pytest.raises(WorkerError) as caught:
            client.request_resource(task_id="research", tool="read_file", resource="notes",
                                    timeout=0.5, operation_id="timed-out")
        assert committed.is_set()
        assert caught.value.code == "worker_timeout" and caught.value.operation_ids == ("timed-out",)
        status = client.operation_status(caught.value.operation_ids[0])
        assert status["ok"] and status["status"] == "succeeded"
        replay = read(client, "timed-out")
        assert replay["ok"] and replay["cached"] and not replay["executor_started"]
        assert len(admissions(provider, fingerprint)) == 1
    finally:
        release.set()


def test_failed_result_is_immutable_even_after_repair(client_env):
    client, provider, fingerprint, root, _ = client_env
    (root / "notes.txt").write_bytes(b"invalid UTF-8: \xff")
    first = read(client, "failed-once")
    assert not first["ok"] and first["completion_recorded"]
    (root / "notes.txt").write_text("repaired")
    retry = read(client, "failed-once")
    assert not retry["ok"] and retry["cached"] and retry["execution_id"] == first["execution_id"]
    assert read(client, "intentional-new-operation")["ok"]
    assert len(admissions(provider, fingerprint)) == 2


def test_vendor_result_keeps_call_identity(client_env):
    client, provider, fingerprint, _, _ = client_env
    result = client.execute_tool_call(task_id="research", format="openai_responses", operation_id="vendor-once", call={
        "type": "function_call", "call_id": "call_upstream", "name": "read_file",
        "arguments": '{"resource":"notes"}', "status": "completed",
    })
    assert result["receipt"]["ok"]
    assert result["tool_result"]["call_id"] == "call_upstream"
    assert json.loads(result["tool_result"]["output"]) == result["receipt"]["result"]
    assert len(admissions(provider, fingerprint)) == 1


def test_vendor_mapping_error_keeps_completed_receipt(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env

    def unrepresentable(*args, **kwargs):
        raise ProviderError(400, "invalid_call", "result cannot be represented")

    monkeypatch.setattr("saga.adapters.format_tool_result", unrepresentable)
    with pytest.raises(WorkerError) as caught:
        client.execute_tool_call(task_id="research", format="anthropic", operation_id="mapping-error", call={
            "type": "tool_use", "id": "toolu_123", "name": "read_file", "input": {"resource": "notes"},
        })
    assert caught.value.code == "tool_result_unrepresentable"
    assert caught.value.receipts[0]["ok"] and caught.value.receipts[0]["completion_recorded"]
    assert caught.value.operation_ids == ("mapping-error",) and not caught.value.outcome_uncertain
    assert len(admissions(provider, fingerprint)) == 1


@pytest.mark.parametrize("field", ["ca_certificate", "client_certificate", "client_key", "provider_public_key"])
@pytest.mark.parametrize("value", [None, "", "truncated\x00ignored", 123, "\ud800"])
def test_native_invalid_paths_fail_at_configuration_boundary(client_env, field, value):
    client, _, _, root, _ = client_env
    config = json.loads(client.config.read_text())
    config[field] = value
    path = root / "invalid-worker.json"
    path.write_text(json.dumps(config))
    invalid = WorkerClient(path, binary=client.binary)
    with pytest.raises(WorkerError) as caught:
        read(invalid, "invalid-path")
    assert caught.value.code == "worker_initialization_failed"
    assert caught.value.receipts == ()
