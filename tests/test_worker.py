"""Exercise on-demand requests and uncertain replies over real mTLS and exec."""

import json
import os
import subprocess

import pytest
from cryptography.hazmat.primitives import serialization

from agent_backend import WorkerClient, WorkerError
from saga.errors import ProviderError

from conftest import rotate_body
from test_kernel import worker_binary
from test_mtls import tls_provider, tls_server


@pytest.fixture
def client_env(worker_binary, tls_provider, provider_env):
    port, pki, provider, fingerprints = tls_provider
    root = provider_env["root"]
    public = root / "provider-public.pem"
    public.write_bytes(provider_env["key"].public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    config = root / "worker.json"
    config.write_text(json.dumps({
        "provider_url": f"https://127.0.0.1:{port}",
        "ca_certificate": str(pki / "ca.pem"),
        "client_certificate": str(pki / "alice.pem"),
        "client_key": str(pki / "alice-key.pem"),
        "provider_public_key": str(public), "agent_id": "alice",
    }))
    log = root / "worker-failures.jsonl"
    client = WorkerClient(config, binary=worker_binary, failure_log=log)
    return client, provider, fingerprints["alice"], root, log


def use_notes(client):
    return client.request_resource(task_id="research", tool="read_file", resource="notes", timeout=15)


def test_on_demand_exact_resources_and_persistent_redacted_failure(client_env):
    client, provider, fingerprint, root, log = client_env
    assert use_notes(client)["ok"]
    marker = "private-content-never-in-audit"
    write = client.request_resource(task_id="research", tool="write_file", resource="output", content=marker)
    assert write["ok"] and write["epoch"] == 2
    denied = client.request_resource(task_id="research", tool="read_file", resource="private")
    assert denied["ok"] is False and denied["executor_started"] is False
    assert denied["error_code"] == "capability_denied" and denied["phase"] == "rotate"
    query = client.request_resource(task_id="research", tool="query_db", resource="records", query="by_id", parameters=[1])
    assert query["ok"] and query["epoch"] == 3
    assert (root / "output.txt").read_text() == marker
    events = provider.audit_events(fingerprint)
    assert sum(event["event"] == "admitted" for event in events) == 3
    failures = provider.failure_events(fingerprint)
    assert any(event["call_id"] == denied["call_id"] for event in failures)
    local = json.loads(log.read_text())
    assert local["call_id"] == denied["call_id"]
    assert local["error_code"] == "capability_denied"
    assert marker not in log.read_text() and "private" not in log.read_text()
    assert log.stat().st_mode & 0o777 == 0o600


def test_definite_epoch_conflict_refreshes_without_duplicate_execution(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.rotate
    attempts = []

    def compete(certificate, body):
        attempts.append(body["expected_epoch"])
        if len(attempts) == 1:
            original(certificate, {**body, "operation_id": "competing-operation"})
            raise ProviderError(409, "epoch_conflict", "generation changed")
        return original(certificate, body)

    monkeypatch.setattr(provider, "rotate", compete)
    result = use_notes(client)
    assert result["ok"] and result["epoch"] == 2
    assert attempts == [0, 1]
    assert sum(e["event"] == "admitted" for e in provider.audit_events(fingerprint)) == 1


def test_state_read_can_retry_a_lost_connection(client_env, monkeypatch):
    client, provider, _, _, _ = client_env
    original = provider.state
    calls = []

    def interrupted(certificate):
        calls.append(1)
        if len(calls) == 1:
            raise ConnectionResetError("test lost state reply")
        return original(certificate)

    monkeypatch.setattr(provider, "state", interrupted)
    assert use_notes(client)["ok"]
    assert len(calls) == 2


def test_finish_reply_loss_retries_only_the_same_completion(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.finish
    calls = []

    def interrupted(certificate, body):
        calls.append(dict(body))
        result = original(certificate, body)
        if len(calls) == 1:
            raise ConnectionResetError("test committed finish reply lost")
        return result

    monkeypatch.setattr(provider, "finish", interrupted)
    result = use_notes(client)
    assert result["ok"] and result["completion_recorded"]
    assert len(calls) == 2 and calls[0] == calls[1]
    events = provider.audit_events(fingerprint)
    assert sum(e["event"] == "admitted" for e in events) == 1
    assert sum(e["event"] == "finished" for e in events) == 1


def test_lost_admission_is_not_replayed_or_treated_as_safe_to_retry(client_env, monkeypatch):
    client, provider, fingerprint, _, log = client_env
    original = provider.admit
    calls = []

    def interrupted(certificate, body):
        calls.append(1)
        original(certificate, body)
        raise ConnectionResetError("test committed admission reply lost")

    monkeypatch.setattr(provider, "admit", interrupted)
    result = use_notes(client)
    assert result["ok"] is False and result["phase"] == "admit"
    assert result["admission_uncertain"] and result["retry_safe"] is False
    assert result["executor_started"] is False and len(calls) == 1
    assert "execution_id" not in result
    busy = use_notes(client)
    assert busy["error_code"] == "execution_busy" and busy["executor_started"] is False
    assert client.revoke()["error_code"] == "execution_busy"
    assert sum(e["event"] == "admitted" for e in provider.audit_events(fingerprint)) == 1
    assert any(e.get("admission_uncertain") for e in map(json.loads, log.read_text().splitlines()))


def test_lost_rotation_reply_never_replays_the_post(client_env, monkeypatch):
    client, provider, fingerprint, _, _ = client_env
    original = provider.rotate
    calls = []

    def interrupted(certificate, body):
        calls.append(1)
        original(certificate, body)
        raise ConnectionResetError("test committed rotation reply lost")

    monkeypatch.setattr(provider, "rotate", interrupted)
    result = use_notes(client)
    assert not result["ok"] and not result["executor_started"]
    assert result["provider_state_uncertain"] and not result["retry_safe"]
    assert len(calls) == 1
    assert sum(e["event"] == "issued" for e in provider.audit_events(fingerprint)) == 1
    assert not any(e["event"] == "admitted" for e in provider.audit_events(fingerprint))


def test_handler_failure_is_finished_and_durably_classified(client_env):
    client, provider, fingerprint, root, _ = client_env
    (root / "notes.txt").write_bytes(b"\xff")
    result = use_notes(client)
    assert result["ok"] is False and result["executor_started"]
    assert result["completion_recorded"] and result["phase"] == "execute"
    finished = [e for e in provider.audit_events(fingerprint) if e["event"] == "finished"]
    assert len(finished) == 1 and finished[0]["outcome"] == "failed"
    assert finished[0]["failure_code"] == "execution_failed"
    (root / "notes.txt").write_text("safe next call")
    assert use_notes(client)["ok"]


def test_valid_utf8_separators_in_resource_are_not_treated_as_receipt_boundaries(client_env):
    client, _, _, root, _ = client_env
    content = "first\u0085next\u2028line\u2029paragraph\x00end"
    (root / "notes.txt").write_text(content)
    result = use_notes(client)
    assert result["ok"] and result["result"]["content"] == content


@pytest.mark.parametrize("literal", ["1e999", "-1e999"])
def test_nonfinite_sql_result_is_not_silently_changed_to_json_null(client_env, literal):
    client, provider, fingerprint, _, _ = client_env
    provider.config["resources"]["records"]["queries"]["nonfinite"] = {
        "sql": f"SELECT {literal} AS value", "parameters": 0,
    }
    result = client.request_resource(task_id="research", tool="query_db", resource="records",
                                     query="nonfinite", parameters=[])
    assert result["ok"] is False, result
    assert result["completion_recorded"]
    assert provider.audit_events(fingerprint)[-1]["outcome"] == "failed"


def test_sql_null_and_finite_number_results_remain_distinct(client_env):
    client, provider, _, _, _ = client_env
    provider.config["resources"]["records"]["queries"]["values"] = {
        "sql": "SELECT NULL AS missing, 1.25 AS finite", "parameters": 0,
    }
    result = client.request_resource(task_id="research", tool="query_db", resource="records",
                                     query="values", parameters=[])
    assert result["ok"] and result["result"]["rows"] == [[None, 1.25]]


def test_sdk_revoke_invalidates_pending_authority_without_issuing_another(client_env):
    client, provider, fingerprint, _, _ = client_env
    grant = provider.rotate(fingerprint, rotate_body())
    result = client.revoke(timeout=10)
    assert result["ok"] and result["revoked"] and result["epoch"] == grant["epoch"] + 1
    with pytest.raises(ProviderError, match="revoked"):
        provider.admit(fingerprint, {"token": grant["token"]})
    assert use_notes(client)["ok"]


def test_local_failure_log_covers_provider_unavailability_and_malformed_call(client_env, worker_binary):
    client, _, _, root, log = client_env
    config = json.loads(client.config.read_text())
    config["provider_url"] = "https://127.0.0.1:1"
    offline = root / "offline.json"
    offline.write_text(json.dumps(config))
    unavailable = WorkerClient(offline, binary=worker_binary, failure_log=log)
    result = use_notes(unavailable)
    assert result["error_code"] == "provider_transport" and result["phase"] == "state"
    assert json.loads(log.read_text())["error_code"] == "provider_transport"
    marker = "secret-input-never-written-to-stderr"
    process = subprocess.run([str(worker_binary), "--config", str(client.config)],
                             input='{"task_id":"' + marker + '\n', text=True, capture_output=True, timeout=10)
    assert process.returncode == 1
    assert marker not in process.stdout and marker not in process.stderr
    assert json.loads(process.stderr)["error_code"] == "invalid_call"


def test_failure_log_rejects_unsafe_existing_destination(client_env, worker_binary):
    client, _, _, root, _ = client_env
    path = root / "wide.log"
    path.write_text("")
    os.chmod(path, 0o644)
    with pytest.raises(ValueError, match="owner-only"):
        WorkerClient(client.config, binary=worker_binary, failure_log=path)
    link = root / "link.log"
    link.symlink_to(path)
    with pytest.raises(ValueError, match="symlinks"):
        WorkerClient(client.config, binary=worker_binary, failure_log=link)


def test_initialization_failure_never_echoes_config_input(client_env, worker_binary):
    client, _, _, root, log = client_env
    marker = "private-configuration-never-written-to-diagnostics"
    invalid = root / "invalid-config.json"
    invalid.write_text('{"client_key":"' + marker)
    process = subprocess.run([str(worker_binary), "--config", str(invalid)], text=True,
                             capture_output=True, timeout=5)
    assert process.returncode == 2 and marker not in process.stderr
    assert json.loads(process.stderr)["error_code"] == "worker_initialization_failed"
    broken = WorkerClient(invalid, binary=worker_binary, failure_log=log)
    with pytest.raises(WorkerError) as error:
        use_notes(broken)
    assert error.value.code == "worker_initialization_failed"
    assert json.loads(log.read_text())["error_code"] == "worker_initialization_failed"


def test_sdk_timeout_preserves_observed_receipts_without_reexecuting(client_env, worker_binary, monkeypatch):
    client, _, _, _, log = client_env
    real_communicate = subprocess.Popen.communicate
    calls = []

    def expire_once(process, *args, **kwargs):
        if not calls:
            calls.append(1)
            # Observe a complete real receipt, then model timeout detection.
            output, errors = real_communicate(process, *args, **kwargs)
            process._saga_test_output = (output, errors)
            raise subprocess.TimeoutExpired(process.args, 0.01)
        return process._saga_test_output

    monkeypatch.setattr(subprocess.Popen, "communicate", expire_once)
    with pytest.raises(WorkerError) as error:
        use_notes(client)
    assert error.value.code == "worker_timeout" and error.value.outcome_uncertain
    assert len(error.value.receipts) == 1 and error.value.receipts[0]["ok"]
    assert json.loads(log.read_text())["error_code"] == "worker_timeout"


@pytest.mark.parametrize("mode", ["timeout", "malformed", "missing"])
def test_batch_preserves_and_logs_completed_denial_before_later_receipt_loss(client_env, monkeypatch, mode):
    client, _, _, _, log = client_env
    original = subprocess.Popen.communicate
    replies = []

    def interrupt_later_receipt(process, *args, **kwargs):
        if not replies:
            output, errors = original(process, *args, **kwargs)
            observed = output.split(b"\n")[0] + b"\n" if mode == "missing" else output + b'{"ok":'
            replies.append((observed, errors))
            if mode == "timeout":
                raise subprocess.TimeoutExpired(process.args, 0.01)
        return replies[0]

    monkeypatch.setattr(subprocess.Popen, "communicate", interrupt_later_receipt)
    # The first call fails parsing before Provider contact; only the worker/SDK
    # can retain its diagnosis. A later incomplete receipt must not erase it.
    records = [{"task_id": "research", "format": "canonical", "call": {}, "extra": True}]
    if mode == "missing":
        records.append(records[0])
    with pytest.raises(WorkerError) as error:
        client.execute_many(records, timeout=10)
    assert len(error.value.receipts) == 1
    first = error.value.receipts[0]
    assert first["error_code"] == "invalid_call"
    events = list(map(json.loads, log.read_text().splitlines()))
    assert events[0]["call_id"] == first["call_id"] and events[0]["error_code"] == "invalid_call"
    assert events[-1]["error_code"] in {"worker_timeout", "invalid_worker_output", "incomplete_worker_output"}
