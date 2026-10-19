"""Public SDK validation happens before launching a worker or touching paths."""

import json
from pathlib import Path

import pytest

from agent_backend import WorkerClient, WorkerError
from test_client_faults import fake_worker


@pytest.mark.parametrize("value", [".valid", ":valid", "-valid", "_valid", "", "a" * 129, "a\x00b", "한글", 123])
def test_invalid_operation_id_does_not_launch(fake_worker, monkeypatch, value):
    client = fake_worker("raise RuntimeError('should not launch')")

    def unexpected(*args, **kwargs):
        raise AssertionError("invalid request reached subprocess")

    monkeypatch.setattr("subprocess.Popen", unexpected)
    with pytest.raises(ValueError):
        client.execute(task_id="task", call={}, operation_id=value)
    with pytest.raises(ValueError):
        client.operation_status(value)


def test_timeout_exposes_the_generated_id_sent_to_worker(fake_worker, tmp_path):
    submitted = tmp_path / "submitted.json"
    # This fixture consumes stdin before its body; use a wrapper retaining it.
    client = fake_worker("time.sleep(10)")
    source = client.binary.read_text().replace("sys.stdin.buffer.read()", "payload = sys.stdin.buffer.read()")
    source = source.replace("time.sleep(10)", f"open({str(submitted)!r}, 'wb').write(payload)\ntime.sleep(10)")
    client.binary.write_text(source)
    with pytest.raises(WorkerError) as caught:
        client.execute(task_id="task", call={}, timeout=0.2)
    record = json.loads(submitted.read_bytes())
    assert caught.value.operation_ids == (record["operation_id"],)
    assert len(record["operation_id"]) == 32 and caught.value.receipts == ()


def test_receipt_from_different_operation_is_protocol_error(fake_worker):
    client = fake_worker("os.write(1, b'{\"ok\":true,\"operation_id\":\"wrong-operation\"}\\n')")
    with pytest.raises(WorkerError) as caught:
        client.execute(task_id="task", call={}, operation_id="submitted-operation")
    assert caught.value.code == "invalid_worker_output"
    assert caught.value.operation_ids == ("submitted-operation",)
    assert caught.value.receipts[0]["operation_id"] == "wrong-operation"


@pytest.mark.parametrize("field", ["config", "binary", "failure_log"])
@pytest.mark.parametrize("value", ["", "a\x00b", "\ud800", b"bytes", 123])
def test_invalid_sdk_path_fails_before_any_filesystem_io(monkeypatch, field, value):
    def unexpected(*args, **kwargs):
        raise AssertionError("invalid path reached filesystem")

    monkeypatch.setattr(Path, "resolve", unexpected)
    kwargs = {"config": "config.json", "binary": "worker", "failure_log": "events.jsonl"}
    kwargs[field] = value
    with pytest.raises(ValueError):
        WorkerClient(**kwargs)
