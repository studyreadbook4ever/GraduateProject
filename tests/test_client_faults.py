"""Fault the SDK boundary with real subprocesses and real file-size failures."""

import concurrent.futures
import fcntl
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_backend import WorkerClient, WorkerError


@pytest.fixture
def fake_worker(tmp_path):
    config = tmp_path / "config.json"
    config.write_text("{}")

    def create(body, *, log=True):
        binary = tmp_path / f"worker-{len(list(tmp_path.glob('worker-*')))}"
        binary.write_text(f"#!{sys.executable}\nimport os, sys, time\nsys.stdin.buffer.read()\n{body}\n")
        binary.chmod(0o700)
        return WorkerClient(config, binary=binary,
                            failure_log=tmp_path / "failures.jsonl" if log else None)

    return create


def emit(*receipts, tail=b""):
    raw = b"".join(json.dumps(receipt, ensure_ascii=False).encode() + b"\n" for receipt in receipts) + tail
    return f"os.write(1, {raw!r})"


SUCCESS = {"ok": True, "call_id": "a" * 32, "result": "private-success-content"}
FAILURE = {"ok": False, "call_id": "b" * 32, "phase": "parse",
           "error_code": "invalid_call", "error": "private-failure-content"}


def events(client):
    return [json.loads(line) for line in client.failure_log.read_text().splitlines()]


def test_valid_unicode_stdout_and_invalid_stderr_are_independent(fake_worker):
    receipt = {"ok": True, "result": "한글😀\u0085\u2028\u2029\x00"}
    client = fake_worker(emit(receipt) + "\nos.write(2, b'private-stderr\\xff')")
    assert client.execute(task_id="x", call={}) == receipt
    assert events(client) == []


def test_invalid_utf8_keeps_complete_receipt_prefix(fake_worker):
    client = fake_worker(emit(SUCCESS, FAILURE, tail=b'{"ok":true,"result":"\xff"}\n'))
    with pytest.raises(WorkerError) as caught:
        client.execute_many([{}, {}, {}], timeout=2)
    assert caught.value.code == "invalid_worker_output"
    assert caught.value.receipts == (SUCCESS, FAILURE)
    assert [event["error_code"] for event in events(client)] == ["invalid_call", "invalid_worker_output"]


def test_real_timeout_has_priority_over_partial_invalid_utf8(fake_worker, tmp_path):
    pid = tmp_path / "worker.pid"
    client = fake_worker(f"open({str(pid)!r}, 'w').write(str(os.getpid()))\n" +
                         emit(FAILURE, tail=b'{"ok":true,"result":"\xff') + "\ntime.sleep(10)")
    started = time.monotonic()
    with pytest.raises(WorkerError) as caught:
        client.execute_many([{}, {}], timeout=0.1)
    assert time.monotonic() - started < 2
    assert caught.value.code == "worker_timeout"
    assert caught.value.receipts == (FAILURE,)
    assert not Path(f"/proc/{pid.read_text()}").exists()
    assert [event["error_code"] for event in events(client)] == ["invalid_call", "worker_timeout"]


def test_timeout_drain_is_bounded_when_another_session_holds_pipe(fake_worker, tmp_path):
    holder = tmp_path / "holder.pid"
    body = f"""read_end, write_end = os.pipe()
pid = os.fork()
if pid == 0:
 os.close(read_end)
 os.setsid()
 open({str(holder)!r}, 'w').write(str(os.getpid()))
 os.write(write_end, b'x')
 time.sleep(10)
 os._exit(0)
os.close(write_end)
os.read(read_end, 1)
{emit(SUCCESS)}
time.sleep(10)
"""
    client = fake_worker(body)
    # Keep Linux subreaper behavior local to this disposable caller, so it can
    # reap the escaped descendant after testing the SDK's bounded pipe drain.
    driver = f"""import ctypes, json, os, signal, time
from pathlib import Path
from agent_backend import WorkerClient, WorkerError
assert ctypes.CDLL(None).prctl(36, 1, 0, 0, 0) == 0
client = WorkerClient({str(client.config)!r}, binary={str(client.binary)!r}, failure_log={str(client.failure_log)!r})
started = time.monotonic()
try:
 try:
  client.execute_many([{{}}, {{}}], timeout=.1)
 except WorkerError as error:
  print(json.dumps({{'code':error.code, 'receipts':error.receipts, 'elapsed':time.monotonic()-started}}))
finally:
 pid = int(Path({str(holder)!r}).read_text())
 os.kill(pid, signal.SIGKILL)
 os.waitpid(pid, 0)
"""
    process = subprocess.run([sys.executable, "-c", driver], capture_output=True, text=True, timeout=4)
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["code"] == "worker_timeout"
    assert result["receipts"] == [SUCCESS]
    assert result["elapsed"] < 1.5
    assert not Path(f"/proc/{holder.read_text()}").exists()


@pytest.mark.parametrize("exception", [KeyboardInterrupt, SystemExit])
def test_actual_external_interrupt_retains_receipts(fake_worker, exception):
    client = fake_worker(emit(SUCCESS) + "\ntime.sleep(10)")

    def interrupt(_signum, _frame):
        raise exception()

    previous = signal.signal(signal.SIGALRM, interrupt)
    signal.setitimer(signal.ITIMER_REAL, 0.2)
    try:
        with pytest.raises(exception) as caught:
            client.execute_many([{}, {}], timeout=2)
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    assert caught.value.receipts == (SUCCESS,)
    assert caught.value.code == "worker_interrupted" and caught.value.outcome_uncertain
    assert caught.value.__notes__
    assert events(client)[0]["error_code"] == "worker_interrupted"


def test_surrogate_input_is_rejected_before_spawning(fake_worker, tmp_path):
    marker = tmp_path / "spawned"
    client = fake_worker(f"open({str(marker)!r}, 'w').write('started')")
    with pytest.raises(ValueError, match="valid UTF-8"):
        client.execute(task_id="x", call={"content": "\ud800"})
    assert not marker.exists()
    assert events(client) == []


def test_fsync_failure_preserves_all_receipts_and_redacts_fallback(fake_worker, monkeypatch, capsys):
    client = fake_worker(emit(SUCCESS, FAILURE) + "\nsys.exit(1)")

    def fail(_descriptor):
        raise OSError("private-storage-error")

    monkeypatch.setattr(os, "fsync", fail)
    with pytest.raises(WorkerError) as caught:
        client.execute_many([{}, {}], timeout=2)
    assert caught.value.code == "failure_log_unavailable"
    assert caught.value.audit_failed
    assert caught.value.receipts == (SUCCESS, FAILURE)
    fallback = capsys.readouterr().err
    assert json.loads(fallback)["error_code"] == "failure_log_unavailable"
    assert "private" not in fallback


@pytest.mark.parametrize("limit", [0, 40])
def test_real_storage_failure_rolls_back_partial_line(fake_worker, limit):
    client = fake_worker(emit(SUCCESS, FAILURE) + "\nsys.exit(1)")
    driver = f"""import json, resource, signal
from agent_backend import WorkerClient, WorkerError
client = WorkerClient({str(client.config)!r}, binary={str(client.binary)!r}, failure_log={str(client.failure_log)!r})
previous = resource.getrlimit(resource.RLIMIT_FSIZE)
signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
resource.setrlimit(resource.RLIMIT_FSIZE, ({limit}, previous[1]))
try:
 try:
  client.execute_many([{{}}, {{}}], timeout=2)
 except WorkerError as error:
  print(json.dumps({{'code': error.code, 'receipts': error.receipts, 'audit_failed': error.audit_failed}}))
finally:
 resource.setrlimit(resource.RLIMIT_FSIZE, previous)
assert client.failure_log.read_bytes() == b''
assert len(client.execute_many([{{}}, {{}}], timeout=2)) == 2
lines = client.failure_log.read_text().splitlines()
assert len(lines) == 1 and json.loads(lines[0])['error_code'] == 'invalid_call'
"""
    process = subprocess.run([sys.executable, "-c", driver], capture_output=True, text=True, timeout=5)
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["code"] == "failure_log_unavailable" and result["audit_failed"]
    assert result["receipts"] == [SUCCESS, FAILURE]
    assert "private" not in process.stderr


def test_audit_open_failure_after_action_retains_all_receipts(fake_worker, tmp_path):
    log = tmp_path / "failures.jsonl"
    client = fake_worker(f"os.chmod({str(log)!r}, 0o644)\n" + emit(SUCCESS, FAILURE) + "\nsys.exit(1)")
    with pytest.raises(WorkerError) as caught:
        client.execute_many([{}, {}], timeout=2)
    assert caught.value.code == "failure_log_unavailable"
    assert caught.value.receipts == (SUCCESS, FAILURE)
    assert caught.value.outcome_uncertain


def test_unavailable_audit_prevents_launch(fake_worker, tmp_path):
    marker = tmp_path / "spawned"
    client = fake_worker(f"open({str(marker)!r}, 'w').write('started')")
    client.failure_log.chmod(0o644)
    with pytest.raises(WorkerError) as caught:
        client.execute(task_id="x", call={})
    assert caught.value.code == "failure_log_unavailable"
    assert not caught.value.outcome_uncertain
    assert not marker.exists()


def test_invalid_audit_field_types_do_not_mask_receipts(fake_worker):
    receipt = {"ok": False, "phase": [], "executor_phase": {"private": "content"}}
    client = fake_worker(emit(receipt) + "\nsys.exit(1)")
    assert client.execute(task_id="x", call={}) == receipt
    assert set(events(client)[0]) == {"event", "created_at"}


def test_concurrent_real_callers_append_complete_events(fake_worker):
    client = fake_worker(emit(FAILURE) + "\nsys.exit(1)")
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: client.execute(task_id="x", call={}, timeout=3), range(32)))
    assert results == [FAILURE] * 32
    assert len(events(client)) == 32
    assert all(event["call_id"] == FAILURE["call_id"] for event in events(client))


@pytest.mark.parametrize("receipt, status", [(SUCCESS, 1), (FAILURE, 0)])
def test_conflicting_receipt_and_exit_status_retains_result(fake_worker, receipt, status):
    client = fake_worker(emit(receipt) + f"\nsys.exit({status})")
    with pytest.raises(WorkerError) as caught:
        client.execute(task_id="x", call={}, timeout=2)
    assert caught.value.code == "worker_exit_failed"
    assert caught.value.receipts == (receipt,)
    assert events(client)[-1]["error_code"] == "worker_exit_failed"


def test_audit_lock_cannot_hold_completed_batch_results_indefinitely(fake_worker, capsys):
    client = fake_worker(emit(FAILURE, FAILURE, FAILURE) + "\nsys.exit(1)")
    with client.failure_log.open("ab") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        started = time.monotonic()
        with pytest.raises(WorkerError) as caught:
            client.execute_many([{}, {}, {}], timeout=0.1)
        elapsed = time.monotonic() - started
        assert elapsed < 1.2, "a held audit lock blocked receipt delivery"
        assert caught.value.code == "failure_log_unavailable" and caught.value.audit_failed
        assert caught.value.receipts == (FAILURE, FAILURE, FAILURE)
    assert events(client) == []
    assert "private" not in capsys.readouterr().err
