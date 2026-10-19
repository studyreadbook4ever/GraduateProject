"""Black-box tests against the production C++ sandbox, on compatible kernels."""

import json
import os
import signal
import socket
import subprocess
import time
from contextlib import ExitStack
from pathlib import Path

import pytest


@pytest.fixture(scope="module")
def worker_binary():
    binary = Path(os.environ.get("SAGA_WORKER_BINARY", Path(__file__).resolve().parents[1] / "build/saga-worker"))
    if not binary.is_file():
        pytest.skip("build saga-worker to run real kernel tests")
    process = subprocess.run([str(binary), "--probe"], capture_output=True, text=True, timeout=5)
    result = json.loads(process.stdout)
    if result["landlock_abi"] < 9:
        assert process.returncode != 0 and result["supported"] is False
        pytest.skip(f"real kernel tests require Landlock ABI 9; this kernel reports ABI {result['landlock_abi']}")
    assert process.returncode == 0 and result["supported"] is True
    return binary


def test_real_filesystem_network_and_unsafe_syscalls(worker_binary, tmp_path):
    read_file = tmp_path / "allowed.txt"; read_file.write_text("allowed read")
    write_file = tmp_path / "output.txt"; write_file.write_text("")
    denied_file = tmp_path / "private.txt"; denied_file.write_text("denied read")
    with ExitStack() as stack:
        ports = []
        for _ in range(2):
            listener = stack.enter_context(socket.socket())
            listener.bind(("127.0.0.1", 0)); listener.listen(4)
            ports.append(listener.getsockname()[1])
        unix = stack.enter_context(socket.socket(socket.AF_UNIX))
        unix_path = tmp_path / "service.sock"
        unix.bind(str(unix_path)); unix.listen(4)
        abstract = stack.enter_context(socket.socket(socket.AF_UNIX))
        abstract_name = f"saga-test-{os.getpid()}-{tmp_path.name}"
        abstract.bind("\0" + abstract_name); abstract.listen(4)
        attempts = [
            {"kind": "read", "path": str(read_file)},
            {"kind": "read", "path": str(denied_file)},
            {"kind": "write", "path": str(read_file), "content": "forbidden"},
            {"kind": "write", "path": str(write_file), "content": "after"},
            {"kind": "tcp_connect", "host": "127.0.0.1", "port": ports[0]},
            {"kind": "tcp_connect", "host": "127.0.0.1", "port": ports[1]},
            {"kind": "unix_connect", "path": str(unix_path)},
            {"kind": "abstract_unix_connect", "name": abstract_name},
            {"kind": "udp_socket"}, {"kind": "fork"}, {"kind": "chmod", "path": str(read_file)},
            {"kind": "tcp_bind", "port": 0}, {"kind": "signal", "pid": os.getpid(), "signal": 0},
            {"kind": "exec"},
        ]
        spec = {"sandbox": {"paths": [{"path": str(read_file), "access": "read"}, {"path": str(write_file), "access": "write"}], "tcp_ports": [ports[0]]}, "attempts": attempts}
        document = tmp_path / "probe.json"; document.write_text(json.dumps(spec))
        process = subprocess.run([str(worker_binary), "--sandbox-probe", str(document)], capture_output=True, text=True, timeout=10)
        assert process.returncode == 0, process.stderr
        result = json.loads(process.stdout)
        assert result["ok"] and result["landlock_abi"] >= 9
        assert len(result["attempts"]) == len(attempts)
        for index, attempt in enumerate(result["attempts"]):
            assert attempt["ok"] is (index in (0, 3, 4)), attempt
            if not attempt["ok"]:
                assert attempt["errno"] in (1, 13), attempt
    assert read_file.read_text() == "allowed read"
    assert write_file.read_text() == "after"
    assert denied_file.read_text() == "denied read"


@pytest.mark.parametrize("phase", ["sandbox_setup", "execution"])
def test_executor_failures_use_static_codes_without_input(worker_binary, tmp_path, phase):
    marker = "private-input-must-not-appear-in-errors"
    specification = {"sandbox": {"paths": [], "tcp_ports": []}, "attempts": []}
    if phase == "sandbox_setup":
        specification["sandbox"]["paths"] = [{"path": str(tmp_path / marker), "access": "read"}]
    else:
        specification["attempts"] = [{"kind": marker}]
    document = tmp_path / "failure.json"
    document.write_text(json.dumps(specification))
    process = subprocess.run([str(worker_binary), "--sandbox-probe", str(document)], capture_output=True, text=True, timeout=10)
    assert process.returncode == 0, process.stderr
    result = json.loads(process.stdout)
    assert result["ok"] is False
    assert result["phase"] == phase
    assert result["error_code"] == ("sandbox_setup_failed" if phase == "sandbox_setup" else "execution_failed")
    assert marker not in process.stdout + process.stderr


@pytest.mark.parametrize("interruption", [signal.SIGKILL, signal.SIGSTOP])
def test_interrupted_executor_is_bounded_and_reaped(worker_binary, tmp_path, interruption):
    with socket.socket() as listener, socket.socket() as pending:
        listener.bind(("127.0.0.1", 0))
        listener.listen(0)
        host, port = listener.getsockname()
        pending.connect((host, port))  # Fill the accept queue to hold the child in connect.
        specification = {
            "sandbox": {"paths": [], "tcp_ports": [port]},
            "attempts": [{"kind": "tcp_connect", "host": host, "port": port}] * 5,
        }
        document = tmp_path / "interrupted.json"
        document.write_text(json.dumps(specification))
        with subprocess.Popen([str(worker_binary), "--sandbox-probe", str(document)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            deadline = time.monotonic() + 2
            child = None
            while time.monotonic() < deadline and process.poll() is None:
                children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
                if children:
                    child = int(children[0])
                    break
                time.sleep(0.001)
            assert child is not None, "sandbox did not create its executor"
            os.kill(child, interruption)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stderr
            result = json.loads(stdout)
            assert result["ok"] is False
            assert result["error_code"] == ("executor_timeout" if interruption == signal.SIGSTOP else "executor_terminated")
            assert not Path(f"/proc/{child}").exists(), "executor was not reaped"


@pytest.mark.skipif(os.environ.get("SAGA_EXTERNAL_E2E") != "1", reason="external dataset experiment is opt-in: SAGA_EXTERNAL_E2E=1")
def test_external_database_and_mtls(worker_binary, tmp_path):
    from experiments.run import run
    receipt = run(worker_binary, tmp_path / "receipt.json")
    assert receipt["status"] == "passed"
    assert receipt["cleanup"] == {"all_processes_reaped": True, "temporary_directory_removed": True}
