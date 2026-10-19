"""Actual worker-process overlap agrees with the per-agent authority gate."""

import json
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from test_worker import client_env
from test_kernel import worker_binary
from test_mtls import tls_provider, tls_server


@pytest.fixture
def gated_resource(client_env):
    client, provider, fingerprint, root, _ = client_env
    release = threading.Event()
    first_entered = threading.Event()
    two_entered = threading.Event()
    lock = threading.Lock()
    counts = {"entered": 0, "active": 0, "maximum": 0}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            with lock:
                counts["entered"] += 1
                counts["active"] += 1
                counts["maximum"] = max(counts["maximum"], counts["active"])
                first_entered.set()
                if counts["active"] == 2:
                    two_entered.set()
            try:
                if not release.wait(10):
                    return
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
            finally:
                with lock:
                    counts["active"] -= 1

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01})
    thread.start()
    provider.config["resources"]["gated"] = {
        "kind": "http", "url": f"http://127.0.0.1:{server.server_address[1]}/gated",
    }
    provider.config["tasks"]["concurrent"] = {"allow": [{"tool": "http_get", "resource": "gated"}]}
    for name in ("alice", "bob"):
        provider.config["agents"][name]["tasks"].append("concurrent")
    bob = json.loads(client.config.read_text())
    bob["agent_id"] = "bob"
    pki = Path(bob["client_certificate"]).parent
    bob["client_certificate"] = str(pki / "bob.pem")
    bob["client_key"] = str(pki / "bob-key.pem")
    bob_config = root / "bob-worker.json"
    bob_config.write_text(json.dumps(bob))
    children = []
    try:
        yield {"alice": client.config, "bob": bob_config, "first": first_entered,
               "two": two_entered, "release": release, "counts": counts,
               "children": children, "provider": provider, "fingerprint": fingerprint}
    finally:
        release.set()
        for child in children:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def start(worker, resource, name):
    child = subprocess.Popen([str(worker), "--config", str(resource[name])], stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    resource["children"].append(child)
    call = {"task_id": "concurrent", "format": "canonical", "call": {
        "tool": "http_get", "arguments": {"resource": "gated"}}}
    child.stdin.write(json.dumps(call) + "\n")
    child.stdin.close()
    child.stdin = None
    return child


def result(child):
    output, error = child.communicate(timeout=10)
    assert child.returncode in (0, 1), error
    values = [json.loads(line) for line in output.splitlines()]
    assert len(values) == 1
    return values[0]


def test_second_process_cannot_bypass_same_agent_gate(worker_binary, gated_resource):
    resource = gated_resource
    first = start(worker_binary, resource, "alice")
    assert resource["first"].wait(2), "first worker never entered resource"
    blocked = result(start(worker_binary, resource, "alice"))
    assert blocked["error_code"] == "execution_busy" and not blocked["executor_started"], blocked
    assert resource["counts"]["entered"] == 1 and resource["counts"]["maximum"] == 1
    resource["release"].set()
    assert result(first)["ok"]
    # A free slot can be reused only after the first execution is finished.
    assert result(start(worker_binary, resource, "alice"))["ok"]
    assert resource["counts"]["entered"] == 2 and resource["counts"]["maximum"] == 1


def test_independently_enrolled_agents_overlap_without_executor_fork_permission(worker_binary, gated_resource):
    resource = gated_resource
    first = start(worker_binary, resource, "alice")
    assert resource["first"].wait(2), "first worker never entered resource"
    second = start(worker_binary, resource, "bob")
    assert resource["two"].wait(2), "independent authority principals failed to overlap"
    assert resource["counts"]["entered"] == 2 and resource["counts"]["maximum"] == 2
    resource["release"].set()
    assert result(first)["ok"] and result(second)["ok"]
