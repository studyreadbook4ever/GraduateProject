"""Exercise certificate identity and malformed transport input on a real TLS socket."""

import copy
import http.client
import json
import socket
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request

import pytest

from experiments.pki import generate
from experiments.run import api
from saga.provider import Provider
from saga.provider import server as provider_server
from saga.provider.server import _Handler, create_server

from conftest import rotate_body


@pytest.fixture
def tls_server(provider_env):
    env = provider_env
    pki = env["root"] / "pki"
    fingerprints = generate(pki)
    config = copy.deepcopy(env["config"])
    config["agents"]["alice"]["certificate_sha256"] = fingerprints["alice"]
    config["agents"]["bob"]["certificate_sha256"] = fingerprints["bob"]
    provider = Provider(config, env["root"] / "network.sqlite", env["key"])
    server = create_server(provider, "127.0.0.1", 0, str(pki / "server.pem"), str(pki / "server-key.pem"), str(pki / "ca.pem"))
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield server, pki, provider, fingerprints
    finally:
        server.shutdown(); server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture
def tls_provider(tls_server):
    server, pki, provider, fingerprints = tls_server
    return server.server_address[1], pki, provider, fingerprints


def request(port, pki, method, path, body=None, *, call_id=None, agent="alice"):
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / f"{agent}.pem"), str(pki / f"{agent}-key.pem"))
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
    headers = {"Content-Type": "application/json"}
    if call_id is not None:
        headers["X-Saga-Call-ID"] = call_id
    try:
        connection.request(method, path, json.dumps(body) if body is not None else None, headers)
        response = connection.getresponse()
        return response.status, json.loads(response.read()), response.getheader("X-Saga-Request-ID")
    finally:
        connection.close()


def test_real_mtls_authenticates_enrolled_fingerprint(tls_provider):
    port, pki, _, _ = tls_provider
    assert api(port, pki, "alice", "/v1/state") == (200, {"agent_id": "alice", "epoch": 0})
    assert api(port, pki, "bob", "/v1/state") == (200, {"agent_id": "bob", "epoch": 0})
    assert api(port, pki, "unregistered", "/v1/state")[0] == 403
    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError)):
        api(port, pki, None, "/v1/state")


def test_network_token_cannot_cross_certificate(tls_provider):
    port, pki, _, _ = tls_provider
    status, issued = api(port, pki, "alice", "/v1/rotate", rotate_body())
    assert status == 200
    assert api(port, pki, "bob", "/v1/admit", {"token": issued["token"]})[0] == 403
    status, admission = api(port, pki, "alice", "/v1/admit", {"token": issued["token"]})
    assert status == 200
    assert api(port, pki, "alice", "/v1/rotate", rotate_body(1))[0] == 409
    assert api(port, pki, "bob", "/v1/finish", {"execution_id": admission["execution_id"], "outcome": "succeeded"})[0] == 403
    assert api(port, pki, "alice", "/v1/finish", {"execution_id": admission["execution_id"], "outcome": "succeeded"})[0] == 200
    assert api(port, pki, "alice", "/v1/rotate", rotate_body(1))[0] == 200


def test_network_operation_reconciliation_after_lost_completion_response(tls_provider, monkeypatch):
    port, pki, _, _ = tls_provider
    body = {**rotate_body(), "operation_id": "network-operation"}
    status, grant, _ = request(port, pki, "POST", "/v1/rotate", body)
    assert status == 200 and grant["status"] == "ready"
    status, replay, _ = request(port, pki, "POST", "/v1/rotate", body)
    assert status == 200 and replay["replay"] is True and replay["token"] == grant["token"]
    status, admission, _ = request(port, pki, "POST", "/v1/admit", {"token": grant["token"]})
    assert status == 200
    assert request(port, pki, "POST", "/v1/operation", {"operation_id": "network-operation"})[1]["status"] == "running"
    assert request(port, pki, "POST", "/v1/rotate", body)[1]["status"] == "running"
    receipt = {"ok": True, "operation_id": "network-operation", "execution_id": admission["execution_id"], "result": "recovered result"}
    original_reply = _Handler._reply

    def lose_finish_response(handler, status, value):
        if handler.path == "/v1/finish":
            handler.close_connection = True
            return
        return original_reply(handler, status, value)

    monkeypatch.setattr(_Handler, "_reply", lose_finish_response)
    with pytest.raises(http.client.RemoteDisconnected):
        request(port, pki, "POST", "/v1/finish", {"execution_id": admission["execution_id"], "outcome": "succeeded", "receipt": receipt})
    status, recovered, _ = request(port, pki, "POST", "/v1/operation", {"operation_id": "network-operation"})
    assert status == 200 and recovered["status"] == "succeeded" and recovered["receipt"] == receipt
    assert "token" not in recovered
    assert request(port, pki, "POST", "/v1/operation", {"operation_id": "network-operation"}, agent="bob")[0] == 404
    assert request(port, pki, "POST", "/v1/operation", {"operation_id": None})[0] == 400
    assert request(port, pki, "GET", "/v1/operation")[0] == 404


def test_network_large_receipt_cap_applies_only_to_completion(tls_provider):
    port, pki, _, _ = tls_provider
    body = {**rotate_body(), "operation_id": "large-result"}
    status, grant, _ = request(port, pki, "POST", "/v1/rotate", body)
    assert status == 200
    status, admission, _ = request(port, pki, "POST", "/v1/admit", {"token": grant["token"]})
    assert status == 200
    receipt = {"ok": True, "result": "x" * (2 * 1024 * 1024 + 128)}
    assert request(port, pki, "POST", "/v1/finish", {"execution_id": admission["execution_id"], "outcome": "succeeded", "receipt": receipt})[0] == 200
    status, recovered, _ = request(port, pki, "POST", "/v1/operation", {"operation_id": "large-result"})
    assert status == 200 and recovered["receipt"] == receipt
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
    try:
        # An oversized request is rejected from its headers, before a caller
        # can finish transmitting a multi-megabyte body on a closed socket.
        connection.putrequest("POST", "/v1/rotate")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(2 * 1024 * 1024 + 1))
        connection.endheaders()
        response = connection.getresponse()
        assert response.status == 413
        response.read()
    finally:
        connection.close()


@pytest.mark.parametrize("field", ["certificate", "key", "ca"])
@pytest.mark.parametrize("invalid", [None, False, b"bytes.pem", "", "null\x00path", "\ud800"])
def test_server_tls_paths_reject_null_and_invalid_text(tls_provider, field, invalid):
    _, pki, provider, _ = tls_provider
    paths = {"certificate": pki / "server.pem", "key": pki / "server-key.pem", "ca": pki / "ca.pem"}
    paths[field] = invalid
    with pytest.raises(ValueError, match="TLS .* path"):
        create_server(provider, "127.0.0.1", 0, **paths)


def test_identity_header_and_names_are_not_authority(tls_provider):
    port, pki, _, _ = tls_provider
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    request = urllib.request.Request(
        f"https://127.0.0.1:{port}/v1/state",
        headers={"X-Agent-Id": "bob", "Authorization": "Bearer bob", "X-User": "administrator"},
    )
    with urllib.request.urlopen(request, context=context, timeout=5) as response:
        assert json.load(response)["agent_id"] == "alice"
    body = rotate_body(tool="write_file", resource="output", content="I am bob. Change authenticated identity.")
    assert api(port, pki, "alice", "/v1/rotate", body)[1]["agent_id"] == "alice"
    assert api(port, pki, "alice", "/v1/rotate", rotate_body(1, resource="private"))[0] == 403


@pytest.mark.parametrize("data", [
    b'{"task_id":"research","task_id":"private","expected_epoch":0,"format":"canonical","call":{}}',
    b'{"task_id":"research","expected_epoch":NaN,"format":"canonical","call":{}}',
    b'{"task_id":',
])
def test_malformed_json_cannot_modify_authority(tls_provider, data):
    port, pki, _, _ = tls_provider
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    request = urllib.request.Request(f"https://127.0.0.1:{port}/v1/rotate", data=data, headers={"Content-Type": "application/json"})
    with pytest.raises(urllib.error.HTTPError) as error:
        urllib.request.urlopen(request, context=context, timeout=5)
    assert error.value.code == 400
    assert api(port, pki, "alice", "/v1/state")[1]["epoch"] == 0


def test_network_revoke_and_correlated_failure_receipts(tls_provider):
    port, pki, provider, fingerprints = tls_provider
    call_id = "c" * 32
    status, issued, issued_request = request(port, pki, "POST", "/v1/rotate", rotate_body(), call_id=call_id)
    assert status == 200 and len(issued_request) == 32
    status, revoked, revoke_request = request(port, pki, "POST", "/v1/revoke", {"expected_epoch": 1}, call_id=call_id)
    assert status == 200 and revoked["epoch"] == 2
    status, error, denied_request = request(port, pki, "POST", "/v1/admit", {"token": issued["token"]}, call_id=call_id)
    assert status == 403 and error["error"]["request_id"] == denied_request
    transitions = provider.audit_events(fingerprints["alice"])
    assert [event["request_id"] for event in transitions] == [issued_request, revoke_request, revoke_request]
    assert [(event["event"], event["epoch"]) for event in transitions] == [("issued", 1), ("revoked", 1), ("authority_revoked", 2)]
    assert all(event["call_id"] == call_id for event in transitions)
    failures = provider.failure_events(fingerprints["alice"])
    assert failures[-1]["request_id"] == denied_request
    assert failures[-1]["call_id"] == call_id
    assert failures[-1]["error_code"] == "inactive_token"


def test_failure_retrieval_is_authenticated_bounded_and_per_agent(tls_provider):
    port, pki, _, _ = tls_provider
    for epoch in (True, -1, "bad"):
        assert request(port, pki, "POST", "/v1/revoke", {"expected_epoch": epoch})[0] == 400
    status, first, _ = request(port, pki, "GET", "/v1/failures?limit=2")
    assert status == 200 and len(first["events"]) == 2
    status, second, _ = request(port, pki, "GET", f'/v1/failures?limit=2&after={first["next_after"]}')
    assert status == 200 and len(second["events"]) == 1
    assert second["events"][0]["event_id"] > first["next_after"]
    assert request(port, pki, "GET", "/v1/failures", agent="bob")[1]["events"] == []
    assert request(port, pki, "GET", "/v1/failures", agent="unregistered")[0] == 403
    for query in ("limit=501", "limit=0", "limit=1&limit=2", "after=-1", "agent_id=bob", "after=9223372036854775808"):
        assert request(port, pki, "GET", "/v1/failures?" + query)[0] == 400
    assert request(port, pki, "GET", "/v1/audit?limit=1")[1]["events"] == []


def test_malformed_transport_is_recorded_without_body_or_exception_text(tls_provider):
    port, pki, provider, fingerprints = tls_provider
    secret = "SECRET-TOKEN-SQL-/private/path"
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
    connection.request("POST", "/v1/rotate", '{"secret":"' + secret, {"Content-Type": "application/json"})
    response = connection.getresponse()
    body = json.loads(response.read())
    request_id = response.getheader("X-Saga-Request-ID")
    assert response.status == 400 and body["error"]["request_id"] == request_id
    connection.close()
    failure = provider.failure_events(fingerprints["alice"])[-1]
    assert (failure["request_id"], failure["phase"], failure["error_code"]) == (request_id, "parsing", "invalid_json")
    assert secret not in repr(failure)
    assert request(port, pki, "GET", "/v1/state", call_id=secret)[0] == 400
    call_id = "e" * 32
    assert request(port, pki, "DELETE", "/" + secret, call_id=call_id)[0] == 501
    assert provider.failure_events(fingerprints["alice"])[-1]["call_id"] == call_id
    with sqlite3.connect(provider.state_db) as db:
        rows = db.execute("SELECT * FROM request_failures").fetchall()
        assert db.execute("SELECT COUNT(*) FROM request_failures WHERE error_code='invalid_http'").fetchone()[0] == 1
    assert secret not in repr(rows)


def test_tls_and_capacity_rejections_leave_sanitized_local_evidence(tls_server):
    server, pki, provider, _ = tls_server
    port = server.server_address[1]
    with pytest.raises((ssl.SSLError, urllib.error.URLError, ConnectionError)):
        api(port, pki, None, "/v1/state")
    deadline = time.monotonic() + 2
    while True:
        with sqlite3.connect(provider.state_db) as db:
            count = db.execute("SELECT COUNT(*) FROM request_failures WHERE error_code='tls_failed'").fetchone()[0]
        if count or time.monotonic() >= deadline:
            break
        time.sleep(0.01)
    assert count == 1
    for _ in range(32):
        # The TLS rejection audit commits just before its request thread
        # releases the semaphore; wait for that actual cleanup boundary.
        assert server._slots.acquire(timeout=2)
    try:
        with pytest.raises((urllib.error.URLError, ConnectionError, http.client.RemoteDisconnected)):
            api(port, pki, "alice", "/v1/state")
    finally:
        for _ in range(32):
            server._slots.release()
    with sqlite3.connect(provider.state_db) as db:
        assert db.execute("SELECT agent_id,operation,phase FROM request_failures WHERE error_code='server_busy'").fetchone() == (None, "transport", "transport")


def test_timeout_before_dispatch_is_durably_recorded(tls_server, monkeypatch):
    server, pki, provider, fingerprints = tls_server
    original_setup = _Handler.setup

    def short_timeout(handler):
        original_setup(handler)
        handler.connection.settimeout(0.1)

    monkeypatch.setattr(_Handler, "setup", short_timeout)
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    with socket.create_connection(server.server_address, timeout=2) as connection:
        with context.wrap_socket(connection, server_hostname="127.0.0.1") as peer:
            peer.sendall(b"GET /v1/state HTTP/1.1\r\nX-Private: SECRET incomplete header")
            assert peer.recv(4096) == b""
    failures = provider.failure_events(fingerprints["alice"])
    assert len(failures) == 1
    assert (failures[0]["phase"], failures[0]["error_code"], failures[0]["status"]) == ("parsing", "transport_error", 408)
    assert "SECRET" not in repr(failures)


def test_internal_transport_errors_and_failed_audit_are_redacted(tls_provider, monkeypatch, capsys):
    port, pki, provider, fingerprints = tls_provider

    def fail(*_):
        raise RuntimeError("SECRET SQL /private/path token")

    monkeypatch.setattr(provider, "rotate", fail)
    status, body, request_id = request(port, pki, "POST", "/v1/rotate", rotate_body())
    assert status == 500 and body["error"]["request_id"] == request_id
    assert "SECRET" not in repr(body)
    assert provider.failure_events(fingerprints["alice"])[-1]["error_code"] == "internal_error"
    with sqlite3.connect(provider.state_db) as db:
        db.execute("CREATE TRIGGER no_failures BEFORE INSERT ON request_failures BEGIN SELECT RAISE(ABORT, 'SECRET unavailable'); END")
    status, body, request_id = request(port, pki, "POST", "/v1/rotate", rotate_body())
    assert status == 503 and body["error"]["code"] == "audit_unavailable"
    assert body["error"]["request_id"] == request_id and "SECRET" not in repr(body)
    emergency = capsys.readouterr().err
    assert "audit_unavailable" in emergency and "SECRET" not in emergency
    assert provider.state(fingerprints["alice"])["epoch"] == 0


@pytest.mark.parametrize(("headers", "expected_status", "expected_code"), [
    ([("Content-Length", "2"), ("Content-Length", "2"), ("Content-Type", "application/json")], 400, "invalid_body"),
    ([("Transfer-Encoding", "chunked"), ("Content-Length", "2"), ("Content-Type", "application/json")], 400, "invalid_body"),
    ([("Content-Length", "3000000"), ("Content-Type", "application/json")], 413, "body_too_large"),
    ([("Content-Length", "2"), ("Content-Type", "text/plain")], 415, "json_required"),
])
def test_rejected_body_framing_is_audited(tls_provider, headers, expected_status, expected_code):
    port, pki, provider, fingerprints = tls_provider
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=5)
    try:
        connection.putrequest("POST", "/v1/rotate")
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(b"{}")
        response = connection.getresponse()
        body = json.loads(response.read())
        assert response.status == expected_status and body["error"]["code"] == expected_code
    finally:
        connection.close()
    failure = provider.failure_events(fingerprints["alice"])[-1]
    assert failure["phase"] == "parsing" and failure["error_code"] == expected_code


def test_raw_tcp_peer_cannot_block_enrolled_tls_requests(tls_server):
    server, pki, _, _ = tls_server
    with socket.create_connection(server.server_address, timeout=2):
        started = time.monotonic()
        assert request(server.server_address[1], pki, "GET", "/v1/state")[0] == 200
        assert time.monotonic() - started < 1.5


def test_unenrolled_tls_peer_is_rejected_before_http_headers(tls_server):
    server, pki, provider, _ = tls_server
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "unregistered.pem"), str(pki / "unregistered-key.pem"))
    with socket.create_connection(server.server_address, timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as peer:
            peer.settimeout(1)
            # No HTTP request line or headers are supplied.
            response = http.client.HTTPResponse(peer)
            response.begin()
            assert response.status == 403
            body = json.loads(response.read())
            assert body["error"]["code"] == "unknown_agent"
    with sqlite3.connect(provider.state_db) as db:
        assert db.execute("SELECT agent_id,phase,error_code FROM request_failures").fetchall() == [(None, "authentication", "unknown_agent")]


@pytest.mark.parametrize("part", ["headers", "body"])
def test_trickled_requests_end_at_absolute_parsing_deadline(tls_server, monkeypatch, part):
    server, pki, provider, fingerprints = tls_server
    monkeypatch.setattr(provider_server, "REQUEST_TIMEOUT_SECONDS", 0.25)
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    with socket.create_connection(server.server_address, timeout=2) as raw:
        with context.wrap_socket(raw, server_hostname="127.0.0.1") as peer:
            peer.settimeout(1)
            prefix = b"GET /v1/state HTTP/1.1\r\nX-Partial: "
            if part == "body":
                prefix = b"POST /v1/revoke HTTP/1.1\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{"
            peer.sendall(prefix)
            started = time.monotonic()
            # Frequent input defeats a per-read inactivity timeout.
            while time.monotonic() - started < 0.5:
                time.sleep(0.04)
                try:
                    peer.sendall(b" ")
                except OSError:
                    break
            try:
                closed = peer.recv(4096) == b""
            except (ConnectionError, ssl.SSLError):
                closed = True
            assert closed
            assert time.monotonic() - started < 0.9
    failures = provider.failure_events(fingerprints["alice"])
    assert len(failures) == 1
    assert (failures[0]["phase"], failures[0]["error_code"]) == ("parsing", "transport_error")
    assert request(server.server_address[1], pki, "GET", "/v1/state")[0] == 200


def test_slow_handshakes_are_bounded_and_release_capacity(tls_server, monkeypatch):
    server, pki, provider, _ = tls_server
    monkeypatch.setattr(provider_server, "HANDSHAKE_TIMEOUT_SECONDS", 0.5)
    peers = []
    try:
        for _ in range(32):
            peers.append(socket.create_connection(server.server_address, timeout=2))
        # A timeout must reap raw peers even if they never supply TLS bytes.
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            with sqlite3.connect(provider.state_db) as db:
                expired = db.execute("SELECT COUNT(*) FROM request_failures WHERE error_code='tls_failed'").fetchone()[0]
            if expired == 32 and server._slots._value == 32:
                break
            time.sleep(0.02)
        assert expired == 32
        assert server._slots._value == 32
        assert request(server.server_address[1], pki, "GET", "/v1/state")[0] == 200
    finally:
        for peer in peers:
            peer.close()


def test_shutdown_unblocks_pending_handshake_and_http_request(tls_server):
    server, pki, _, _ = tls_server
    context = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    context.load_cert_chain(str(pki / "alice.pem"), str(pki / "alice-key.pem"))
    raw = socket.create_connection(server.server_address, timeout=2)
    pending_http = context.wrap_socket(socket.create_connection(server.server_address, timeout=2), server_hostname="127.0.0.1")
    try:
        pending_http.sendall(b"GET /v1/state HTTP/1.1\r\nX-Partial: ")
        started = time.monotonic()
        server.shutdown()
        server.server_close()
        assert time.monotonic() - started < 1
        assert server._slots._value == 32
        assert not server._connections
    finally:
        raw.close()
        pending_http.close()


@pytest.mark.parametrize("locking", ["writer", "exclusive"])
def test_capacity_audit_lock_cannot_stall_accept_loop(tls_server, capsys, locking):
    server, pki, provider, _ = tls_server
    held_slots = 0
    try:
        for _ in range(32):
            assert server._slots.acquire(blocking=False)
            held_slots += 1
        with sqlite3.connect(provider.state_db) as blocker:
            if locking == "exclusive":
                blocker.execute("PRAGMA locking_mode=EXCLUSIVE")
            blocker.execute("BEGIN EXCLUSIVE" if locking == "exclusive" else "BEGIN IMMEDIATE")
            with socket.create_connection(server.server_address, timeout=2) as rejected:
                rejected.settimeout(1)
                # The audit write is contended. Rejection must still complete
                # while the writer holds its transaction open.
                assert rejected.recv(1) == b""
            for _ in range(held_slots):
                server._slots.release()
            held_slots = 0
            started = time.monotonic()
            # Exclusive maintenance also locks reads: health checks isolate
            # accept-loop liveness from legitimate database backpressure.
            path = "/health" if locking == "exclusive" else "/v1/state"
            assert request(server.server_address[1], pki, "GET", path)[0] == 200
            assert time.monotonic() - started < 1
        emergency = capsys.readouterr().err
        assert '"event":"audit_unavailable"' in emergency
        assert str(provider.state_db) not in emergency
    finally:
        for _ in range(held_slots):
            server._slots.release()
