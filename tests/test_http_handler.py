"""Adversarial HTTP wire responses through the actual admitted native handler."""

import socket
import threading
from contextlib import contextmanager

import pytest

from test_kernel import worker_binary
from test_mtls import tls_provider, tls_server
from test_worker import client_env


@contextmanager
def raw_endpoint(response):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        failures = []

        def serve():
            try:
                with listener.accept()[0] as connection:
                    connection.settimeout(5)
                    request = b""
                    while b"\r\n\r\n" not in request:
                        part = connection.recv(4096)
                        if not part:
                            raise RuntimeError("incomplete test request")
                        request += part
                    connection.sendall(response)
                    connection.shutdown(socket.SHUT_WR)
            except BaseException as error:
                failures.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield listener.getsockname()[1]
        finally:
            thread.join(timeout=7)
            assert not thread.is_alive(), "raw endpoint did not stop"
            assert not failures, failures


def fetch(client_env, response):
    client, provider, fingerprint, _, _ = client_env
    with raw_endpoint(response) as port:
        provider.config["resources"]["wire"] = {"kind": "http", "url": f"http://127.0.0.1:{port}/resource"}
        provider.config["tasks"]["research"]["allow"].append({"tool": "http_get", "resource": "wire"})
        receipt = client.request_resource(task_id="research", tool="http_get", resource="wire", timeout=15)
    return receipt, provider.audit_events(fingerprint)[-1]


@pytest.mark.parametrize("response", [
    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nhi",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nextra",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc",
    b"HTTP/1.1 200 OK\r\nContent-Length: nonsense\r\n\r\nabc",
    b"HTTP/1.X 200 OK\r\n\r\nabc",
    b"HTTP/1.1 200garbage\r\n\r\nabc",
    b"HTTP/1.1 099 Bad\r\n\r\nabc",
    b"HTTP/1.1 200 OK\r\nBroken Header\r\n\r\nabc",
    b"HTTP/1.1 200 OK\r\nContent-Length : 2\r\n\r\nhi",
    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n",
    b"HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551616\r\n\r\nhi",
    b"HTTP/1.1 200 OK\r\nContent-Length: 2, 3\r\n\r\nhi",
    b"HTTP/1.1 204 No Content\r\n\r\nforbidden",
    b"HTTP/1.1 100 Continue\r\n\r\n",
], ids=["truncated", "overlong", "conflicting-lengths", "invalid-length", "version", "status-suffix",
        "status-range", "header-syntax", "header-whitespace", "unsupported-transfer-encoding",
        "length-overflow", "conflicting-combined-lengths", "body-forbidden", "no-final-status"])
def test_invalid_or_incomplete_http_is_never_a_success(client_env, response):
    receipt, completion = fetch(client_env, response)
    assert receipt["ok"] is False, receipt
    assert receipt["executor_started"] and receipt["completion_recorded"]
    assert completion["event"] == "finished" and completion["outcome"] == "failed"


@pytest.mark.parametrize("response,status,body", [
    (b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi", 200, "hi"),
    (b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\nmissing", 404, "missing"),
    (b"HTTP/1.1 200 OK\r\nX-Note: transfer-encoding: irrelevant\r\nContent-Length: 2\r\n\r\nhi", 200, "hi"),
    (b"HTTP/1.1 200 OK\r\nContent-Length: 02, 2\r\nContent-Length: 2\r\n\r\nhi", 200, "hi"),
    (b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi", 200, "hi"),
    (b"HTTP/1.1 304 Not Modified\r\nContent-Length: 19\r\n\r\n", 304, ""),
    (b"HTTP/1.1 304 Not Modified\r\nContent-Length: 18446744073709551615\r\n\r\n", 304, ""),
], ids=["exact-length", "close-delimited-status-result", "header-value-is-not-header-name",
        "identical-lengths", "informational-then-final", "no-body-metadata-length", "large-no-body-metadata"])
def test_complete_registered_http_responses_remain_valid(client_env, response, status, body):
    receipt, completion = fetch(client_env, response)
    assert receipt["ok"] is True, receipt
    assert receipt["result"] == {"status": status, "body": body}
    assert completion["outcome"] == "succeeded"
