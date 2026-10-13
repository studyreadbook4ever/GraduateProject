"""Exercise certificate identity and malformed transport input on a real TLS socket."""

import copy
import json
import ssl
import threading
import urllib.error
import urllib.request

import pytest

from experiments.pki import generate
from experiments.run import api
from saga.provider import Provider
from saga.provider.server import create_server

from conftest import rotate_body


@pytest.fixture
def tls_provider(provider_env):
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
        yield server.server_address[1], pki, provider, fingerprints
    finally:
        server.shutdown(); server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


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
