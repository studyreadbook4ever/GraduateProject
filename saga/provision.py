"""Create an isolated development deployment with fresh certificates and data."""

import datetime
import ipaddress
import os
import sqlite3
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from .jsonutil import dumps


def _write(path: Path, raw: bytes, mode: int = 0o600):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    with os.fdopen(descriptor, "wb") as output:
        output.write(raw)


def _write_key(path: Path, key):
    _write(path, key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))


def _name(common_name: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(subject, key, issuer, issuer_key, ca=False, server=False):
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=0 if ca else None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False, key_agreement=False, key_cert_sign=ca, crl_sign=ca, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
    )
    if not ca:
        builder = builder.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
    if server:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.IPAddress(ipaddress.ip_address("::1")), x509.DNSName("localhost")]), critical=False)
    return builder.sign(issuer_key, algorithm=None)


def provision(directory: str | Path, provider_port: int = 8443, http_port: int = 8765) -> dict:
    """Write a fresh owner-only development directory; never overwrite files.

    The CA key stays here for test enrollment only. Production operators should
    use an existing certificate authority and their normal key-management flow.
    """
    directory = Path(directory).absolute()
    if any(path.is_symlink() for path in [directory, *directory.parents]):
        raise ValueError("provisioning directory must not contain symlinks")
    if directory.exists():
        if not directory.is_dir() or any(directory.iterdir()):
            raise ValueError("provisioning requires a new or empty directory")
    else:
        directory.mkdir(mode=0o700, parents=True)
    os.chmod(directory, 0o700)
    if not 1 <= provider_port <= 65535 or not 1 <= http_port <= 65535:
        raise ValueError("ports must be between 1 and 65535")
    ca_key = Ed25519PrivateKey.generate()
    ca_cert = _certificate("SAGA development CA", ca_key, _name("SAGA development CA"), ca_key, ca=True)
    _write_key(directory / "ca-key.pem", ca_key)
    _write(directory / "ca.pem", ca_cert.public_bytes(serialization.Encoding.PEM))
    certificates = {}
    for name in ("server", "agent", "other-agent"):
        key = Ed25519PrivateKey.generate()
        certificate = _certificate(name, key, ca_cert.subject, ca_key, server=name == "server")
        certificates[name] = certificate
        _write_key(directory / f"{name}-key.pem", key)
        _write(directory / f"{name}.pem", certificate.public_bytes(serialization.Encoding.PEM))
    signing_key = Ed25519PrivateKey.generate()
    _write_key(directory / "provider-signing-key.pem", signing_key)
    _write(directory / "provider-public-key.pem", signing_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    _write(directory / "notes.txt", b"An isolated SAGA capability demonstration.\n")
    _write(directory / "private.txt", b"This resource is not registered for the demo agent.\n")
    _write(directory / "demo.sqlite", b"")
    with sqlite3.connect(directory / "demo.sqlite") as db:
        db.execute("CREATE TABLE messages (id INTEGER PRIMARY KEY, text TEXT NOT NULL)")
        db.execute("INSERT INTO messages(text) VALUES ('task-scoped capability')")
    provider_config = {
        "agents": {
            "demo-agent": {"certificate_sha256": certificates["agent"].fingerprint(hashes.SHA256()).hex(), "tasks": ["demo"]},
            "other-agent": {"certificate_sha256": certificates["other-agent"].fingerprint(hashes.SHA256()).hex(), "tasks": []},
        },
        "tasks": {"demo": {"allow": [{"tool": tool, "resource": resource} for tool, resource in [("read_file", "notes"), ("write_file", "notes"), ("query_db", "database"), ("http_get", "status")]]}},
        "resources": {
            "notes": {"kind": "file", "path": str(directory / "notes.txt")},
            "database": {"kind": "sqlite", "path": str(directory / "demo.sqlite"), "queries": {"message": {"sql": "SELECT text FROM messages WHERE id = ?", "parameters": 1}}},
            "status": {"kind": "http", "url": f"http://127.0.0.1:{http_port}/status"},
        },
        "token_ttl_seconds": 60,
    }
    worker_config = {
        "provider_url": f"https://127.0.0.1:{provider_port}",
        "ca_certificate": str(directory / "ca.pem"),
        "client_certificate": str(directory / "agent.pem"),
        "client_key": str(directory / "agent-key.pem"),
        "provider_public_key": str(directory / "provider-public-key.pem"),
        "agent_id": "demo-agent",
    }
    _write(directory / "provider.json", (dumps(provider_config) + "\n").encode())
    _write(directory / "worker.json", (dumps(worker_config) + "\n").encode())
    call = {"task_id": "demo", "format": "canonical", "call": {"tool": "read_file", "arguments": {"resource": "notes"}}}
    _write(directory / "calls.jsonl", (dumps(call) + "\n").encode())
    return {"directory": str(directory), "provider_config": str(directory / "provider.json"), "worker_config": str(directory / "worker.json")}
