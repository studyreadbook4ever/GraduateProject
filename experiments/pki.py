"""Disposable CA and agent certificates for examples and integration tests."""

import datetime as dt
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _private(path, key):
    path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    path.chmod(0o600)


def generate(directory):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SAGA isolated experiment CA")])
    ca = (
        x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(True, False, False, False, False, True, True, False, False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (directory / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    # Only certificates are needed after issuing; the ephemeral CA key is never saved.
    fingerprints = {}
    for name in ("server", "alice", "bob", "unregistered"):
        key = ec.generate_private_key(ec.SECP256R1())
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "alice" if name == "unregistered" else name)]))
            .issuer_name(ca_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(True, False, False, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.SERVER_AUTH if name == "server" else ExtendedKeyUsageOID.CLIENT_AUTH
            ]), critical=False)
        )
        if name == "server":
            cert = cert.add_extension(x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")
            ]), critical=False)
        cert = cert.sign(ca_key, hashes.SHA256())
        (directory / f"{name}.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        _private(directory / f"{name}-key.pem", key)
        fingerprints[name] = cert.fingerprint(hashes.SHA256()).hex()
    signer = ed25519.Ed25519PrivateKey.generate()
    _private(directory / "provider-key.pem", signer)
    (directory / "provider-public.pem").write_bytes(signer.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return fingerprints
