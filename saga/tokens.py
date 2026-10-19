"""Small signed capabilities, without JWT algorithm negotiation."""

import base64
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .config import path_string
from .jsonutil import dumps, loads

_COMPONENT = re.compile(r"^[A-Za-z0-9_-]+$")


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode(value: str) -> bytes:
    if not _COMPONENT.fullmatch(value):
        raise ValueError("invalid token encoding")
    raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    if _encode(raw) != value:
        raise ValueError("noncanonical token encoding")
    return raw


def load_private_key(value: Ed25519PrivateKey | str | Path) -> Ed25519PrivateKey:
    key = value if isinstance(value, Ed25519PrivateKey) else serialization.load_pem_private_key(Path(path_string(value, "signing key path")).read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Provider signing key must be Ed25519")
    return key


def load_public_key(value: Ed25519PublicKey | str | Path) -> Ed25519PublicKey:
    key = value if isinstance(value, Ed25519PublicKey) else serialization.load_pem_public_key(Path(path_string(value, "public key path")).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Provider public key must be Ed25519")
    return key


def sign_token(payload: dict, key: Ed25519PrivateKey) -> str:
    raw = dumps(payload).encode("utf-8")
    return _encode(raw) + "." + _encode(key.sign(raw))


def verify_token(token: str, public_key: Ed25519PublicKey | str | Path) -> dict:
    """Verify the signature and decode JSON; the Provider checks grant state.

    This function does not confer execution authority: expiry, certificate
    binding and one-use admission remain stateful Provider checks.
    """
    if not isinstance(token, str) or len(token) > 1_500_000 or token.count(".") != 1:
        raise ValueError("invalid token")
    payload64, signature64 = token.split(".")
    try:
        raw, signature = _decode(payload64), _decode(signature64)
        if len(signature) != 64:
            raise ValueError("invalid signature length")
        load_public_key(public_key).verify(signature, raw)
        payload = loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("token payload is not an object")
        return payload
    except (InvalidSignature, UnicodeError, RecursionError) as exc:
        raise ValueError("invalid token") from exc
