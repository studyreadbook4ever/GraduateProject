"""Independent Provider fixtures; no developer credentials or databases."""

import sqlite3

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from saga.provider import Provider


ALICE = "a" * 64
BOB = "b" * 64


@pytest.fixture
def provider_env(tmp_path):
    notes = tmp_path / "notes.txt"
    notes.write_text("Alice's notes. Natural-language identities are untrusted.\n")
    output = tmp_path / "output.txt"
    output.write_text("")
    private = tmp_path / "private.txt"
    private.write_text("Bob only\n")
    database = tmp_path / "records.sqlite"
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE records (id INTEGER PRIMARY KEY, value TEXT)")
        db.execute("INSERT INTO records VALUES (1, 'sample')")
    config = {
        "agents": {
            "alice": {"certificate_sha256": ALICE, "tasks": ["research"]},
            "bob": {"certificate_sha256": BOB, "tasks": ["private"]},
        },
        "tasks": {
            "research": {
                "allow": [
                    {"tool": "read_file", "resource": "notes"},
                    {"tool": "write_file", "resource": "output"},
                    {"tool": "query_db", "resource": "records"},
                ]
            },
            "private": {"allow": [{"tool": "read_file", "resource": "private"}]},
        },
        "resources": {
            "notes": {"kind": "file", "path": str(notes)},
            "output": {"kind": "file", "path": str(output)},
            "private": {"kind": "file", "path": str(private)},
            "records": {
                "kind": "sqlite", "path": str(database),
                "queries": {"by_id": {"sql": "SELECT value FROM records WHERE id = ?", "parameters": 1}},
            },
        },
        "token_ttl_seconds": 60,
    }
    key = Ed25519PrivateKey.generate()
    state = tmp_path / "state.sqlite"
    now = [1_750_000_000.0]
    provider = Provider(config, state, key, clock=lambda: now[0])
    return {
        "provider": provider, "config": config, "state": state,
        "key": key, "now": now, "root": tmp_path,
    }


def rotate_body(epoch=0, tool="read_file", resource="notes", **arguments):
    return {
        "task_id": "research", "expected_epoch": epoch, "format": "canonical",
        "call": {"tool": tool, "arguments": {"resource": resource, **arguments}},
    }
