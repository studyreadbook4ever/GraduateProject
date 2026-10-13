"""Transactional capability authority.

All generation changes and execution admissions serialize in SQLite. A running
admission holds the agent gate until its exact execution ID is finished. There
is no lease expiry or worker-controlled revocation endpoint.
"""

import copy
import os
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path
from urllib.parse import urlsplit

from ..adapters import AdapterRegistry
from ..config import json_parameter, regular_path, sqlite_snapshot, validate_config
from ..errors import ProviderError
from ..jsonutil import dumps, loads
from ..tokens import load_private_key, sign_token, verify_token


def _reject(status: int, code: str, message: str):
    raise ProviderError(status, code, message)


def _body(value, fields: set[str]):
    if not isinstance(value, dict) or value.keys() != fields:
        _reject(400, "invalid_request", "request fields do not match this endpoint")


class Provider:
    def __init__(self, config: dict, state_db: str | Path, signing_key, clock=time.time, adapters: AdapterRegistry | None = None):
        self.config = validate_config(config)
        self.state_db = Path(state_db).absolute()
        self.signing_key = load_private_key(signing_key)
        self.clock = clock
        self.adapters = adapters or AdapterRegistry()
        self._identities = {agent["certificate_sha256"]: name for name, agent in self.config["agents"].items()}
        self.state_db.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        if any(part.is_symlink() for part in [self.state_db, *self.state_db.parents]):
            raise ValueError("state database path must not contain symlinks")
        directory_stat = self.state_db.parent.stat()
        if directory_stat.st_mode & 0o077 or directory_stat.st_uid != os.geteuid():
            raise ValueError("state database requires an owner-only directory (mode 0700)")
        if self.state_db.exists() and not self.state_db.is_file():
            raise ValueError("state database must be a regular file")
        fd = os.open(self.state_db, os.O_CREAT | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.chmod(self.state_db, 0o600)
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS agents (
                    agent_id TEXT PRIMARY KEY,
                    epoch INTEGER NOT NULL DEFAULT 0,
                    current_jti TEXT
                );
                CREATE TABLE IF NOT EXISTS grants (
                    jti TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                    task_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    token TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('ACTIVE','REVOKED','EXECUTING','FINISHED')),
                    issued_at INTEGER NOT NULL,
                    expires_at INTEGER NOT NULL,
                    execution_id TEXT UNIQUE,
                    UNIQUE(agent_id, epoch)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_live_grant_per_agent
                    ON grants(agent_id) WHERE status IN ('ACTIVE','EXECUTING');
                CREATE TABLE IF NOT EXISTS executions (
                    execution_id TEXT PRIMARY KEY,
                    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                    jti TEXT NOT NULL UNIQUE REFERENCES grants(jti),
                    admitted_at INTEGER NOT NULL,
                    outcome TEXT CHECK(outcome IN ('succeeded','failed')),
                    finished_at INTEGER
                );
                CREATE UNIQUE INDEX IF NOT EXISTS one_execution_per_agent
                    ON executions(agent_id) WHERE finished_at IS NULL;
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    jti TEXT NOT NULL,
                    event TEXT NOT NULL,
                    execution_id TEXT,
                    created_at INTEGER NOT NULL
                );
            """)
            for agent_id in self.config["agents"]:
                db.execute("INSERT OR IGNORE INTO agents(agent_id) VALUES (?)", (agent_id,))

    def _connect(self):
        db = sqlite3.connect(self.state_db, timeout=10, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA busy_timeout=10000")
        return db

    @contextmanager
    def _transaction(self):
        db = self._connect()
        try:
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _agent(self, certificate_sha256: str) -> str:
        if not isinstance(certificate_sha256, str):
            _reject(403, "unknown_agent", "certificate is not enrolled")
        agent_id = self._identities.get(certificate_sha256.lower())
        if agent_id is None:
            _reject(403, "unknown_agent", "certificate is not enrolled")
        return agent_id

    def state(self, certificate_sha256: str) -> dict:
        agent_id = self._agent(certificate_sha256)
        with closing(self._connect()) as db:
            row = db.execute("SELECT epoch FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
        return {"agent_id": agent_id, "epoch": row["epoch"]}

    def _capability(self, agent_id: str, task_id, format_name, call) -> dict:
        if not isinstance(task_id, str) or task_id not in self.config["agents"][agent_id]["tasks"]:
            _reject(403, "task_denied", "agent is not authorized for this task")
        normalized = self.adapters.normalize(format_name, call)
        tool, arguments = normalized["tool"], normalized["arguments"]
        resource_id = arguments.get("resource")
        if not isinstance(resource_id, str) or not any(rule["tool"] == tool and rule["resource"] == resource_id for rule in self.config["tasks"][task_id]["allow"]):
            _reject(403, "capability_denied", "tool and resource are not allowed for this task")
        required = {"resource"}
        if tool == "write_file":
            required.add("content")
        elif tool == "query_db":
            required |= {"query", "parameters"}
        if arguments.keys() != required:
            _reject(400, "invalid_arguments", "tool arguments do not match its schema")
        resource = self.config["resources"][resource_id]
        try:
            if resource["kind"] == "file":
                regular_path(resource["path"])
            elif resource["kind"] == "sqlite":
                sqlite_snapshot(resource["path"])
        except (ValueError, OSError):
            _reject(403, "resource_unavailable", "registered resource is no longer a safe file or database snapshot")
        if tool == "write_file":
            try:
                content_valid = isinstance(arguments["content"], str) and len(arguments["content"].encode("utf-8")) <= 1_048_576
            except UnicodeError:
                content_valid = False
            if not content_valid:
                _reject(400, "invalid_arguments", "content must be a string within the size limit")
        if tool == "query_db":
            query_name = arguments["query"]
            if not isinstance(query_name, str) or query_name not in resource["queries"]:
                _reject(403, "query_denied", "query name is not registered")
            parameters = arguments["parameters"]
            if not isinstance(parameters, list) or len(parameters) != resource["queries"][query_name]["parameters"] or not all(json_parameter(value) for value in parameters):
                _reject(400, "invalid_arguments", "query parameters do not match the registered query")
            if any(isinstance(value, int) and not isinstance(value, bool) and not -(2**63) <= value < 2**63 for value in parameters):
                _reject(400, "invalid_arguments", "SQLite integers must fit signed 64 bits")
        operation = {"read_file": "read", "write_file": "write", "query_db": "query", "http_get": "get"}[tool]
        if tool == "http_get":
            execution = {"url": resource["url"]}
            sandbox = {"paths": [], "tcp_ports": [urlsplit(resource["url"]).port or 80]}
        else:
            execution = {"path": resource["path"]}
            if tool == "query_db":
                execution["sql"] = resource["queries"][arguments["query"]]["sql"]
            sandbox = {"paths": [{"path": resource["path"], "access": "write" if tool == "write_file" else "read"}], "tcp_ports": []}
        capability = {"tool": tool, "resource": resource_id, "operation": operation, "arguments": copy.deepcopy(arguments), "execution": execution, "sandbox": sandbox}
        try:
            encoded = dumps(capability).encode("utf-8")
        except (UnicodeError, ValueError, RecursionError):
            _reject(400, "invalid_arguments", "arguments must be valid finite UTF-8 JSON")
        if len(encoded) > 1_048_576:
            _reject(413, "capability_too_large", "capability exceeds the serialized size limit")
        return capability

    def rotate(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        _body(body, {"task_id", "expected_epoch", "format", "call"})
        expected = body["expected_epoch"]
        if isinstance(expected, bool) or not isinstance(expected, int) or not 0 <= expected < 2**63 - 1:
            _reject(400, "invalid_epoch", "expected_epoch must be a nonnegative 64-bit integer")
        capability = self._capability(agent_id, body["task_id"], body["format"], body["call"])
        with self._transaction() as db:
            state = db.execute("SELECT epoch,current_jti FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if state["epoch"] != expected:
                _reject(409, "epoch_conflict", "agent generation changed; fetch current state")
            executing = db.execute("SELECT 1 FROM executions WHERE agent_id=? AND finished_at IS NULL", (agent_id,)).fetchone()
            if executing:
                _reject(409, "execution_busy", "finish the current execution before rotating")
            epoch, issued = expected + 1, int(self.clock())
            jti = secrets.token_hex(24)
            payload = {"v": 1, "iss": "saga-cap/provider", "aud": "saga-cap/worker", "sub": agent_id, "certificate_sha256": certificate_sha256.lower(), "task_id": body["task_id"], "epoch": epoch, "jti": jti, "iat": issued, "exp": issued + self.config["token_ttl_seconds"], "capability": capability}
            # Signing may fail; any exception rolls back revocation and generation.
            token = sign_token(payload, self.signing_key)
            if len(token) > 1_500_000:
                _reject(413, "capability_too_large", "signed capability exceeds the token size limit")
            previous = db.execute("SELECT jti,epoch FROM grants WHERE jti=? AND agent_id=? AND status IN ('ACTIVE','FINISHED')", (state["current_jti"], agent_id)).fetchone()
            if previous:
                db.execute("UPDATE grants SET status='REVOKED' WHERE jti=?", (previous["jti"],))
            if previous:
                self._audit(db, agent_id, previous["epoch"], previous["jti"], "revoked", issued)
            db.execute("INSERT INTO grants(jti,agent_id,task_id,epoch,token,payload,status,issued_at,expires_at) VALUES (?,?,?,?,?,?,'ACTIVE',?,?)", (jti, agent_id, body["task_id"], epoch, token, dumps(payload), issued, payload["exp"]))
            db.execute("UPDATE agents SET epoch=?,current_jti=? WHERE agent_id=?", (epoch, jti, agent_id))
            self._audit(db, agent_id, epoch, jti, "issued", issued)
        return {"token": token, "epoch": epoch, "agent_id": agent_id}

    def admit(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        _body(body, {"token"})
        try:
            payload = verify_token(body["token"], self.signing_key.public_key())
        except (ValueError, TypeError):
            _reject(403, "invalid_token", "token signature or encoding is invalid")
        if payload.get("sub") != agent_id or payload.get("certificate_sha256") != certificate_sha256.lower() or not isinstance(payload.get("jti"), str):
            _reject(403, "token_binding", "token is not bound to this certificate's agent")
        with self._transaction() as db:
            grant = db.execute("SELECT * FROM grants WHERE jti=? AND agent_id=?", (payload["jti"], agent_id)).fetchone()
            if grant is None or grant["token"] != body["token"]:
                _reject(403, "unknown_token", "token is not issued by this authority")
            state = db.execute("SELECT epoch,current_jti FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if state["current_jti"] != grant["jti"] or state["epoch"] != grant["epoch"] or grant["status"] != "ACTIVE":
                _reject(403, "inactive_token", "token is revoked or has already been consumed")
            if grant["expires_at"] <= int(self.clock()):
                _reject(403, "expired_token", "token has expired")
            capability = loads(grant["payload"])["capability"]
            try:
                current = self._capability(agent_id, grant["task_id"], "canonical", {"tool": capability["tool"], "arguments": capability["arguments"]})
            except ProviderError as exc:
                raise ProviderError(403, "policy_changed", "issued capability is no longer authorized by current policy") from exc
            if current != capability:
                _reject(403, "policy_changed", "registered execution scope changed after issuance")
            execution_id = secrets.token_hex(24)
            db.execute("UPDATE grants SET status='EXECUTING',execution_id=? WHERE jti=?", (execution_id, grant["jti"]))
            db.execute("INSERT INTO executions(execution_id,agent_id,jti,admitted_at) VALUES (?,?,?,?)", (execution_id, agent_id, grant["jti"], int(self.clock())))
            self._audit(db, agent_id, grant["epoch"], grant["jti"], "admitted", int(self.clock()), execution_id)
        return {"execution_id": execution_id, "capability": capability}

    def finish(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        _body(body, {"execution_id", "outcome"})
        if not isinstance(body["execution_id"], str) or not isinstance(body["outcome"], str) or body["outcome"] not in {"succeeded", "failed"}:
            _reject(400, "invalid_completion", "completion requires an execution ID and succeeded or failed")
        with self._transaction() as db:
            execution = db.execute("SELECT * FROM executions WHERE execution_id=? AND agent_id=?", (body["execution_id"], agent_id)).fetchone()
            if execution is None:
                _reject(403, "unknown_execution", "execution is not owned by this agent")
            grant = db.execute("SELECT epoch,payload FROM grants WHERE jti=?", (execution["jti"],)).fetchone()
            if loads(grant["payload"]).get("certificate_sha256") != certificate_sha256.lower():
                _reject(403, "execution_binding", "completion requires the execution's original certificate")
            if execution["finished_at"] is not None:
                if execution["outcome"] != body["outcome"]:
                    _reject(409, "completion_conflict", "execution already finished with another outcome")
            else:
                db.execute("UPDATE executions SET outcome=?,finished_at=? WHERE execution_id=?", (body["outcome"], int(self.clock()), body["execution_id"]))
                db.execute("UPDATE grants SET status='FINISHED' WHERE jti=? AND status='EXECUTING'", (execution["jti"],))
                self._audit(db, agent_id, grant["epoch"], execution["jti"], "finished", int(self.clock()), body["execution_id"])
        return {"execution_id": body["execution_id"], "outcome": body["outcome"], "finished": True}

    @staticmethod
    def _audit(db, agent_id, epoch, jti, event, created_at, execution_id=None):
        db.execute("INSERT INTO audit_events(agent_id,epoch,jti,event,execution_id,created_at) VALUES (?,?,?,?,?,?)", (agent_id, epoch, jti, event, execution_id, created_at))

    def audit_events(self, certificate_sha256: str) -> list[dict]:
        """Read committed transitions for an enrolled agent; never expose tokens."""
        agent_id = self._agent(certificate_sha256)
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM audit_events WHERE agent_id=? ORDER BY event_id", (agent_id,)).fetchall()
        return [dict(row) for row in rows]
