"""Transactional capability authority.

All generation changes and execution admissions serialize in SQLite. A running
admission holds the agent gate until its exact execution ID is finished. There
is no lease expiry. Revocation fences future admission, never a running effect.
"""

import copy
import os
import re
import secrets
import sqlite3
import sys
import time
from contextlib import closing, contextmanager
from contextvars import ContextVar
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from ..adapters import AdapterRegistry
from ..config import json_parameter, path_string, regular_path, sqlite_snapshot, validate_config
from ..errors import ProviderError
from ..jsonutil import dumps, loads
from ..tokens import load_private_key, sign_token, verify_token


FAILURE_CODES = frozenset({
    "execution_failed", "sandbox_unavailable", "sandbox_setup_failed",
    "worker_timeout", "invalid_worker_output", "worker_failed", "completion_uncertain",
})
MAX_RECEIPT_BYTES = 4 * 1024 * 1024 + 64 * 1024
_ERROR_CODES = frozenset({
    "invalid_request", "unknown_agent", "task_denied", "capability_denied",
    "invalid_arguments", "resource_unavailable", "query_denied", "invalid_call",
    "capability_too_large", "invalid_epoch", "epoch_conflict", "execution_busy",
    "invalid_token", "token_binding", "unknown_token", "inactive_token",
    "expired_token", "policy_changed", "invalid_completion", "unknown_execution",
    "execution_binding", "completion_conflict", "certificate_required",
    "invalid_body", "body_too_large", "json_required", "invalid_json",
    "unknown_endpoint", "invalid_call_id", "invalid_pagination", "invalid_http",
    "tls_failed", "server_busy", "transport_error", "internal_error", "audit_unavailable",
    "invalid_operation_id", "operation_conflict", "unknown_operation", "operation_binding",
})
_request = ContextVar("saga_provider_request", default=None)


def _audited(operation):
    """Capture direct calls as well as requests already scoped by the server."""
    def decorate(method):
        @wraps(method)
        def wrapped(self, *args, **kwargs):
            def run():
                _request.get()["operation"] = operation
                try:
                    return method(self, *args, **kwargs)
                except Exception as exc:
                    self.record_failure(exc)
                    raise
            if _request.get() is not None:
                return run()
            with self.request_context(operation):
                return run()
        return wrapped
    return decorate


def _reject(status: int, code: str, message: str):
    raise ProviderError(status, code, message)


def _body(value, fields: set[str]):
    if not isinstance(value, dict) or value.keys() != fields:
        _reject(400, "invalid_request", "request fields do not match this endpoint")


class Provider:
    def __init__(self, config: dict, state_db: str | Path, signing_key, clock=time.time, adapters: AdapterRegistry | None = None):
        self.config = validate_config(config)
        self.state_db = Path(path_string(state_db, "state database path")).absolute()
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
                CREATE TABLE IF NOT EXISTS operations (
                    agent_id TEXT NOT NULL REFERENCES agents(agent_id),
                    operation_id TEXT NOT NULL,
                    certificate_sha256 TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    semantic_call TEXT NOT NULL,
                    jti TEXT NOT NULL UNIQUE REFERENCES grants(jti),
                    PRIMARY KEY(agent_id,operation_id)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    jti TEXT NOT NULL,
                    event TEXT NOT NULL,
                    execution_id TEXT,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS request_failures (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    call_id TEXT,
                    agent_id TEXT,
                    operation TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    error_code TEXT NOT NULL,
                    status INTEGER NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS failures_by_agent
                    ON request_failures(agent_id,event_id);
            """)
            # Serialize migrations across independent Provider process starts.
            # Existing grants and unfinished gates are preserved throughout.
            db.execute("BEGIN IMMEDIATE")
            with db:
                for table, columns in {
                    "audit_events": {"request_id": "TEXT", "call_id": "TEXT", "outcome": "TEXT", "failure_code": "TEXT"},
                    "executions": {"failure_code": "TEXT", "receipt": "TEXT"},
                }.items():
                    existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
                    for column, kind in columns.items():
                        if column not in existing:
                            db.execute(f"ALTER TABLE {table} ADD COLUMN {column} {kind}")
                for agent_id in self.config["agents"]:
                    db.execute("INSERT OR IGNORE INTO agents(agent_id) VALUES (?)", (agent_id,))

    def _connect(self, *, nonblocking=False):
        # SQLite can need locks even during PRAGMA setup. Establish the busy
        # policy at connect(), before any query on an accept-loop audit path.
        db = sqlite3.connect(self.state_db, timeout=0 if nonblocking else 10, isolation_level=None)
        try:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys=ON")
            db.execute("PRAGMA synchronous=FULL")
            return db
        except BaseException:
            db.close()
            raise

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

    @contextmanager
    def request_context(self, operation="unknown", call_id=None):
        """One generated request identity; call IDs carry correlation, no authority."""
        context = {
            "request_id": secrets.token_hex(16), "call_id": None,
            "agent_id": None, "operation": operation, "phase": "authentication",
            "failure_recorded": False,
        }
        token = _request.set(context)
        try:
            if call_id is not None:
                self.set_call_id(call_id)
            yield context
        except Exception as exc:
            self.record_failure(exc)
            raise
        finally:
            _request.reset(token)

    @staticmethod
    def set_call_id(call_id):
        if not isinstance(call_id, str) or re.fullmatch(r"[0-9a-f]{32}", call_id) is None:
            _reject(400, "invalid_call_id", "X-Saga-Call-ID must be 32 lowercase hexadecimal characters")
        _request.get()["call_id"] = call_id

    @staticmethod
    def phase(name):
        if _request.get() is not None:
            _request.get()["phase"] = name

    def record_failure(self, error, *, nonblocking=False):
        """Commit only fixed diagnostic fields, after the action transaction rolls back.

        If durable storage itself fails, emit a redacted emergency event and fail
        closed. No exception message or request value is copied into either sink.
        """
        context = _request.get()
        if context is None:
            with self.request_context("transport"):
                self.phase("transport")
                return self.record_failure(error, nonblocking=nonblocking)
        if context["failure_recorded"]:
            return
        if isinstance(error, ProviderError):
            code = error.code if error.code in _ERROR_CODES else "internal_error"
            status = error.status if type(error.status) is int and 400 <= error.status <= 599 else 500
        elif isinstance(error, (TimeoutError, ConnectionError)):
            code, status = "transport_error", 499
        else:
            code, status = "internal_error", 500
        try:
            with closing(self._connect(nonblocking=nonblocking)) as db:
                db.execute("INSERT INTO request_failures(request_id,call_id,agent_id,operation,phase,error_code,status,created_at) VALUES (?,?,?,?,?,?,?,?)", (
                    context["request_id"], context["call_id"], context["agent_id"],
                    context["operation"], context["phase"], code, status, int(self.clock()),
                ))
        except Exception:
            context["failure_recorded"] = True
            try:
                sys.stderr.write(dumps({"event": "audit_unavailable", "request_id": context["request_id"], "call_id": context["call_id"]}) + "\n")
                sys.stderr.flush()
            except Exception:
                # A closed diagnostic pipe must not replace the typed failure
                # or escape the server's capacity/error cleanup paths.
                pass
            raise ProviderError(503, "audit_unavailable", "durable failure audit is unavailable") from None
        context["failure_recorded"] = True

    def _agent(self, certificate_sha256: str) -> str:
        self.phase("authentication")
        if not isinstance(certificate_sha256, str):
            _reject(403, "unknown_agent", "certificate is not enrolled")
        agent_id = self._identities.get(certificate_sha256.lower())
        if agent_id is None:
            _reject(403, "unknown_agent", "certificate is not enrolled")
        if _request.get() is not None:
            _request.get()["agent_id"] = agent_id
        return agent_id

    @_audited("state")
    def state(self, certificate_sha256: str) -> dict:
        agent_id = self._agent(certificate_sha256)
        self.phase("state")
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

    @staticmethod
    def _operation_id(value):
        if not isinstance(value, str) or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value) is None:
            _reject(400, "invalid_operation_id", "operation_id must be 1 through 128 ASCII identifier characters")
        return value

    def _operation(self, db, agent_id, operation_id, certificate_sha256):
        row = db.execute("""
            SELECT o.*,g.epoch,g.status AS grant_status,g.token,g.issued_at,g.expires_at,
                   e.execution_id,e.admitted_at,e.outcome,e.failure_code,e.finished_at,e.receipt
            FROM operations o JOIN grants g ON g.jti=o.jti
            LEFT JOIN executions e ON e.jti=o.jti
            WHERE o.agent_id=? AND o.operation_id=?
        """, (agent_id, operation_id)).fetchone()
        if row is not None and row["certificate_sha256"] != certificate_sha256.lower():
            _reject(403, "operation_binding", "operation requires its original certificate")
        return row

    def _operation_status(self, row):
        # A completed effect remains completed even when a subsequent rotation
        # revokes its old grant. Expiry never releases an admitted execution.
        if row["finished_at"] is not None:
            status = row["outcome"]
        elif row["execution_id"] is not None:
            status = "running"
        elif row["grant_status"] != "ACTIVE":
            status = "revoked"
        elif row["expires_at"] <= int(self.clock()):
            status = "expired"
        else:
            status = "ready"
        return {
            "operation_id": row["operation_id"], "agent_id": row["agent_id"],
            "task_id": row["task_id"], "epoch": row["epoch"], "status": status,
            "execution_id": row["execution_id"], "outcome": row["outcome"],
            "failure_code": row["failure_code"],
            "receipt": loads(row["receipt"]) if row["receipt"] is not None else None,
            "created_at": row["issued_at"], "admitted_at": row["admitted_at"],
            "finished_at": row["finished_at"],
        }

    @_audited("operation")
    def operation(self, certificate_sha256: str, body: dict) -> dict:
        """Recover an operation without granting permission to dispatch again."""
        agent_id = self._agent(certificate_sha256)
        self.phase("parsing")
        _body(body, {"operation_id"})
        operation_id = self._operation_id(body["operation_id"])
        self.phase("operation_read")
        with closing(self._connect()) as db:
            row = self._operation(db, agent_id, operation_id, certificate_sha256)
            if row is None:
                _reject(404, "unknown_operation", "operation does not exist for this agent")
            return self._operation_status(row)

    @_audited("rotate")
    def rotate(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        self.phase("parsing")
        fields = {"task_id", "expected_epoch", "format", "call"}
        if not isinstance(body, dict) or body.keys() not in (fields, fields | {"operation_id"}):
            _reject(400, "invalid_request", "request fields do not match this endpoint")
        expected = body["expected_epoch"]
        if isinstance(expected, bool) or not isinstance(expected, int) or not 0 <= expected < 2**63 - 1:
            _reject(400, "invalid_epoch", "expected_epoch must be a nonnegative 64-bit integer")
        operation_id, semantic_call = None, None
        if "operation_id" in body:
            operation_id = self._operation_id(body["operation_id"])
            try:
                semantic_call = dumps(self.adapters.normalize(body["format"], body["call"]))
                if len(semantic_call.encode("utf-8")) > 1_048_576:
                    _reject(413, "capability_too_large", "operation call exceeds the serialized size limit")
            except (TypeError, ValueError, UnicodeError, RecursionError):
                _reject(400, "invalid_call", "operation call must be finite UTF-8 JSON")
        self.phase("rotation")
        with self._transaction() as db:
            if operation_id is not None:
                previous_operation = self._operation(db, agent_id, operation_id, certificate_sha256)
                if previous_operation is not None:
                    if previous_operation["task_id"] != body["task_id"] or previous_operation["semantic_call"] != semantic_call:
                        _reject(409, "operation_conflict", "operation_id is already bound to another task or call")
                    result = self._operation_status(previous_operation)
                    result["replay"] = True
                    if result["status"] == "ready":
                        result["token"] = previous_operation["token"]
                    return result
            self.phase("policy")
            # The idempotency binding and executed capability must use the
            # same normalization snapshot, including trusted custom adapters.
            # Calling a stateful adapter twice could bind A while granting B.
            capability = self._capability(agent_id, body["task_id"], "canonical", loads(semantic_call)) if operation_id is not None else self._capability(agent_id, body["task_id"], body["format"], body["call"])
            self.phase("rotation")
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
            if operation_id is not None:
                db.execute("INSERT INTO operations(agent_id,operation_id,certificate_sha256,task_id,semantic_call,jti) VALUES (?,?,?,?,?,?)", (agent_id, operation_id, certificate_sha256.lower(), body["task_id"], semantic_call, jti))
            db.execute("UPDATE agents SET epoch=?,current_jti=? WHERE agent_id=?", (epoch, jti, agent_id))
            self._audit(db, agent_id, epoch, jti, "issued", issued)
            if operation_id is not None:
                result = self._operation_status(self._operation(db, agent_id, operation_id, certificate_sha256))
                result.update(token=token, replay=False)
                return result
        return {"token": token, "epoch": epoch, "agent_id": agent_id}

    @_audited("revoke")
    def revoke(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        self.phase("parsing")
        _body(body, {"expected_epoch"})
        expected = body["expected_epoch"]
        if isinstance(expected, bool) or not isinstance(expected, int) or not 0 <= expected < 2**63 - 1:
            _reject(400, "invalid_epoch", "expected_epoch must be a nonnegative 64-bit integer")
        self.phase("revocation")
        with self._transaction() as db:
            state = db.execute("SELECT epoch,current_jti FROM agents WHERE agent_id=?", (agent_id,)).fetchone()
            if state["epoch"] != expected:
                _reject(409, "epoch_conflict", "agent generation changed; fetch current state")
            if db.execute("SELECT 1 FROM executions WHERE agent_id=? AND finished_at IS NULL", (agent_id,)).fetchone():
                _reject(409, "execution_busy", "finish the current execution before revoking")
            previous = db.execute("SELECT jti,epoch FROM grants WHERE jti=? AND agent_id=? AND status IN ('ACTIVE','FINISHED')", (state["current_jti"], agent_id)).fetchone()
            if previous:
                db.execute("UPDATE grants SET status='REVOKED' WHERE jti=?", (previous["jti"],))
                self._audit(db, agent_id, previous["epoch"], previous["jti"], "revoked", int(self.clock()))
            epoch = expected + 1
            db.execute("UPDATE agents SET epoch=?,current_jti=NULL WHERE agent_id=?", (epoch, agent_id))
            self._audit(db, agent_id, epoch, "", "authority_revoked", int(self.clock()))
        return {"agent_id": agent_id, "epoch": epoch, "revoked": True}

    @_audited("admit")
    def admit(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        self.phase("parsing")
        _body(body, {"token"})
        try:
            payload = verify_token(body["token"], self.signing_key.public_key())
        except (ValueError, TypeError):
            _reject(403, "invalid_token", "token signature or encoding is invalid")
        if payload.get("sub") != agent_id or payload.get("certificate_sha256") != certificate_sha256.lower() or not isinstance(payload.get("jti"), str):
            _reject(403, "token_binding", "token is not bound to this certificate's agent")
        self.phase("admission")
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

    @_audited("finish")
    def finish(self, certificate_sha256: str, body: dict) -> dict:
        agent_id = self._agent(certificate_sha256)
        self.phase("parsing")
        required = {"execution_id", "outcome"}
        if not isinstance(body, dict) or not required <= body.keys() or not body.keys() <= required | {"failure_code", "receipt"}:
            _reject(400, "invalid_request", "request fields do not match this endpoint")
        if not isinstance(body["execution_id"], str) or not isinstance(body["outcome"], str) or body["outcome"] not in {"succeeded", "failed"}:
            _reject(400, "invalid_completion", "completion requires an execution ID and succeeded or failed")
        failure_code = body.get("failure_code")
        if "failure_code" in body and (body["outcome"] != "failed" or not isinstance(failure_code, str) or failure_code not in FAILURE_CODES):
            _reject(400, "invalid_completion", "failure_code must be a registered code for a failed execution")
        receipt = None
        if "receipt" in body:
            value = body["receipt"]
            if not isinstance(value, dict) or type(value.get("ok")) is not bool or value["ok"] != (body["outcome"] == "succeeded"):
                _reject(400, "invalid_completion", "receipt must be an object with an ok flag matching the outcome")
            if "execution_id" in value and value["execution_id"] != body["execution_id"]:
                _reject(400, "invalid_completion", "receipt execution ID differs from the completion")
            try:
                receipt = dumps(value)
                if len(receipt.encode("utf-8")) > MAX_RECEIPT_BYTES:
                    _reject(413, "invalid_completion", "receipt exceeds the serialized size limit")
            except (TypeError, ValueError, UnicodeError, RecursionError):
                _reject(400, "invalid_completion", "receipt must be finite UTF-8 JSON")
        self.phase("completion")
        with self._transaction() as db:
            execution = db.execute("SELECT * FROM executions WHERE execution_id=? AND agent_id=?", (body["execution_id"], agent_id)).fetchone()
            if execution is None:
                _reject(403, "unknown_execution", "execution is not owned by this agent")
            grant = db.execute("SELECT epoch,payload FROM grants WHERE jti=?", (execution["jti"],)).fetchone()
            if loads(grant["payload"]).get("certificate_sha256") != certificate_sha256.lower():
                _reject(403, "execution_binding", "completion requires the execution's original certificate")
            if receipt is not None and "operation_id" in body["receipt"]:
                operation = db.execute("SELECT operation_id FROM operations WHERE jti=?", (execution["jti"],)).fetchone()
                if operation is None or body["receipt"]["operation_id"] != operation["operation_id"]:
                    _reject(400, "invalid_completion", "receipt operation ID differs from the admitted operation")
            if execution["finished_at"] is not None:
                if execution["outcome"] != body["outcome"] or ("failure_code" in body and execution["failure_code"] != failure_code) or (receipt is not None and execution["receipt"] != receipt):
                    _reject(409, "completion_conflict", "execution already finished with another outcome")
            else:
                db.execute("UPDATE executions SET outcome=?,failure_code=?,receipt=?,finished_at=? WHERE execution_id=?", (body["outcome"], failure_code, receipt, int(self.clock()), body["execution_id"]))
                db.execute("UPDATE grants SET status='FINISHED' WHERE jti=? AND status='EXECUTING'", (execution["jti"],))
                self._audit(db, agent_id, grant["epoch"], execution["jti"], "finished", int(self.clock()), body["execution_id"], body["outcome"], failure_code)
        return {"execution_id": body["execution_id"], "outcome": body["outcome"], "finished": True}

    def _audit(self, db, agent_id, epoch, jti, event, created_at, execution_id=None, outcome=None, failure_code=None):
        context = _request.get() or {}
        db.execute("INSERT INTO audit_events(agent_id,epoch,jti,event,execution_id,created_at,request_id,call_id,outcome,failure_code) VALUES (?,?,?,?,?,?,?,?,?,?)", (agent_id, epoch, jti, event, execution_id, created_at, context.get("request_id"), context.get("call_id"), outcome, failure_code))

    @staticmethod
    def _pagination(after, limit):
        if type(after) is not int or not 0 <= after < 2**63 or (limit is not None and (type(limit) is not int or not 1 <= limit <= 500)):
            _reject(400, "invalid_pagination", "after must be a nonnegative event ID and limit must be 1 through 500")

    @_audited("audit")
    def audit_events(self, certificate_sha256: str, *, after=0, limit=None) -> list[dict]:
        """Read committed transitions for an enrolled agent; never expose tokens."""
        agent_id = self._agent(certificate_sha256)
        self.phase("audit_read")
        self._pagination(after, limit)
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM audit_events WHERE agent_id=? AND event_id>? ORDER BY event_id LIMIT ?", (agent_id, after, limit if limit is not None else -1)).fetchall()
        return [dict(row) for row in rows]

    @_audited("failures")
    def failure_events(self, certificate_sha256: str, *, after=0, limit=100) -> list[dict]:
        """Read only this enrolled agent's sanitized request failures."""
        agent_id = self._agent(certificate_sha256)
        self.phase("audit_read")
        self._pagination(after, limit)
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM request_failures WHERE agent_id=? AND event_id>? ORDER BY event_id LIMIT ?", (agent_id, after, limit if limit is not None else 100)).fetchall()
        return [dict(row) for row in rows]
