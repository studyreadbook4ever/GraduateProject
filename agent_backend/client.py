"""Run structured model calls through the C++ coordinator without a shell."""

from __future__ import annotations

import fcntl
import json
import math
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import time
import uuid
from collections.abc import Iterable
from pathlib import Path

from saga.config import path_string
from saga.errors import ProviderError


def _operation_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value):
        raise ValueError("operation_id must start with an ASCII letter or digit and contain up to 128 letters, digits or _.:-")
    return value


class WorkerError(RuntimeError):
    """A worker/protocol/audit failure, retaining every observed receipt."""

    def __init__(self, message: str = "", *, code: str = "worker_protocol", receipts=(),
                 audit_failed: bool = False, outcome_uncertain: bool = True, operation_ids=()):
        super().__init__(message)
        self.code = code
        self.receipts = tuple(receipts)
        self.audit_failed = audit_failed
        # Missing receipts do not establish whether submitted actions had effects.
        self.outcome_uncertain = outcome_uncertain
        self.operation_ids = tuple(operation_ids)


class WorkerClient:
    """A small adapter for runtimes that do not link the C++ library directly.

    Each submitted record receives its own capability and fresh executor. The
    task ID is a registered policy ID, not a name extracted from a prompt.
    A timeout terminates this client's process group; the Provider retains any
    unfinished admission gate. It never assumes that effects were rolled back.
    """

    _cleanup_timeout = 0.5
    _audit_lock_timeout = 0.5

    def __init__(self, config: str | Path, *, binary: str | Path = "saga-worker",
                 failure_log: str | Path | None = None):
        config_text = path_string(config, "worker configuration path")
        binary_text = path_string(binary, "worker executable path")
        log_text = path_string(failure_log, "failure log path") if failure_log is not None else None
        self.config = Path(config_text).resolve(strict=True)
        candidate = shutil.which(binary_text)
        if candidate is None:
            raise FileNotFoundError(f"worker executable not found: {binary}")
        self.binary = Path(candidate).resolve(strict=True)
        self.failure_log = Path(log_text).absolute() if log_text is not None else None
        if self.failure_log is not None:
            descriptor = self._open_log()
            os.close(descriptor)

    def _open_log(self) -> int:
        path = self.failure_log
        if any(parent.is_symlink() for parent in [path, *path.parents]):
            raise ValueError("failure log path must not contain symlinks")
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            attributes = os.fstat(descriptor)
            if not stat.S_ISREG(attributes.st_mode) or attributes.st_uid != os.geteuid() or attributes.st_mode & 0o077:
                raise ValueError("failure log must be an owner-only regular file")
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor

    def _log_failure(self, receipt: dict | None = None, *, code: str | None = None,
                     lock_deadline: float | None = None):
        if self.failure_log is None:
            return
        event = {"event": "worker_failure", "created_at": int(time.time())}
        if code:
            event["error_code"] = code
        if receipt:
            for field in ("call_id", "request_id", "execution_id"):
                value = receipt.get(field)
                if isinstance(value, str) and len(value) in (32, 48) and all(c in "0123456789abcdef" for c in value):
                    event[field] = value
            phase = receipt.get("phase")
            operation_id = receipt.get("operation_id")
            if isinstance(operation_id, str) and re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}", operation_id):
                event["operation_id"] = operation_id
            if isinstance(phase, str) and phase in {"parse", "state", "rotate", "verify", "admit", "execute", "finish", "revoke", "reconcile"}:
                event["phase"] = phase
            executor_phase = receipt.get("executor_phase")
            if isinstance(executor_phase, str) and executor_phase in {"sandbox_setup", "execution"}:
                event["executor_phase"] = executor_phase
            error_code = receipt.get("error_code")
            if isinstance(error_code, str) and 0 < len(error_code) <= 64 and all(c in "abcdefghijklmnopqrstuvwxyz0123456789_" for c in error_code):
                event["error_code"] = error_code
            for field in ("executor_started", "admission_uncertain", "completion_recorded", "execution_ok"):
                if type(receipt.get(field)) is bool:
                    event[field] = receipt[field]
            if type(receipt.get("http_status")) is int and 0 <= receipt["http_status"] <= 599:
                event["http_status"] = receipt["http_status"]
        raw = (json.dumps(event, separators=(",", ":")) + "\n").encode("utf-8")
        with os.fdopen(self._open_log(), "ab", buffering=0) as stream:
            if lock_deadline is None:
                lock_deadline = time.monotonic() + self._audit_lock_timeout
            while True:
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    remaining = lock_deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("failure audit lock is unavailable") from None
                    time.sleep(min(0.01, remaining))
            start = os.lseek(stream.fileno(), 0, os.SEEK_END)
            written = 0
            try:
                remaining = memoryview(raw)
                while remaining:
                    count = stream.write(remaining)
                    if not count:
                        raise OSError("failure audit write failed")
                    written += count
                    remaining = remaining[count:]
                os.fsync(stream.fileno())
            except BaseException:
                # Cooperating appenders share this lock. Remove a short append
                # so a later event cannot be joined to its incomplete JSON line.
                # This provides no transaction guarantee across a process crash.
                if written < len(raw):
                    try:
                        os.ftruncate(stream.fileno(), start)
                        os.fsync(stream.fileno())
                    except OSError:
                        pass
                raise

    @staticmethod
    def _audit_fallback():
        # Never echo exception text, paths, worker stderr, or receipt content.
        try:
            sys.stderr.write('{"event":"worker_audit_unavailable","error_code":"failure_log_unavailable"}\n')
            sys.stderr.flush()
        except Exception:
            pass

    def _record_failures(self, receipts: list[dict], *, code: str | None = None) -> bool:
        """Attempt every failure event without discarding any execution result."""
        audit_failed = False
        # A batch shares one lock-wait budget; a stuck appender must not add a
        # separate timeout for every previously observed failed call.
        lock_deadline = time.monotonic() + self._audit_lock_timeout
        events = [(receipt, None) for receipt in receipts if not receipt["ok"]]
        if code:
            events.append((None, code))
        for receipt, event_code in events:
            try:
                self._log_failure(receipt, code=event_code, lock_deadline=lock_deadline)
            except Exception:
                audit_failed = True
                self._audit_fallback()
        return audit_failed

    def request_resource(self, *, task_id: str, tool: str, resource: str,
                         timeout: float | None = None, operation_id: str | None = None, **arguments) -> dict:
        """Request and use one exact registered resource; no cached authority."""
        return self.execute(task_id=task_id, timeout=timeout, operation_id=operation_id, call={
            "tool": tool, "arguments": {"resource": resource, **arguments},
        })

    def revoke(self, *, timeout: float | None = None) -> dict:
        """Revoke pending authority. An executing action returns execution_busy."""
        return self._run([], timeout=timeout, revoke=True)[0]

    def execute(self, *, task_id: str, call: dict, format: str = "canonical",
                timeout: float | None = None, operation_id: str | None = None) -> dict:
        record = {"task_id": task_id, "format": format, "call": call}
        if operation_id is not None:
            record["operation_id"] = _operation_id(operation_id)
        return self.execute_many(
            [record], timeout=timeout
        )[0]

    def operation_status(self, operation_id: str, *, timeout: float | None = None) -> dict:
        """Reconcile a durable operation without issuing authority or executing."""
        return self._run([], timeout=timeout, operation_id=_operation_id(operation_id))[0]

    def execute_tool_call(self, *, task_id: str, call: dict, format: str,
                          timeout: float | None = None, operation_id: str | None = None) -> dict:
        """Return one vendor result item with the original tool-call identity."""
        from saga.adapters import format_tool_result, normalize_tool_call

        tool_call = normalize_tool_call(format, call)
        operation_id = uuid.uuid4().hex if operation_id is None else _operation_id(operation_id)
        receipt = self.execute(task_id=task_id, call=tool_call.canonical,
                               operation_id=operation_id, timeout=timeout)
        # Keep execution/retry metadata next to the model-facing item.
        value = receipt.get("result") if receipt["ok"] else {"error": receipt.get("error", "Tool execution failed"),
                                                            "code": receipt.get("error_code", "execution_failed")}
        try:
            tool_result = format_tool_result(tool_call, value, is_error=not receipt["ok"])
        except (ProviderError, ValueError, TypeError, RecursionError) as error:
            raise WorkerError("tool result cannot be represented in the requested API format",
                              code="tool_result_unrepresentable", receipts=[receipt],
                              outcome_uncertain=False, operation_ids=[operation_id]) from error
        return {"receipt": receipt, "tool_result": tool_result}

    def execute_many(self, records: Iterable[dict], *,
                     timeout: float | None = None) -> list[dict]:
        calls = []
        for record in records:
            if not isinstance(record, dict):
                raise ValueError("each worker record must be an object")
            record = dict(record)
            record["operation_id"] = _operation_id(record["operation_id"]) if "operation_id" in record else uuid.uuid4().hex
            calls.append(record)
        if not calls:
            return []
        return self._run(calls, timeout=timeout)

    def _observed_receipts(self, output: bytes) -> tuple[list[dict], bool]:
        """Decode each JSONL record independently, preserving a valid prefix."""
        receipts = []
        # JSONL is delimited by LF, not Unicode text separators inside strings.
        for line in output.split(b"\n"):
            if not line:
                continue
            try:
                receipt = json.loads(line.decode("utf-8"))
            except (ValueError, RecursionError):
                return receipts, False
            if not isinstance(receipt, dict) or type(receipt.get("ok")) is not bool:
                return receipts, False
            receipts.append(receipt)
        return receipts, True

    def _stop_and_collect(self, process: subprocess.Popen, error: BaseException) -> bytes:
        """Kill our group and bound draining even if another session holds a pipe."""
        output = error.output if isinstance(error, subprocess.TimeoutExpired) else b""
        try:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except OSError:
                # A changed/missing process group must not prevent reaping the
                # direct child where it is still possible to kill it.
                try:
                    process.kill()
                except OSError:
                    pass
            try:
                output, _errors = process.communicate(timeout=self._cleanup_timeout)
            except subprocess.TimeoutExpired as cleanup_error:
                output = cleanup_error.output or output
            except Exception:
                # Preserve the original interruption when pipe cleanup fails.
                pass
        finally:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None:
                    try:
                        stream.close()
                    except OSError:
                        pass
            try:
                process.wait(timeout=self._cleanup_timeout)
            except (OSError, subprocess.TimeoutExpired):
                pass
        return output or b""

    def _run(self, calls: list[dict], *, timeout: float | None, revoke: bool = False,
             operation_id: str | None = None) -> list[dict]:
        operation_ids = tuple(call["operation_id"] for call in calls) if operation_id is None else (operation_id,)
        if timeout is not None and (isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0):
            raise ValueError("timeout must be a positive finite number")
        try:
            payload = "".join(json.dumps(record, ensure_ascii=False, allow_nan=False)
                              + "\n" for record in calls).encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("worker requests must contain valid UTF-8 text") from None
        if self.failure_log is not None:
            try:
                descriptor = self._open_log()
                os.close(descriptor)
            except Exception:
                self._audit_fallback()
                raise WorkerError("worker failure audit is unavailable; no worker was launched",
                                  code="failure_log_unavailable", audit_failed=True,
                                  outcome_uncertain=False, operation_ids=operation_ids) from None
        command = [str(self.binary), "--config", str(self.config)]
        if revoke:
            command.append("--revoke")
        if operation_id is not None:
            command.extend(["--operation", operation_id])
        try:
            process = subprocess.Popen(
                command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except OSError:
            audit_failed = self._record_failures([], code="worker_launch_failed")
            raise WorkerError("worker could not be launched", code="worker_launch_failed",
                              audit_failed=audit_failed, outcome_uncertain=False, operation_ids=operation_ids) from None
        try:
            output, _errors = process.communicate(payload, timeout=timeout)
        except BaseException as error:
            output = self._stop_and_collect(process, error)
            partial, _valid = self._observed_receipts(output)
            code = "worker_timeout" if isinstance(error, subprocess.TimeoutExpired) else "worker_interrupted"
            audit_failed = self._record_failures(partial, code=code)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                # Preserve cancellation semantics while exposing completed calls
                # to callers that need to reconcile effects before another try.
                error.receipts = tuple(partial)
                error.code = code
                error.outcome_uncertain = True
                error.audit_failed = audit_failed
                error.operation_ids = operation_ids
                error.add_note(f"Worker interrupted; {len(partial)} complete receipt(s) retained in .receipts.")
                raise
            if isinstance(error, subprocess.TimeoutExpired):
                raise WorkerError("worker timed out; submitted calls may have effects",
                                  code=code, receipts=partial, audit_failed=audit_failed, operation_ids=operation_ids) from None
            raise WorkerError("worker communication failed; submitted calls may have effects",
                              code=code, receipts=partial, audit_failed=audit_failed, operation_ids=operation_ids) from None
        receipts, valid = self._observed_receipts(output)
        if not receipts and process.returncode == 2:
            code, message = "worker_initialization_failed", "worker initialization failed"
        elif not valid:
            code, message = "invalid_worker_output", "worker returned malformed receipts"
        elif len(receipts) != (1 if revoke or operation_id is not None else len(calls)):
            code, message = "incomplete_worker_output", "worker did not return one execution receipt per call"
        elif calls and any("operation_id" in receipt and receipt["operation_id"] != call["operation_id"]
                           for receipt, call in zip(receipts, calls)):
            code, message = "invalid_worker_output", "worker returned a receipt for a different operation"
        elif process.returncode != int(any(not receipt["ok"] for receipt in receipts)):
            code, message = "worker_exit_failed", f"worker exited with status {process.returncode}"
        else:
            code = None
        audit_failed = self._record_failures(receipts, code=code)
        if code:
            raise WorkerError(message, code=code, receipts=receipts, audit_failed=audit_failed,
                              operation_ids=operation_ids)
        if audit_failed:
            raise WorkerError("worker failure audit could not be persisted; submitted calls may have effects",
                              code="failure_log_unavailable", receipts=receipts, audit_failed=True,
                              operation_ids=operation_ids)
        return receipts
