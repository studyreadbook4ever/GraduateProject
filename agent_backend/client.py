"""Run structured model calls through the C++ coordinator without a shell."""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
from collections.abc import Iterable
from pathlib import Path


class WorkerError(RuntimeError):
    """The worker could not produce a complete, parseable execution receipt."""


class WorkerClient:
    """A small adapter for runtimes that do not link the C++ library directly.

    Each submitted record receives its own capability and fresh executor. The
    task ID is a registered policy ID, not a name extracted from a prompt.
    A timeout terminates this client's process group; the Provider retains any
    unfinished admission gate. It never assumes that effects were rolled back.
    """

    def __init__(self, config: str | Path, *, binary: str | Path = "saga-worker"):
        self.config = Path(config).resolve(strict=True)
        candidate = shutil.which(str(binary))
        if candidate is None:
            raise FileNotFoundError(f"worker executable not found: {binary}")
        self.binary = Path(candidate).resolve(strict=True)

    def execute(self, *, task_id: str, call: dict, format: str = "canonical",
                timeout: float | None = None) -> dict:
        return self.execute_many(
            [{"task_id": task_id, "format": format, "call": call}], timeout=timeout
        )[0]

    def execute_many(self, records: Iterable[dict], *,
                     timeout: float | None = None) -> list[dict]:
        calls = list(records)
        if not calls:
            return []
        payload = "".join(json.dumps(record, ensure_ascii=False, allow_nan=False)
                          + "\n" for record in calls)
        process = subprocess.Popen(
            [str(self.binary), "--config", str(self.config)],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, encoding="utf-8", start_new_session=True,
        )
        try:
            output, _errors = process.communicate(payload, timeout=timeout)
        except BaseException:
            # This process group belongs only to this invocation. Killing it is
            # resource cleanup; it does not release Provider execution state.
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.communicate()
            raise
        try:
            receipts = [json.loads(line) for line in output.splitlines() if line]
        except (ValueError, RecursionError) as error:
            raise WorkerError("worker returned malformed receipts") from error
        if len(receipts) != len(calls) or any(
            not isinstance(receipt, dict) or type(receipt.get("ok")) is not bool
            for receipt in receipts
        ):
            raise WorkerError("worker did not return one execution receipt per call")
        if process.returncode not in (0, 1):
            raise WorkerError(f"worker exited with status {process.returncode}")
        return receipts
