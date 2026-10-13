"""Integration boundary between an agent runtime and the trusted C++ worker."""

from .client import WorkerClient, WorkerError

__all__ = ["WorkerClient", "WorkerError"]
