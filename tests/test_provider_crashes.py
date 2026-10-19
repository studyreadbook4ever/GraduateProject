"""Kill real authorities at transaction boundaries, then reopen their state."""

import multiprocessing
import os
import sqlite3
from contextlib import contextmanager

import pytest

from saga.provider import Provider, ProviderError

from conftest import ALICE, rotate_body


def snapshot(path):
    with sqlite3.connect(path) as database:
        return {table: database.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
                for table in ("agents", "grants", "executions", "audit_events")}


def crash_transaction(config, path, key, now, operation, timing, token, execution):
    provider = Provider(config, path, key, clock=lambda: now)
    transaction = provider._transaction

    @contextmanager
    def interrupted():
        with transaction() as database:
            yield database
            if timing == "before_commit":
                os._exit(87)  # No Python finally/rollback/connection cleanup.
        os._exit(88)  # Commit reached storage; the response never reached caller.

    provider._transaction = interrupted
    if operation == "rotate":
        provider.rotate(ALICE, rotate_body(1))
    elif operation == "revoke":
        provider.revoke(ALICE, {"expected_epoch": 1})
    elif operation == "admit":
        provider.admit(ALICE, {"token": token})
    else:
        provider.finish(ALICE, {"execution_id": execution, "outcome": "failed"})
    os._exit(99)


@pytest.mark.parametrize("operation", ["rotate", "revoke", "admit", "finish"])
@pytest.mark.parametrize("timing", ["before_commit", "after_commit"])
def test_real_process_death_preserves_atomic_authority_and_execution_gate(provider_env, operation, timing):
    env = provider_env
    provider = env["provider"]
    token = provider.rotate(ALICE, rotate_body())["token"]
    execution = provider.admit(ALICE, {"token": token})["execution_id"] if operation == "finish" else None
    before = snapshot(env["state"])
    context = multiprocessing.get_context("fork")
    process = context.Process(target=crash_transaction, args=(
        env["config"], env["state"], env["key"], env["now"][0], operation, timing, token, execution))
    process.start()
    process.join(timeout=10)
    try:
        assert not process.is_alive(), "authority did not reach crash boundary"
        assert process.exitcode == (87 if timing == "before_commit" else 88)
    finally:
        if process.is_alive():
            process.kill()
            process.join(timeout=5)
    reopened = Provider(env["config"], env["state"], env["key"], clock=lambda: env["now"][0])
    with sqlite3.connect(env["state"]) as database:
        assert database.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
        assert database.execute("PRAGMA foreign_key_check").fetchall() == []
        assert database.execute("SELECT count(*) FROM grants WHERE status IN ('ACTIVE','EXECUTING')").fetchone()[0] <= 1
        assert database.execute("SELECT count(*) FROM executions WHERE finished_at IS NULL").fetchone()[0] <= 1
    if timing == "before_commit":
        assert snapshot(env["state"]) == before
        if operation == "finish":
            with pytest.raises(ProviderError) as busy:
                reopened.revoke(ALICE, {"expected_epoch": 1})
            assert busy.value.code == "execution_busy"
            reopened.finish(ALICE, {"execution_id": execution, "outcome": "failed"})
        else:
            admitted = reopened.admit(ALICE, {"token": token})
            reopened.finish(ALICE, {"execution_id": admitted["execution_id"], "outcome": "succeeded"})
        return
    if operation in {"rotate", "revoke"}:
        assert reopened.state(ALICE)["epoch"] == 2
        with pytest.raises(ProviderError) as inactive:
            reopened.admit(ALICE, {"token": token})
        assert inactive.value.code == "inactive_token"
        if operation == "rotate":
            with sqlite3.connect(env["state"]) as database:
                current_token = database.execute("SELECT token FROM grants WHERE status='ACTIVE'").fetchone()[0]
        else:
            current_token = reopened.rotate(ALICE, rotate_body(2))["token"]
        admitted = reopened.admit(ALICE, {"token": current_token})
        reopened.finish(ALICE, {"execution_id": admitted["execution_id"], "outcome": "succeeded"})
    elif operation == "admit":
        env["now"][0] += 3600
        for action in (lambda: reopened.rotate(ALICE, rotate_body(1)),
                       lambda: reopened.revoke(ALICE, {"expected_epoch": 1})):
            with pytest.raises(ProviderError) as busy:
                action()
            assert busy.value.code == "execution_busy"
        with sqlite3.connect(env["state"]) as database:
            execution = database.execute("SELECT execution_id FROM executions").fetchone()[0]
        # Only the test operator knows this crashed process never ran a handler.
        reopened.finish(ALICE, {"execution_id": execution, "outcome": "failed"})
        assert reopened.rotate(ALICE, rotate_body(1))["epoch"] == 2
    else:
        count = len(reopened.audit_events(ALICE))
        reopened.finish(ALICE, {"execution_id": execution, "outcome": "failed"})
        assert len(reopened.audit_events(ALICE)) == count
        assert reopened.rotate(ALICE, rotate_body(1))["epoch"] == 2
