"""Measure execution cycling and agent admission without weakening production.

Run `python -m experiments.tradeoffs --help`. All PKI, Provider state, and handler
inputs are disposable and independent. Latency samples are retained in JSON;
there are no hardware-specific performance pass/fail thresholds.
"""

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .pki import generate
from .run import Services

ROOT = Path(__file__).resolve().parents[1]


def distribution(values):
    ordered = sorted(values)
    if not ordered:
        raise ValueError("at least one sample required")

    def nearest(fraction):
        import math
        return ordered[math.ceil(fraction * len(ordered)) - 1]

    return {"samples": len(values), "min_seconds": ordered[0], "p50_seconds": nearest(.5),
            "p95_seconds": nearest(.95), "max_seconds": ordered[-1],
            "mean_seconds": statistics.mean(values), "raw_seconds": values}


class SlowService:
    def __init__(self, delay):
        self.delay = delay
        self.condition = threading.Condition()
        self.active = 0
        self.maximum = 0
        self.entered = 0
        self.events = []
        self.hold_event = None
        self.request_threads = set()
        owner = self

        class Server(ThreadingHTTPServer):
            def get_request(self):
                request, address = super().get_request()
                request.settimeout(3)
                return request, address

            def process_request(self, request, address):
                request_thread = threading.Thread(target=self.process_request_thread,
                                                  args=(request, address), daemon=True)
                with owner.condition:
                    owner.request_threads.add(request_thread)
                request_thread.start()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                begin = time.monotonic()
                with owner.condition:
                    owner.active += 1
                    owner.entered += 1
                    owner.maximum = max(owner.maximum, owner.active)
                    hold = owner.hold_event
                    owner.condition.notify_all()
                try:
                    if hold is not None and not hold.wait(10):
                        raise TimeoutError("diagnostic release was not signalled")
                    time.sleep(owner.delay)
                    data = b"isolated slow resource"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                finally:
                    with owner.condition:
                        owner.active -= 1
                        owner.events.append({"start": begin, "end": time.monotonic()})
                        owner.condition.notify_all()

            def log_message(self, *_):
                pass

        self.server = Server(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": .05})
        self.thread.start()

    @property
    def port(self):
        return self.server.server_address[1]

    def snapshot(self):
        with self.condition:
            return self.entered, len(self.events)

    def hold(self):
        with self.condition:
            if self.active or self.hold_event is not None:
                raise RuntimeError("cannot arm a busy diagnostic resource")
            self.hold_event = threading.Event()

    def release(self):
        with self.condition:
            if self.hold_event is not None:
                self.hold_event.set()
                self.hold_event = None

    def wait_for_entries(self, expected):
        deadline = time.monotonic() + 2
        with self.condition:
            while self.entered < expected:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("worker did not enter slow handler")
                self.condition.wait(remaining)

    def close(self):
        self.release()
        try:
            self.server.shutdown()
            self.thread.join(timeout=5)
            deadline = time.monotonic() + 5
            with self.condition:
                requests = list(self.request_threads)
            for request in requests:
                request.join(timeout=max(0, deadline - time.monotonic()))
            if self.thread.is_alive() or any(request.is_alive() for request in requests):
                raise RuntimeError("slow service threads did not terminate")
            with self.condition:
                if self.active:
                    raise RuntimeError("slow resource still has active handlers")
        finally:
            self.server.server_close()


def launch(worker, config, call, processes):
    process = subprocess.Popen([str(worker), "--config", str(config)], stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    processes.append(process)
    # Supplying one record while retaining the coordinator is sufficient for the
    # deterministic overlap check. Close stdin so the coordinator then exits.
    process.stdin.write(json.dumps(call) + "\n")
    process.stdin.close()
    process.stdin = None
    return process


def finish(process):
    output, errors = process.communicate(timeout=20)
    records = [json.loads(line) for line in output.splitlines() if line]
    if len(records) != 1 or process.returncode not in (0, 1):
        raise RuntimeError(f"worker failed to return one receipt: {errors[-200:]}")
    return records[0]


def concurrency(worker, configs, slow, rounds, processes):
    call = {"task_id": "bench", "format": "canonical", "call": {
        "tool": "http_get", "arguments": {"resource": "slow"}}}
    same, distinct, serial = [], [], []
    denied_codes = []
    overlaps = []
    for _ in range(rounds):
        entered, _ = slow.snapshot()
        slow.hold()
        start = time.monotonic()
        first = launch(worker, configs["alice"], call, processes)
        slow.wait_for_entries(entered + 1)
        denied = finish(launch(worker, configs["alice"], call, processes))
        slow.release()
        accepted = finish(first)
        assert accepted["ok"] and accepted["executor_started"], accepted
        assert denied.get("error_code") == "execution_busy" and not denied["executor_started"], denied
        assert slow.snapshot()[0] == entered + 1, "same-agent competitor reached resource"
        same.append(time.monotonic() - start)
        denied_codes.append(denied["error_code"])

        entered, event_offset = slow.snapshot()
        slow.hold()
        start = time.monotonic()
        first = launch(worker, configs["alice"], call, processes)
        slow.wait_for_entries(entered + 1)
        second = launch(worker, configs["bob"], call, processes)
        slow.wait_for_entries(entered + 2)
        slow.release()
        assert finish(first)["ok"] and finish(second)["ok"], "distinct-agent worker failed"
        distinct.append(time.monotonic() - start)
        with slow.condition:
            pair = slow.events[event_offset:]
        assert len(pair) == 2
        overlap = min(event["end"] for event in pair) - max(event["start"] for event in pair)
        assert overlap > 0, "distinct enrolled principals did not overlap at the resource"
        overlaps.append(overlap)

        start = time.monotonic()
        for name in ("alice", "bob"):
            assert finish(launch(worker, configs[name], call, processes))["ok"]
        serial.append(time.monotonic() - start)
    return {
        "rounds": rounds, "resource_delay_seconds": slow.delay,
        "same_agent_one_accept_one_reject": distribution(same),
        "same_agent_rejected_error_codes": denied_codes,
        "distinct_agents_two_successes": distribution(distinct),
        "distinct_agents_actual_handler_overlap": distribution(overlaps),
        "serial_two_agents_two_successes": distribution(serial),
        "handler_maximum_concurrency": slow.maximum,
        "synchronization": "same-agent handler held until competitor rejected; distinct handlers held until both entered; fixed resource delay begins after release",
        "timing_scope": "whole matched worker subprocess lifecycle, including CLI startup; overlap separately measured inside HTTP handlers",
    }


def run(worker, harness, receipt_path, *, iterations, warmup, rounds, delay, memory_sizes):
    worker, harness = worker.resolve(), harness.resolve()
    started = time.monotonic()
    receipt = {"status": "failed", "environment": {
        "utc_started": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "platform": platform.platform(), "machine": platform.machine(),
        "python": platform.python_version(), "logical_cpus": os.cpu_count(),
        "cpu_affinity_count": len(os.sched_getaffinity(0)),
        "worker_sha256": hashlib.sha256(worker.read_bytes()).hexdigest(),
        "harness_sha256": hashlib.sha256(harness.read_bytes()).hexdigest(),
        "cpu_model": next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                           if line.startswith("model name")), "unknown"),
        "load_average_at_start": os.getloadavg(),
    }, "mechanism": [], "checks": []}
    processes = []
    services = None
    slow = None
    temporary = tempfile.TemporaryDirectory(prefix="saga-tradeoff-")
    try:
        root = Path(temporary.name)
        notes = root / "notes.txt"
        notes.write_text("x" * 4096)
        other = root / "other.txt"
        other.write_text("y" * 4096)
        invariant = subprocess.run([str(harness), "--mode", "invariants", "--file", str(notes), "--other", str(other)],
                                   text=True, capture_output=True, check=True, timeout=15)
        receipt["invariants"] = json.loads(invariant.stdout)
        receipt["checks"].append("Landlock layers intersect; production denies executor fork and exec")
        for memory_mib in memory_sizes:
            for mode in ("direct", "fork_only", "fork_exec_control", "sandbox_empty", "sandbox_read"):
                result = subprocess.run([str(harness), "--mode", mode, "--file", str(notes),
                                         "--iterations", str(iterations), "--warmup", str(warmup),
                                         "--memory-mib", str(memory_mib)], text=True, capture_output=True,
                                        check=True, timeout=max(30, (iterations + warmup) // 10))
                receipt["mechanism"].append(json.loads(result.stdout))
        receipt["checks"].append("per-call mechanism samples come from one long-lived C++ coordinator per mode; process startup excluded")
        pki = root / "pki"
        fingerprints = generate(pki)
        slow = SlowService(delay)
        config = {
            "agents": {name: {"certificate_sha256": fingerprints[name], "tasks": ["bench"]} for name in ("alice", "bob")},
            "tasks": {"bench": {"allow": [{"tool": "read_file", "resource": "notes"},
                                             {"tool": "http_get", "resource": "slow"}]}},
            "resources": {"notes": {"kind": "file", "path": str(notes)},
                          "slow": {"kind": "http", "url": f"http://127.0.0.1:{slow.port}/delay"}},
            "token_ttl_seconds": 60,
        }
        (root / "provider.json").write_text(json.dumps(config))
        services = Services(root)
        port = services.start("provider")
        configs = {}
        for name in ("alice", "bob"):
            path = root / f"worker-{name}.json"
            path.write_text(json.dumps({"provider_url": f"https://127.0.0.1:{port}",
                "ca_certificate": str(pki / "ca.pem"), "client_certificate": str(pki / f"{name}.pem"),
                "client_key": str(pki / f"{name}-key.pem"), "provider_public_key": str(pki / "provider-public.pem"),
                "agent_id": name}))
            path.chmod(0o600)
            configs[name] = path
        result = subprocess.run([str(harness), "--mode", "worker", "--config", str(configs["alice"]),
                                 "--iterations", str(iterations), "--warmup", str(warmup)],
                                text=True, capture_output=True, check=True, timeout=max(60, iterations))
        receipt["end_to_end"] = json.loads(result.stdout)
        receipt["checks"].append("one C++ Worker instance performs the full real mTLS/Provider/fresh-executor/finish pipeline sequentially")
        receipt["concurrency"] = concurrency(worker, configs, slow, rounds, processes)
        receipt["checks"].append("same principal never overlaps; independently enrolled principals overlap at real slow HTTP resource")
        receipt["status"] = "passed"
    except Exception as error:
        receipt["error"] = f"{type(error).__name__}: {error}"
        if isinstance(error, subprocess.CalledProcessError):
            receipt["subprocess_stderr"] = error.stderr[-1000:]
        raise
    finally:
        cleanup_errors = []

        def cleanup(name, action):
            try:
                return action()
            except Exception as error:
                cleanup_errors.append({"component": name, "error_type": type(error).__name__})
                return None

        for process in processes:
            if process.poll() is None:
                cleanup("worker_kill", process.kill)
                cleanup("worker_reap", lambda process=process: process.communicate(timeout=5))
        if services:
            receipt["provider_cleanup"] = cleanup("provider", services.close)
        if slow:
            cleanup("http_service", slow.close)
        cleanup("temporary_directory", temporary.cleanup)
        receipt["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            receipt["status"] = "failed"
        receipt["temporary_directory_removed"] = not Path(temporary.name).exists()
        receipt["all_worker_processes_reaped"] = all(process.poll() is not None for process in processes)
        receipt["elapsed_seconds"] = time.monotonic() - started
        receipt["environment"]["load_average_at_end"] = os.getloadavg()
        receipt_path.parent.mkdir(parents=True, exist_ok=True)
        receipt_path.write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] != "passed":
        raise RuntimeError("diagnostic cleanup failed; see receipt")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--worker", type=Path, default=ROOT / "build/saga-worker")
    parser.add_argument("--harness", type=Path, default=ROOT / "build/saga-cycle-benchmark")
    parser.add_argument("--receipt", type=Path, default=ROOT / ".artifacts/concurrency-tradeoffs.json")
    parser.add_argument("--iterations", type=int, default=200)
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--rounds", type=int, default=12)
    parser.add_argument("--delay", type=float, default=.25)
    parser.add_argument("--memory-mib", type=int, nargs="+", default=[0, 64, 256])
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100000 or not 0 <= args.warmup <= 10000 or not 1 <= args.rounds <= 100 or not .05 <= args.delay <= 1:
        parser.error("sample counts or delay outside diagnostic limits")
    if any(not 0 <= value <= 512 for value in args.memory_mib):
        parser.error("parent memory allocation must be 0 through 512 MiB")
    receipt = run(args.worker, args.harness, args.receipt, iterations=args.iterations, warmup=args.warmup,
                  rounds=args.rounds, delay=args.delay, memory_sizes=args.memory_mib)
    print(json.dumps({"status": receipt["status"], "receipt": str(args.receipt), "checks": receipt["checks"]}))


if __name__ == "__main__":
    main()
