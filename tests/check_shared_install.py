"""Check the default shared install after relocating its entire prefix.

Run with --source ., --work /temporary/new-directory and optionally --libdir
lib64. Uses only the standard library plus CMake/C++ build dependencies. Runtime
checks clear the environment so LD_LIBRARY_PATH cannot hide a broken install.
"""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess


def command(*arguments, expected=0, **kwargs):
    process = subprocess.run([str(argument) for argument in arguments],
                             capture_output=True, text=True, timeout=180, **kwargs)
    if expected is not None and process.returncode != expected:
        raise RuntimeError(f"command failed: {arguments[0]}\n{process.stdout}\n{process.stderr}")
    return process


def check(source: Path, work: Path, libdir: str | None = None):
    work.mkdir(parents=True, exist_ok=True)
    if any(work.iterdir()):
        raise ValueError("installation check requires a new or empty work directory")
    build, original, relocated = (work / name for name in ("build", "original", "relocated"))
    arguments = ["cmake", "-S", source, "-B", build, "-DCMAKE_BUILD_TYPE=Release",
                 "-DBUILD_TESTING=OFF", "-DBUILD_SHARED_LIBS=ON",
                 f"-DCMAKE_INSTALL_PREFIX={original}"]
    if libdir is not None:
        directory = Path(libdir)
        if not libdir or directory.is_absolute() or ".." in directory.parts or str(directory) != libdir:
            raise ValueError("libdir must be a normalized relative directory")
        arguments.append(f"-DCMAKE_INSTALL_LIBDIR={libdir}")
    command(*arguments)
    command("cmake", "--build", build, "--parallel", "2")
    command("cmake", "--install", build)
    original.rename(relocated)
    build.rename(work / "build-unavailable")

    binary = relocated / "bin/saga-worker"
    dynamic = command("readelf", "-d", binary).stdout
    paths = re.findall(r"\((?:RPATH|RUNPATH)\).*\[([^]]*)\]", dynamic)
    library, = relocated.rglob("libsaga_worker.so")
    expected_path = "$ORIGIN/" + os.path.relpath(library.parent, binary.parent)
    assert paths == [expected_path], (paths, expected_path)
    process = command(binary, "--probe", expected=None, env={}, cwd="/")
    try:
        probe = json.loads(process.stdout)
    except ValueError as error:
        raise RuntimeError(f"installed worker failed before its probe\n{process.stderr}") from error
    assert type(probe.get("landlock_abi")) is int, probe
    assert probe.get("required_abi") == 9, probe
    supported = probe["landlock_abi"] >= 9
    assert probe.get("supported") is supported, probe
    assert process.returncode == (0 if supported else 1), (process.returncode, process.stderr)

    if supported:
        specification = work / "probe.json"
        specification.write_text(json.dumps({
            "sandbox": {"paths": [], "tcp_ports": []},
            "attempts": [{"kind": "udp_socket"},
                         {"kind": "environment", "name": "LD_LIBRARY_PATH"}],
        }))
        result = json.loads(command(binary, "--sandbox-probe", specification, env={}, cwd="/").stdout)
        assert result["ok"] is True, result
        assert all(item["ok"] is False for item in result["attempts"]), result

    # The example owns its JSON parser and discovers only the installed Saga
    # target. A known public Ed25519 key is sufficient for initialization; the
    # deliberately unavailable loopback Provider produces a failing receipt.
    consumer = work / "consumer"
    consumer_arguments = ["cmake", "-S", source / "examples/cpp", "-B", consumer,
                          f"-DCMAKE_PREFIX_PATH={relocated}"]
    if libdir is not None:
        # Some distributions disable automatic lib64 package lookup. An
        # explicitly selected nondefault directory needs an explicit Saga_DIR.
        consumer_arguments.append(f"-DSaga_DIR={relocated / libdir / 'cmake/Saga'}")
    command(*consumer_arguments)
    command("cmake", "--build", consumer, "--parallel", "2")
    if supported:
        public_key = work / "public.pem"
        public_der = bytes.fromhex("302a300506032b6570032100" +
                                   "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        public_key.write_text("-----BEGIN PUBLIC KEY-----\n" +
                              base64.b64encode(public_der).decode("ascii") +
                              "\n-----END PUBLIC KEY-----\n")
        config = work / "worker.json"
        config.write_text(json.dumps({
            "provider_url": "https://127.0.0.1:1", "ca_certificate": "unused-ca",
            "client_certificate": "unused-certificate", "client_key": "unused-key",
            "provider_public_key": str(public_key), "agent_id": "demo-agent",
        }))
        example = command(consumer / "saga-example", config, expected=1, env={}, cwd="/")
        receipt = json.loads(example.stdout)
        assert receipt["ok"] is False and receipt["executor_started"] is False, receipt

    report = {"shared_install": "passed", "relocated_prefix": str(relocated),
              "libdir": libdir or "default", "landlock_abi": probe["landlock_abi"],
              "runpath": paths[0],
              "executor_probe": "passed" if supported else "unsupported kernel",
              "installed_example": "passed" if supported else "compiled"}
    (work / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--libdir")
    options = parser.parse_args()
    check(options.source.resolve(), options.work.resolve(), options.libdir)
