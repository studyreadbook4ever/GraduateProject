"""Opt-in installed-executor regression using a private SQLite SONAME.

Run with --source ., --sqlite /absolute/libsqlite3.so, --work /temporary/path,
and --shared 0 or 1. The unique SONAME prevents a system SQLite fallback from
concealing an executor that still depends on its original build directory.
"""

import argparse
import json
from pathlib import Path
import re
import subprocess


def command(*arguments, **kwargs):
    result = subprocess.run([str(argument) for argument in arguments], capture_output=True, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError(f"command failed: {arguments[0]}\n{result.stdout}\n{result.stderr}")
    return result


def check(source: Path, sqlite: Path, work: Path, shared: bool):
    original = work / "original-dependency"
    installed = work / "installed"
    build = work / "build"
    original.mkdir(parents=True)
    (installed / "lib").mkdir(parents=True)
    dynamic = command("readelf", "-d", sqlite).stdout
    match = re.search(r"\(SONAME\).*\[([^]]+)\]", dynamic)
    if match is None:
        raise RuntimeError("private dependency check requires a SQLite shared library with SONAME")
    old = match.group(1).encode()
    if len(old) < 8:
        raise RuntimeError("SQLite SONAME is too short for a distinct ELF library name")
    name = "lib" + "s" * (len(old) - 8) + ".so.0"
    data = sqlite.read_bytes()
    if old + b"\0" not in data:
        raise RuntimeError("SQLite SONAME was not found in its ELF string table")
    data = data.replace(old + b"\0", name.encode() + b"\0")
    for directory in (original, installed / "lib"):
        (directory / name).write_bytes(data)
    command("cmake", "-S", source, "-B", build, "-DCMAKE_BUILD_TYPE=Release", "-DBUILD_TESTING=OFF",
            f"-DBUILD_SHARED_LIBS={'ON' if shared else 'OFF'}", f"-DSQLite3_LIBRARY={original / name}",
            f"-DCMAKE_INSTALL_RPATH={installed / 'lib'}")
    command("cmake", "--build", build, "-j", "2")
    command("cmake", "--install", build, "--prefix", installed)
    helper_dynamic = command("readelf", "-d", build / "saga-executor").stdout
    assert "(RPATH)" not in helper_dynamic and "(RUNPATH)" not in helper_dynamic
    original.rename(work / "removed-dependency")
    binary = installed / "bin/saga-worker"
    # The coordinator must load the installed private DSO; a system fallback
    # would make this test pass without exercising installation compatibility.
    dependencies = command("ldd", binary, env={}).stdout
    assert str(installed / "lib" / name) in dependencies, dependencies
    marker = "parent-environment-must-not-cross-exec"
    document = work / "probe.json"
    document.write_text(json.dumps({
        "sandbox": {"paths": [], "tcp_ports": []},
        "attempts": [
            {"kind": "udp_socket"},
            {"kind": "environment", "name": "SAGA_HOST_SECRET"},
            {"kind": "environment", "name": "LD_LIBRARY_PATH"},
        ],
    }))
    process = command(binary, "--sandbox-probe", document, env={"SAGA_HOST_SECRET": marker}, cwd="/")
    result = json.loads(process.stdout)
    assert result["ok"] is True, result
    assert all(attempt["ok"] is False for attempt in result["attempts"]), result
    assert marker not in process.stdout + process.stderr
    print(f"installed private SQLite executor passed (shared={shared})")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--sqlite", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--shared", choices=("0", "1"), default="0")
    arguments = parser.parse_args()
    check(arguments.source.resolve(), arguments.sqlite.resolve(), arguments.work.resolve(), arguments.shared == "1")
