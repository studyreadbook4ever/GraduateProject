"""Path syntax is rejected before filesystem/native calls, without touching data."""

import copy
import os
from pathlib import Path

import pytest

from saga.config import load_config, path_string, regular_path, validate_config
from saga.jsonutil import loads
from saga.provision import provision
from saga.tokens import load_private_key, load_public_key


class TextPath:
    def __init__(self, value):
        self.value = value

    def __fspath__(self):
        return self.value


BAD_PATHS = [None, "", 0, False, [], {}, b"/tmp/file", "/tmp/a\x00b", "/tmp/\ud800", "/tmp/\udfff"]


@pytest.mark.parametrize("value", BAD_PATHS)
def test_path_text_rejects_invalid_values_with_stable_error(value):
    with pytest.raises(ValueError, match="^input path must be nonempty UTF-8 path text without NUL$"):
        path_string(value, "input path")


@pytest.mark.parametrize("value", BAD_PATHS)
def test_invalid_paths_never_reach_filesystem(monkeypatch, value):
    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid path reached filesystem")

    monkeypatch.setattr(Path, "is_symlink", unexpected)
    monkeypatch.setattr(Path, "is_file", unexpected)
    monkeypatch.setattr(Path, "read_bytes", unexpected)
    with pytest.raises(ValueError):
        regular_path(value)
    with pytest.raises(ValueError):
        load_config(value)


@pytest.mark.parametrize("value", [None, "", b"/tmp/file", "/tmp/a\x00b", "/tmp/\ud800", 3])
def test_pathlike_cannot_smuggle_invalid_text(value):
    with pytest.raises(ValueError):
        path_string(TextPath(value))


def test_python_paths_accept_pathlike_but_json_policy_does_not(tmp_path):
    filename = tmp_path / "한글.txt"
    filename.write_bytes(b"first\x00second")
    assert path_string(filename) == os.fspath(filename)
    assert path_string(TextPath(str(filename))) == str(filename)
    assert regular_path(str(filename)) == str(filename)
    assert filename.read_bytes() == b"first\x00second"
    with pytest.raises(ValueError):
        regular_path(filename)


@pytest.mark.parametrize("raw", ['null', '""', '"/tmp/a\\u0000b"', '"/tmp/\\ud800"'])
def test_decoded_json_path_is_rejected_before_io(raw, monkeypatch):
    monkeypatch.setattr(Path, "is_symlink", lambda *_: pytest.fail("invalid JSON path reached filesystem"))
    with pytest.raises(ValueError):
        regular_path(loads(raw))


@pytest.mark.parametrize("value", [None, "", "/tmp/a\x00b", "/tmp/\ud800"])
@pytest.mark.parametrize("kind", ["file", "sqlite"])
def test_registered_policy_rejects_invalid_resource_paths(provider_env, value, kind):
    config = copy.deepcopy(provider_env["config"])
    resource = {"kind": kind, "path": value}
    if kind == "sqlite":
        resource["queries"] = {"select": {"sql": "SELECT 1", "parameters": 0}}
    config["resources"]["notes"] = resource
    with pytest.raises(ValueError, match="^resource path must be nonempty UTF-8 path text without NUL$"):
        validate_config(config)


def test_long_resource_path_reports_safe_validation_error(tmp_path):
    with pytest.raises(ValueError) as failure:
        regular_path(str(tmp_path / ("private_filename" * 1000)))
    assert "private_filename" not in str(failure.value)


def test_regular_path_still_refuses_non_normalized_and_symlink_paths(tmp_path):
    filename = tmp_path / "notes.txt"
    filename.write_text("x")
    link = tmp_path / "link"
    link.symlink_to(filename)
    for value in (str(link), str(filename) + "/", str(tmp_path) + "/./notes.txt", str(tmp_path) + "/../notes.txt", "notes.txt"):
        with pytest.raises(ValueError):
            regular_path(value)


@pytest.mark.parametrize("value", BAD_PATHS)
@pytest.mark.parametrize("entrypoint", [load_config, load_private_key, load_public_key, provision])
def test_python_entrypoints_reject_invalid_paths_before_io(monkeypatch, value, entrypoint):
    def unexpected(*_args, **_kwargs):
        pytest.fail("invalid path reached filesystem")

    monkeypatch.setattr(Path, "read_bytes", unexpected)
    monkeypatch.setattr(Path, "absolute", unexpected)
    monkeypatch.setattr(Path, "is_symlink", unexpected)
    with pytest.raises(ValueError, match="must be nonempty UTF-8 path text without NUL"):
        entrypoint(value)


@pytest.mark.parametrize("bad_port", [None, True, False, "8443", 8443.5, 0, -1, 65536])
@pytest.mark.parametrize("port_field", ["provider_port", "http_port"])
def test_provision_validates_ports_before_creating_directory(tmp_path, bad_port, port_field):
    destination = tmp_path / "deployment"
    with pytest.raises(ValueError, match="ports must be integers"):
        provision(destination, **{port_field: bad_port})
    assert not destination.exists()


def test_python_pathlike_key_and_config_roundtrip(tmp_path):
    result = provision(TextPath(str(tmp_path / "deployment")))
    directory = Path(result["directory"])
    config = load_config(TextPath(result["provider_config"]))
    assert config["resources"]["notes"]["path"] == str(directory / "notes.txt")
    private = load_private_key(TextPath(str(directory / "provider-signing-key.pem")))
    public = load_public_key(TextPath(str(directory / "provider-public-key.pem")))
    message = b"path boundary test"
    public.verify(private.sign(message), message)
