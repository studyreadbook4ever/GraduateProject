"""Validate administrator-owned policy before starting the Provider."""

import copy
import ipaddress
import math
import re
import sqlite3
from contextlib import closing
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

from .jsonutil import loads

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_FINGERPRINT = re.compile(r"^[0-9a-fA-F]{64}$")
TOOLS = {"read_file", "write_file", "query_db", "http_get"}


def identifier(value, label: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {label}")
    return value


def regular_path(value) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("resource path must be an absolute regular file")
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        raise ValueError("resource path must be normalized and absolute")
    for component in [path, *path.parents]:
        if component.is_symlink():
            raise ValueError("resource path contains a symlink")
    if not path.is_file():
        raise ValueError("resource path must name an existing regular file")
    return str(path)


def sqlite_snapshot(value) -> str:
    """Require a quiescent rollback-format snapshot for immutable SQLite reads.

    An operator must freeze its contents while it is registered. Ignoring an
    active WAL can silently omit committed data, so WAL databases and journal
    sidecars are rejected instead of being queried as stale snapshots.
    """
    path = regular_path(value)
    with open(path, "rb") as source:
        header = source.read(100)
    if len(header) < 100 or header[:16] != b"SQLite format 3\x00" or header[18:20] != b"\x01\x01":
        raise ValueError("SQLite resource must be a rollback-format snapshot without WAL")
    if any(Path(path + suffix).exists() or Path(path + suffix).is_symlink() for suffix in ("-wal", "-shm", "-journal")):
        raise ValueError("SQLite snapshot must not have journal sidecars")
    return path


def _fields(value, required: set[str], allowed: set[str], label: str) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or not value.keys() <= allowed:
        raise ValueError(f"invalid {label} fields")
    return value


def _validate_query(path: str, query: dict) -> None:
    _fields(query, {"sql", "parameters"}, {"sql", "parameters"}, "named query")
    sql, count = query["sql"], query["parameters"]
    if not isinstance(sql, str) or len(sql) > 65536 or not re.match(r"\s*SELECT\b", sql, re.IGNORECASE):
        raise ValueError("named query must be a single SELECT statement")
    if isinstance(count, bool) or not isinstance(count, int) or not 0 <= count <= 128:
        raise ValueError("query parameter count must be between 0 and 128")
    permitted = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION}
    if hasattr(sqlite3, "SQLITE_RECURSIVE"):
        permitted.add(sqlite3.SQLITE_RECURSIVE)

    def authorizer(action, _first, second, _database, _trigger):
        if action == sqlite3.SQLITE_FUNCTION and second == "load_extension":
            return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK if action in permitted else sqlite3.SQLITE_DENY

    try:
        with closing(sqlite3.connect(Path(path).as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
            db.set_authorizer(authorizer)
            db.execute("EXPLAIN " + sql, [None] * count).fetchall()
    except sqlite3.Error as exc:
        raise ValueError("named query must compile as a read-only SELECT with its declared parameters") from exc


def validate_config(config: dict) -> dict:
    config = copy.deepcopy(config)
    _fields(config, {"agents", "tasks", "resources"}, {"agents", "tasks", "resources", "token_ttl_seconds"}, "Provider configuration")
    for field in ("agents", "tasks", "resources"):
        if not isinstance(config[field], dict) or not config[field]:
            raise ValueError(f"{field} must be a nonempty object")
    ttl = config.setdefault("token_ttl_seconds", 60)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 1 <= ttl <= 3600:
        raise ValueError("token TTL must be an integer between 1 and 3600 seconds")
    for name, resource in config["resources"].items():
        identifier(name, "resource ID")
        if not isinstance(resource, dict):
            raise ValueError("invalid resource")
        kind = resource.get("kind")
        if kind == "file":
            _fields(resource, {"kind", "path"}, {"kind", "path"}, "file resource")
            resource["path"] = regular_path(resource["path"])
        elif kind == "sqlite":
            _fields(resource, {"kind", "path", "queries"}, {"kind", "path", "queries"}, "SQLite resource")
            resource["path"] = sqlite_snapshot(resource["path"])
            if not isinstance(resource["queries"], dict) or not resource["queries"]:
                raise ValueError("SQLite resource must declare named queries")
            for query_name, query in resource["queries"].items():
                identifier(query_name, "query name")
                _validate_query(resource["path"], query)
        elif kind == "http":
            _fields(resource, {"kind", "url"}, {"kind", "url"}, "HTTP resource")
            if not isinstance(resource["url"], str) or len(resource["url"]) > 4096:
                raise ValueError("invalid HTTP resource URL")
            url = urlsplit(resource["url"])
            try:
                address = ipaddress.ip_address(url.hostname or "")
                port = 80 if url.port is None else url.port
            except ValueError as exc:
                raise ValueError("HTTP resource requires a numeric loopback address and valid port") from exc
            if url.scheme != "http" or not address.is_loopback or url.username is not None or url.password is not None or url.fragment or not 1 <= port <= 65535:
                raise ValueError("HTTP resources support plain HTTP on numeric loopback only")
            if url.netloc.endswith(":") or "%" in (url.hostname or ""):
                raise ValueError("HTTP authority must have a numeric host and a nonempty port if specified")
            if any(ord(character) <= 32 or ord(character) >= 127 for character in resource["url"]):
                raise ValueError("HTTP URL must be an ASCII URI without whitespace or control characters")
            resource["url"] = urlunsplit((url.scheme, url.netloc, url.path or "/", url.query, ""))
        else:
            raise ValueError("unknown resource kind")
    kinds = {"read_file": "file", "write_file": "file", "query_db": "sqlite", "http_get": "http"}
    for task_id, task in config["tasks"].items():
        identifier(task_id, "task ID")
        _fields(task, {"allow"}, {"allow"}, "task policy")
        if not isinstance(task["allow"], list):
            raise ValueError("task allow policy must be a list")
        seen = set()
        for grant in task["allow"]:
            _fields(grant, {"tool", "resource"}, {"tool", "resource"}, "allow rule")
            tool, resource = grant["tool"], grant["resource"]
            if not isinstance(tool, str) or tool not in TOOLS or not isinstance(resource, str) or resource not in config["resources"]:
                raise ValueError("allow rule names an unknown tool or resource")
            if config["resources"][resource]["kind"] != kinds[tool]:
                raise ValueError("allow rule tool and resource kind do not match")
            if (tool, resource) in seen:
                raise ValueError("duplicate allow rule")
            seen.add((tool, resource))
    fingerprints = set()
    for agent_id, agent in config["agents"].items():
        identifier(agent_id, "agent ID")
        _fields(agent, {"certificate_sha256", "tasks"}, {"certificate_sha256", "tasks"}, "agent policy")
        fingerprint = agent["certificate_sha256"]
        if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
            raise ValueError("certificate fingerprint must be 64 hexadecimal characters")
        fingerprint = fingerprint.lower()
        if fingerprint in fingerprints:
            raise ValueError("a certificate cannot identify multiple agents")
        fingerprints.add(fingerprint)
        agent["certificate_sha256"] = fingerprint
        if not isinstance(agent["tasks"], list) or any(not isinstance(task, str) or task not in config["tasks"] for task in agent["tasks"]):
            raise ValueError("agent tasks must name registered tasks")
        if len(set(agent["tasks"])) != len(agent["tasks"]):
            raise ValueError("duplicate agent task")
    return config


def load_config(path: str | Path) -> dict:
    return validate_config(loads(Path(path).read_bytes()))


def json_parameter(value) -> bool:
    return value is None or isinstance(value, (str, bool, int)) or (isinstance(value, float) and math.isfinite(value))
