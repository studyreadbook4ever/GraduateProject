"""Normalize tool-call syntax without deriving any identity from model output.

Adapters accept exactly one call. A response envelope or tool-call batch must
be split by its caller before normalization, so mixed calls cannot accidentally
receive a shared grant.
"""

from collections.abc import Callable

from .errors import ProviderError
from .jsonutil import loads


def _bad(message: str):
    raise ProviderError(400, "invalid_call", message)


def _mapping(value, allowed: set[str], required: set[str], label: str) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or not value.keys() <= allowed:
        _bad(f"invalid {label} fields")
    return value


def _canonical(name, arguments) -> dict:
    if not isinstance(name, str) or not name or len(name) > 128:
        _bad("tool name must be a nonempty string")
    if not isinstance(arguments, dict):
        _bad("tool arguments must be an object")
    return {"tool": name, "arguments": arguments}


def canonical(call) -> dict:
    call = _mapping(call, {"tool", "arguments"}, {"tool", "arguments"}, "canonical call")
    return _canonical(call["tool"], call["arguments"])


def openai(call) -> dict:
    call = _mapping(call, {"id", "type", "function"}, {"function"}, "OpenAI call")
    if "type" in call and call["type"] != "function":
        _bad("OpenAI call type must be function")
    function = _mapping(call["function"], {"name", "arguments"}, {"name", "arguments"}, "OpenAI function")
    arguments = function["arguments"]
    if isinstance(arguments, str):
        try:
            if len(arguments.encode("utf-8")) > 1_048_576:
                _bad("tool arguments exceed the size limit")
            arguments = loads(arguments)
        except (ValueError, UnicodeError, RecursionError):
            _bad("OpenAI arguments are not valid JSON")
    return _canonical(function["name"], arguments)


def anthropic(call) -> dict:
    call = _mapping(call, {"type", "id", "name", "input"}, {"type", "name", "input"}, "Anthropic call")
    if call["type"] != "tool_use":
        _bad("Anthropic call type must be tool_use")
    return _canonical(call["name"], call["input"])


def gemini(call) -> dict:
    call = _mapping(call, {"functionCall"}, {"functionCall"}, "Gemini call")
    function = _mapping(call["functionCall"], {"name", "args", "id"}, {"name", "args"}, "Gemini function")
    return _canonical(function["name"], function["args"])


def mcp(call) -> dict:
    call = _mapping(call, {"jsonrpc", "id", "method", "params"}, {"method", "params"}, "MCP call")
    if call["method"] != "tools/call" or ("jsonrpc" in call and call["jsonrpc"] != "2.0"):
        _bad("MCP method must be tools/call")
    params = _mapping(call["params"], {"name", "arguments", "_meta"}, {"name", "arguments"}, "MCP parameters")
    # Transport metadata is deliberately excluded from authorization.
    return _canonical(params["name"], params["arguments"])


class AdapterRegistry:
    """A Provider-owned registry; clients cannot register adapters over HTTP."""

    def __init__(self):
        self._adapters: dict[str, Callable] = {
            "canonical": canonical,
            "openai": openai,
            "anthropic": anthropic,
            "gemini": gemini,
            "mcp": mcp,
        }

    def register(self, name: str, adapter: Callable) -> None:
        if not isinstance(name, str) or not name or name in self._adapters or not callable(adapter):
            raise ValueError("adapter name must be new and adapter must be callable")
        self._adapters[name] = adapter

    def normalize(self, format_name: str, call) -> dict:
        if not isinstance(format_name, str) or format_name not in self._adapters:
            _bad("unsupported tool-call format")
        return canonical(self._adapters[format_name](call))


def normalize_call(format_name: str, call) -> dict:
    return AdapterRegistry().normalize(format_name, call)
