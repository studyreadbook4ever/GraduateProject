"""Translate individual tool calls without treating model metadata as authority.

Pass plain JSON dictionaries (for example, SDK objects converted with
``model_dump(exclude_none=True)``). Full responses, call batches, streaming
fragments and vendor-hosted tools are deliberately unsupported. Split completed
calls explicitly and retain the original model turn in your conversation state.
"""

import math
from collections.abc import Callable
from dataclasses import dataclass, field

from .errors import ProviderError
from .jsonutil import dumps, loads


_ARGUMENT_LIMIT = 1_048_576
_RESULT_LIMIT = 4_194_304 + 65_536


def _bad(message: str):
    raise ProviderError(400, "invalid_call", message)


def _mapping(value, allowed: set[str], required: set[str], label: str) -> dict:
    if not isinstance(value, dict) or not required <= value.keys() or not value.keys() <= allowed:
        _bad(f"invalid {label} fields; pass one completed call, splitting response envelopes and batches explicitly")
    return value


def _text(value, label: str, *, limit: int = 1024) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        _bad(f"{label} must be nonempty text without control characters")
    try:
        value.encode("utf-8")
    except UnicodeError:
        _bad(f"{label} must be valid UTF-8 text")
    return value


def _json_text(value, label: str, *, limit: int = _ARGUMENT_LIMIT) -> str:
    """Reject lossy Python-to-JSON coercions and bound every dialect equally."""
    def check(item, depth=0):
        if depth > 128:
            raise ValueError("JSON is too deep")
        if item is None or isinstance(item, (str, bool, int)):
            return
        if isinstance(item, float) and math.isfinite(item):
            return
        if isinstance(item, list):
            for child in item:
                check(child, depth + 1)
            return
        if isinstance(item, dict) and all(isinstance(key, str) for key in item):
            for child in item.values():
                check(child, depth + 1)
            return
        raise ValueError("not a JSON value")

    try:
        check(value)
        encoded = dumps(value)
        if len(encoded.encode("utf-8")) > limit:
            code = "capability_too_large" if label == "tool arguments" else "result_too_large"
            raise ProviderError(413, code, f"{label} exceed the size limit")
        return encoded
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _bad(f"{label} must contain finite UTF-8 JSON values")


def _canonical(name, arguments) -> dict:
    _text(name, "tool name", limit=128)
    if not isinstance(arguments, dict):
        _bad("tool arguments must be an object")
    # Return a snapshot, so caller mutation cannot change metadata after parsing.
    return {"tool": name, "arguments": loads(_json_text(arguments, "tool arguments"))}


def _optional_id(call: dict, field: str = "id"):
    if field in call:
        _text(call[field], "tool call ID")


def canonical(call) -> dict:
    call = _mapping(call, {"tool", "arguments"}, {"tool", "arguments"}, "canonical call")
    return _canonical(call["tool"], call["arguments"])


def _openai_arguments(arguments):
    # Dicts remain accepted for compatibility with the original local adapter.
    if isinstance(arguments, str):
        try:
            if len(arguments.encode("utf-8")) > _ARGUMENT_LIMIT:
                raise ProviderError(413, "capability_too_large", "tool arguments exceed the size limit")
            return loads(arguments)
        except (ValueError, UnicodeError, RecursionError):
            _bad("OpenAI arguments are not valid JSON")
    return arguments


def openai(call) -> dict:
    """An individual Chat Completions function tool-call object."""
    call = _mapping(call, {"id", "type", "function"}, {"function"}, "OpenAI Chat Completions call")
    if "type" in call and call["type"] != "function":
        _bad("OpenAI call type must be function")
    _optional_id(call)
    function = _mapping(call["function"], {"name", "arguments"}, {"name", "arguments"}, "OpenAI function")
    return _canonical(function["name"], _openai_arguments(function["arguments"]))


def openai_responses(call) -> dict:
    """An individual completed Responses API function_call output item."""
    call = _mapping(call, {"id", "call_id", "type", "name", "arguments", "status"},
                    {"type", "call_id", "name", "arguments"}, "OpenAI Responses call")
    if call["type"] != "function_call":
        _bad("OpenAI Responses item type must be function_call")
    if "status" in call and call["status"] != "completed":
        _bad("OpenAI Responses function call must be completed before execution")
    _optional_id(call)
    _optional_id(call, "call_id")
    return _canonical(call["name"], _openai_arguments(call["arguments"]))


def anthropic(call) -> dict:
    call = _mapping(call, {"type", "id", "name", "input"}, {"type", "name", "input"}, "Anthropic call")
    if call["type"] != "tool_use":
        _bad("Anthropic call type must be tool_use")
    _optional_id(call)
    return _canonical(call["name"], call["input"])


def gemini(call) -> dict:
    call = _mapping(call, {"functionCall", "thoughtSignature"}, {"functionCall"}, "Gemini call part")
    if "thoughtSignature" in call:
        _text(call["thoughtSignature"], "Gemini thought signature", limit=_ARGUMENT_LIMIT)
    function = _mapping(call["functionCall"], {"name", "args", "id"}, {"name"}, "Gemini function")
    _optional_id(function)
    return _canonical(function["name"], function.get("args", {}))


def _mcp_id(value):
    # bool is an int subclass in Python, but it is not a JSON-RPC request ID.
    if type(value) is int:
        _json_text(value, "MCP request ID")
        return value
    return _text(value, "MCP request ID")


def mcp(call) -> dict:
    call = _mapping(call, {"jsonrpc", "id", "method", "params"}, {"method", "params"}, "MCP call")
    if call["method"] != "tools/call" or ("jsonrpc" in call and call["jsonrpc"] != "2.0"):
        _bad("MCP method must be tools/call with JSON-RPC 2.0")
    if "id" in call:
        _mcp_id(call["id"])
    params = _mapping(call["params"], {"name", "arguments", "_meta"}, {"name"}, "MCP parameters")
    if "_meta" in params:
        if not isinstance(params["_meta"], dict):
            _bad("MCP metadata must be an object")
        _json_text(params["_meta"], "MCP metadata")
    # Transport metadata is deliberately excluded from authorization.
    return _canonical(params["name"], params.get("arguments", {}))


class AdapterRegistry:
    """A Provider-owned registry; clients cannot register adapters over HTTP."""

    def __init__(self):
        self._adapters: dict[str, Callable] = {
            "canonical": canonical,
            "openai": openai,
            "openai_chat": openai,
            "openai_responses": openai_responses,
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
    """Return only authorization-relevant fields, retaining the original API."""
    return AdapterRegistry().normalize(format_name, call)


@dataclass(frozen=True)
class ToolCall:
    """A local correlation handle. Its ID is never an authorization identity."""

    format: str
    tool: str
    call_id: str | int | None
    _arguments_json: str = field(repr=False)

    @property
    def canonical(self) -> dict:
        return {"tool": self.tool, "arguments": loads(self._arguments_json)}


def normalize_tool_call(format_name: str, call) -> ToolCall:
    """Parse one call and retain the upstream identifier needed for its result.

    Unlike legacy normalize_call, dialects that require a result identifier
    require it here. A missing Gemini identifier remains absent on the result.
    """
    normalized = normalize_call(format_name, call)
    if format_name in {"openai", "openai_chat", "anthropic", "mcp"}:
        if "id" not in call:
            _bad("tool call ID is required for result correlation")
        call_id = call["id"]
    elif format_name == "openai_responses":
        call_id = call["call_id"]
    elif format_name == "gemini":
        call_id = call["functionCall"].get("id")
    else:
        call_id = None
    return ToolCall(format_name, normalized["tool"], call_id, dumps(normalized["arguments"]))


def format_tool_result(call: ToolCall, result, *, is_error: bool = False) -> dict:
    """Build one vendor result item/block; callers own enclosing conversations.

    This maps local JSON results. It does not implement a vendor SDK, MCP
    transport/handshake, streaming, multimodal results, or hosted tool execution.
    An uncertain execution must be reconciled by the caller before any retry.
    """
    if not isinstance(call, ToolCall) or type(is_error) is not bool:
        _bad("result mapping requires a ToolCall and boolean is_error")
    text = _json_text(result, "tool result", limit=_RESULT_LIMIT)
    value = loads(text)
    if call.format in {"openai", "openai_chat"}:
        if is_error:
            text = dumps({"error": value})
        return {"role": "tool", "tool_call_id": call.call_id, "content": text}
    if call.format == "openai_responses":
        if is_error:
            text = dumps({"error": value})
        return {"type": "function_call_output", "call_id": call.call_id, "output": text}
    if call.format == "anthropic":
        return {"type": "tool_result", "tool_use_id": call.call_id, "content": text, "is_error": is_error}
    if call.format == "gemini":
        response = {"name": call.tool, "response": {"error" if is_error else "result": value}}
        if call.call_id is not None:
            response["id"] = call.call_id
        return {"functionResponse": response}
    if call.format == "mcp":
        structured = value if isinstance(value, dict) else {"result": value}
        return {"jsonrpc": "2.0", "id": call.call_id, "result": {
            "content": [{"type": "text", "text": dumps(structured)}],
            "structuredContent": structured, "isError": is_error,
        }}
    if call.format == "canonical":
        return {"tool": call.tool, "result": value, "is_error": is_error}
    _bad("unsupported tool-result format")
