"""Every API dialect normalizes into the same authority-free call."""

import copy
import json
from dataclasses import FrozenInstanceError

import pytest

from saga.adapters import AdapterRegistry, format_tool_result, normalize_call, normalize_tool_call
from saga.errors import ProviderError


CALL = {"tool": "read_file", "arguments": {"resource": "notes"}}
FORMATS = [
    ("canonical", CALL),
    ("openai", {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": '{"resource":"notes"}'}}),
    ("anthropic", {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"resource": "notes"}}),
    ("gemini", {"functionCall": {"name": "read_file", "args": {"resource": "notes"}}}),
    ("mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"resource": "notes"}}}),
]
FORMATS += [
    ("openai_chat", copy.deepcopy(FORMATS[1][1])),
    ("openai_responses", {"id": "fc_item_1", "call_id": "call_result_1", "type": "function_call", "name": "read_file", "arguments": '{"resource":"notes"}', "status": "completed"}),
]


@pytest.mark.parametrize("format,call", FORMATS)
def test_all_formats_normalize(format, call):
    assert normalize_call(format, call) == CALL


@pytest.mark.parametrize("format,call", [
    ("canonical", [CALL, CALL]),
    ("openai", {"tool_calls": [FORMATS[1][1], FORMATS[1][1]]}),
    ("openai", {"function": {"name": "read_file", "arguments": '{"resource":"notes", "resource":"private"}'}}),
    ("canonical", {"tool": "read_file", "arguments": {"resource": "notes"}, "agent_id": "bob"}),
    ("unknown", CALL),
])
def test_ambiguous_or_identity_bearing_calls_are_rejected(format, call):
    with pytest.raises(ProviderError):
        normalize_call(format, call)


def dialect_call(format, arguments):
    """Independent literal wire shapes for semantic equivalence vectors."""
    if format == "canonical":
        return {"tool": "write_file", "arguments": arguments}
    if format in {"openai", "openai_chat"}:
        return {"id": "upstream_1", "type": "function", "function": {"name": "write_file", "arguments": json.dumps(arguments)}}
    if format == "openai_responses":
        return {"id": "fc_different_item_id", "call_id": "upstream_1", "type": "function_call", "name": "write_file", "arguments": json.dumps(arguments)}
    if format == "anthropic":
        return {"id": "upstream_1", "type": "tool_use", "name": "write_file", "input": arguments}
    if format == "gemini":
        return {"functionCall": {"id": "upstream_1", "name": "write_file", "args": arguments}, "thoughtSignature": "opaque-signature"}
    if format == "mcp":
        return {"jsonrpc": "2.0", "id": "upstream_1", "method": "tools/call", "params": {"name": "write_file", "arguments": arguments, "_meta": {"agent_id": "untrusted", "task_id": "private"}}}
    raise AssertionError(format)


DIALECTS = [format for format, _ in FORMATS]


@pytest.mark.parametrize("format", DIALECTS)
@pytest.mark.parametrize("arguments", [
    {"resource": "output", "content": "한글\nline\u2028separator\x00literal\\u0000"},
    {"nested": {"null": None, "bool": True, "integer": 42, "real": 0.5, "list": [0, False, None, "é"]}},
    {},
])
def test_semantic_argument_vectors_are_lossless_and_detached(format, arguments):
    original = copy.deepcopy(arguments)
    call = dialect_call(format, arguments)
    normalized = normalize_call(format, call)
    assert normalized == {"tool": "write_file", "arguments": original}
    arguments["later"] = "caller mutation"
    assert normalized["arguments"] == original


@pytest.mark.parametrize("format", DIALECTS)
def test_upstream_call_id_is_preserved_for_result_mapping(format):
    handle = normalize_tool_call(format, dialect_call(format, {"resource": "output", "content": "secret"}))
    assert handle.canonical == {"tool": "write_file", "arguments": {"resource": "output", "content": "secret"}}
    assert handle.call_id == (None if format == "canonical" else "upstream_1")
    assert "secret" not in repr(handle)
    with pytest.raises(FrozenInstanceError):
        handle.call_id = "other"
    handle.canonical["arguments"]["content"] = "changed"
    assert handle.canonical["arguments"]["content"] == "secret"
    result = {"content": "한글\x00\n", "values": [None, 1, True]}
    mapped = format_tool_result(handle, result)
    if format in {"openai", "openai_chat"}:
        assert mapped["role"] == "tool"
        assert mapped["tool_call_id"] == "upstream_1"
        assert json.loads(mapped["content"]) == result
    elif format == "openai_responses":
        assert mapped["type"] == "function_call_output"
        assert mapped["call_id"] == "upstream_1"  # Never fc_different_item_id.
        assert json.loads(mapped["output"]) == result
    elif format == "anthropic":
        assert mapped["type"] == "tool_result"
        assert mapped["tool_use_id"] == "upstream_1"
        assert mapped["is_error"] is False
        assert json.loads(mapped["content"]) == result
    elif format == "gemini":
        assert mapped == {"functionResponse": {"id": "upstream_1", "name": "write_file", "response": {"result": result}}}
    elif format == "mcp":
        assert mapped["jsonrpc"] == "2.0"
        assert mapped["id"] == "upstream_1"
        assert mapped["result"]["structuredContent"] == result
        assert json.loads(mapped["result"]["content"][0]["text"]) == result
        assert mapped["result"]["isError"] is False
    else:
        assert mapped == {"tool": "write_file", "result": result, "is_error": False}


@pytest.mark.parametrize("format", DIALECTS)
def test_error_results_are_marked_in_each_dialect(format):
    handle = normalize_tool_call(format, dialect_call(format, {}))
    result = format_tool_result(handle, {"code": "resource_unavailable"}, is_error=True)
    if format in {"openai", "openai_chat", "openai_responses"}:
        text = result.get("content", result.get("output"))
        assert json.loads(text) == {"error": {"code": "resource_unavailable"}}
    elif format == "anthropic":
        assert result["is_error"] is True
    elif format == "gemini":
        assert result["functionResponse"]["response"] == {"error": {"code": "resource_unavailable"}}
    elif format == "mcp":
        assert result["result"]["isError"] is True
    else:
        assert result["is_error"] is True


@pytest.mark.parametrize("call_id", [0, -1, 42, "request-42"])
def test_mcp_request_id_is_not_coerced(call_id):
    call = {"jsonrpc": "2.0", "id": call_id, "method": "tools/call", "params": {"name": "read_file"}}
    handle = normalize_tool_call("mcp", call)
    result = format_tool_result(handle, None)
    assert result["id"] == call_id
    assert type(result["id"]) is type(call_id)
    assert result["result"]["structuredContent"] == {"result": None}


def test_optional_gemini_id_and_empty_arguments():
    handle = normalize_tool_call("gemini", {"functionCall": {"name": "read_file"}})
    assert handle.canonical == {"tool": "read_file", "arguments": {}}
    assert format_tool_result(handle, "done") == {"functionResponse": {"name": "read_file", "response": {"result": "done"}}}


@pytest.mark.parametrize("format", ["openai", "openai_chat", "anthropic", "mcp"])
def test_result_mapping_requires_upstream_id(format):
    call = dialect_call(format, {})
    del call["id"]
    assert normalize_call(format, call) == {"tool": "write_file", "arguments": {}}
    with pytest.raises(ProviderError, match="required for result correlation"):
        normalize_tool_call(format, call)


@pytest.mark.parametrize("format", DIALECTS)
def test_response_envelopes_and_batches_are_explicitly_rejected(format):
    call = dialect_call(format, {})
    for response in ([call, call], {"output": [call]}, {"content": [call]}, {"choices": [{"message": {"tool_calls": [call]}}]}, {"candidates": [{"content": {"parts": [call]}}]}):
        with pytest.raises(ProviderError, match="splitting response envelopes and batches explicitly"):
            normalize_tool_call(format, response)


@pytest.mark.parametrize("arguments", [None, [], "{}", {"x": float("nan")}, {"x": float("inf")}, {1: "integer key"}, {"x": (1, 2)}, {"x": b"binary"}, {"x": "\ud800"}])
@pytest.mark.parametrize("format", ["canonical", "anthropic", "gemini", "mcp"])
def test_invalid_json_arguments_cannot_be_coerced(format, arguments):
    with pytest.raises(ProviderError) as failure:
        normalize_call(format, dialect_call(format, arguments))
    assert failure.value.code == "invalid_call"


@pytest.mark.parametrize("arguments", ['{"resource":"notes","resource":"private"}', '{"x":NaN}', '{"x":Infinity}', '{"x":1e999}', '{"x":"\\ud800"}', '{"x":', 'null', '[]'])
@pytest.mark.parametrize("format", ["openai", "openai_responses"])
def test_openai_json_text_is_strict(format, arguments):
    call = dialect_call(format, {})
    if format == "openai":
        call["function"]["arguments"] = arguments
    else:
        call["arguments"] = arguments
    with pytest.raises(ProviderError):
        normalize_tool_call(format, call)


@pytest.mark.parametrize("format", DIALECTS)
def test_argument_size_limit_applies_to_all_dialects(format):
    with pytest.raises(ProviderError, match="size limit"):
        normalize_call(format, dialect_call(format, {"content": "한" * 400_000}))


@pytest.mark.parametrize("format", DIALECTS)
def test_cycles_and_deeply_nested_json_fail_safely(format):
    # OpenAI JSON strings cannot represent cycles; test depth for those formats.
    arguments = {}
    for _ in range(140):
        arguments = {"nested": arguments}
    with pytest.raises(ProviderError):
        normalize_call(format, dialect_call(format, arguments))
    if format not in {"openai", "openai_chat", "openai_responses"}:
        arguments = {}
        arguments["cycle"] = arguments
        with pytest.raises(ProviderError):
            normalize_call(format, dialect_call(format, arguments))


@pytest.mark.parametrize("status", [None, "in_progress", "incomplete", "failed"])
def test_responses_call_must_be_complete(status):
    call = dialect_call("openai_responses", {})
    call["status"] = status
    with pytest.raises(ProviderError, match="must be completed"):
        normalize_tool_call("openai_responses", call)


@pytest.mark.parametrize("format", ["openai", "openai_chat", "openai_responses", "anthropic", "gemini", "mcp"])
@pytest.mark.parametrize("bad_id", [None, True, 1.5, "", "secret\x00suffix", "\udfff"])
def test_invalid_correlation_ids_are_rejected(format, bad_id):
    call = dialect_call(format, {})
    if format == "openai_responses":
        call["call_id"] = bad_id
    elif format == "gemini":
        call["functionCall"]["id"] = bad_id
    else:
        call["id"] = bad_id
    with pytest.raises(ProviderError):
        normalize_tool_call(format, call)


def test_custom_adapter_remains_provider_owned_and_authority_free():
    registry = AdapterRegistry()
    registry.register("trusted", lambda call: {"tool": "read_file", "arguments": {"resource": call}})
    assert registry.normalize("trusted", "notes") == CALL
    with pytest.raises(ProviderError):
        normalize_call("trusted", "notes")
    registry.register("unsafe", lambda call: {**CALL, "agent_id": "alice"})
    with pytest.raises(ProviderError):
        registry.normalize("unsafe", None)


@pytest.mark.parametrize("format", DIALECTS)
def test_result_limit_accepts_maximum_executor_output(format):
    handle = normalize_tool_call(format, dialect_call(format, {}))
    # Escaped text is much larger than decoded file bytes and may exceed the
    # input argument limit while remaining inside the 4 MiB executor envelope.
    output = {"content": "\\" * (2_097_152 - 1024)}
    mapped = format_tool_result(handle, output)
    assert len(json.dumps(output).encode()) < 4_194_304
    assert mapped


def test_oversized_results_and_non_json_results_fail_with_safe_errors():
    handle = normalize_tool_call("canonical", CALL)
    for result in (float("inf"), {"secret": "\ud800"}, {1: "bad key"}, b"bytes"):
        with pytest.raises(ProviderError) as failure:
            format_tool_result(handle, result)
        assert failure.value.code == "invalid_call"
    with pytest.raises(ProviderError) as failure:
        format_tool_result(handle, {"private": "x" * (4_194_304 + 65_536)})
    assert failure.value.status == 413
    assert failure.value.code == "result_too_large"
    assert "private" not in str(failure.value)
