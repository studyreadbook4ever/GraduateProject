"""Every API dialect normalizes into the same authority-free call."""

import pytest

from saga.adapters import normalize_call
from saga.errors import ProviderError


CALL = {"tool": "read_file", "arguments": {"resource": "notes"}}
FORMATS = [
    ("canonical", CALL),
    ("openai", {"id": "call_1", "type": "function", "function": {"name": "read_file", "arguments": '{"resource":"notes"}'}}),
    ("anthropic", {"type": "tool_use", "id": "toolu_1", "name": "read_file", "input": {"resource": "notes"}}),
    ("gemini", {"functionCall": {"name": "read_file", "args": {"resource": "notes"}}}),
    ("mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "read_file", "arguments": {"resource": "notes"}}}),
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
