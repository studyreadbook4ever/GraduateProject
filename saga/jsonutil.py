"""One JSON interpretation at every trust boundary."""

import json


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def loads(value: str | bytes):
    def invalid_constant(_):
        raise ValueError("non-finite JSON number")

    if isinstance(value, bytes):
        value = value.decode("utf-8")
    return json.loads(value, object_pairs_hook=_object, parse_constant=invalid_constant)


def dumps(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
