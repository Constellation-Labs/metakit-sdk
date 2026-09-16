"""
RFC 8785 JSON Canonicalization with server-aligned null dropping.

Provides deterministic JSON serialization according to RFC 8785.
This ensures identical JSON objects always produce identical strings.

Before canonicalizing, null-valued object fields are recursively dropped
(array nulls are preserved), so the bytes produced for signing/verification
match what the authoritative Scala server (metakit ``JsonBinaryCodec.dropNulls``),
the TypeScript SDK (``dropNullFields``) and the Rust SDK (``drop_null_fields``)
re-derive. See metakit ``docs/content-hash.md``.
"""

from typing import Any

import rfc8785


def drop_null_fields(value: Any) -> Any:
    """
    Recursively drop null-valued object fields (server-aligned).

    Behavior — byte-for-byte matched to metakit's ``JsonBinaryCodec.dropNulls``,
    the TypeScript SDK's ``dropNullFields`` and the Rust SDK's
    ``drop_null_fields``:

    - Object (dict) fields whose value is ``None`` are removed, recursively.
    - Array (list/tuple) elements are NEVER removed — ``None`` elements are
      positional and preserved; nested objects inside arrays are still cleaned.
    - Primitives (including a top-level ``None``) pass through unchanged.

    Args:
        value: Any JSON-serializable value

    Returns:
        The same value with null object-fields recursively removed

    Example:
        >>> drop_null_fields({"a": 1, "b": None, "c": [1, None]})
        {'a': 1, 'c': [1, None]}
    """
    if isinstance(value, dict):
        return {k: drop_null_fields(v) for k, v in value.items() if v is not None}
    if isinstance(value, (list, tuple)):
        return [drop_null_fields(element) for element in value]
    return value


def canonicalize(data: Any) -> str:
    """
    Canonicalize JSON data according to RFC 8785.

    Null-valued object fields are dropped before canonicalization to match
    the authoritative Scala server (see :func:`drop_null_fields`). This makes
    the bytes produced for signing/verification here agree with what the
    chain re-derives.

    Key features:
    - Null-valued object fields dropped (server-aligned; array nulls preserved)
    - Object keys sorted by UTF-16BE binary comparison
    - Numbers serialized in shortest decimal representation
    - No whitespace
    - Proper Unicode escaping

    Args:
        data: Any JSON-serializable object (dict, list, str, int, float, bool, None)

    Returns:
        Canonical JSON string

    Example:
        >>> canonicalize({"b": 2, "a": 1})
        '{"a":1,"b":2}'
        >>> canonicalize({"a": None, "b": 1})  # null object-fields are dropped
        '{"b":1}'
    """
    return canonicalize_bytes(data).decode("utf-8")


def canonicalize_bytes(data: Any) -> bytes:
    """
    Canonicalize JSON data and return as UTF-8 bytes.

    Null-valued object fields are dropped before canonicalization
    (see :func:`drop_null_fields`).

    Args:
        data: Any JSON-serializable object

    Returns:
        Canonical JSON as UTF-8 encoded bytes
    """
    return rfc8785.dumps(drop_null_fields(data))
