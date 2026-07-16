"""
Binary Encoding.

Converts JSON data to binary format for cryptographic operations.
Supports both regular encoding and DataUpdate encoding with Constellation prefix.
"""

import base64
from typing import Any

from constellation_metagraph.core.canonicalize import canonicalize
from constellation_metagraph.core.types import CONSTELLATION_PREFIX


def to_bytes(data: Any, is_data_update: bool = False) -> bytes:
    """
    Convert data to binary bytes for signing.

    For regular data:
        JSON -> RFC 8785 canonicalization -> UTF-8 bytes

    For DataUpdate (is_data_update=True):
        JSON -> RFC 8785 -> UTF-8 -> Base64 -> prepend Constellation prefix -> UTF-8 bytes

    Args:
        data: Any JSON-serializable object
        is_data_update: If True, applies DataUpdate encoding with Constellation prefix

    Returns:
        Binary bytes

    Example:
        >>> # Regular encoding
        >>> to_bytes({"action": "test"})
        b'{"action":"test"}'

        >>> # DataUpdate encoding
        >>> to_bytes({"action": "test"}, is_data_update=True)
        b'\\x19Constellation Signed Data:\\n...'
    """
    canonical_json = canonicalize(data)
    utf8_bytes = canonical_json.encode("utf-8")

    if is_data_update:
        # Base64 encode the UTF-8 bytes
        base64_string = base64.b64encode(utf8_bytes).decode("ascii")
        # Create the wrapped string with Constellation prefix
        wrapped_string = f"{CONSTELLATION_PREFIX}{len(base64_string)}\n{base64_string}"
        return wrapped_string.encode("utf-8")

    return utf8_bytes


def encode_data_update(data: Any) -> bytes:
    """
    Encode data as a DataUpdate with Constellation prefix.

    This is equivalent to `to_bytes(data, is_data_update=True)`.

    Args:
        data: Any JSON-serializable object

    Returns:
        Binary bytes with Constellation prefix
    """
    return to_bytes(data, is_data_update=True)
