"""
Codec Utilities.

Encoding/decoding utilities for the Constellation signature protocol.
"""

import base64
import json
from typing import Any, TypeVar

from constellation_metagraph.core.binary import encode_data_update, to_bytes
from constellation_metagraph.core.types import CONSTELLATION_PREFIX

T = TypeVar("T")

# Re-export from binary
__all__ = ["to_bytes", "encode_data_update", "decode_data_update", "CONSTELLATION_PREFIX"]


def decode_data_update(data: bytes) -> Any:
    """
    Decode a DataUpdate encoded message back to its original JSON.

    Args:
        data: DataUpdate encoded bytes

    Returns:
        Decoded JSON object

    Raises:
        ValueError: If bytes are not valid DataUpdate encoding
    """
    text = data.decode("utf-8")

    # Validate prefix
    if not text.startswith(CONSTELLATION_PREFIX):
        raise ValueError("Invalid DataUpdate encoding: missing Constellation prefix")

    # Parse the format: \x19Constellation Signed Data:\n{length}\n{base64}
    without_prefix = text[len(CONSTELLATION_PREFIX) :]
    newline_index = without_prefix.find("\n")

    if newline_index == -1:
        raise ValueError("Invalid DataUpdate encoding: missing length delimiter")

    length_str = without_prefix[:newline_index]
    base64_data = without_prefix[newline_index + 1 :]

    try:
        expected_length = int(length_str)
    except ValueError:
        raise ValueError("Invalid DataUpdate encoding: invalid length")

    if len(base64_data) != expected_length:
        raise ValueError("Invalid DataUpdate encoding: length mismatch")

    # Decode base64 to UTF-8 JSON
    json_bytes = base64.b64decode(base64_data)
    json_string = json_bytes.decode("utf-8")

    return json.loads(json_string)
