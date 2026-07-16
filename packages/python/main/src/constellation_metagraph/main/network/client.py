"""
Base HTTP client for network operations.
"""

import json
from typing import Any, Optional, TypeVar
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .types import NetworkError, RequestOptions

T = TypeVar("T")

DEFAULT_TIMEOUT = 30.0


class HttpClient:
    """Simple HTTP client using urllib."""

    def __init__(self, base_url: str, timeout: float = DEFAULT_TIMEOUT):
        self._base_url = base_url.rstrip("/")
        self._default_timeout = timeout

    def get(self, path: str, options: Optional[RequestOptions] = None) -> Any:
        """Make a GET request."""
        return self._request("GET", path, None, options)

    def post(
        self,
        path: str,
        body: Optional[Any] = None,
        options: Optional[RequestOptions] = None,
    ) -> Any:
        """Make a POST request."""
        return self._request("POST", path, body, options)

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[Any] = None,
        options: Optional[RequestOptions] = None,
    ) -> Any:
        url = f"{self._base_url}{path}"
        opts = options or RequestOptions()
        timeout = opts.timeout if opts.timeout is not None else self._default_timeout

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **opts.headers,
        }

        data = None
        if body is not None:
            data = json.dumps(body, default=self._serialize).encode("utf-8")

        request = Request(url, data=data, headers=headers, method=method)

        try:
            with urlopen(request, timeout=timeout) as response:
                text = response.read().decode("utf-8")
                if not text:
                    return None
                try:
                    return json.loads(text)
                except json.JSONDecodeError:
                    return text

        except HTTPError as e:
            response_text = ""
            try:
                response_text = e.read().decode("utf-8")
            except Exception:
                pass
            raise NetworkError(
                f"HTTP {e.code}: {e.reason}",
                status_code=e.code,
                response=response_text,
            ) from e

        except URLError as e:
            raise NetworkError(f"Network error: {e.reason}") from e

        except TimeoutError:
            raise NetworkError(f"Request timeout after {timeout}s")

        except Exception as e:
            raise NetworkError(str(e)) from e

    def _serialize(self, obj: Any) -> Any:
        """Custom serializer for dataclasses."""
        if hasattr(obj, "__dict__"):
            return {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
