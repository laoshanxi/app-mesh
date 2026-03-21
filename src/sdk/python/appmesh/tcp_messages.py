"""TCP message classes for HTTP-like communication."""
__all__ = ["RequestMessage", "ResponseMessage"]

# Standard library imports
from dataclasses import dataclass, field
from typing import Any, Dict, Type, get_type_hints

# Third-party imports
import msgpack


@dataclass
class RequestMessage:
    """TCP request message for HTTP-like communication."""

    uuid: str = ""
    request_uri: str = ""
    http_method: str = ""
    client_addr: str = ""
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)
    query: Dict[str, str] = field(default_factory=dict)

    def serialize(self) -> bytes:
        """Serialize request message to bytes."""
        return msgpack.packb(self.__dict__, use_bin_type=True)


@dataclass
class ResponseMessage:
    """TCP response message for HTTP-like communication."""

    uuid: str = ""
    request_uri: str = ""
    http_status: int = 0
    body_msg_type: str = ""
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_bytes(cls, buf: bytes) -> "ResponseMessage":
        """Deserialize TCP msgpack buffer with proper type conversion."""
        data = msgpack.unpackb(buf, raw=False)
        hints = get_type_hints(cls)
        instance = cls()

        for key, value in data.items():
            if key in hints:
                setattr(instance, key, cls._convert_type(value, hints[key]))

        return instance

    @staticmethod
    def _convert_type(value: Any, expected_type: Type) -> Any:
        """Convert value to expected type."""
        if value is None:
            return {
                str: "",
                bytes: b"",
                int: 0,
            }.get(expected_type, None)

        if expected_type is str:
            return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else str(value)

        if expected_type is bytes:
            return value.encode("utf-8") if isinstance(value, str) else value

        if expected_type is int:
            return int(value or 0)

        return value
