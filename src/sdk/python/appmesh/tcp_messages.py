# tcp_messages.py

from typing import get_type_hints
import msgpack


class RequestMessage:
    """TCP request message for HTTP-like communication"""

    def __init__(self):
        self.uuid: str = ""
        self.request_uri: str = ""
        self.http_method: str = ""
        self.client_addr: str = ""
        self.body: bytes = b""
        self.headers: dict = {}
        self.query: dict = {}

    def serialize(self) -> bytes:
        """Serialize request message to bytes"""
        return msgpack.dumps(vars(self), use_bin_type=True)


class ResponseMessage:
    """TCP response message for HTTP-like communication"""

    uuid: str
    request_uri: str
    http_status: int
    body_msg_type: str
    body: bytes
    headers: dict

    def __init__(self):
        self.uuid = ""
        self.request_uri = ""
        self.http_status = 0
        self.body_msg_type = ""
        self.body = b""
        self.headers = {}

    def deserialize(self, buf: bytes):
        """Deserialize TCP msgpack buffer with proper type conversion."""
        dic = msgpack.unpackb(buf, raw=False)
        hints = get_type_hints(self.__class__)

        for k, v in dic.items():
            if k not in hints:
                continue  # Skip unknown fields

            # handle all types (int, bytes, dict, str)
            t = hints[k]
            if t is str:
                if isinstance(v, bytes):
                    v = v.decode("utf-8", errors="replace")
                elif v is None:
                    v = ""
                else:
                    v = str(v)
            elif t is bytes:
                if isinstance(v, str):
                    v = v.encode("utf-8")  # handle accidental str
                elif v is None:
                    v = b""
            elif t is int:
                v = int(v or 0)
            setattr(self, k, v)

        return self
