# tcp_messages.py

import msgpack


class RequestMessage:
    """HTTP request message"""

    uuid: str = ""
    request_uri: str = ""
    http_method: str = ""
    client_addr: str = ""
    body: bytes = b""
    headers: dict = {}
    querys: dict = {}

    def serialize(self) -> bytes:
        """Serialize request message to bytes"""
        # http://www.cnitblog.com/luckydmz/archive/2019/11/20/91959.html
        self_dict = vars(self)
        self_dict["headers"] = self.headers
        self_dict["querys"] = self.querys
        return msgpack.dumps(self_dict)


class ResponseMessage:
    """HTTP response message"""

    uuid: str = ""
    request_uri: str = ""
    http_status: int = 0
    body_msg_type: str = ""
    body: str = ""
    headers: dict = {}

    def desirialize(self, buf: bytes):
        """Deserialize response message"""
        dic = msgpack.unpackb(buf)
        for k, v in dic.items():
            setattr(self, k, v)
        return self
