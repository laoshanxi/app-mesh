"""Python 3.6 fallback for the ``fastmcp`` surface the App Mesh MCP server uses.

fastmcp (and its uvicorn/starlette/pydantic stack) requires Python >= 3.10;
the legacy line targets Ubuntu 18.04's system Python 3.6. This module keeps
the same API surface — ``FastMCP``, ``CurrentAccessToken``/``AccessToken``,
plus the auth classes ``auth.py`` imports — on top of the standard library:

- Transport: the MCP Streamable HTTP subset. ``POST /mcp`` speaks JSON-RPC 2.0
  (initialize / tools/list / tools/call / ping); plain ``application/json``
  replies, no SSE channel. ``GET /.well-known/oauth-protected_resource``
  publishes the OAuth resource metadata so MCP clients can discover the
  authorization server.
- Auth: this process stays an OAuth resource server. The compat verifier
  accepts a bearer token only when the App Mesh daemon accepts it (the
  ``get_current_principal`` call runs with the caller's token); the daemon
  remains the single authority, and every tool call forwards the same token.

On hosts with Python >= 3.10 the real fastmcp is preferred; the server and
auth modules import this only when fastmcp is unavailable.
"""
import inspect
import json
import logging
import os
import ssl
import socketserver
import typing
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlsplit

log = logging.getLogger("fastmcp_compat")

_SUPPORTED_PROTOCOLS = ("2025-06-18", "2025-03-26", "2024-11-05")
_DEFAULT_PROTOCOL = "2025-03-26"


# --------------------------------------------------------------------------- #
# Auth surface (used by auth.py; mirrors fastmcp.server.auth)
# --------------------------------------------------------------------------- #
AnyHttpUrl = str  # pydantic's URL type is a string here; no validation needed


class AccessToken(object):
    def __init__(self, token="", client_id="", scopes=None, expires_at=None):
        self.token = token
        self.client_id = client_id
        self.scopes = list(scopes or [])
        self.expires_at = expires_at


class _AccessTokenMarker(object):
    """Default marker produced by CurrentAccessToken(); never client-visible."""

    def __repr__(self):
        return "CurrentAccessToken()"


def CurrentAccessToken():  # noqa: N802 - fastmcp's spelling
    return _ACCESS_TOKEN_MARKER


_ACCESS_TOKEN_MARKER = _AccessTokenMarker()


def _daemon_ssl_verify():
    ca = os.environ.get("APPMESH_CA")
    if ca:
        return ca
    return os.environ.get("APPMESH_SSL_VERIFY", "true").lower() not in ("false", "0", "no")


class JWTVerifier(object):
    """Token validation delegated to the daemon: the daemon accepts the token
    (it is the audience and the authority) iff the principal lookup with the
    forwarded bearer succeeds. jwks/issuer/audience are kept for logging and
    parity; the wire format check below is the cheap first gate."""

    def __init__(self, jwks_uri="", issuer="", audience="", algorithm="RS256"):
        self.jwks_uri = jwks_uri
        self.issuer = issuer
        self.audience = audience
        self.algorithm = algorithm

    def verify(self, token):
        if not token or token.count(".") != 2:
            return None
        try:
            from appmesh import AppMeshClient
            base = os.environ.get("APPMESH_URL", "https://127.0.0.1:6060")
            client = AppMeshClient(base_url=base, ssl_verify=_daemon_ssl_verify(), bearer_token=token)
            principal = client.get_current_principal()
        except Exception as exc:  # daemon said no (401/403/...) or transport failed
            log.debug("token rejected by the daemon: %s", exc)
            return None
        if not isinstance(principal, dict):
            return None
        return AccessToken(
            token=token,
            client_id=str(principal.get("id") or principal.get("principal_id") or ""),
            scopes=[],
        )


class RemoteAuthProvider(object):
    def __init__(self, token_verifier=None, authorization_servers=None, base_url="", scopes_supported=None):
        self.token_verifier = token_verifier
        self.authorization_servers = [str(u) for u in (authorization_servers or [])]
        self.base_url = base_url
        self.scopes_supported = list(scopes_supported or [])

    def verify_token(self, token):
        return self.token_verifier.verify(token) if self.token_verifier else None

    def protected_resource_metadata(self):
        return {
            "resource": self.base_url,
            "authorization_servers": self.authorization_servers,
            "scopes_supported": self.scopes_supported or None,
            "bearer_methods": ["header"],
        }


# --------------------------------------------------------------------------- #
# Tool schema generation (annotation -> JSON Schema, py3.6 typing included)
# --------------------------------------------------------------------------- #
def _annotation_schema(annotation):
    if annotation is inspect.Parameter.empty or annotation is None:
        return None
    if annotation is str:
        return {"type": "string"}
    if annotation is bool:  # before int: bool is an int subclass
        return {"type": "boolean"}
    if annotation is int:
        return {"type": "integer"}
    if annotation is float:
        return {"type": "number"}
    if annotation is dict or annotation is typing.Dict:
        return {"type": "object"}
    if annotation is list or annotation is typing.List:
        return {"type": "array"}
    origin = getattr(annotation, "__origin__", None)
    if origin is typing.Union:  # Optional[X] -> X (optionality rides the default)
        args = [a for a in annotation.__args__ if a is not type(None)]
        return _annotation_schema(args[0]) if args else None
    if origin in (dict, typing.Dict):
        return {"type": "object"}
    if origin in (list, typing.List):
        return {"type": "array"}
    return {"type": "string"}  # unknown annotation: permissive scalar


class _Tool(object):
    def __init__(self, fn, description):
        self.fn = fn
        self.name = fn.__name__
        self.description = description or (inspect.getdoc(fn) or "")
        self.parameters = list(inspect.signature(fn).parameters.values())

    def schema(self):
        properties, required = {}, []
        for param in self.parameters:
            if isinstance(param.default, _AccessTokenMarker) or param.default is _ACCESS_TOKEN_MARKER:
                continue  # server-injected credential, never client-visible
            schema = _annotation_schema(param.annotation)
            if schema is None:
                schema = {"type": "string"}
            properties[param.name] = schema
            if param.default is inspect.Parameter.empty:
                required.append(param.name)
        input_schema = {"type": "object", "properties": properties}
        if required:
            input_schema["required"] = required
        return {"name": self.name, "description": self.description, "inputSchema": input_schema}

    def invoke(self, arguments, access_token):
        kwargs = dict(arguments or {})
        for param in self.parameters:
            if isinstance(param.default, _AccessTokenMarker) or param.default is _ACCESS_TOKEN_MARKER:
                kwargs[param.name] = access_token
        return self.fn(**kwargs)


# --------------------------------------------------------------------------- #
# JSON-RPC / MCP protocol core
# --------------------------------------------------------------------------- #
class FastMCP(object):
    def __init__(self, name, auth=None):
        self.name = name
        self.auth = auth
        self._tools = {}

    def tool(self, description=None):
        def register(fn):
            tool = _Tool(fn, description)
            self._tools[tool.name] = tool
            return fn
        return register

    # ----- protocol -----
    def _handle_message(self, message, access_token):
        """One JSON-RPC message -> one reply object (None for notifications)."""
        method = message.get("method")
        msg_id = message.get("id")
        is_notification = "id" not in message
        if method == "initialize":
            requested = str((message.get("params") or {}).get("protocolVersion") or "")
            protocol = requested if requested in _SUPPORTED_PROTOCOLS else _DEFAULT_PROTOCOL
            result = {
                "protocolVersion": protocol,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": self.name, "version": "1.0.0"},
            }
            return None if is_notification else {"jsonrpc": "2.0", "id": msg_id, "result": result}
        if method == "ping":
            return None if is_notification else {"jsonrpc": "2.0", "id": msg_id, "result": {}}
        if method == "tools/list":
            result = {"tools": [t.schema() for t in self._tools.values()]}
            return None if is_notification else {"jsonrpc": "2.0", "id": msg_id, "result": result}
        if method == "tools/call":
            params = message.get("params") or {}
            tool = self._tools.get(params.get("name"))
            if tool is None:
                return {"jsonrpc": "2.0", "id": msg_id,
                        "error": {"code": -32602, "message": "unknown tool: %s" % params.get("name")}}
            try:
                value = tool.invoke(params.get("arguments"), access_token)
                content_text = json.dumps(value, default=str, ensure_ascii=False)
                return {"jsonrpc": "2.0", "id": msg_id,
                        "result": {"content": [{"type": "text", "text": content_text}], "isError": False}}
            except Exception as exc:
                log.warning("tool %s failed: %s", tool.name, exc, exc_info=True)
                return {"jsonrpc": "2.0", "id": msg_id,
                        "result": {"content": [{"type": "text", "text": "error: %s" % exc}], "isError": True}}
        if method in ("notifications/initialized", "notifications/cancelled"):
            return None
        if is_notification:
            return None
        return {"jsonrpc": "2.0", "id": msg_id,
                "error": {"code": -32601, "message": "method not found: %s" % method}}

    def _handle_body(self, body, access_token):
        """A POST body (one message or a batch) -> reply payload (or None -> 202)."""
        try:
            payload = json.loads(body.decode("utf-8"))
        except ValueError:
            return {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        if isinstance(payload, list):
            replies = [r for r in (self._handle_message(m, access_token) for m in payload if isinstance(m, dict)) if r]
            return replies or None
        if isinstance(payload, dict):
            return self._handle_message(payload, access_token)
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}

    # ----- HTTP transport -----
    def _make_handler(self, server_base):
        mcp = self
        auth = self.auth

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            server_version = "appmesh-mcp-compat/1.0"

            def log_message(self, fmt, *args):
                log.debug("%s %s", self.address_string(), fmt % args)

            def _send_json(self, status, payload, extra_headers=None):
                body = json.dumps(payload).encode("utf-8") if payload is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                for key, value in (extra_headers or {}).items():
                    self.send_header(key, value)
                self.end_headers()
                if body:
                    self.wfile.write(body)

            def _auth_challenge(self):
                metadata = auth.base_url.rstrip("/") + "/.well-known/oauth-protected_resource"
                self._send_json(
                    401,
                    {"error": "unauthorized", "error_description": "a valid bearer token is required"},
                    {"WWW-Authenticate": 'Bearer resource_metadata="%s"' % metadata},
                )

            def do_OPTIONS(self):  # noqa: N802
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def do_GET(self):  # noqa: N802
                path = urlsplit(self.path).path
                if path == "/.well-known/oauth-protected_resource":
                    self._send_json(200, auth.protected_resource_metadata())
                    return
                if path == "/mcp":
                    self._send_json(405, {"error": "SSE streaming is not supported by this server"})
                    return
                self._send_json(404, {"error": "not found"})

            def do_POST(self):  # noqa: N802
                path = urlsplit(self.path).path
                if path != "/mcp":
                    self._send_json(404, {"error": "not found"})
                    return
                try:
                    length = int(self.headers.get("Content-Length") or 0)
                except ValueError:
                    length = 0
                body = self.rfile.read(length) if length > 0 else b""
                # initialize/ping stay open so a client can complete the OAuth
                # handshake; every other method proves the bearer first.
                probe = body[:512]
                unauthenticated_ok = b'"initialize"' in probe or b'"ping"' in probe
                access_token = None
                if auth is not None and not unauthenticated_ok:
                    header = self.headers.get("Authorization") or ""
                    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
                    access_token = auth.verify_token(token) if token else None
                    if access_token is None:
                        self._auth_challenge()
                        return
                reply = mcp._handle_body(body, access_token)
                if reply is None:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                else:
                    self._send_json(200, reply)

        return Handler

    def run(self, transport="http", host="0.0.0.0", port=6071, uvicorn_config=None):
        if transport not in ("http", "streamable-http"):
            raise RuntimeError("this fallback server supports the Streamable HTTP transport only")
        base = "https" if (uvicorn_config or {}).get("ssl_certfile") else "http"
        server_base = "%s://%s:%d" % (base, host, port)

        class ThreadingHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
            daemon_threads = True

        httpd = ThreadingHTTPServer((host, int(port)), self._make_handler(server_base))
        config = uvicorn_config or {}
        cert, key = config.get("ssl_certfile"), config.get("ssl_keyfile")
        if cert and key:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert, keyfile=key)
            httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        log.info("fastmcp fallback server (%s) listening on %s:%s (TLS: %s)",
                 self.name, host, port, bool(cert and key))
        httpd.serve_forever()
