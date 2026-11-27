"""Unit coverage for opt-in HMAC request signing (Security.md, "Request replay
protection and signatures").

The canonical string, sorted query, and empty-body hash must mirror the
daemon's src/daemon/security/RequestSignature.cpp byte-for-byte; the known-answer
vectors below are the ones fixed by the daemon's test/security/request_hardening.cpp.
"""

import hashlib
import hmac
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock
from urllib import parse

import msgpack
import requests
from requests.structures import CaseInsensitiveDict

from appmesh import request_signature
from appmesh.client_http import AppMeshClient
from appmesh.client_tcp import AppMeshClientTCP
from appmesh.client_wss import AppMeshClientWSS
from appmesh.tcp_messages import ResponseMessage

# sha256hex("") — the no-body / streamed-body hash, fixed by the daemon test.
EMPTY_BODY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# Independent HMAC vector: secret/canonical computed outside the SDK helper.
KAT_SECRET = "test-secret"
KAT_BODY = b'{"command":"echo hi"}'
KAT_BODY_HASH = hashlib.sha256(KAT_BODY).hexdigest()
KAT_SIGNATURE = "0f96a352b966fe6d68f4a9c3f2b86a6a79084ab511f3aed0d34a20de0af1158d"


def _verify(key_id, secret, timestamp, nonce, signature, method, path, decoded_query, body):
    """Recompute the signature the way the daemon does (independent of the helper)."""
    canonical = "\n".join(
        [method, path, decoded_query, hashlib.sha256(body).hexdigest(), timestamp, nonce]
    )
    return hmac.compare_digest(
        signature, hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()
    )


class TestCanonicalString(unittest.TestCase):
    """Known-answer vectors pinning the wire format (mirror of the daemon test)."""

    def test_empty_body_hash_known_answer(self):
        self.assertEqual(request_signature.sha256_hex(b""), EMPTY_BODY_SHA256)
        self.assertEqual(request_signature.EMPTY_BODY_SHA256_HEX, EMPTY_BODY_SHA256)

    def test_no_body_signs_empty_string_hash(self):
        headers = request_signature.signed_headers(
            "ak-1", "s", "GET", "/appmesh/applications", None, None,
            timestamp="1000", nonce="nonce-1",
        )
        canonical = request_signature.canonical_string(
            "GET", "/appmesh/applications", "a=1&b=2", EMPTY_BODY_SHA256, "1000", "nonce-1"
        )
        self.assertEqual(
            canonical,
            "GET\n/appmesh/applications\na=1&b=2\n" + EMPTY_BODY_SHA256 + "\n1000\nnonce-1",
        )
        self.assertEqual(headers["X-Request-Key"], "ak-1")
        self.assertEqual(headers["X-Timestamp"], "1000")
        self.assertEqual(headers["X-Nonce"], "nonce-1")

    def test_sign_known_answer_vector(self):
        # PUT with query + body, signed with a fixed secret/timestamp/nonce.
        canonical = request_signature.canonical_string(
            "PUT", "/appmesh/app/example", "k=v", KAT_BODY_HASH, "1700000000", "abc123"
        )
        self.assertEqual(
            canonical,
            "PUT\n/appmesh/app/example\nk=v\n" + KAT_BODY_HASH + "\n1700000000\nabc123",
        )
        self.assertEqual(request_signature.sign(KAT_SECRET, canonical), KAT_SIGNATURE)

    def test_signed_headers_verify_against_daemon_formula(self):
        headers = request_signature.signed_headers(
            "ak-3f9c2a81b0d4", KAT_SECRET, "PUT", "/appmesh/app/example",
            {"k": "v"}, KAT_BODY, timestamp="1700000000", nonce="abc123",
        )
        self.assertEqual(headers["X-Signature"], KAT_SIGNATURE)
        self.assertTrue(
            _verify(headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"],
                    headers["X-Nonce"], headers["X-Signature"],
                    "PUT", "/appmesh/app/example", "k=v", KAT_BODY)
        )


class TestCanonicalQuery(unittest.TestCase):
    """sortedQuery: decoded k=v pairs joined with '&', sorted by key then value."""

    def test_empty_query_is_empty_string(self):
        self.assertEqual(request_signature.canonical_query(None), "")
        self.assertEqual(request_signature.canonical_query({}), "")

    def test_sorted_by_key_then_value(self):
        self.assertEqual(
            request_signature.canonical_query({"b": "2", "a": "1"}),
            "a=1&b=2",
        )
        self.assertEqual(
            request_signature.canonical_query({"k": "v2", "a": "x", "k2": "v"}),
            "a=x&k=v2&k2=v",
        )
        # Same key: values sort within the key.
        self.assertEqual(
            request_signature.canonical_query({"k": "2", "a": "0"}),
            "a=0&k=2",
        )

    def test_values_stay_decoded(self):
        # The daemon canonicalizes the decoded query map; encoded input is the
        # caller's business — here the values are decoded already.
        query = {"filter": "a b&c=d"}
        self.assertEqual(request_signature.canonical_query(query), "filter=a b&c=d")


class TestWireQueryEncoding(unittest.TestCase):
    """The daemon decodes %XX but keeps '+' literal, so the wire query must be
    percent-encoded with quote (never quote_plus)."""

    def test_encode_query_never_emits_plus_for_space(self):
        encoded = request_signature.encode_query({"name": "two words", "t": "1"})
        self.assertNotIn("+", encoded)
        self.assertIn("name=two%20words", encoded)

    def test_encoded_query_round_trips_to_the_signed_values(self):
        query = {"events": "START,EXIT", "stdout_position": "0", "filter": "a b&c=d"}
        encoded = request_signature.encode_query(query)
        # Decode exactly like the daemon: %XX only, '+' literal.
        daemon_map = {
            parse.unquote(key): parse.unquote(value)
            for key, value in (pair.split("=", 1) for pair in encoded.split("&"))
        }
        self.assertEqual(daemon_map, query)
        # The canonical query built from the daemon-visible map matches the one
        # built from the original dict.
        self.assertEqual(
            request_signature.canonical_query(daemon_map),
            request_signature.canonical_query(query),
        )

    def test_empty_query_encodes_to_none(self):
        self.assertIsNone(request_signature.encode_query(None))
        self.assertIsNone(request_signature.encode_query({}))


class TestFileEndpointEmptyBodyHash(unittest.TestCase):
    """Streamed file endpoints sign the empty-string body hash (documented
    exemption): the signature binds method/path/query/timestamp/nonce, not the
    file content."""

    def test_file_endpoints_sign_empty_hash_even_with_body(self):
        for path in ("/appmesh/file/upload", "/appmesh/file/download", "/appmesh/file/delete"):
            with_body = request_signature.signed_headers(
                "ak", "s", "POST", path, None, b"file-content-bytes",
                timestamp="1700000000", nonce="n",
            )
            empty_body = request_signature.signed_headers(
                "ak", "s", "POST", path, None, None, timestamp="1700000000", nonce="n",
            )
            self.assertEqual(with_body["X-Signature"], empty_body["X-Signature"], path)
            self.assertTrue(
                _verify("ak", "s", "1700000000", "n", with_body["X-Signature"],
                        "POST", path, "", b""),
                path,
            )

    def test_ws_data_channel_routes_sign_the_stripped_path(self):
        # The trailing "/ws" selects the WSS transfer channel, not the signed
        # resource: the daemon's canonicalFileRoute signs the route without it
        # (Security.md, "Request replay protection and signatures").
        for ws_path, route in (
            ("/appmesh/file/download/ws", "/appmesh/file/download"),
            ("/appmesh/file/upload/ws", "/appmesh/file/upload"),
        ):
            self.assertEqual(request_signature.canonical_signing_path(ws_path), route)
            self.assertEqual(request_signature.canonical_signing_path(route), route)
            self.assertEqual(request_signature.canonical_signing_path("/appmesh/applications"),
                             "/appmesh/applications")
            ws = request_signature.signed_headers(
                "ak", "s", "GET", ws_path, None, b"file-bytes",
                timestamp="1700000000", nonce="n",
            )
            route_headers = request_signature.signed_headers(
                "ak", "s", "GET", route, None, None, timestamp="1700000000", nonce="n",
            )
            self.assertEqual(ws["X-Signature"], route_headers["X-Signature"], ws_path)
            self.assertTrue(
                _verify("ak", "s", "1700000000", "n", ws["X-Signature"],
                        "GET", route, "", b""),
                ws_path,
            )

    def test_non_file_endpoint_hashes_the_actual_body(self):
        headers = request_signature.signed_headers(
            "ak", "s", "PUT", "/appmesh/app/x", None, b"payload",
            timestamp="1700000000", nonce="n",
        )
        self.assertTrue(
            _verify("ak", "s", "1700000000", "n", headers["X-Signature"],
                    "PUT", "/appmesh/app/x", "", b"payload")
        )


class _FakeTransport:
    """Minimal TCP transport double capturing the serialized request frame."""

    def __init__(self):
        self.sent = []
        self.response = None

    def connected(self):
        return True

    def connect(self):
        raise AssertionError("transport must already be connected")

    def send_message(self, data):
        self.sent.append(data)

    def receive_message(self):
        return self.response


def _response_frame(request_data: bytes) -> bytes:
    request_uuid = msgpack.unpackb(request_data, raw=False)["uuid"]
    reply = ResponseMessage(uuid=request_uuid, http_status=200, body=b"{}",
                            headers={"Content-Type": "application/json"})
    return msgpack.packb(reply.__dict__, use_bin_type=True)


class TestHeadersAttached(unittest.TestCase):
    """A signed client must attach the four headers on every transport, and an
    unsigned client must attach none."""

    def _http_client(self, signed: bool) -> AppMeshClient:
        client = AppMeshClient(base_url="https://127.0.0.1:6060", ssl_verify=True)
        if signed:
            client.enable_request_signature("ak-3f9c2a81b0d4", KAT_SECRET)
        return client

    def test_http_request_carries_signature_headers(self):
        client = self._http_client(signed=True)
        resp = mock.Mock(status_code=200)
        with mock.patch.object(client.session, "put", return_value=resp) as put:
            client._request_http(
                AppMeshClient._Method.PUT, path="/appmesh/app/example",
                query={"k": "two words"}, body={"command": "echo hi"},
            )
        headers = put.call_args[1]["headers"]
        self.assertIn("X-Request-Key", headers)
        self.assertEqual(headers["X-Request-Key"], "ak-3f9c2a81b0d4")
        self.assertEqual(headers["X-Timestamp"], str(int(headers["X-Timestamp"])))
        nonce = headers["X-Nonce"]
        self.assertTrue(nonce)
        # The signed request carries its query inside the prepared URL (signing
        # and sending share one prepared request), percent-encoded (no
        # '+'-for-space) so the daemon-visible decoded value equals the signed one.
        wire_query = parse.urlsplit(put.call_args[1]["url"]).query
        self.assertNotIn("+", wire_query)
        self.assertIn("k=two%20words", wire_query)
        decoded = {"k": parse.unquote(wire_query.split("=", 1)[1])}
        # Body is the JSON string actually sent.
        body = put.call_args[1]["data"].encode()
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], nonce,
            headers["X-Signature"], "PUT", "/appmesh/app/example",
            request_signature.canonical_query(decoded), body,
        ))

    def test_http_signs_the_wire_path_not_the_raw_path(self):
        # requests re-quotes the URL before the wire (a space becomes %20), so
        # the signature must bind the requoted wire path; signing the caller's
        # raw path would fail verification on the daemon.
        client = self._http_client(signed=True)
        resp = mock.Mock(status_code=200)
        with mock.patch.object(client.session, "put", return_value=resp) as put:
            client._request_http(
                AppMeshClient._Method.PUT, path="/appmesh/app/my app",
                body={"command": "echo hi"},
            )
        kwargs = put.call_args[1]
        # Derive the wire path independently, exactly as requests prepares it.
        prepared = requests.Request(method="PUT", url=kwargs["url"]).prepare()
        wire_path = parse.urlsplit(prepared.url).path
        self.assertEqual(wire_path, "/appmesh/app/my%20app")
        headers = kwargs["headers"]
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], headers["X-Nonce"],
            headers["X-Signature"], "PUT", wire_path, "", kwargs["data"].encode(),
        ))

    def test_http_delete_carries_the_signed_query(self):
        # DELETE must pass params like every other method so the signed query
        # is the one on the wire.
        client = self._http_client(signed=True)
        resp = mock.Mock(status_code=200)
        with mock.patch.object(client.session, "delete", return_value=resp) as delete:
            client._request_http(
                AppMeshClient._Method.DELETE, path="/appmesh/app/example",
                query={"k": "two words"},
            )
        kwargs = delete.call_args[1]
        # Signed requests embed the query in the prepared URL they send.
        wire_query = parse.urlsplit(kwargs["url"]).query
        self.assertIn("k=two%20words", wire_query)
        headers = kwargs["headers"]
        decoded = {"k": parse.unquote(wire_query.split("=", 1)[1])}
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], headers["X-Nonce"],
            headers["X-Signature"], "DELETE", "/appmesh/app/example",
            request_signature.canonical_query(decoded), b"",
        ))

    def test_http_unsigned_request_has_no_signature_headers(self):
        client = self._http_client(signed=False)
        resp = mock.Mock(status_code=200)
        with mock.patch.object(client.session, "get", return_value=resp) as get:
            client._request_http(AppMeshClient._Method.GET, path="/appmesh/applications")
        headers = get.call_args[1]["headers"]
        for header in ("X-Request-Key", "X-Timestamp", "X-Nonce", "X-Signature"):
            self.assertNotIn(header, headers)

    def test_http_get_stream_signs_as_get(self):
        # GET_STREAM is a client-only pseudo-method; the wire method GET is signed.
        client = self._http_client(signed=True)
        resp = mock.Mock(status_code=200)
        with mock.patch.object(client.session, "get", return_value=resp) as get:
            client._request_http(AppMeshClient._Method.GET_STREAM, path="/appmesh/file/download",
                                 header={"X-File-Path": "/tmp/x"})
        headers = get.call_args[1]["headers"]
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], headers["X-Nonce"],
            headers["X-Signature"], "GET", "/appmesh/file/download", "", b"",
        ))

    def test_tcp_frame_carries_signature_headers_with_uuid_nonce(self):
        client = AppMeshClientTCP(("127.0.0.1", 6062), ssl_verify=False,
                                  api_key="ak-3f9c2a81b0d4", api_secret=KAT_SECRET)
        transport = _FakeTransport()
        client.tcp_transport = transport
        query = {"timeout": "5", "z": "last"}
        body = {"command": "echo hi"}

        transport.response = None
        # The reply is built from the last sent frame (correlated by uuid).
        transport.receive_message = lambda: _response_frame(transport.sent[-1])
        client._request_http(AppMeshClient._Method.PUT, path="/appmesh/app/example",
                             query=query, body=body)

        frame = msgpack.unpackb(transport.sent[0], raw=False)
        headers = frame["headers"]
        self.assertEqual(headers["X-Request-Key"], "ak-3f9c2a81b0d4")
        # The framed message uuid doubles as the nonce.
        self.assertEqual(headers["X-Nonce"], frame["uuid"])
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], headers["X-Nonce"],
            headers["X-Signature"], "PUT", "/appmesh/app/example",
            request_signature.canonical_query(frame["query"]), frame["body"],
        ))

    def test_tcp_unsigned_frame_has_no_signature_headers(self):
        client = AppMeshClientTCP(("127.0.0.1", 6062), ssl_verify=False)
        transport = _FakeTransport()
        client.tcp_transport = transport
        transport.receive_message = lambda: _response_frame(transport.sent[-1])
        client._request_http(AppMeshClient._Method.GET, path="/appmesh/applications")
        frame = msgpack.unpackb(transport.sent[0], raw=False)
        for header in ("X-Request-Key", "X-Timestamp", "X-Nonce", "X-Signature"):
            self.assertNotIn(header, frame["headers"])


class TestWSSFileSideChannelSignature(unittest.TestCase):
    """The /appmesh/file/{upload,download}/ws data channel enforces the same
    request-signature hardening as every other route, so a signing WSS client
    must sign the side-channel request too (empty-body hash). The canonical
    signing path drops the trailing "/ws" (daemon canonicalFileRoute): the
    suffix selects the transfer channel, not the signed resource."""

    @staticmethod
    def _octet_stream_response(body: bytes = b"") -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        resp.headers = CaseInsensitiveDict({"Content-Type": "application/octet-stream"})
        resp._content = body
        resp._content_consumed = True
        return resp

    def _client(self) -> AppMeshClientWSS:
        client = AppMeshClientWSS(("gateway.local", 6063), ssl_verify=False, bearer_token="token",
                                  api_key="ak-3f9c2a81b0d4", api_secret=KAT_SECRET)
        client._request_http = mock.Mock()  # the control-channel precheck answers 200
        return client

    def test_download_data_request_is_signed(self):
        client = self._client()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "get", return_value=self._octet_stream_response(b"file-bytes")
        ) as get:
            client.download_file("/tmp/remote.txt", str(Path(tmp) / "got.txt"))
        headers = get.call_args[1]["headers"]
        self.assertEqual(headers["X-Request-Key"], "ak-3f9c2a81b0d4")
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], headers["X-Nonce"],
            headers["X-Signature"], "GET", "/appmesh/file/download", "", b"",
        ))

    def test_upload_data_request_is_signed(self):
        client = self._client()
        with tempfile.TemporaryDirectory() as tmp, mock.patch.object(
            client.session, "post", return_value=self._octet_stream_response()
        ) as post:
            src = Path(tmp) / "put.txt"
            src.write_bytes(b"payload")
            client.upload_file(str(src), "/tmp/remote-put.txt")
        headers = post.call_args[1]["headers"]
        self.assertTrue(_verify(
            headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"], headers["X-Nonce"],
            headers["X-Signature"], "POST", "/appmesh/file/upload", "", b"",
        ))


class TestSignatureOptIn(unittest.TestCase):
    """Signing activates only when both the key id and the secret are set."""

    def test_partial_constructor_pair_is_rejected(self):
        with self.assertRaises(ValueError):
            AppMeshClient(api_key="ak-1")
        with self.assertRaises(ValueError):
            AppMeshClient(api_secret="s")

    def test_enable_requires_non_empty_strings(self):
        client = AppMeshClient(ssl_verify=True)
        with self.assertRaises(ValueError):
            client.enable_request_signature("", "s")
        with self.assertRaises(ValueError):
            client.enable_request_signature("ak-1", "")

    def test_enable_and_disable_toggle(self):
        client = AppMeshClient(ssl_verify=True)
        self.assertFalse(client._request_signature_enabled())
        client.enable_request_signature("ak-1", "s")
        self.assertTrue(client._request_signature_enabled())
        client.disable_request_signature()
        self.assertFalse(client._request_signature_enabled())


def _start_capture_server():
    """Start a loopback HTTP server that records the exact request line,
    headers, and body the client put on the wire — the exact inputs the
    daemon's signature verifier canonicalizes. Returns (server, captures)."""
    captures = []

    class Handler(BaseHTTPRequestHandler):
        def _capture(self):
            length = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(length) if length else b""
            captures.append({"method": self.command, "target": self.path,
                             "headers": self.headers, "body": body})
            payload = b"{}"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        do_GET = do_PUT = do_POST = do_DELETE = _capture

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, captures


class TestSignedWirePath(unittest.TestCase):
    """The signed path must equal the path on the wire byte-for-byte. The mock
    session tests above cannot see requests' own URL repair, so these cases go
    through a real loopback server and verify daemon-style against the captured
    request line."""

    def _signed_get(self, base_url, path):
        client = AppMeshClient(base_url=base_url, ssl_verify=True)
        client.enable_request_signature("ak-3f9c2a81b0d4", KAT_SECRET)
        try:
            client._request_http(AppMeshClient._Method.GET, path=path)
        finally:
            client.close()

    def test_signed_path_equals_wire_path(self):
        # (caller path, wire path): a bare "%" is repaired to %25 (the classic
        # 401), a lowercase escape is normalized to uppercase hex, non-ASCII is
        # percent-encoded; %2F and %2Ab are already wire form and must not move.
        cases = [
            ("/appmesh/app/100%", "/appmesh/app/100%25"),
            ("/appmesh/app/a%2ab", "/appmesh/app/a%2Ab"),
            ("/appmesh/app/中文", "/appmesh/app/%E4%B8%AD%E6%96%87"),
            ("/appmesh/app/a%2Fb", "/appmesh/app/a%2Fb"),
            ("/appmesh/app/a%2Ab", "/appmesh/app/a%2Ab"),
        ]
        server, captures = _start_capture_server()
        try:
            base = f"http://127.0.0.1:{server.server_port}"
            for caller_path, _ in cases:
                self._signed_get(base, caller_path)
            self.assertEqual(len(captures), len(cases))
            for (caller_path, expected_wire), captured in zip(cases, captures):
                wire_path = captured["target"].split("?", 1)[0]
                self.assertEqual(wire_path, expected_wire, caller_path)
                headers = captured["headers"]
                self.assertTrue(
                    _verify(headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"],
                            headers["X-Nonce"], headers["X-Signature"],
                            "GET", wire_path, "", b""),
                    f"signature must verify against the wire path for {caller_path}",
                )
        finally:
            server.shutdown()
            server.server_close()

    def test_base_url_path_prefix_is_signed_and_sent(self):
        # A base URL with a path prefix (reverse-proxy deployments): the prefix
        # must reach the wire AND the signature — urljoin used to drop it.
        server, captures = _start_capture_server()
        try:
            self._signed_get(f"http://127.0.0.1:{server.server_port}/pfx", "/appmesh/app/example")
            captured = captures[0]
            wire_path = captured["target"].split("?", 1)[0]
            self.assertEqual(wire_path, "/pfx/appmesh/app/example")
            headers = captured["headers"]
            self.assertTrue(
                _verify(headers["X-Request-Key"], KAT_SECRET, headers["X-Timestamp"],
                        headers["X-Nonce"], headers["X-Signature"],
                        "GET", wire_path, "", b""),
            )
        finally:
            server.shutdown()
            server.server_close()


# Cross-language golden vectors (mirrored by the daemon C++, Go, Java,
# JavaScript, and Rust test suites): they pin the canonical layout and the HMAC
# itself with a fixed timestamp and nonce (no time-window involvement). The
# path/query values are the wire-encoded forms.
GOLDEN_SECRET = "golden-secret"
GOLDEN_VECTORS = [
    # (method, wire path, canonical query, body, timestamp, nonce, signature)
    ("GET", "/appmesh/app/100%25", "", b"", "1700000000", "nonce-golden-0001",
     "1036298fce978dab3ca5393a17c8dbeafcd22e8394585a96ce5a60ad39694d8c"),
    ("GET", "/appmesh/app/list", "flag=true&name=dh-bot", b"", "1700000001", "nonce-golden-0002",
     "0c9287088c6ca609fad7436f3f4646451faa8e180733e28e10e4eee11f34a9c5"),
    ("POST", "/appmesh/file/download", "", b"", "1700000002", "nonce-golden-0003",
     "dea6aa318b1fc84f8ffaadc859e4b36a90a9d6c5619f737dd037c78e5d17ac7d"),
    ("GET", "/appmesh/app/%E4%B8%AD%E6%96%87", "a=1%26b%3D2", b"", "1700000003", "nonce-golden-0004",
     "6cf618bfb9264d61d5b23dbaa42d366f59054bce99b9addab3253f98aaadb0ab"),
    ("POST", "/appmesh/appmesh/run", "", b'{"command":"echo hi"}', "1700000004", "nonce-golden-0005",
     "0a8de849eda2abf6389d40f11299aaf09e7b440615a6ee0c7e01012a92a1f876"),
]


class TestCrossLanguageGoldenVectors(unittest.TestCase):
    """Every SDK (and the daemon) must produce these exact signatures."""

    def test_canonical_and_signature_match_the_vectors(self):
        for method, path, query, body, timestamp, nonce, expected in GOLDEN_VECTORS:
            canonical = request_signature.canonical_string(
                method, path, query, request_signature.sha256_hex(body), timestamp, nonce
            )
            self.assertEqual(request_signature.sign(GOLDEN_SECRET, canonical), expected, path)
            # The header helper agrees when handed the wire forms directly (a
            # string query is already canonical; no body → empty-string hash).
            headers = request_signature.signed_headers(
                "ak-golden", GOLDEN_SECRET, method, path, query, body,
                timestamp=timestamp, nonce=nonce,
            )
            self.assertEqual(headers["X-Signature"], expected, path)
            self.assertEqual(headers["X-Request-Key"], "ak-golden")


if __name__ == "__main__":
    unittest.main()
