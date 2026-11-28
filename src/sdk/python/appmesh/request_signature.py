# request_signature.py
"""Opt-in HMAC-SHA256 request signing (docs/source/security/Security.md, "Request replay
protection and signatures").

The signature is an integrity layer on top of bearer authentication, produced
with a per-principal API key; it does not replace the bearer token. This module
mirrors the daemon's ``src/daemon/security/RequestSignature.cpp`` byte-for-byte:

    stringToSign = METHOD + "\\n" + path + "\\n" + sortedQuery + "\\n"
                   + sha256hex(body) + "\\n" + timestamp + "\\n" + nonce

- path: the request path without the query, exactly as sent (not percent-decoded).
  The WSS data-channel file routes sign the route WITHOUT the trailing "/ws"
  (the suffix selects the transfer channel, not the signed resource — the
  daemon's ``RequestHardening::canonicalFileRoute``)
- sortedQuery: decoded ``key=value`` pairs joined with '&', sorted by key then
  value; an empty query is an empty string
- sha256hex(body): lowercase hex SHA-256 of the raw body bytes; no body hashes
  the empty string

The secret is kept in memory only and never logged; only its HMAC crosses the wire.
"""

# Standard library imports
import hashlib
import hmac
import time
import uuid
from typing import Dict, Mapping, Optional, Union
from urllib import parse

__all__ = [
    "HEADER_KEY_ID",
    "HEADER_TIMESTAMP",
    "HEADER_NONCE",
    "HEADER_SIGNATURE",
    "EMPTY_BODY_SHA256_HEX",
    "FILE_ENDPOINT_EMPTY_HASH_PATHS",
    "canonical_query",
    "canonical_signing_path",
    "canonical_string",
    "encode_query",
    "sha256_hex",
    "sign",
    "signed_headers",
]

# Signature header names (docs/source/security/Security.md, "Signature format")
HEADER_KEY_ID = "X-Request-Key"
HEADER_TIMESTAMP = "X-Timestamp"
HEADER_NONCE = "X-Nonce"
HEADER_SIGNATURE = "X-Signature"

# Streamed file endpoints: their body crosses the wire as a stream (or a socket
# side channel), so they sign the empty-string body hash instead of the file
# content. Documented exemption; same list the daemon enforces hardening on.
FILE_ENDPOINT_EMPTY_HASH_PATHS = frozenset(
    {
        "/appmesh/file/upload",
        "/appmesh/file/download",
        "/appmesh/file/delete",
        "/appmesh/file/upload/ws",
        "/appmesh/file/download/ws",
    }
)

# The WSS HTTPS data-channel routes carry a "/ws" suffix that selects the
# transfer channel, not the signed resource: the daemon's
# RequestHardening::canonicalFileRoute signs these routes without the trailing
# "/ws" (docs/source/security/Security.md, "Request replay protection and signatures").
FILE_ENDPOINT_WS_SIGNING_PATHS = {
    "/appmesh/file/upload/ws": "/appmesh/file/upload",
    "/appmesh/file/download/ws": "/appmesh/file/download",
}

# Lowercase hex SHA-256 of the empty string (no-body / streamed-body hash).
EMPTY_BODY_SHA256_HEX = hashlib.sha256(b"").hexdigest()

# Client-only streaming pseudo-methods; the wire HTTP method is what gets signed.
_WIRE_METHOD = {"GET_STREAM": "GET", "POST_STREAM": "POST"}


def sha256_hex(data: Union[str, bytes, bytearray, memoryview]) -> str:
    """Return the lowercase hex SHA-256 of the raw bytes (a str is UTF-8 encoded)."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(bytes(data)).hexdigest()


def canonical_query(query: Optional[Mapping[str, str]]) -> str:
    """Join the decoded query parameters as ``k=v`` pairs with ``&``, sorted by
    key then value — the exact form of ``RequestSignature::canonicalQuery``.
    An empty/absent query yields an empty string."""
    if not query:
        return ""
    pairs = sorted((str(key), str(value)) for key, value in query.items())
    return "&".join(f"{key}={value}" for key, value in pairs)


def canonical_signing_path(path: str) -> str:
    """Return the path the daemon signs for ``path``.

    The trailing "/ws" of the WSS HTTPS data-channel file routes selects the
    transfer channel, not the signed resource, so the canonical signing path
    drops it — the exact rule of the daemon's
    ``RequestHardening::canonicalFileRoute``. Every other path passes through
    unchanged."""
    return FILE_ENDPOINT_WS_SIGNING_PATHS.get(path, path)


def canonical_string(
    method: str,
    path: str,
    query: Union[str, Mapping[str, str]],
    body_sha256_hex: str,
    timestamp: str,
    nonce: str,
) -> str:
    """Build the string to sign, byte-for-byte as the daemon does.

    ``query`` may be the already-sorted query string or the decoded parameter
    mapping (it is canonicalized here)."""
    sorted_query = query if isinstance(query, str) else canonical_query(query)
    return "\n".join((_WIRE_METHOD.get(method, method), path, sorted_query, body_sha256_hex, timestamp, nonce))


def sign(secret: Union[str, bytes], canonical: str) -> str:
    """Return the lowercase hex HMAC-SHA256 of the canonical string under the secret."""
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hmac.new(secret, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


def encode_query(query: Optional[Mapping[str, str]]) -> Optional[str]:
    """Percent-encode the query for the wire with ``urllib.parse.quote``
    (never ``quote_plus``): the daemon percent-decodes the query but keeps a
    literal ``+`` untouched, so an encoded value must never contain ``+`` in
    place of a space — the daemon-visible decoded values must equal the values
    the client signed. Returns ``None`` for an empty query."""
    if not query:
        return None
    return "&".join(
        f"{parse.quote(str(key), safe='')}={parse.quote(str(value), safe='')}" for key, value in query.items()
    )


def signed_headers(
    key_id: str,
    secret: str,
    method: str,
    path: str,
    query: Optional[Mapping[str, str]] = None,
    body: Union[str, bytes, bytearray, memoryview, None] = b"",
    *,
    nonce: Optional[str] = None,
    timestamp: Optional[Union[str, int]] = None,
) -> Dict[str, str]:
    """Build the four signature headers for one request.

    Args:
        key_id: API key id (``X-Request-Key``), e.g. ``ak-3f9c2a81b0d4``.
        secret: API key secret — the HMAC key; never sent or logged.
        method: HTTP method as sent on the wire (GET/PUT/POST/DELETE; the
            client-only GET_STREAM/POST_STREAM pseudo-methods are mapped).
        path: request path without the query, exactly as sent (still
            percent-encoded; never decoded here). The WSS data-channel file
            routes ("/appmesh/file/{upload,download}/ws") are signed under the
            route without the trailing "/ws" (daemon canonicalFileRoute).
        query: decoded query parameter values.
        body: raw body bytes; ``None`` and the streamed file endpoints
            (FILE_ENDPOINT_EMPTY_HASH_PATHS) sign the empty-string hash.
        nonce: unique random value per request; defaults to a fresh uuid4 hex.
        timestamp: unix seconds; defaults to now.

    Returns:
        Dict with ``X-Request-Key``/``X-Timestamp``/``X-Nonce``/``X-Signature``.
    """
    timestamp = str(int(time.time())) if timestamp is None else str(timestamp)
    nonce = uuid.uuid4().hex if nonce is None else str(nonce)
    signing_path = canonical_signing_path(path)
    if signing_path in FILE_ENDPOINT_EMPTY_HASH_PATHS or body is None:
        body_hash = EMPTY_BODY_SHA256_HEX
    else:
        body_hash = sha256_hex(body)
    signature = sign(secret, canonical_string(method, signing_path, query or {}, body_hash, timestamp, nonce))
    return {
        HEADER_KEY_ID: key_id,
        HEADER_TIMESTAMP: timestamp,
        HEADER_NONCE: nonce,
        HEADER_SIGNATURE: signature,
    }
