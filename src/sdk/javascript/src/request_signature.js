// request_signature.js - opt-in HMAC-SHA256 request signing (anti-tamper layer)
//
// Mirrors the daemon verifier in src/daemon/security/RequestSignature.{h,cpp}
// byte-for-byte. The canonical string is:
//   METHOD + "\n" + path + "\n" + sortedQuery + "\n" + sha256hex(body) + "\n" + timestamp + "\n" + nonce
// - path: the request path without the query, exactly as sent (not
//   percent-decoded). The WSS data-channel file routes sign the route WITHOUT
//   the trailing "/ws" (the suffix selects the transfer channel, not the
//   signed resource — daemon RequestHardening::canonicalFileRoute)
// - sortedQuery: decoded k=v pairs joined with '&', sorted by key then value, empty
//   string when there is no query (%XX-decoding only; '+' stays literal)
// - body: lowercase hex SHA-256 of the raw body bytes; no body hashes the empty string
// - streamed endpoints (/appmesh/file/download|upload|delete and the SSE output|task streams)
//   sign the empty-string body hash (documented exemption: the streamed content is not bound)
//
// The secret is never logged and never exposed through a getter or toString().
// Node.js only: signing uses node:crypto (no npm dependencies).

let _crypto = null

async function nodeCrypto () {
  if (_crypto) return _crypto
  // The specifier is indirect and webpackIgnore keeps the browser bundle from
  // trying to resolve the Node builtin; the import only runs where signing is
  // used (Node.js).
  const specifier = 'node:crypto'
  const mod = await import(/* webpackIgnore: true */ specifier)
  _crypto = mod.default && mod.default.createHmac ? mod.default : mod
  return _crypto
}

/** Streamed file routes: the signature binds method/path/query/timestamp/nonce, not the bytes.
 * The exact daemon set (RequestHardening::canonicalFileRoute) — subpaths are not exempt. */
const EMPTY_BODY_EXEMPT_PATHS = new Set(['/appmesh/file/download', '/appmesh/file/upload', '/appmesh/file/delete'])

/** SSE stream routes (/appmesh/app/{name}/output|task/stream): the daemon's SSE hardening
 * check ignores the request body, so these sign the empty-string hash (docs/source/Streaming.md). */
const EMPTY_BODY_EXEMPT_STREAM_RE = /^\/appmesh\/app\/[^/]+\/(output|task)\/stream$/

/** Header names (must match HTTP_HEADER_KEY_* in src/common/Utility.h). */
export const REQUEST_SIGNATURE_HEADERS = Object.freeze({
  KEY_ID: 'X-Request-Key',
  TIMESTAMP: 'X-Timestamp',
  NONCE: 'X-Nonce',
  SIGNATURE: 'X-Signature'
})

/** True for streamed endpoints (file transfer, SSE streams) that sign the empty-string body hash. */
export function isEmptyBodyExemptPath (path) {
  if (typeof path !== 'string') return false
  const signingPath = canonicalSigningPath(path)
  return EMPTY_BODY_EXEMPT_PATHS.has(signingPath) || EMPTY_BODY_EXEMPT_STREAM_RE.test(signingPath)
}

/**
 * The canonical path the daemon signs: the trailing "/ws" of the WSS HTTPS
 * data-channel file routes selects the transfer channel, not the signed
 * resource, so it is dropped (daemon RequestHardening::canonicalFileRoute;
 * docs/source/Security.md, "Request replay protection and signatures").
 * Every other path passes through unchanged.
 */
export function canonicalSigningPath (path) {
  if (path === '/appmesh/file/download/ws') return '/appmesh/file/download'
  if (path === '/appmesh/file/upload/ws') return '/appmesh/file/upload'
  return path
}

function toHexLower (buffer) {
  return Buffer.from(buffer).toString('hex')
}

/**
 * Opt-in request signer for one per-principal API key
 * (POST /appmesh/security/apikeys). The signature is an integrity layer on top
 * of the bearer, not a replacement for it.
 */
export class RequestSigner {
  /**
   * @param {string} keyId - API key id sent as X-Request-Key
   * @param {string} secret - API key secret (kept private, never logged)
   */
  constructor (keyId, secret) {
    if (typeof keyId !== 'string' || keyId.trim() === '') {
      throw new TypeError('keyId must be a non-empty string')
    }
    if (typeof secret !== 'string' || secret === '') {
      throw new TypeError('secret must be a non-empty string')
    }
    // Non-enumerable (never leaked by JSON.stringify / object spread of the
    // signer); writable stays true so tests and subclasses may replace them.
    Object.defineProperty(this, '_keyId', { value: keyId, writable: true })
    Object.defineProperty(this, '_secret', { value: secret, writable: true })
  }

  /** The API key id this signer advertises. */
  get keyId () {
    return this._keyId
  }

  /**
   * Attach the four signature headers to a request header object, generating a
   * fresh unix-seconds timestamp and a random unique nonce.
   *
   * @param {Object} headers - request header object (mutated)
   * @param {string} method - HTTP method exactly as sent on the wire
   * @param {string} path - request path without query, exactly as sent; the
   *   WSS data-channel file routes ("/appmesh/file/{upload,download}/ws") are
   *   signed under the route without the trailing "/ws" (canonicalSigningPath)
   * @param {string} canonicalQuery - already-canonicalized query ('' when none)
   * @param {Buffer|Uint8Array|null} body - raw body bytes; null means no body;
   *   ignored for the streamed file endpoints, which always sign the empty hash
   * @param {string} [timestamp] - override (tests / known-answer vectors)
   * @param {string} [nonce] - override (tests / known-answer vectors)
   */
  async attach (headers, method, path, canonicalQuery, body, timestamp, nonce) {
    const ts = timestamp || String(Math.floor(Date.now() / 1000))
    const n = nonce || (await this.randomNonce())
    const signPath = canonicalSigningPath(path)
    const canonical = canonicalString(method, signPath, canonicalQuery, await sha256HexFor(signPath, body), ts, n)
    headers[REQUEST_SIGNATURE_HEADERS.KEY_ID] = this._keyId
    headers[REQUEST_SIGNATURE_HEADERS.TIMESTAMP] = ts
    headers[REQUEST_SIGNATURE_HEADERS.NONCE] = n
    headers[REQUEST_SIGNATURE_HEADERS.SIGNATURE] = await this.sign(canonical)
  }

  /** A random per-request nonce (hex; the daemon accepts up to 128 chars, no whitespace). */
  async randomNonce () {
    const crypto = await nodeCrypto()
    return crypto.randomBytes(16).toString('hex')
  }

  /** Lowercase hex HMAC-SHA256 of the canonical string under this signer's secret. */
  async sign (canonical) {
    const crypto = await nodeCrypto()
    return crypto.createHmac('sha256', this._secret).update(canonical, 'utf8').digest('hex')
  }

  /** Redacted: never exposes the secret. */
  toString () {
    return `RequestSigner[keyId=${this._keyId}]`
  }
}

/** The exact canonical string both sides must build byte-for-byte. */
export function canonicalString (method, path, query, bodySha256Hex, timestamp, nonce) {
  if (!method || !path) throw new TypeError('method and path are required')
  return [method, path, query || '', bodySha256Hex, timestamp, nonce].join('\n')
}

/** Empty-string body hash (the streamed-file-endpoint exemption value). */
export const EMPTY_BODY_SHA256 =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'

/**
 * Lowercase hex SHA-256 of the raw body bytes, applying the streamed-file
 * exemption: those endpoints sign the empty-string hash regardless of body.
 */
export async function bodySha256Hex (path, body) {
  return sha256HexFor(path, body)
}

async function sha256HexFor (path, body) {
  const bytes = (body === null || body === undefined || isEmptyBodyExemptPath(path))
    ? Buffer.alloc(0)
    : Buffer.from(body)
  const crypto = await nodeCrypto()
  return crypto.createHash('sha256').update(bytes).digest('hex')
}

/**
 * Sorted 'k=v&k2=v2' form used in the canonical string. Inputs are the decoded
 * parameter pairs (the TCP query map, or values decoded from the wire query).
 * Pairs are sorted by key, then by value.
 */
export function canonicalQuery (params) {
  if (!params) return ''
  const pairs = Object.entries(params)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => [String(k), String(v)])
  // Order by UTF-8 bytes, matching the daemon (not UTF-16 code units).
  pairs.sort((a, b) => {
    const byKey = Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8'))
    return byKey !== 0 ? byKey : Buffer.compare(Buffer.from(a[1], 'utf8'), Buffer.from(b[1], 'utf8'))
  })
  return pairs.map(([k, v]) => `${k}=${v}`).join('&')
}

/**
 * Canonical query built from the encoded query string exactly as it goes on the
 * wire (HTTP transport). Mirrors the daemon parser loop: split on '&', split
 * each pair at the first '=', decode each component with %XX-only decoding
 * ('+' stays literal, a malformed escape keeps the whole raw component), then
 * dedup decoded-key-first-wins (daemon std::map::emplace) and sort. An empty
 * segment (e.g. "a=1&&b=2") inserts ("", "") and the canonical output keeps
 * its "="; a trailing '&' adds no segment (the daemon loop ends at its bounds).
 */
export function canonicalQueryFromEncoded (encodedQuery) {
  if (!encodedQuery) return ''
  // Null prototype: query keys like "toString" or "__proto__" are plain data
  // here, never shadowed or dropped by Object prototype members.
  const decoded = Object.create(null)
  for (let pos = 0; pos < encodedQuery.length;) {
    const amp = encodedQuery.indexOf('&', pos)
    const pair = amp < 0 ? encodedQuery.slice(pos) : encodedQuery.slice(pos, amp)
    const eq = pair.indexOf('=')
    const key = eq < 0 ? pair : pair.slice(0, eq)
    const value = eq < 0 ? '' : pair.slice(eq + 1)
    // Decode first, then dedup: the daemon decodes each component and emplaces,
    // so the first value for a DECODED key wins (e.g. "a=1&a%61=2" keeps "a=1").
    const decodedKey = percentDecode(key)
    if (!Object.prototype.hasOwnProperty.call(decoded, decodedKey)) {
      decoded[decodedKey] = percentDecode(value)
    }
    if (amp < 0) break
    pos = amp + 1
  }
  const decodedPairs = Object.entries(decoded)
  // Order by UTF-8 bytes, matching the daemon (not UTF-16 code units: a
  // non-BMP character sorts before U+E000..U+FFFF in UTF-16, after it in UTF-8).
  decodedPairs.sort((a, b) => {
    const byKey = Buffer.compare(Buffer.from(a[0], 'utf8'), Buffer.from(b[0], 'utf8'))
    return byKey !== 0 ? byKey : Buffer.compare(Buffer.from(a[1], 'utf8'), Buffer.from(b[1], 'utf8'))
  })
  return decodedPairs.map(([k, v]) => `${k}=${v}`).join('&')
}

/** %XX-only decode; a malformed escape keeps the whole raw value (daemon behavior). */
function percentDecode (value) {
  if (!value.includes('%')) return value
  const bytes = []
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i)
    if (c === 0x25 /* % */) {
      const hi = value.charCodeAt(i + 1)
      const lo = value.charCodeAt(i + 2)
      const hex = (h) => (h >= 0x30 && h <= 0x39) || (h >= 0x41 && h <= 0x46) || (h >= 0x61 && h <= 0x66)
      if (!hex(hi) || !hex(lo)) {
        // Malformed escape: the daemon keeps the raw value verbatim.
        return value
      }
      bytes.push(parseInt(value.slice(i + 1, i + 3), 16))
      i += 2
    } else if (c < 0x80) {
      bytes.push(c)
    } else {
      // Non-ASCII in the raw component: keep its UTF-8 bytes.
      const part = Buffer.from(value[i], 'utf8')
      bytes.push(...part)
    }
  }
  return Buffer.from(bytes).toString('utf8')
}

/**
 * Pure percent-encoded query serialization used when signing is enabled, so the
 * query on the wire decodes back (daemon-side, %XX-only) to exactly the values
 * the signature was computed from. null/undefined parameters are skipped
 * (matching axios's default serializer).
 */
export function serializeQueryPurePercent (params) {
  if (!params) return ''
  return Object.entries(params)
    .filter(([, v]) => v !== null && v !== undefined)
    .map(([k, v]) => `${encodeURIComponent(String(k))}=${encodeURIComponent(String(v))}`)
    .join('&')
}
