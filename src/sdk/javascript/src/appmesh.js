// appmesh.js
import axios from 'axios';
import { StaticAccessTokenProvider } from './token_provider.js';
import { RefreshTokenProvider } from './refresh_token_provider.js';
import {
  RequestSigner, canonicalQueryFromEncoded, serializeQueryPurePercent, isEmptyBodyExemptPath,
} from './request_signature.js';

// Lazy-resolved Node.js https/fs modules (null in browser)
let _https = null;
let _fs = null;
let _httpsReady = null; // Promise that resolves when https/fs are loaded

// Constants using Object.freeze to prevent modifications
const CONSTANTS = Object.freeze({
  HTTP_USER_AGENT_HEADER_NAME: "User-Agent",
  HTTP_USER_AGENT: "appmesh/javascript",
  DEFAULT_RUN_APP_TIMEOUT_SECONDS: "P2D",
  DEFAULT_RUN_APP_LIFECYCLE_SECONDS: "P2DT12H",
  HTTP_HEADER_KEY_AUTH: "Authorization",
  HTTP_HEADER_KEY_X_TARGET_HOST: "X-Target-Host",
  HTTP_HEADER_KEY_X_FILE_PATH: "X-File-Path",
});

// Environment detection
const ENV = Object.freeze({
  isNode: !(typeof window !== 'undefined' && window.document !== 'undefined')
});

// Same absolute-URL test as axios's helpers/isAbsoluteURL.js: "<scheme>://" or
// a protocol-relative "//" URL bypasses baseURL combination.
const _ABSOLUTE_URL_RE = /^([a-z][a-z\d+\-.]*:)?\/\//i;

/**
 * The encoded request path exactly as axios puts it on the wire: axios combines
 * baseURL + url by concatenation (core/buildFullPath.js + helpers/combineURLs.js
 * — a baseURL path PREFIX stays in the path), then the Node adapter parses the
 * result with `new URL(fullPath)` and sends `parsed.pathname`. Signing this
 * value (instead of the caller-supplied raw url) makes the signed path the wire
 * path: a space or non-ASCII character is percent-encoded on the wire and in
 * the signature alike, and a baseURL path prefix is included.
 * @private
 */
function _wireRequestPath(baseURL, url) {
  const base = String(baseURL || '');
  const rel = String(url || '');
  let fullPath = rel;
  if (base && !_ABSOLUTE_URL_RE.test(rel)) {
    // combineURLs: strip trailing '/' from the base, leading '/' from the url.
    let end = base.length;
    while (end > 0 && base.charCodeAt(end - 1) === 47 /* / */) end--;
    fullPath = rel ? base.slice(0, end) + '/' + rel.replace(/^\/+/, '') : base;
  }
  try {
    return new URL(fullPath).pathname;
  } catch (_) {
    try {
      // Path-only url (no baseURL, no scheme): axios supplies a synthetic base
      // for such URLs; mirror that so the pathname is still computed.
      return new URL(fullPath, 'http://localhost').pathname;
    } catch (_e) {
      return rel;
    }
  }
}

/**
 * Custom error for AppMesh with enhanced debugging
 */
class AppMeshError extends Error {
  /**
   * Create AppMesh error
   * @param {string} message - Error message
   * @param {number|null} statusCode - HTTP status code
   * @param {any} responseData - Raw response data
   * @param {string|null} errorCode - Machine-readable error code
   */
  constructor(message, statusCode = null, responseData = null, errorCode = null) {
    super(message);
    this.name = 'AppMeshError';
    this.statusCode = statusCode;
    this.responseData = responseData;
    this.errorCode = errorCode;
    this.timestamp = new Date().toISOString();
  }
}

/**
 * App removed before its async-run exit was observed. Typed replacement for the
 * old -1 sentinel, keeping real (possibly negative) exit codes unambiguous.
 */
class AppRemovedError extends AppMeshError {
  /** @param {string} message - Error message */
  constructor(message) {
    super(message, null, null, 'APP_REMOVED');
    this.name = 'AppRemovedError';
  }
}

/**
 * Transport disconnected while waiting for an async run, or the daemon delivered
 * an unparseable exit code. Typed replacement for the old -2 sentinel exit code.
 */
class TransportDisconnectedError extends AppMeshError {
  /** @param {string} message - Error message */
  constructor(message) {
    super(message, null, null, 'TRANSPORT_DISCONNECTED');
    this.name = 'TransportDisconnectedError';
  }
}

/** The daemon rejected a request, or a stream ended with reason 'error' (Python AppMeshRequestError). */
class AppMeshRequestError extends AppMeshError {
  /**
   * @param {string} message - Error message
   * @param {number|null} [statusCode=null] - HTTP status code
   */
  constructor(message, statusCode = null) {
    super(message, statusCode, null, 'REQUEST');
    this.name = 'AppMeshRequestError';
  }
}

/** A call or stream exceeded its overall timeout (Python AppMeshTimeoutError). */
class AppMeshTimeoutError extends AppMeshError {
  /** @param {string} message - Error message */
  constructor(message) {
    super(message, null, null, 'TIMEOUT');
    this.name = 'AppMeshTimeoutError';
  }
}

// Default output handler
const defaultOutputHandler = (output, position) => {
  if (ENV.isNode) {
    process.stdout.write(output);
  } else {
    console.log(output);
  }
};

/**
 * Converts ISO8601 duration to seconds
 * @param {string|number} duration - Duration string or seconds
 * @returns {number} Total seconds
 * @throws {Error} If format invalid
 */
function parseDuration(duration) {
  // Return if already number
  if (typeof duration === "number") {
    return duration;
  }

  if (typeof duration !== 'string') {
    throw new Error("Invalid input type. Expected number or ISO 8601 duration string.");
  } else if (/^\d+$/.test(duration)) {
    // Parse if string contains only numbers
    return parseInt(duration, 10);
  }

  // Check empty string
  if (!duration.trim()) {
    throw new Error('Duration string cannot be empty');
  }

  // Check ISO8601 format (must start with P)
  if (!duration.startsWith('P')) {
    throw new Error('Invalid ISO8601 duration: must start with P');
  }

  // Regex pattern for ISO8601 duration
  const numbers = "\\d+";
  const fractionalNumbers = `${numbers}(?:[\\.,]${numbers})?`;
  const datePattern = `(${numbers}Y)?(${numbers}M)?(${numbers}W)?(${numbers}D)?`;
  const timePattern = `T(${fractionalNumbers}H)?(${fractionalNumbers}M)?(${fractionalNumbers}S)?`;
  const iso8601 = `P(?:${datePattern}(?:${timePattern})?)`;
  const objMap = ["years", "months", "weeks", "days", "hours", "minutes", "seconds"];

  // Parse duration string
  const matches = duration.replace(/,/g, ".").match(new RegExp(iso8601));
  if (!matches) {
    throw new RangeError("invalid duration: " + duration);
  }

  // Get matched groups
  const slicedMatches = matches.slice(1);

  // Verify valid matches exist
  if (slicedMatches.filter(v => v != null).length === 0) {
    throw new RangeError("invalid duration: " + duration);
  }

  // Allow only one fractional unit
  if (slicedMatches.filter(v => /\./.test(v || "")).length > 1) {
    throw new RangeError("only the smallest unit can be fractional");
  }

  // Build duration object from matches
  const durationObject = slicedMatches.reduce((prev, next, idx) => {
    prev[objMap[idx]] = parseFloat(next || "0") || 0;
    return prev;
  }, {});

  // Convert to seconds
  let seconds = 0;

  seconds += durationObject.years * 31536000; // 365d * 24h * 60m * 60s
  seconds += durationObject.months * 2592000; // 30d * 24h * 60m * 60s (approx)
  seconds += durationObject.weeks * 604800;   // 7d * 24h * 60m * 60s
  seconds += durationObject.days * 86400;     // 24h * 60m * 60s
  seconds += durationObject.hours * 3600;     // 60m * 60s
  seconds += durationObject.minutes * 60;
  seconds += durationObject.seconds;

  return seconds;
}

/**
 * Case-insensitive header lookup (axios lowercases names; the TCP transport keeps the daemon's case).
 * @param {Object} headers - Response headers
 * @param {string} name - Header name (any case)
 * @returns {*} Header value or undefined
 * @private
 */
function _getHeader(headers, name) {
  if (!headers) return undefined;
  const lower = name.toLowerCase();
  const key = Object.keys(headers).find(k => k.toLowerCase() === lower);
  return key === undefined ? undefined : headers[key];
}

/**
 * Strict axios transformResponse: JSON-typed or JSON-looking string bodies must parse;
 * malformed JSON raises a typed AppMeshError instead of silently degrading to a string.
 * Text-typed bodies stay strings; non-string bodies (binary downloads, streams) pass through.
 * @param {any} data - Response body
 * @param {Object} [headers] - Response headers (AxiosHeaders or plain object)
 * @param {number} [status] - HTTP status code
 * @returns {any} Parsed JSON, raw text, or the original non-string body
 * @throws {AppMeshError} With errorCode 'JSON_PARSE' when a JSON body fails to parse
 * @private
 */
function _transformResponseJson(data, headers, status) {
  if (typeof data !== "string" || data === "") {
    return data;
  }
  const contentType = String(_getHeader(headers, "content-type") || "").toLowerCase();
  // Parse strictly only when the server declared JSON. Every other body stays a
  // string: task replies are typed application/octet-stream and stdout is
  // text/plain, and both may merely look like JSON.
  if (!contentType.includes("json")) {
    return data;
  }
  try {
    return JSON.parse(data);
  } catch (error) {
    throw new AppMeshError(`Response body is not valid JSON: ${error.message}`, status ?? null, data, "JSON_PARSE");
  }
}

/**
 * Resolve a user name or numeric string to a UID (Node.js/Unix only).
 * @param {string} user - User name or numeric UID
 * @returns {Promise<number|null>} UID or null if unresolvable
 * @private
 */
async function _resolveUid(user) {
  // If already numeric, return directly
  const num = parseInt(user, 10);
  if (!isNaN(num) && String(num) === user.trim()) return num;
  try {
    const { spawnSync } = await import('child_process');
    const result = spawnSync('id', ['-u', user], { encoding: 'utf8', timeout: 3000 });
    if (result.status !== 0 || !result.stdout) return null;
    return parseInt(result.stdout.trim(), 10);
  } catch (_) {
    return null;
  }
}

/**
 * Resolve a group name or numeric string to a GID (Node.js/Unix only).
 * @param {string} group - Group name or numeric GID
 * @returns {Promise<number|null>} GID or null if unresolvable
 * @private
 */
async function _resolveGid(group) {
  const num = parseInt(group, 10);
  if (!isNaN(num) && String(num) === group.trim()) return num;
  const record = await _lookupGroup('name', group);
  return record ? record.gid : null;
}

/**
 * Read one group record from the OS directory service (Node.js/Unix only).
 * Linux answers through getent; macOS ships no getent and is queried through its
 * directory service instead, so both lookups need the fallback to work there.
 * @param {'name'|'gid'} key - Field to look the group up by
 * @param {string} value - Group name or numeric GID
 * @returns {Promise<{name: string, gid: number}|null>} Parsed record, or null when unresolved
 * @private
 */
async function _lookupGroup(key, value) {
  try {
    const { spawnSync } = await import('child_process');
    // Linux: "name:x:gid:members", accepting either a name or a numeric gid
    const result = spawnSync('getent', ['group', String(value)], { encoding: 'utf8', timeout: 3000 });
    if (result.status === 0 && result.stdout) {
      const parts = result.stdout.trim().split(':');
      const gid = parts.length >= 3 ? parseInt(parts[2], 10) : NaN;
      return parts[0] && !isNaN(gid) ? { name: parts[0], gid } : null;
    }
    // macOS: "name: staff" / "gid: 20" lines, and empty output when unknown
    const macResult = spawnSync('dscacheutil', ['-q', 'group', '-a', key, String(value)],
      { encoding: 'utf8', timeout: 3000 });
    if (macResult.status !== 0 || !macResult.stdout) return null;
    const lines = macResult.stdout.split('\n');
    const nameLine = lines.find(entry => entry.startsWith('name:'));
    const gidLine = lines.find(entry => entry.startsWith('gid:'));
    if (!nameLine || !gidLine) return null;
    const name = nameLine.slice('name:'.length).trim();
    const gid = parseInt(gidLine.slice('gid:'.length).trim(), 10);
    return name && !isNaN(gid) ? { name, gid } : null;
  } catch (_) {
    return null;
  }
}

/**
 * Resolve a numeric UID to a user name (Node.js/Unix only).
 * @param {number|string} uid - Numeric UID
 * @returns {Promise<string|null>} User name or null if unresolvable
 * @private
 */
async function _resolveUserName(uid) {
  try {
    const { spawnSync } = await import('child_process');
    // `id -un` accepts a numeric UID on Linux and macOS; getent is Linux-only.
    const result = spawnSync('id', ['-un', String(uid)], { encoding: 'utf8', timeout: 3000 });
    if (result.status !== 0 || !result.stdout) return null;
    const name = result.stdout.trim();
    return name || null;
  } catch (_) {
    return null;
  }
}

/**
 * Resolve a numeric GID to a group name (Node.js/Unix only).
 * @param {number|string} gid - Numeric GID
 * @returns {Promise<string|null>} Group name or null if unresolvable
 * @private
 */
async function _resolveGroupName(gid) {
  const record = await _lookupGroup('gid', gid);
  return record ? record.name : null;
}

// Default App Mesh CA bundle, preferred when no sslConfig is given and the file exists
const DEFAULT_CA_FILE = '/opt/appmesh/ssl/ca.pem';

// Only these body types can be safely replayed on a retry after a 401 response
function _isReplayableBody(data) {
  return data === undefined || data === null || typeof data === 'string' ||
    (typeof Buffer !== 'undefined' && Buffer.isBuffer(data));
}

// Extract the bearer token a rejected request carried, so a provider's refresh
// can dedup concurrent 401s against the token that was actually sent
function _extractBearerToken(headers) {
  if (!headers) return null;
  const value = typeof headers.get === 'function'
    ? headers.get(CONSTANTS.HTTP_HEADER_KEY_AUTH)
    : (headers[CONSTANTS.HTTP_HEADER_KEY_AUTH] || headers.authorization);
  return (typeof value === 'string' && value.startsWith('Bearer ')) ? value.slice('Bearer '.length) : null;
}

// PEM material: Buffers/inline PEM pass through; any other string is a file path —
// a missing path is a hard error, never a silent no-verify fallback.
function _loadPem(value) {
  return (typeof value === 'string' && !value.includes('-----BEGIN')) ? _fs.readFileSync(value) : value;
}

// Resolve the sslConfig tri-state into https.Agent TLS options (Node.js only):
// null/undefined = App Mesh default CA if installed else system CAs; false = explicit
// insecure; object = custom ca/cert/key (rejectUnauthorized defaults to true).
function _resolveSslOptions(sslConfig) {
  if (sslConfig === false) return { rejectUnauthorized: false };
  if (!sslConfig) {
    return _fs.existsSync(DEFAULT_CA_FILE)
      ? { ca: _fs.readFileSync(DEFAULT_CA_FILE), rejectUnauthorized: true }
      : { rejectUnauthorized: true }; // fall back to system trust roots, verification stays on
  }
  const opts = { ...sslConfig };
  for (const k of ['ca', 'cert', 'key']) if (opts[k]) opts[k] = _loadPem(opts[k]);
  if (typeof opts.rejectUnauthorized !== 'boolean') opts.rejectUnauthorized = true;
  return opts;
}

/** Terminal marker of an SSE stream: the async generator's return value (Python SseEnd counterpart). */
class SseEnd {
  /**
   * @param {string} reason - exit | removed | timeout | eof | final | disconnected | error | closed
   * @param {Object} [fields] - Fields carried by the terminal `end` frame
   * @param {number|null} [fields.exitCode] - Process exit code when reason is 'exit'
   * @param {number|null} [fields.position] - Output streams: final stdout byte cursor
   * @param {number|null} [fields.status] - Task streams: HTTP status carried by an error end frame
   * @param {string|null} [fields.message] - Task streams: error message
   * @param {string|null} [fields.result] - Task streams: the final result payload
   */
  constructor(reason, fields = {}) {
    /** @type {string} One of the constructor's reason values; 'closed' = peer cut the stream */
    this.reason = reason;
    /** @type {number|null} Process exit code when reason is 'exit' */
    this.exitCode = fields.exitCode ?? null;
    /** @type {number|null} Output streams: final stdout byte cursor */
    this.position = fields.position ?? null;
    /** @type {number|null} Task streams: HTTP status carried by an error end frame */
    this.status = fields.status ?? null;
    /** @type {string|null} Task streams: error message */
    this.message = fields.message ?? null;
    /** @type {string|null} Task streams: the final result payload (the same string runTask would return) */
    this.result = fields.result ?? null;
  }
}

/**
 * Yield `[event, payload]` pairs from an SSE body: a blank line dispatches the frame,
 * `event:`/`data:` set its fields, `:` lines are heartbeats (Python iter_sse_events rules).
 * @private
 * @param {Object} body - Streamed response body (axios responseType 'stream')
 */
async function* _iterSseEvents(body) {
  const decoder = new TextDecoder('utf-8');
  let pending = '';
  let eventName = 'message';
  let dataLines = [];
  for await (const chunk of body) {
    pending += typeof chunk === 'string' ? chunk : decoder.decode(chunk, { stream: true });
    let newline;
    while ((newline = pending.indexOf('\n')) >= 0) {
      const line = pending.slice(0, newline).replace(/\r$/, '');
      pending = pending.slice(newline + 1);
      if (line === '') {
        if (eventName !== 'message' || dataLines.length > 0) {
          const data = dataLines.join('\n');
          let payload = {};
          if (data) {
            try {
              payload = JSON.parse(data);
            } catch (error) {
              throw new AppMeshError(`malformed SSE frame (${eventName}): ${error.message}`);
            }
          }
          yield [eventName, payload];
        }
        eventName = 'message';
        dataLines = [];
      } else if (line.startsWith(':')) {
        // heartbeat comment
      } else if (line.startsWith('event:')) {
        eventName = line.slice('event:'.length).trim();
      } else if (line.startsWith('data:')) {
        dataLines.push(line.slice('data:'.length).trimStart());
      }
    }
  }
}

/**
 * Build the terminal marker from an `end` frame payload.
 * @private
 * @param {Object} payload - Parsed `end` frame data
 * @param {Object} [extra] - Additional fields (e.g. the collected final result)
 * @returns {SseEnd} Terminal marker
 */
function _endFromPayload(payload, extra = {}) {
  return new SseEnd(String(payload.reason ?? 'closed'), {
    exitCode: payload.exit_code,
    position: payload.position,
    status: payload.status,
    message: payload.message,
    ...extra
  });
}

/**
 * Turn an error/timeout terminal frame into the matching exception.
 * @private
 * @param {SseEnd} end - Terminal marker
 * @throws {AppMeshRequestError} reason is 'error'
 * @throws {AppMeshTimeoutError} reason is 'timeout'
 * @throws {AppMeshError} reason is unknown
 */
function _raiseOnErrorEnd(end) {
  if (end.reason === 'error') {
    throw new AppMeshRequestError(end.message || 'stream failed with an error', end.status ?? null);
  }
  if (end.reason === 'timeout') {
    throw new AppMeshTimeoutError(end.message || 'stream timed out');
  }
  if (!['exit', 'removed', 'eof', 'final', 'disconnected', 'closed'].includes(end.reason)) {
    throw new AppMeshError(`stream ended with unknown reason: ${end.reason}`);
  }
}

/**
 * AppMesh REST Service client
 */
class AppMeshClient {
  /**
   * Initialize AppMesh client
   * @param {string} baseURL - Service URL
   * @param {Object|false|null} [sslConfig] - SSL tri-state: `null`/`undefined` (default) verifies
   *   against the App Mesh default CA (/opt/appmesh/ssl/ca.pem) if installed, else the system CAs;
   *   `false` disables verification; an object supplies custom `ca`/`cert`/`key` (Buffer, inline
   *   PEM, or file path — a missing path is a hard error).
   * @param {Object} [tokenProvider] - Optional duck-typed token provider
   *   (`{ async getAccessToken(), canRefresh(), async refreshAccessToken(rejectedToken), clear() }`,
   *   see token_provider.js). When it can refresh, a request rejected with HTTP 401 is retried
   *   once with the refreshed token.
   * @example
   * const sslConfig = {
   *   cert: fs.readFileSync("client.pem"),
   *   key: fs.readFileSync("client-key.pem"),
   *   ca: fs.readFileSync("ca.pem"),
   *   rejectUnauthorized: true
   * };
   */
  constructor(baseURL = ENV.isNode ? 'https://127.0.0.1:6060' : window.location.origin,
    sslConfig = null, tokenProvider = null) {
    // Base URL for API requests
    this.baseURL = baseURL;

    // Host to forward requests to
    this.forwardingHost = null;

    // Opt-in HMAC request signer (REST.RequestSignature hardening); null when disabled
    this._requestSigner = null;

    // Token provider: single source of truth for the access token; transports
    // read from it via _getAccessToken()
    this._tokenProvider = null;
    if (tokenProvider) {
      this.setTokenProvider(tokenProvider);
    }

    // Configure axios instance
    const axiosConfig = {
      baseURL,
      timeout: 300000, // 5 minutes
      validateStatus: status => true,
      // Strict JSON handling: malformed JSON bodies raise a typed error
      // instead of axios's default silent fallback to the raw string
      transformResponse: [_transformResponseJson]
    };

    // Store SSL config for deferred agent setup
    this._sslConfig = sslConfig;
    this._client = axios.create(axiosConfig);

    // Node.js only: start loading https/fs modules (resolved before first request)
    if (ENV.isNode && !_httpsReady) {
      _httpsReady = Promise.all([import('https'), import('fs')]).then(([h, f]) => {
        _https = h.default || h;
        _fs = f.default || f;
      }).catch(() => { /* browser bundle — ignore */ });
    }

    // Request interceptor
    this._client.interceptors.request.use(
      async config => {
        // Apply common headers
        config.headers = { ...config.headers, ...(await this._commonHeaders()) };
        return config;
      },
      error => {
        // Handle request setup errors
        const err = new AppMeshError('Request configuration error: ' + (error.message || 'Unknown error'))
        return Promise.reject(err);
      }
    );

    // Response interceptor
    this._client.interceptors.response.use(response => this._handleUnauthorizedRetry(response), error => {
        // Typed SDK errors (e.g. JSON parse failures from transformResponse) pass through unchanged
        if (error instanceof AppMeshError) {
          return Promise.reject(error);
        }
        // Network-level failure (DNS, connection refused, timeout, ...)
        const err = new AppMeshError('Request failed: ' + (error.message || 'Unknown error'),
          error.response?.status ?? null, error.response?.data ?? null);
        err.cause = error;
        return Promise.reject(err);
      }
    );
  }

  /**
   * Attach a refresh-capable token provider. The provider is duck-typed: it must
   * implement `async getAccessToken()`; `canRefresh()`, `async refreshAccessToken(rejectedToken)`
   * and `clear()` follow the contract in token_provider.js.
   * @param {Object} provider - Token provider
   */
  setTokenProvider(provider) {
    if (!provider || typeof provider.getAccessToken !== 'function') {
      throw new TypeError('tokenProvider must implement async getAccessToken()');
    }
    this._tokenProvider = provider;
  }

  /** Attach a caller-owned, non-refreshing access token in memory. */
  setBearerToken(token) {
    if (token === null || token === undefined) {
      this.clearBearerToken();
      return;
    }
    this.setTokenProvider(new StaticAccessTokenProvider(token));
  }

  /** Source-compatible alias for setBearerToken(). */
  setToken(token) {
    this.setBearerToken(token);
  }

  /** Remove the locally attached bearer without contacting Engine or the authentication service. */
  clearBearerToken() {
    const provider = this._tokenProvider;
    if (provider && typeof provider.clear === 'function') {
      provider.clear();
    }
    this._tokenProvider = null;
  }

  /**
   * Enable HMAC request signing on every subsequent request (opt-in) with a
   * per-principal API key (`POST /appmesh/security/apikeys`). Each request then
   * carries the `X-Request-Key`, `X-Timestamp`, `X-Nonce` and `X-Signature`
   * headers (Node.js only). The signature is an integrity layer on top of the
   * bearer, not a replacement for it. The secret is kept in memory only and
   * never logged.
   * @param {string} keyId - API key id
   * @param {string} secret - API key secret
   */
  enableRequestSignature(keyId, secret) {
    this._requestSigner = new RequestSigner(keyId, secret);
  }

  /** Disable request signing; subsequent requests carry no signature headers. */
  disableRequestSignature() {
    this._requestSigner = null;
  }

  /** Whether `enableRequestSignature` is currently active on this client. */
  isRequestSignatureEnabled() {
    return this._requestSigner !== null;
  }

  /**
   * Attach the four signature headers to a prepared axios request config.
   * The path is signed exactly as axios puts it on the wire (`_wireRequestPath`:
   * percent-encoded, baseURL path prefix included) and the canonical query is
   * derived from the exact wire query: signing forces a pure percent-encoded
   * params serialization so the daemon's %-only decode yields exactly the
   * signed values. The body is serialized the way axios will put it on the
   * wire. The streamed file endpoints sign the empty-string hash (the WSS
   * data-channel "/ws" routes sign the stripped route, canonicalSigningPath).
   * @private
   */
  async _applyRequestSignature(config) {
    const signer = this._requestSigner;
    if (!signer || !config) return;

    // Sign the wire path, not the caller's raw url: axios re-quotes the path
    // (space → %20) and keeps the baseURL path prefix, so the daemon verifies
    // a different path than the raw one whenever either differs.
    const path = _wireRequestPath(config.baseURL || this._client.defaults.baseURL || this.baseURL, config.url);
    let canonicalQuery = '';
    if (config.params && typeof config.params === 'object' && Object.keys(config.params).length > 0) {
      // Deterministic wire form: pure percent encoding, null/undefined skipped.
      config.paramsSerializer = serializeQueryPurePercent;
      canonicalQuery = canonicalQueryFromEncoded(serializeQueryPurePercent(config.params));
    }

    const contentType = this._headerValue(config.headers, 'content-type');
    const bodyBytes = isEmptyBodyExemptPath(path)
      ? Buffer.alloc(0)
      : this._wireBodyBytes(config.data, contentType);

    const method = String(config.method || 'get').toUpperCase();
    const headers = {};
    await signer.attach(headers, method, path, canonicalQuery, bodyBytes);
    for (const [name, value] of Object.entries(headers)) {
      if (config.headers && typeof config.headers.set === 'function') {
        config.headers.set(name, value);
      } else {
        config.headers = { ...config.headers, [name]: value };
      }
    }
  }

  /**
   * Case-insensitive lookup on a plain header object or AxiosHeaders.
   * @private
   */
  _headerValue(headers, name) {
    if (!headers) return undefined;
    if (typeof headers.get === 'function') return headers.get(name);
    const key = Object.keys(headers).find(k => k.toLowerCase() === name.toLowerCase());
    return key === undefined ? undefined : headers[key];
  }

  /**
   * The body bytes as axios will serialize them for the wire, mirroring the
   * default transformRequest: plain objects (and JSON-typed strings) become
   * JSON, other strings pass through, buffers pass through. A body that cannot
   * be replayed byte-for-byte (stream, File, FormData) cannot be signed.
   * @private
   */
  _wireBodyBytes(data, contentType) {
    if (data === null || data === undefined) {
      return Buffer.alloc(0);
    }
    if (typeof data === 'string') {
      if (String(contentType || '').toLowerCase().includes('application/json')) {
        // axios trims a JSON-parseable string body and re-encodes a non-JSON one.
        try {
          JSON.parse(data);
          return Buffer.from(data.trim(), 'utf8');
        } catch (error) {
          if (error.name !== 'SyntaxError') throw error;
          return Buffer.from(JSON.stringify(data), 'utf8');
        }
      }
      return Buffer.from(data, 'utf8');
    }
    if (Buffer.isBuffer(data) || data instanceof Uint8Array || data instanceof ArrayBuffer) {
      return Buffer.from(data);
    }
    if (typeof data === 'object') {
      return Buffer.from(JSON.stringify(data), 'utf8');
    }
    throw new AppMeshError(
      'cannot sign a streaming request body; only the /appmesh/file/* endpoints accept unbound bodies');
  }

  /** Return the current in-memory access token from the attached provider. */
  async _getAccessToken() {
    return this._tokenProvider ? await this._tokenProvider.getAccessToken() : null;
  }

  /**
   * Retry a request once after a 401 when the attached provider can refresh.
   *
   * Only replayable bodies (undefined/string/Buffer) are retried — streaming or
   * multipart bodies fail with the original 401. The provider's
   * `refreshAccessToken(rejectedToken)` is called at most once per request
   * (guarded by `config.__appmeshRetried`); a second 401 surfaces unchanged so
   * `_request` raises the standard typed error.
   *
   * @private
   * @param {Object} response - Axios response (validateStatus passes every status here)
   * @returns {Promise<Object>} The original response or the retried response
   */
  async _handleUnauthorizedRetry(response) {
    const config = response.config || {};
    const provider = this._tokenProvider;
    if (response.status !== 401 || config.__appmeshRetried || !provider) {
      return response;
    }
    const canRefresh = typeof provider.canRefresh === 'function' ? await provider.canRefresh() : !!provider.canRefresh;
    if (!canRefresh || typeof provider.refreshAccessToken !== 'function' || !_isReplayableBody(config.data)) {
      return response;
    }
    // A signed request's 401 is terminal unless the server pins the blame on
    // the bearer (WWW-Authenticate ... invalid_token): refresh tokens are
    // single-use, so force-refreshing on a signature rejection would burn the
    // session without fixing the request.
    if (this._requestSigner) {
      const headers = response.headers || {};
      const challenge = typeof headers.get === 'function'
        ? headers.get('WWW-Authenticate')
        : (headers['WWW-Authenticate'] || headers['www-authenticate']);
      if (!challenge || !challenge.includes('invalid_token')) {
        return response;
      }
    }

    const rejectedToken = _extractBearerToken(config.headers) ?? (await this._getAccessToken());
    const newToken = await provider.refreshAccessToken(rejectedToken);
    if (typeof newToken !== 'string' || !newToken.trim()) {
      return response;
    }

    config.__appmeshRetried = true;
    const authorization = `Bearer ${newToken.trim()}`;
    if (config.headers && typeof config.headers.set === 'function') {
      config.headers.set(CONSTANTS.HTTP_HEADER_KEY_AUTH, authorization);
    } else {
      config.headers = { ...config.headers, [CONSTANTS.HTTP_HEADER_KEY_AUTH]: authorization };
    }
    // The retry is a new request: it needs a fresh signature (a replayed nonce
    // would be rejected by the daemon's replay protection).
    if (this._requestSigner) {
      await this._applyRequestSignature(config);
    }
    return this._client(config);
  }

  /** Return Engine's public OAuth/OIDC configuration. */
  async getAuthConfig() {
    return (await this._request("get", "/appmesh/auth/config")).data;
  }

  /** Return the verified principal represented by the current bearer. */
  async getCurrentPrincipal() {
    return (await this._request("get", "/appmesh/principal/self")).data;
  }

  /**
   * Get all applications info
   * @returns {Object} All apps info
   */
  async listApps() {
    const response = await this._request("get", "/appmesh/applications");
    return response.data;
  }

  /**
   * Get app information
   * @param {string} name - App name
   * @returns {Object} App config
   */
  async getApp(name) {
    const response = await this._request("get", `/appmesh/app/${name}`);
    return response.data;
  }

  /**
   * Check app health status
   * @param {string} name - App name
   * @returns {boolean} True if healthy; false only when the daemon's health verdict says unhealthy
   * @throws {AppMeshError} On auth/missing-app/server errors (non-200) or network/transport failure
   */
  async checkAppHealth(name) {
    const response = await this._request("get", `/appmesh/app/${name}/health`);
    return parseInt(response.data, 10) === 0;
  }

  /**
   * Add or update an application.
   * @param {string} name - App name
   * @param {Object} appJson - App configuration; see the App schema in openapi.yaml for all fields
   * @returns {Promise<Object>} Registered app
   * @example
   * const appConfig = {
   *   name: "ping",
   *   command: "ping github.com -w 3",
   *   shell: false,
   *   session_login: false,
   *   description: "",
   *   metadata: "",
   *   stdin: "none",         // "pipe" keeps the daemon-side write end open so sendInput() can drive the process
   *   working_dir: "",
   *   enabled: 1,
   *   docker_image: "",
   *   docker_ports: [],       // docker run -p spelling: "[hostIp:]hostPort:containerPort[/protocol]"
   *   docker_volumes: [],     // docker run -v spelling
   *   docker_network: null,   // host, bridge, none or a network name
   *   stdout_backup_count: 3,
   *   start_time: "",
   *   end_time: "",
   *   interval: null,
   *   cron_schedule: null,
   *   daily_limitation: { daily_start: "", daily_end: "" },
   *   stop_grace_period: null,
   *   health_check_cmd: null,
   *   depends_on: [],
   *   permission: null,
   *   env: {},
   *   secret_env: {},
   *   pid: null,
   *   resource_limit: { cpu_shares: null, cpu: null, memory_mb: null, memory_virt_mb: null }, // cpu = fractional cores (NanoCPUs)
   *   behavior: { exit: "standby", exit_code_actions: { "0": "keepalive" } }
   * };
   * await client.addApp("ping", appConfig);
   */
  async addApp(name, appJson) {
    const response = await this._request("put", `/appmesh/app/${name}`, appJson);
    return response.data;
  }

  /**
   * Delete application
   * @param {string} name - App name
   * @returns {Promise<boolean>} Success status
   */
  async deleteApp(name) {
    try {
      const response = await this._request("delete", `/appmesh/app/${name}`);
      return response.status === 200;
    } catch (error) {
      if (error.statusCode === 404) return false;
      throw error;
    }
  }

  /**
   * Enable application
   * @param {string} name - App name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async enableApp(name) {
    await this._request("post", `/appmesh/app/${name}/enable`);
    return true;
  }

  /**
   * Disable application
   * @param {string} name - App name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async disableApp(name) {
    await this._request("post", `/appmesh/app/${name}/disable`);
    return true;
  }

  /**
   * Get incremental stdout/stderr for a running or completed process.
   * @param {string} app_name - App name
   * @param {number} [stdout_position=0] - Output cursor; use the previous `AppOutput.outPosition`
   * value to continue reading
   * @param {number} [stdout_index=0] - History slot; `0` targets the current process
   * @param {number} [stdout_maxsize=10240] - Max output size
   * @param {string} [process_uuid=""] - Process UUID
   * @param {number} [timeout=0] - Server long-poll timeout in seconds
   * @returns {Promise<AppOutput>} Output body, next cursor, and exit code when available
   */
  async getAppOutput(app_name, stdout_position = 0, stdout_index = 0, stdout_maxsize = 10240,
    process_uuid = "", timeout = 0) {
    const params = {
      stdout_position: stdout_position.toString(),
      stdout_index: stdout_index.toString(),
      stdout_maxsize: stdout_maxsize.toString(),
      process_uuid: process_uuid,
      timeout: parseDuration(timeout).toString()
    };

    const response = await this._request("get", `/appmesh/app/${app_name}/output`, null, { params });
    // axios lowercases header names; the TCP transport keeps the daemon's exact case
    const outPositionHeader = _getHeader(response.headers, "X-Output-Position");
    const exitCodeHeader = _getHeader(response.headers, "X-Exit-Code");
    const outPosition = outPositionHeader ? parseInt(outPositionHeader, 10) : null;
    const exitCode = exitCodeHeader ? parseInt(exitCodeHeader, 10) : null;
    return new AppOutput(response.status, response.data, outPosition, exitCode);
  }

  /**
   * Run an app synchronously and stream the returned stdout body to `stdoutHandler`.
   * @param {Object} app - App configuration
   * @param {Function} [stdoutHandler=defaultOutputHandler] - Stdout handler callback(data, position)
   * @param {number|string} [maxTime] - Max runtime
   * @param {number|string} [lifecycle] - Lifecycle time
   * @returns {Promise<number|null>} Exit code parsed from `X-Exit-Code`, or `null` when absent
   */
  async runAppSync(app, stdoutHandler = defaultOutputHandler, maxTime = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS,
    lifecycle = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = {
      timeout: parseDuration(maxTime),
      lifecycle: parseDuration(lifecycle)
    };

    const response = await this._request("post", "/appmesh/app/syncrun", app, { params });
    let exitCode = null;

    if (stdoutHandler) {
      stdoutHandler(response.data, 0);
    }
    if (response.status === 200) {
      // axios lowercases header names; the TCP transport keeps the daemon's exact case
      const exitCodeHeader = _getHeader(response.headers, "X-Exit-Code");
      if (exitCodeHeader) {
        exitCode = parseInt(exitCodeHeader, 10);
      }
    }

    return exitCode;
  }

  /**
   * Run an app asynchronously and return a handle for later polling.
   * @param {Object} app - App config
   * @param {string|number} [maxTime] - Max runtime
   * @param {string|number} [lifecycle] - Lifecycle time
   * @returns {AppRun} Running app handle that also snapshots the current forwarding host
   */
  async runAppAsync(app, maxTime = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS,
    lifecycle = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = {
      timeout: parseDuration(maxTime),
      lifecycle: parseDuration(lifecycle)
    };

    const response = await this._request("post", "/appmesh/app/run", app, { params });
    return new AppRun(this, response.data.name, response.data.process_uuid);
  }

  /**
   * Wait for an async app to complete, optionally streaming incremental output.
   * @param {AppRun} run - AppRun object
   * @param {Function} [stdoutHandler=defaultOutputHandler] - Stdout handler callback(data, position)
   * @param {number} [timeout=0] - Max wait time
   * @returns {Promise<number|null>} Exit code, or `null` only on timeout. On success
   * the SDK also attempts to delete the temporary run app.
   * @throws {AppMeshError} If polling the app output fails.
   */
  async waitForAsyncRun(run, stdoutHandler = defaultOutputHandler, timeout = 0) {
    if (run) {
      let lastOutputPosition = 0;
      const start = new Date();
      const interval = 1;

      while (run.procUid.length > 0) {
        const appOut = await this.getAppOutput(run.appName, lastOutputPosition, 0, 20480, run.procUid, interval);
        if (appOut.output && stdoutHandler) {
          stdoutHandler(appOut.output, lastOutputPosition);
        }

        if (appOut.outPosition !== null) {
          lastOutputPosition = appOut.outPosition;
        }

        if (appOut.exitCode !== null) {
          // Process finished
          await this.deleteApp(run.appName);
          return appOut.exitCode;
        }

        if (timeout > 0 && (new Date() - start) / 1000 > timeout) {
          // Timeout reached
          break;
        }
        // Small delay to prevent tight looping
        await new Promise((resolve) => setTimeout(resolve, 100));
      }
    }
    return null;
  }

  /**
   * Send task to running application
   * @param {string} appName - App name
   * @param {string} data - Task data
   * @param {number} [timeout=300] - Timeout in seconds
   * @returns {Promise<string>} Response from app
   */
  async runTask(appName, data, timeout = 300) {
    if (timeout <= 0) {
      timeout = 300;
    }
    const response = await this._request("post", `/appmesh/app/${appName}/task`, data, {
      params: { timeout: timeout.toString() }
    });
    return response.data;
  }

  /**
   * Cancel running task
   * @param {string} appName - App name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async cancelTask(appName) {
    await this._request("delete", `/appmesh/app/${appName}/task`);
    return true;
  }

  /**
   * Stream an application's stdout incrementally over server-sent events.
   *
   * Replays from `stdoutPosition`, then (with `follow`) yields new output until exit,
   * removal or `timeout`. The server de-duplicates the replay/live boundary.
   *
   * @param {string} appName - Name of the target application
   * @param {Object} [opts={}] - Stream options
   * @param {number} [opts.stdoutPosition=0] - Byte cursor to start from (0 replays from the beginning)
   * @param {string} [opts.processUuid=''] - Pin the stream to one run; empty follows the current run
   * @param {boolean} [opts.follow=true] - `false` replays to the current end of output and stops
   * @param {number} [opts.timeout=3600] - Overall stream lifetime cap in seconds (server-side)
   * @returns {AsyncGenerator<string>} Yields each stdout chunk; the return value (final
   *   `next()` result, `{ done: true, value }`) is the terminal {@link SseEnd} with
   *   `exitCode`/`position` filled on a natural exit
   * @throws {AppMeshRequestError} The stream ended with an error
   */
  async *followOutput(appName, opts = {}) {
    const { stdoutPosition = 0, processUuid = '', follow = true, timeout = 3600 } = opts;
    const params = {
      stdout_position: String(stdoutPosition),
      follow: follow ? "true" : "false",
      timeout: String(timeout)
    };
    if (processUuid) {
      params.process_uuid = processUuid;
    }
    const response = await this._sseRequest("get", `/appmesh/app/${appName}/output/stream`, { params });
    let end = null;
    try {
      for await (const [event, payload] of _iterSseEvents(response.data)) {
        if (event === "stdout") {
          yield String(payload.output ?? "");
        } else if (event === "end") {
          end = _endFromPayload(payload);
          break;
        }
      }
    } catch (error) {
      // Transport-level failure (connection reset) normalizes like _request
      throw this.onError(error);
    } finally {
      response.data?.destroy?.();
    }
    if (end === null) {
      end = new SseEnd("closed");
    }
    _raiseOnErrorEnd(end);
    return end;
  }

  /**
   * Streaming task RPC: send an invocation and yield incremental results as they arrive.
   *
   * The runTask() counterpart for continuous-output services (LLM agents): the worker
   * pushes partial results (`worker.sendTaskPartial`) before its final reply, in order.
   *
   * @param {string} appName - Name of the target application
   * @param {string} data - Payload to deliver to the application (same contract as runTask)
   * @param {Object} [opts={}] - Stream options
   * @param {number} [opts.timeout=300] - Maximum seconds for the whole call; the stream ends
   *   with `SseEnd(reason='timeout')` (raised as AppMeshTimeoutError) when exceeded
   * @returns {AsyncGenerator<string>} Yields each partial; the return value is an {@link SseEnd}
   *   whose `result` carries the final payload (what runTask would return)
   * @throws {AppMeshTimeoutError} The task did not finish within `timeout`
   * @throws {AppMeshRequestError} The stream ended with an error
   */
  async *runTaskStream(appName, data, opts = {}) {
    const { timeout = 300 } = opts;
    const params = timeout && timeout > 0 ? { timeout: String(timeout) } : {};
    const response = await this._sseRequest("post", `/appmesh/app/${appName}/task/stream`, { params, body: data });
    let end = null;
    let finalResult = null;
    try {
      for await (const [event, payload] of _iterSseEvents(response.data)) {
        if (event === "partial") {
          yield String(payload.data ?? "");
        } else if (event === "final") {
          finalResult = payload.result ?? null;
        } else if (event === "end") {
          end = _endFromPayload(payload, { result: finalResult });
          break;
        }
      }
    } catch (error) {
      // Transport-level failure (connection reset) normalizes like _request
      throw this.onError(error);
    } finally {
      response.data?.destroy?.();
    }
    if (end === null) {
      end = new SseEnd("closed", { result: finalResult });
    }
    _raiseOnErrorEnd(end);
    return end;
  }

  /**
   * Run a one-shot application remotely and stream its stdout incrementally.
   *
   * runAppAsync() + followOutput() + deleteApp(): stdout chunks are yielded as produced,
   * unlike the fully-buffered runAppSync() that answers only after completion.
   *
   * @param {Object|string} app - App config, or a shell command string (runs with `shell: true`, daemon-generated name)
   * @param {string|number} [maxTime] - Maximum runtime for the remote process (seconds or ISO 8601 duration)
   * @param {string|number} [lifecycle] - Retention window for the temporary run app (seconds or ISO 8601 duration)
   * @returns {AsyncGenerator<string>} Yields each stdout chunk; the return value is the run's
   *   {@link SseEnd} (`exitCode` on a natural exit). The temporary app is always deleted on exit.
   * @throws {AppMeshRequestError} The stream ended with an error
   */
  async *streamRun(app, maxTime = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS,
    lifecycle = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const appConfig = typeof app === "string" ? { command: app, shell: true } : app;
    const run = await this.runAppAsync(appConfig, maxTime, lifecycle);
    let end;
    try {
      // Delegate to followOutput and re-yield: JS has no `yield from`.
      const stream = this.followOutput(run.appName, {
        processUuid: run.procUid,
        follow: true,
        timeout: Math.max(parseDuration(maxTime), parseDuration(lifecycle))
      });
      let next = await stream.next();
      while (!next.done) {
        yield next.value;
        next = await stream.next();
      }
      end = next.value;
    } finally {
      try {
        await this.deleteApp(run.appName);
      } catch (_) { /* best-effort cleanup of the temporary run app */ }
    }
    return end;
  }

  /**
   * Inject bytes into the stdin of a running application.
   *
   * The app must be registered with `stdin: "pipe"`: the daemon holds the write end
   * open, making the process conversational (REPL) while followOutput() reads its output.
   *
   * @param {string} appName - Name of the target application
   * @param {string|Buffer} data - Bytes (or text, encoded as UTF-8) to write to the process stdin
   * @param {Object} [opts={}] - Write options
   * @param {boolean} [opts.close=false] - Also close the pipe write end so the process reads EOF
   * @param {string} [opts.processUuid=''] - Restrict the write to this run; empty targets the current run
   * @returns {Promise<number>} Number of bytes written
   * @throws {AppMeshError} The stdin pipe buffer is full (retry with the remainder) or the write failed
   */
  async sendInput(appName, data, opts = {}) {
    const { close = false, processUuid = '' } = opts;
    const headers = close ? { "X-Input-Close": "true" } : {};
    const params = processUuid ? { process_uuid: processUuid } : {};
    const response = await this._request("post", `/appmesh/app/${appName}/input`, data, { headers, params });
    return parseInt(response.data?.bytes_written ?? 0, 10);
  }

  /**
   * Download a remote file.
   *
   * Plain-HTTP transport: GET answers the file bytes; the agent proxy serves
   * the same route from local disk.
   *
   * - **Node.js**: `localFile` is a filesystem path — the response body is written to it,
   *   and when `applyAttrs` is true the returned mode and best-effort owner/group metadata
   *   are applied on non-Windows platforms.
   * - **Browser**: `localFile` is only the *suggested download filename* (its basename is
   *   used); no path is honored — the browser's download UI decides where the file goes,
   *   and `applyAttrs` has no effect.
   *
   * @param {string} filePath - Remote file path
   * @param {string} [localFile=null] - Local file path (Node.js) or suggested filename (browser);
   * defaults to the basename of filePath
   * @param {boolean} [applyAttrs=false] - Node.js only: apply returned mode and best-effort
   * owner/group metadata on non-Windows platforms
   */
  async downloadFile(filePath, localFile = null, applyAttrs = false) {
    if (!localFile) localFile = filePath.split(/[\\/]/).pop();
    const headers = { [CONSTANTS.HTTP_HEADER_KEY_X_FILE_PATH]: encodeURIComponent(filePath) };
    // Node streams the body to disk; the browser needs the whole buffer for Blob.
    const response = await this._request("get", "/appmesh/file/download", null, {
      headers,
      config: {
        responseType: ENV.isNode ? "stream" : "arraybuffer"
      }
    });
    // A streamed body cannot be read twice, so error details stay header-level in Node.
    const errDetail = ENV.isNode ? "" : response.data;

    // A JSON reply without Content-Disposition is a legacy placeholder, not content.
    if (response.status === 200 && !response.headers?.["content-disposition"] &&
        String(response.headers?.["content-type"] ?? "").toLowerCase().includes("json")) {
      if (ENV.isNode) response.data.destroy(); // release the unread stream's socket
      throw new AppMeshError(
        `File download is not supported by this server surface: ${filePath}`, response.status, errDetail);
    }

    if (response.status !== 200) {
      throw new AppMeshError(`Failed to download file: ${filePath}`, response.status, errDetail);
    }

    if (ENV.isNode) {
      const fsMod = await import('fs');
      // stream/promises needs Node 15; engines declares 14, so promisify the callback form.
      const { promisify } = await import('util');
      const pipeline = promisify((await import('stream')).pipeline);
      const fs = fsMod.promises;

      try {
        await pipeline(response.data, fsMod.createWriteStream(localFile));

        if (applyAttrs && process.platform !== 'win32') {
          const respHeaders = response.headers; // avoid shadowing outer `headers`
          try {
            const mode = respHeaders["x-file-mode"];
            if (mode) {
              const modeVal = parseInt(mode, 10);
              if (Number.isInteger(modeVal) && modeVal >= 0 && modeVal <= 0o777) {
                await fs.chmod(localFile, modeVal);
              } else {
                console.warn("Warning: Invalid x-file-mode value:", mode);
              }
            }
            // chown: resolve user/group names to uid/gid via id(1) command
            const username = respHeaders["x-file-user"];
            const groupName = respHeaders["x-file-group"];
            if (username && groupName) {
              const uid = await _resolveUid(username);
              const gid = await _resolveGid(groupName);
              if (uid !== null && gid !== null) {
                await fs.chown(localFile, uid, gid);
              }
            }
          } catch (ex) {
            console.warn("Warning: Unable to apply file attributes to", localFile, ex.message);
          }
        }
      } catch (error) {
        throw new AppMeshError(`Failed to write file to ${localFile}: ${error.message}`, response.status);
      }
    } else {
      // Browser download
      const blob = new Blob([response.data]);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.style.display = "none";
      a.href = url;
      a.download = localFile.split("/").pop();
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    }
  }

  /**
   * Upload a file to the remote server.
   *
   * Plain-HTTP transport: POST streams the raw file bytes as the body; the
   * agent proxy accepts the same route.
   *
   * @param {string|File} localFile - Local file path/object
   * @param {string} [filePath=null] - Remote target path; defaults to the basename of localFile
   * @param {boolean} [applyAttrs=false] - In Node.js, send local permission bits plus
   * user/group (names when resolvable locally, numeric ids otherwise)
   */
  async uploadFile(localFile, filePath = null, applyAttrs = false) {
    if (!filePath) {
      // Node.js passes a path string; browser passes a File (use its name)
      const sourceName = typeof localFile === 'string' ? localFile : localFile && localFile.name;
      if (!sourceName) {
        throw new AppMeshError('filePath is required when localFile is a Blob without a name');
      }
      filePath = sourceName.split(/[\\/]/).pop();
    }
    const headers = { [CONSTANTS.HTTP_HEADER_KEY_X_FILE_PATH]: encodeURIComponent(filePath) };
    let body;

    if (ENV.isNode) {
      const fs = await import('fs');
      const stat = fs.statSync(localFile);

      if (applyAttrs) {
        headers["X-File-Mode"] = (stat.mode & 0o777).toString(); // Only permission bits
        const username = await _resolveUserName(stat.uid);
        const groupName = await _resolveGroupName(stat.gid);
        headers["X-File-User"] = username || String(stat.uid);
        headers["X-File-Group"] = groupName || String(stat.gid);
      }

      // Stream larger files; buffer small ones.
      body = stat.size < 10 * 1024 * 1024 ? fs.readFileSync(localFile) : fs.createReadStream(localFile);
    } else {
      // Browser environment
      if (localFile instanceof File || localFile instanceof Blob) {
        body = localFile;
      } else {
        throw new AppMeshError('In browser, localFile must be File or Blob');
      }
    }

    const response = await this._request("post", "/appmesh/file/upload", body, {
      headers,
      config: {
        maxBodyLength: Infinity,
        maxContentLength: Infinity
      }
    });
    if (response.status !== 200 && response.status !== 201) {
      throw new AppMeshError(`Failed to upload file: ${filePath}`, response.status, response.data);
    }
    // A 200 JSON status reply means a legacy daemon stored nothing.
    const contentType = String(response.headers?.["content-type"] ?? "").toLowerCase();
    if (response.status === 200 && contentType.includes("json") &&
        response.data && typeof response.data === "object" && "message" in response.data) {
      throw new AppMeshError(
        `File upload is not supported by this server surface: ${filePath}`, response.status, response.data);
    }
  }

  /**
   * Get host resource usage
   * @returns {Object} Resource stats
   */
  async getHostResources() {
    const response = await this._request("get", "/appmesh/resources");
    return response.data;
  }

  /**
   * Get current configuration
   * @returns {Promise<Object>} Config JSON
   */
  async getConfig() {
    const response = await this._request("get", "/appmesh/config");
    return response.data;
  }

  /**
   * Apply a partial config update and return the merged server config.
   * @param {Object} config - Partial config document to POST to `/appmesh/config`
   * @returns {Object} Updated config
   */
  async setConfig(config) {
    const response = await this._request("post", "/appmesh/config", config);
    return response.data;
  }

  /**
   * Set log level
   * @param {string} [level="DEBUG"] - Log level
   * @returns {string} Updated level
   */
  async setLogLevel(level = "DEBUG") {
    const response = await this.setConfig({ BaseConfig: { LogLevel: level } });
    return response.BaseConfig.LogLevel;
  }

  /**
   * Add label to server
   * @param {string} labelName - Label name
   * @param {string} labelValue - Label value
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async addLabel(labelName, labelValue) {
    await this._request("put", `/appmesh/label/${labelName}`, null, { params: { value: labelValue } });
    return true;
  }


  /**
   * Delete label from server
   * @param {string} labelName - Label name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async deleteLabel(labelName) {
    await this._request("delete", `/appmesh/label/${labelName}`);
    return true;
  }


  /**
   * Get all server labels
   * @returns {Promise<Object>} All labels
   */
  async listLabels() {
    const response = await this._request("get", "/appmesh/labels");
    return response.data;
  }


  /** List Engine authorization overlays keyed by immutable principal ID. */
  async listPrincipals() {
    return (await this._request("get", "/appmesh/principals")).data;
  }

  /** Update an Engine authorization overlay; never mutate IdP account data. */
  async updatePrincipal(principalId, policy) {
    await this._request("post", `/appmesh/principal/${encodeURIComponent(principalId)}`, policy);
    return true;
  }

  /** Delete only an Engine authorization overlay. */
  async deletePrincipal(principalId) {
    await this._request("delete", `/appmesh/principal/${encodeURIComponent(principalId)}`);
    return true;
  }

  /** Safe compatibility alias returning a Principal, not an IdP user. */
  async getCurrentUser() {
    return this.getCurrentPrincipal();
  }

  /**
   * Get available permissions
   * @returns {Object[]} Permission list
   */
  async listPermissions() {
    const response = await this._request("get", "/appmesh/permissions");
    return response.data;
  }

  /** Get effective permissions for the current verified principal. */
  async getPrincipalPermissions() {
    const response = await this._request("get", "/appmesh/principal/self/permissions");
    return response.data;
  }

  /** Safe compatibility alias for getPrincipalPermissions(). */
  async getUserPermissions() {
    return this.getPrincipalPermissions();
  }

  /**
   * Get all roles and permissions
   * @returns {Object[]} Role array
   */
  async listRoles() {
    const response = await this._request("get", "/appmesh/roles");
    return response.data;
  }

  /**
   * Update or add role
   * @param {string} roleName - Role name
   * @param {Object} rolePermissionJson - Permission IDs
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async updateRole(roleName, rolePermissionJson) {
    await this._request("post", `/appmesh/role/${roleName}`, rolePermissionJson);
    return true;
  }

  /**
   * Delete role
   * @param {string} roleName - Role name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async deleteRole(roleName) {
    await this._request("delete", `/appmesh/role/${roleName}`);
    return true;
  }

  /**
   * Get raw Prometheus metrics text from the server.
   * @returns {Promise<string>} Metrics text
   */
  async getMetrics() {
    const response = await this._request("get", "/appmesh/metrics", null, {
      config: { responseType: "text" }
    });
    return response.data;
  }

  /**
   * Event subscription is only available over the TCP transport.
   * @throws {AppMeshError} Always — use AppMeshClientTCP for event subscriptions.
   */
  async subscribe() {
    throw new AppMeshError("subscribe requires the TCP client (AppMeshClientTCP, imported from 'appmesh/tcp'); " +
      "the HTTP client does not support event subscriptions");
  }

  /**
   * Event subscription is only available over the TCP transport.
   * @throws {AppMeshError} Always — use AppMeshClientTCP for event subscriptions.
   */
  async unsubscribe() {
    throw new AppMeshError("unsubscribe requires the TCP client (AppMeshClientTCP, imported from 'appmesh/tcp'); " +
      "the HTTP client does not support event subscriptions");
  }

  /**
   * Perform a raw App Mesh REST request using this client's transport, auth and error handling.
   * Stable seam for worker-role wrappers (AppMeshWorker) and advanced callers.
   * @param {string} method - HTTP method (get, post, put, delete, ...)
   * @param {string} path - Endpoint path (e.g. "/appmesh/applications")
   * @param {Object|string|Buffer} [body=null] - Request payload
   * @param {Object} [options={}] - Request options: { headers, params, config }
   * @returns {Promise<any>} Response object ({ status, headers, data, ... })
   * @throws {AppMeshError} If the request fails (non-2xx)
   */
  async request(method, path, body = null, options = {}) {
    return this._request(method, path, body, options);
  }

  /**
   * Generate common request headers
   * @private
   * @returns {Promise<Object>} Headers object
   */
  async _commonHeaders() {
    const headers = {};
    // Add user agent in Node.js
    if (ENV.isNode) {
      headers[CONSTANTS.HTTP_USER_AGENT_HEADER_NAME] = CONSTANTS.HTTP_USER_AGENT;
    }

    const token = await this._getAccessToken();
    if (token) {
      headers[CONSTANTS.HTTP_HEADER_KEY_AUTH] = `Bearer ${token}`;
    }

    // Forwarding host, sent as given: a bare host is resolved to the server's own
    // service port; the client-side port may be a host-side mapping absent on the target.
    if (this.forwardingHost) {
      headers[CONSTANTS.HTTP_HEADER_KEY_X_TARGET_HOST] = this.forwardingHost;
    }
    return headers;
  }

  /**
   * Wrapper function to handle HTTP requests and error checking.
   * @async
   * @private
   * @param {string} method - The HTTP method (get, post, put, delete, etc.)
   * @param {string} path - The endpoint URL
   * @param {Object} [body=null] - The request payload (for POST, PUT, PATCH)
   * @param {Object} [options={}] - Additional options for the request
   * @returns {Promise<any>} The http response object
   * @throws {AppMeshError} If the request fails
   */
  async _request(method, path, body = null, options = {}) {
    // Ensure HTTPS agent is ready (first-call lazy setup for Node.js ESM)
    await this._ensureHttpsAgent();

    const { headers = {}, params = {}, config = {} } = options;

    try {
      const requestConfig = {
        method,
        url: path,
        withCredentials: false,
        ...config,
        headers: { ...headers },
        params: { ...params }
      };

      if (body !== null) {
        requestConfig.data = body;
      }

      // Opt-in request signature: attach the four headers to this exact request.
      if (this._requestSigner) {
        await this._applyRequestSignature(requestConfig);
      }

      const response = await this._client(requestConfig);
      if (response.status < 200 || response.status >= 300) {
        const errMsg = this._extractErrorMessage(response.data);
        throw new AppMeshError(errMsg, response.status, response.data);
      }

      return response;
    } catch (error) {
      throw this.onError(error);
    }
  }

  /**
   * Lazily install the shared https.Agent on the axios instance (Node.js ESM first-use setup).
   * @private
   */
  async _ensureHttpsAgent() {
    if (ENV.isNode && _httpsReady && !this._client.defaults.httpsAgent) {
      await _httpsReady;
      if (_https) {
        this._client.defaults.httpsAgent = new _https.Agent({
          ..._resolveSslOptions(this._sslConfig),
          keepAlive: true,
          keepAliveMsecs: 3000
        });
      }
    }
  }

  /**
   * Open a server-sent-events stream as a streamed response. Plain HTTP by design: SSE
   * frames cannot ride a framed (TCP/WSS) transport, so framed subclasses redirect this
   * hook to direct HTTPS (the WSS file data side-channel shape).
   *
   * @private
   * @param {string} method - HTTP method ('get' or 'post')
   * @param {string} path - Endpoint path
   * @param {Object} [options={}] - `{ params, headers, body }`
   * @returns {Promise<Object>} Axios response with a streamed `data` body
   * @throws {AppMeshError} Non-200 statuses, like `_request`
   */
  async _sseRequest(method, path, options = {}) {
    await this._ensureHttpsAgent();
    const { params = {}, headers = {}, body } = options;
    const requestConfig = {
      method,
      url: path,
      withCredentials: false,
      responseType: "stream",
      // Own server-side lifetime and 15s heartbeats: axios's 5-minute default would cut long follows short.
      timeout: 0,
      headers: { ...headers },
      params: { ...params }
    };
    if (body !== undefined && body !== null) {
      requestConfig.data = body;
    }
    if (this._requestSigner) {
      await this._applyRequestSignature(requestConfig);
    }

    let response;
    try {
      response = await this._client(requestConfig);
    } catch (error) {
      throw this.onError(error);
    }
    if (response.status !== 200) {
      // The error reply is short; collect it for the message.
      let detail = "";
      try {
        const chunks = [];
        for await (const chunk of response.data) chunks.push(chunk);
        detail = Buffer.concat(chunks).toString("utf8");
      } catch (_) { /* socket already gone — raise a status-only error */ }
      const message = detail
        ? this._extractErrorMessage(detail)
        : `SSE request failed with status ${response.status}`;
      throw new AppMeshError(message, response.status, detail || null);
    }
    return response;
  }

  /**
   * Extract user-friendly error message from response data
   * @private
   * @param {any} data - Response data
   * @returns {string|null} Error message or null
   */
  _extractErrorMessage(responseData) {
    if (!responseData) {
      return "Unknown error";
    }

    if (responseData instanceof ArrayBuffer) {
      try {
        const textDecoder = new TextDecoder("utf-8");
        const text = textDecoder.decode(responseData);
        try {
          const parsedJson = JSON.parse(text);
          return parsedJson.message || parsedJson.error || "Binary response error";
        } catch (e) {
          return text; // not json, return raw text
        }
      } catch (e) {
        return 'Binary response error (could not decode)';
      }
    }

    if (typeof responseData === 'string') {
      try {
        const parsedJson = JSON.parse(responseData);
        return parsedJson.message || parsedJson.error || responseData;
      } catch (e) {
        return responseData;
      }
    }

    if (typeof responseData === 'object') {
      return responseData.message || responseData.error || JSON.stringify(responseData);
    }

    return String(responseData);
  }

  /**
   * Comprehensive error handler for all client errors.
   * The default implementation only normalizes the error type; override this
   * method to add logging or user-facing reporting.
   * @protected
   * @param {Error} error - The caught error
   * @returns {AppMeshError} Standardized AppMeshError
   */
  onError(error) {
    return error instanceof AppMeshError ? error : new AppMeshError(error.message || 'Unknown error');
  }
}

/**
 * Class representing output from an AppMesh application
 * Immutable after creation
 */
class AppOutput {
  /**
   * @param {number} status - HTTP status
   * @param {string} output - Content
   * @param {number} position - Read position
   * @param {number} exitCode - Exit code
   */
  constructor(status, output, position, exitCode) {
    this.statusCode = Number(status);
    this.output = String(output);
    this.outPosition = position !== null ? Number(position) : null;
    this.exitCode = exitCode !== null ? Number(exitCode) : null;
  }
}

/**
 * Class representing a running AppMesh application
 * Handles async operation results
 */
class AppRun {
  /**
   * Application run object indicating a remote run from runAsync()
   * @param {AppMeshClient} client - AppMeshClient object
   * @param {string} appName - Application name
   * @param {string} processId - Process UUID from runAsync()
   */
  constructor(client, appName, processId) {
    /** @type {string} Application name */
    this.appName = appName;

    /** @type {string} Process UUID from runAsync() */
    this.procUid = processId;

    /** @type {AppMeshClient} AppMeshClient object */
    this._client = client;

    /** @type {string} Delegate host indicates the target server for this app run */
    this._forwardingHost = client.forwardingHost;
  }

  /**
   * Context manager for forward host override to self._client.
   * Note: this temporarily mutates the shared client's forwardingHost for the duration of the
   * callback — do not run concurrent requests on the same client that rely on a different
   * forwarding host.
   * @param {function} callback - Function to execute within the forward host context
   * @returns {Promise<*>} Result of the callback function
   */
  async withForwardingHost(callback) {
    const originalValue = this._client.forwardingHost;
    this._client.forwardingHost = this._forwardingHost;
    try {
      return await callback();
    } finally {
      this._client.forwardingHost = originalValue;
    }
  }

  /**
   * Wait for an async run to finish while restoring the saved forwarding host.
   * @param {function} [stdoutHandler=defaultOutputHandler] - Stdout handler callback(data, position)
   * @param {number} [timeout=0] - Wait max timeout seconds and return if not finished, 0 means wait until finished
   * @returns {Promise<number|null>} Return exit code if process finished, return null for timeout or exception
   */
  async wait(stdoutHandler = defaultOutputHandler, timeout = 0) {
    return this.withForwardingHost(() =>
      this._client.waitForAsyncRun(this, stdoutHandler, timeout)
    );
  }
}

// Export the main classes
export {
  AppMeshClient, AppOutput, AppRun, AppMeshError, AppRemovedError, TransportDisconnectedError,
  AppMeshRequestError, AppMeshTimeoutError, SseEnd,
  DEFAULT_CA_FILE, StaticAccessTokenProvider, RefreshTokenProvider, RequestSigner
};
// Exported for the TCP client (Node.js only); not part of the browser-facing API
export { _resolveUid, _resolveGid, _resolveUserName, _resolveGroupName };
export default AppMeshClient;

