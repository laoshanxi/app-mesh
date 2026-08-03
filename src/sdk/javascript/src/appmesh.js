// appmesh.js
import axios from 'axios';

// Lazy-resolved Node.js https/fs modules (null in browser)
let _https = null;
let _fs = null;
let _httpsReady = null; // Promise that resolves when https/fs are loaded

// Constants using Object.freeze to prevent modifications
const CONSTANTS = Object.freeze({
  HTTP_USER_AGENT_HEADER_NAME: "User-Agent",
  HTTP_USER_AGENT: "appmesh/javascript",
  HTTP_STATUS_PRECONDITION_REQUIRED: 428,
  DEFAULT_TOKEN_EXPIRE_SECONDS: "P1W",
  DEFAULT_RUN_APP_TIMEOUT_SECONDS: "P2D",
  DEFAULT_RUN_APP_LIFECYCLE_SECONDS: "P2DT12H",
  DEFAULT_JWT_AUDIENCE: "appmesh-service",
  HTTP_HEADER_KEY_AUTH: "Authorization",
  HTTP_HEADER_KEY_X_TARGET_HOST: "X-Target-Host",
  HTTP_HEADER_KEY_X_FILE_PATH: "X-File-Path",

  // Auto-refresh pacing: the loop wakes every TOKEN_REFRESH_POLL_SECONDS but renews only
  // once the token has burned TOKEN_REFRESH_LIFETIME_RATIO of its own lifetime.
  TOKEN_REFRESH_POLL_SECONDS: 300,   // poll cap, NOT a renew interval
  TOKEN_REFRESH_OFFSET_SECONDS: 30,  // floor for the pre-expiry margin
  TOKEN_REFRESH_LIFETIME_RATIO: 0.6, // rest is the retry budget
  TOKEN_REFRESH_JITTER_RATIO: 0.1,   // of the margin, so clients don't renew in lockstep
  TOKEN_REFRESH_RETRY_BASE_SECONDS: 5,
  TOKEN_REFRESH_RETRY_MAX_SECONDS: 60,
  TOKEN_REFRESH_LOG_EVERY: 10,       // log the 1st failure, then every Nth
});

// Environment detection
const ENV = Object.freeze({
  isNode: !(typeof window !== 'undefined' && typeof window.document !== 'undefined')
});

// Base64 utilities for Node.js and browser
const base64Utils = ENV.isNode ? {
  encode: str => Buffer.from(str).toString('base64'),
  decode: str => Buffer.from(str, 'base64').toString()
} : {
  encode: str => btoa(str),
  decode: str => atob(str)
};

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
 * Error thrown when the server requires a TOTP code to complete login (HTTP 428).
 *
 * Subclasses AppMeshError with `statusCode` fixed to 428, so existing catch-based
 * callers keep working. Carries the server-issued challenge as `totpChallenge`,
 * ready to pass to `validate_totp(username, totpChallenge, totpCode)`.
 */
class TotpRequiredError extends AppMeshError {
  /**
   * @param {string} message - Error message
   * @param {any} responseData - Raw 428 response body (object or JSON string containing `totp_challenge`)
   */
  constructor(message, responseData = null) {
    super(message, 428, responseData, 'TOTP_REQUIRED');
    this.name = 'TotpRequiredError';
    let data = responseData;
    if (typeof data === 'string') {
      try { data = JSON.parse(data); } catch (_) { data = null; }
    }
    /** @type {string|null} Server-issued TOTP challenge for validate_totp() */
    this.totpChallenge = (data && typeof data === 'object' && typeof data.totp_challenge === 'string')
      ? data.totp_challenge
      : null;
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
  const objMap = [
    "years", "months", "weeks", "days", "hours", "minutes", "seconds",
  ];

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
  try {
    const { spawnSync } = await import('child_process');
    // getent group <name> returns "name:x:gid:members"
    const result = spawnSync('getent', ['group', group], { encoding: 'utf8', timeout: 3000 });
    if (result.status !== 0 || !result.stdout) return null;
    const parts = result.stdout.trim().split(':');
    return parts.length >= 3 ? parseInt(parts[2], 10) : null;
  } catch (_) {
    return null;
  }
}

/**
 * Decode the `exp` and `iat` claims from a JWT without signature verification.
 * @param {string} token - JWT string (header.payload.signature)
 * @returns {{exp: number, iat: number}|null} Claims (`iat` is 0 when absent), or null when
 *   the token is not a decodable JWT carrying `exp`
 * @private
 */
function _decodeJwtTimes(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(base64Utils.decode(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    if (typeof payload.exp !== 'number') return null;
    return { exp: payload.exp, iat: typeof payload.iat === 'number' ? payload.iat : 0 };
  } catch (_) {
    return null;
  }
}

/**
 * FNV-1a 32-bit hash, matching the Go SDK so both derive the same jitter from a token.
 * @param {string} str - Input string (JWTs are ASCII, so code units are bytes)
 * @returns {number} Unsigned 32-bit hash
 * @private
 */
function _fnv1a32(str) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return hash >>> 0;
}

// Default App Mesh CA bundle, preferred when no sslConfig is given and the file exists
const DEFAULT_CA_FILE = '/opt/appmesh/ssl/ca.pem';

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
   * @param {boolean|null} [useRefreshToken=null] - See {@link AppMeshClient#set_use_refresh_token}.
   * @example
   * const sslConfig = {
   *   cert: fs.readFileSync("client.pem"),
   *   key: fs.readFileSync("client-key.pem"),
   *   ca: fs.readFileSync("ca.pem"),
   *   rejectUnauthorized: true
   * };
   */
  constructor(baseURL = ENV.isNode ? 'https://127.0.0.1:6060' : window.location.origin, sslConfig = null, useRefreshToken = null) {
    // Base URL for API requests
    this.baseURL = baseURL;

    // Host to forward requests to
    this.forwardingHost = null;

    // Current JWT token known to this client (single token store; transports
    // sync from it via _handleTokenUpdate/_getAccessToken)
    this._token = null;

    // Refresh token from the login/totp-validate/renew response body; issued by both
    // Keycloak and local-JWT daemons, absent against an older daemon that returns none.
    this._refreshToken = null;

    // Expire seconds from login, replayed on renew so the caller's TTL is kept.
    this._tokenExpireSeconds = null;

    // {exp, iat} as reported by the daemon in the login/renew body. The only lifetime
    // source available in a browser, where the auth cookie is HttpOnly and unreadable.
    this._tokenTimes = null;

    // Per-client jitter seed, used only when no token is readable: the session times
    // alone are identical for every client that logs in during the same second.
    this._jitterSeed = Math.random().toString(36).slice(2);

    // Bumped by logout() so a response from a superseded session cannot revive it.
    this._sessionEpoch = 0;

    // Auto-refresh state: pending timer, consecutive renewal failures (drives the
    // backoff), and the tail of the renewal queue that serializes renew_token().
    this._autoRefreshEnabled = false;
    this._autoRefreshJwt = null;
    // Tri-state opt-in for being ISSUED a refresh token; null follows auto-refresh.
    this._useRefreshToken = useRefreshToken;
    this._refreshTimer = null;
    this._refreshFailures = 0;
    this._renewChain = null;

    // Configure axios instance
    const axiosConfig = {
      baseURL,
      timeout: 300000, // 5 minutes
      validateStatus: status => true
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
      config => {
        // Apply common headers
        config.headers = { ...config.headers, ...this._commonHeaders() };
        return config;
      },
      error => {
        // Handle request setup errors
        const err = new AppMeshError('Request configuration error: ' + (error.message || 'Unknown error'))
        return Promise.reject(err);
      }
    );

    // Response interceptor
    this._client.interceptors.response.use(
      response => response,
      error => {
        // Network-level failure (DNS, connection refused, timeout, ...)
        const err = new AppMeshError('Request failed: ' + (error.message || 'Unknown error'), error.response?.status ?? null, error.response?.data ?? null);
        err.cause = error;
        return Promise.reject(err);
      }
    );
  }

  /**
   * Login with username/password and let the server attach the session token cookie.
   * @param {string} username
   * @param {string} password
   * @param {string} [totpCode] - TOTP code if 2FA is enabled
   * @param {string|number} [tokenExpire] - Token expiry (integer seconds or ISO 8601 string)
   * @param {string} [audience] - JWT audience
   * @returns {Promise<void>} Resolves when login succeeds.
   * @throws {TotpRequiredError} When the server requires TOTP (HTTP 428) and no valid code was
   * supplied. Catch it, read `error.totpChallenge`, then complete the login with
   * `validate_totp(username, error.totpChallenge, totpCode)`:
   * @example
   * try {
   *   await client.login(user, pass);
   * } catch (err) {
   *   if (err instanceof TotpRequiredError) {
   *     await client.validate_totp(user, err.totpChallenge, totpCode);
   *   } else {
   *     throw err;
   *   }
   * }
   */
  async login(username, password, totpCode = null, tokenExpire = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS, audience = CONSTANTS.DEFAULT_JWT_AUDIENCE) {
    // Validate inputs
    if (!username || !password) {
      throw new AppMeshError('Username and password are required', 400, null, 'INVALID_CREDENTIALS');
    }

    const auth = base64Utils.encode(`${username}:${password}`);
    const headers = {
      [CONSTANTS.HTTP_HEADER_KEY_AUTH]: `Basic ${auth}`,
      "X-Set-Cookie": "true"
    };
    // Omitted, not "false", when declined: the daemon only issues on an explicit opt-in.
    if (this._wantRefreshToken()) headers["X-Refresh-Token-Request"] = "true";
    if (totpCode) headers["X-Totp-Code"] = totpCode;
    if (tokenExpire) headers["X-Expire-Seconds"] = parseDuration(tokenExpire);
    if (audience) headers["X-Audience"] = audience;

    const response = await this._request("post", "/appmesh/login", null, { headers });
    this._captureRefreshToken(response);
    this._tokenExpireSeconds = tokenExpire ? parseDuration(tokenExpire) : null;
  }

  /**
   * Verify an external JWT token and optionally update this client session.
   *
   * @param {string} token - JWT token to verify
   * @param {string} [permission=null] - Permission to check
   * @param {string} [audience] - JWT audience
   * @param {boolean} [updateSession=true] - When true, updates this client session with the
   *   verified token and persists local auth state on success. When false, the token is only
   *   verified and local state is unchanged.
   * @returns {Promise<{success: boolean, responseText: string}>} Verification result (success is always true).
   * @throws {AppMeshError} If verification fails (invalid token, permission or audience mismatch, network error).
   */
  async authenticate(token, permission = null, audience = CONSTANTS.DEFAULT_JWT_AUDIENCE, updateSession = true) {
    const headers = { Authorization: `Bearer ${token}` };
    if (permission) headers["X-Permission"] = permission;
    if (audience) headers["X-Audience"] = audience;
    if (updateSession) headers["X-Set-Cookie"] = "true";
    const response = await this._request("post", "/appmesh/auth", null, { headers });
    if (updateSession) {
      // /appmesh/auth returns the same body as login. In a browser this is the only way to
      // learn the lifetime — set_token() cannot replace an HttpOnly cookie — so without it
      // auto-refresh would idle at the poll interval until the session silently died.
      this._captureRefreshToken(response);
    }
    const responseText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    return { success: true, responseText };
  }

  /**
   * Set a JWT token directly without server-side verification.
   * Use when the token is already known to be valid.
   * For server-side verification, use authenticate() instead.
   * @param {string} token - A valid JWT token string. In Node.js this updates the outgoing Cookie
   * header; in browsers it cannot replace the HttpOnly auth cookie.
   */
  set_token(token) {
    if (ENV.isNode) {
      this._handleTokenUpdate(token);
    } else {
      // Browser: auth token is HttpOnly (set by server via Set-Cookie),
      // document.cookie cannot access or override HttpOnly cookies.
      // Use authenticate() for browser-based token verification instead.
      console.warn('set_token() is not supported in browser mode (auth cookie is HttpOnly). Use authenticate() instead.');
    }
  }

  /**
   * Get the current access token known to this client.
   * @returns {string|null} Current JWT token or null
   * @protected
   */
  _getAccessToken() {
    return this._token || null;
  }

  /**
   * Store a new access token and propagate it to the transport layer.
   * Called after login/renew/authenticate responses and by set_token().
   * Base implementation keeps the token in memory, syncs the Node.js outgoing
   * Cookie header, and reschedules auto-refresh when enabled.
   * Subclasses using other transports (e.g. TCP) override this to sync their own store.
   * @param {string|null} token - New JWT token (falsy clears the in-memory token)
   * @protected
   */
  _handleTokenUpdate(token) {
    const COOKIE_NAME = 'appmesh_auth_token';
    this._token = token || null;
    if (ENV.isNode && this._token) {
      const existingCookies = this._client.defaults.headers.Cookie || '';
      const cookies = existingCookies.split('; ').filter(c =>
        c && !c.startsWith(COOKIE_NAME + '=')
      );
      cookies.push(`${COOKIE_NAME}=${this._token}`);
      this._client.defaults.headers.Cookie = cookies.join('; ');
    }
    this._autoRefreshJwt = this._token;
    if (this._autoRefreshEnabled) {
      this._scheduleTokenRefresh();
    }
  }

  /**
   * Store the refresh token carried by a login/totp-validate/renew response body.
   * Both modes rotate it on renew, so a present value replaces the stored one and an
   * absent value keeps it.
   * @param {Object} response - Response object from _request
   * @private
   */
  _captureRefreshToken(response, epoch = this._sessionEpoch) {
    if (epoch !== this._sessionEpoch) return; // superseded by a logout
    let data = response && response.data;
    if (typeof data === 'string') {
      try { data = JSON.parse(data); } catch (_) { return; }
    }
    if (!data) return;
    if (typeof data.refresh_token === 'string' && data.refresh_token) {
      this._refreshToken = data.refresh_token;
    }
    // The daemon reports the lifetime in the response body, which stays readable even when
    // the token itself is an HttpOnly cookie. That is what lets a browser pace itself off
    // the real lifetime instead of falling back to a fixed cadence.
    if (Number.isFinite(data.expire_time) && Number.isFinite(data.issued_at)) {
      this._tokenTimes = { exp: data.expire_time, iat: data.issued_at };
    }
  }

  /**
   * Logout from the current session.
   */
  async logout() {
    try {
      // OAuth2 (Keycloak) proxy mode: present the refresh token so the daemon can end the
      // upstream session. Optional — logoff still succeeds (local revoke) without it.
      const headers = this._refreshToken ? { "X-Refresh-Token": this._refreshToken } : {};
      await this._request("post", "/appmesh/self/logoff", null, { headers });
    } catch (error) {
      console.error("Failed to logoff:", error.message);
    } finally {
      // Clean up keepAlive connections
      if (ENV.isNode && this._client.defaults.httpsAgent) {
        this._client.defaults.httpsAgent.destroy();
      }

      this._stopAutoRefresh();
      // Supersede any renewal already in flight: its response would otherwise land after
      // this block and re-populate the token, the refresh token and the times — leaving a
      // logged-out client holding a credential pair the daemon minted after logoff.
      this._sessionEpoch++;
      this._token = null;
      this._refreshToken = null;
      this._tokenTimes = null;

      // Clear the outgoing auth cookie (Node); the browser's HttpOnly auth cookie is cleared
      // server-side on logoff.
      if (ENV.isNode) {
        this._client.defaults.headers.Cookie = null;
      }
    }
  }

  /**
   * Enable or disable background token auto-refresh.
   * @param {boolean} enable - true to start, false to stop
   * @param {string} [jwtToken] - Optional token used only to calculate the first refresh delay
   */
  set_auto_refresh_token(enable, jwtToken = null) {
    this._stopAutoRefresh();
    this._autoRefreshEnabled = enable;
    if (enable) {
      this._autoRefreshJwt = jwtToken || this._getAccessToken() || null;
      this._scheduleTokenRefresh();
    }
  }

  /**
   * Choose whether login/totp-validate/renew ask the daemon to issue a refresh token.
   *
   * A refresh token is long-lived, so a one-shot script would leak one per run.
   *
   * @param {boolean|null} [value=null] - `null` follows auto-refresh; `true`/`false` force it.
   *   In a browser the default is `false`: the auth cookie is HttpOnly to keep XSS away from
   *   the credential, and pacing/renewal work without it.
   */
  set_use_refresh_token(value = null) {
    this._useRefreshToken = value;
  }

  /**
   * Resolve the refresh-token tri-state for the outgoing request.
   * @returns {boolean} true to send the opt-in header; false to omit it entirely
   * @private
   */
  _wantRefreshToken() {
    if (typeof this._useRefreshToken === 'boolean') return this._useRefreshToken;
    return ENV.isNode && this._autoRefreshEnabled;
  }

  /** @private */
  _stopAutoRefresh() {
    this._autoRefreshEnabled = false;
    this._refreshFailures = 0;
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }
  }

  /**
   * Seconds before expiry at which to renew: a fraction of the token's own lifetime,
   * floored at TOKEN_REFRESH_OFFSET_SECONDS.
   * @param {string} token - JWT the margin is derived from (also seeds the jitter)
   * @param {number} exp - Expiry claim, epoch seconds
   * @param {number} iat - Issued-at claim, epoch seconds; 0 when absent
   * @returns {number} Margin in seconds
   * @private
   */
  static _refreshMargin(token, exp, iat) {
    const lifetime = (iat > 0 && exp > iat) ? exp - iat : exp - Date.now() / 1000;
    let margin = Math.max(lifetime * (1 - CONSTANTS.TOKEN_REFRESH_LIFETIME_RATIO), CONSTANTS.TOKEN_REFRESH_OFFSET_SECONDS);

    // Jitter derived from the token: stable across polls, distinct per client.
    const spread = margin * CONSTANTS.TOKEN_REFRESH_JITTER_RATIO;
    margin += ((_fnv1a32(token) % 2001) / 1000 - 1) * spread;

    // Clamp last: the 30s floor (and its jitter) must never exceed the token's own life,
    // or every renewal would land past the refresh point and the loop would spin at ~1Hz.
    return lifetime > 0 ? Math.min(margin, lifetime / 2) : margin;
  }

  /**
   * Bounded exponential backoff for the nth consecutive renewal failure (n >= 1).
   * @param {number} failures - Consecutive failure count
   * @returns {number} Delay in seconds
   * @private
   */
  static _refreshRetryDelay(failures) {
    const shift = Math.min(Math.max(failures - 1, 0), 16);
    return Math.min(CONSTANTS.TOKEN_REFRESH_RETRY_BASE_SECONDS * Math.pow(2, shift), CONSTANTS.TOKEN_REFRESH_RETRY_MAX_SECONDS);
  }

  /**
   * Decide how long to sleep and whether a renewal is due when that sleep ends.
   * The sleep is capped at the poll interval so a token replaced elsewhere is noticed;
   * waking early is not by itself a reason to renew.
   * @returns {{delaySec: number, due: boolean}}
   * @private
   */
  _computeRefreshPlan() {
    const poll = CONSTANTS.TOKEN_REFRESH_POLL_SECONDS;

    const token = this._autoRefreshJwt || this._getAccessToken();
    const tokenTimes = token ? _decodeJwtTimes(token) : null;

    // In a browser the auth cookie is HttpOnly, so the token is never readable here. Pace
    // off the lifetime the daemon reported in the login/renew body instead — same 60% rule
    // as every other SDK, rather than the fixed cadence this change exists to remove.
    //
    // Prefer whichever source expires later. _autoRefreshJwt is set once by
    // set_auto_refresh_token and never updated in a browser (_handleTokenUpdate is
    // Node-only), so a frozen copy would otherwise shadow the times every renewal
    // refreshes — and once it aged past its refresh point the loop would renew once per
    // second forever, which is far worse than the cadence this replaced.
    const times = this._tokenTimes && (!tokenTimes || this._tokenTimes.exp > tokenTimes.exp)
      ? this._tokenTimes
      : tokenTimes;

    if (!token && !times) {
      // A held refresh token can still mint a new access token, so an access token lost
      // to an expired cookie is recoverable — but only if we actually try.
      if (this._refreshToken) return { delaySec: 1, due: true };
      return { delaySec: poll, due: false }; // nothing to renew, just idle
    }
    if (!times) return { delaySec: poll, due: true }; // unreadable lifetime: fixed cadence

    const nowSec = Date.now() / 1000;
    // Times saying the session is already dead cannot be acted on once per second: a
    // successful renewal would have replaced them, so they are stale rather than urgent.
    // Fall back to the fixed cadence, which bounds the worst case at the poll interval.
    if (times.exp <= nowSec) return { delaySec: poll, due: true };

    // Jitter needs a per-client seed; without a readable token the session times alone
    // would collide for every client that logged in during the same second, so mix in
    // this client's own random seed.
    const seed = token || `${this._jitterSeed}.${times.iat}.${times.exp}`;
    const wait = times.exp - AppMeshClient._refreshMargin(seed, times.exp, times.iat) - nowSec;
    if (wait <= 0) return { delaySec: 1, due: true };  // at or past the refresh point
    if (wait > poll) return { delaySec: poll, due: false }; // not due; wake only to re-evaluate
    return { delaySec: wait, due: true };
  }

  /** @private */
  _scheduleTokenRefresh() {
    if (!this._autoRefreshEnabled) return;

    // Replace any pending timer so re-scheduling (e.g. from _handleTokenUpdate) never stacks timers
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }

    let { delaySec, due } = this._computeRefreshPlan();
    if (this._refreshFailures > 0) {
      // Retry on the backoff schedule, not the stale plan.
      delaySec = AppMeshClient._refreshRetryDelay(this._refreshFailures);
      due = true;
    }

    this._refreshTimer = setTimeout(async () => {
      this._refreshTimer = null;
      if (!this._autoRefreshEnabled) return;
      if (due) {
        try {
          // _request captures the renewed token cookie and routes it through
          // _handleTokenUpdate, which updates _autoRefreshJwt for precise delays
          await this.renew_token();
          if (this._refreshFailures > 0) {
            console.info(`Auto-refresh: token renewal recovered after ${this._refreshFailures} failure(s)`);
          }
          this._refreshFailures = 0;
        } catch (err) {
          this._refreshFailures++;
          // Log sparsely: a daemon outage must not flood at the backoff rate.
          if (this._refreshFailures === 1 || this._refreshFailures % CONSTANTS.TOKEN_REFRESH_LOG_EVERY === 0) {
            console.warn(`Auto-refresh: token renewal failed (attempt ${this._refreshFailures}):`, err.message);
          }
        }
      }
      this._scheduleTokenRefresh(); // keep the loop armed, failure or not
    }, delaySec * 1000);

    // Don't block Node.js process exit
    if (this._refreshTimer.unref) {
      this._refreshTimer.unref();
    }
  }

  /**
   * Renew the current JWT token.
   *
   * A held refresh token is the sole credential the daemon needs, so renewal succeeds even
   * after the access token expired — that is how a missed refresh window recovers without a
   * re-login. Without one, the daemon authenticates the access token instead.
   *
   * @param {string|number} [tokenExpire] - Token expiry (integer seconds or ISO 8601 string).
   *   Defaults to the value used at login; the header is omitted when that is unknown, so the
   *   daemon applies its own default rather than silently extending a short-lived token.
   */
  async renew_token(tokenExpire = null) {
    // Serialize renewals: rotation makes a refresh token single-use, so two concurrent
    // renewals present the same one and the loser is told it is revoked — permanently
    // wedging a client that holds no other credential. (See also the AppMeshWorker
    // constructor docs on sharing one client instead of running two renew loops.)
    const run = (this._renewChain || Promise.resolve()).then(() => this._renewTokenOnce(tokenExpire));
    this._renewChain = run.catch(() => { /* a failed renewal must not break the queue */ });
    return run;
  }

  /** @private */
  async _renewTokenOnce(tokenExpire) {
    const expire = (tokenExpire === null || tokenExpire === undefined) ? this._tokenExpireSeconds : tokenExpire;
    const headers = {};
    if (this._wantRefreshToken()) headers["X-Refresh-Token-Request"] = "true";
    if (expire !== null && expire !== undefined) {
      headers["X-Expire-Seconds"] = parseDuration(expire);
    }
    if (this._refreshToken) {
      headers["X-Refresh-Token"] = this._refreshToken;
    }

    let response;
    try {
      response = await this._request("post", "/appmesh/token/renew", null, { headers });
    } catch (error) {
      // A rejected refresh token will never be accepted again (rotated away, revoked, or the
      // session ended). Drop it so the next attempt presents the access token instead.
      if (error && error.statusCode === 401) this._refreshToken = null;
      throw error;
    }
    // Both modes rotate the refresh token on renew — store the new one for the next cycle.
    this._captureRefreshToken(response);
  }

  /**
   * Get the decoded OTP provisioning URI for the current user.
   * @returns {Promise<string>} Decoded `otpauth://...` URI, not just the raw secret field
   */
  async get_totp_uri() {
    const response = await this._request("post", "/appmesh/totp/secret");
    return base64Utils.decode(response.data["mfa_uri"]);
  }

  /**
   * Setup 2FA with a verification code and update the current session token cookie.
   * @param {string} totpCode - TOTP verification code
   */
  async enable_totp(totpCode) {
    const headers = { "X-Totp-Code": totpCode };
    await this._request("post", "/appmesh/totp/setup", null, { headers });
  }

  /**
   * Validate a TOTP login challenge and update the current session token cookie.
   * @param {string} username - Username
   * @param {string} totpChallenge - Server challenge
   * @param {string} totpCode - TOTP code
   * @param {string|number} [tokenExpire] - Token expiry in seconds or ISO8601 duration (e.g. "P1DT12H", 604800)
   */
  async validate_totp(username, totpChallenge, totpCode, tokenExpire = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const body = {
      "user_name": username,
      "totp_code": totpCode,
      "totp_challenge": totpChallenge,
      "expire_seconds": parseDuration(tokenExpire)
    };
    // Set cookie header for browser
    const headers = { "X-Set-Cookie": "true" };
    if (this._wantRefreshToken()) headers["X-Refresh-Token-Request"] = "true";

    const response = await this._request("post", "/appmesh/totp/validate", body, { headers });
    // A validated challenge completes the login, so it owes the same session setup as
    // login(); auto-refresh itself is (re)armed by _handleTokenUpdate when the token lands.
    this._captureRefreshToken(response);
    this._tokenExpireSeconds = tokenExpire ? parseDuration(tokenExpire) : null;
  }

  /**
   * Disable TOTP for user
   * @param {string} [user='self'] - Username
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async disable_totp(user = "self") {
    await this._request("post", `/appmesh/totp/${user}/disable`);
    return true;
  }

  /**
   * Get all applications info
   * @returns {Object} All apps info
   */
  async list_apps() {
    const response = await this._request("get", "/appmesh/applications");
    return response.data;
  }

  /**
   * Get app information
   * @param {string} name - App name
   * @returns {Object} App config
   */
  async get_app(name) {
    const response = await this._request("get", `/appmesh/app/${name}`);
    return response.data;
  }

  /**
   * Check app health status
   * @param {string} name - App name
   * @returns {boolean} True if healthy; false if the daemon reports unhealthy (non-200 or missing app)
   * @throws {AppMeshError} On network/transport failure (no HTTP status received)
   */
  async check_app_health(name) {
    try {
      const response = await this._request("get", `/appmesh/app/${name}/health`);
      return parseInt(response.data, 10) === 0;
    } catch (error) {
      if (error.statusCode != null) {
        return false; // non-200 or missing app → not healthy
      }
      throw error; // network/transport failure → propagate
    }
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
   *   working_dir: "",
   *   status: 1,
   *   docker_image: "",
   *   stdout_cache_num: 3,
   *   start_time: "",
   *   end_time: "",
   *   start_interval_seconds: null,
   *   cron: false,
   *   daily_limitation: { daily_start: "", daily_end: "" },
   *   retention: null,
   *   health_check_cmd: null,
   *   permission: null,
   *   env: {},
   *   sec_env: {},
   *   pid: null,
   *   resource_limit: { cpu_shares: null, memory_mb: null, memory_virt_mb: null },
   *   behavior: { exit: "standby", control: { "0": "keepalive" } }
   * };
   * await client.add_app("ping", appConfig);
   */
  async add_app(name, appJson) {
    const response = await this._request("put", `/appmesh/app/${name}`, appJson);
    return response.data;
  }

  /**
   * Delete application
   * @param {string} name - App name
   * @returns {Promise<boolean>} Success status
   */
  async delete_app(name) {
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
  async enable_app(name) {
    await this._request("post", `/appmesh/app/${name}/enable`);
    return true;
  }

  /**
   * Disable application
   * @param {string} name - App name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async disable_app(name) {
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
  async get_app_output(app_name, stdout_position = 0, stdout_index = 0, stdout_maxsize = 10240, process_uuid = "", timeout = 0) {
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
  async run_app_sync(app, stdoutHandler = defaultOutputHandler, maxTime = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifecycle = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = {
      timeout: parseDuration(maxTime),
      lifecycle: parseDuration(lifecycle)
    };

    const response = await this._request("post", "/appmesh/app/syncrun", app, { params });
    let exitCode = null;

    if (response.status === 200) {
      if (stdoutHandler) {
        stdoutHandler(response.data, 0);
      }
      // axios lowercases header names; the TCP transport keeps the daemon's exact case
      const exitCodeHeader = _getHeader(response.headers, "X-Exit-Code");
      if (exitCodeHeader) {
        exitCode = parseInt(exitCodeHeader, 10);
      }
    } else if (stdoutHandler) {
      stdoutHandler(response.data, 0);
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
  async run_app_async(app, maxTime = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifecycle = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
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
  async wait_for_async_run(run, stdoutHandler = defaultOutputHandler, timeout = 0) {
    if (run) {
      let lastOutputPosition = 0;
      const start = new Date();
      const interval = 1;

      while (run.procUid.length > 0) {
        const appOut = await this.get_app_output(run.appName, lastOutputPosition, 0, 20480, run.procUid, interval);
        if (appOut.output && stdoutHandler) {
          stdoutHandler(appOut.output, lastOutputPosition);
        }

        if (appOut.outPosition !== null) {
          lastOutputPosition = appOut.outPosition;
        }

        if (appOut.exitCode !== null) {
          // Process finished
          await this.delete_app(run.appName);
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
  async run_task(appName, data, timeout = 300) {
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
  async cancel_task(appName) {
    await this._request("delete", `/appmesh/app/${appName}/task`);
    return true;
  }

  /**
   * Download a remote file. Behavior differs by environment:
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
   * @param {boolean} [applyAttrs=true] - Node.js only: apply returned mode and best-effort
   * owner/group metadata on non-Windows platforms
   */
  async download_file(filePath, localFile = null, applyAttrs = true) {
    if (!localFile) localFile = filePath.split(/[\\/]/).pop();
    const headers = { [CONSTANTS.HTTP_HEADER_KEY_X_FILE_PATH]: encodeURIComponent(filePath) };
    const response = await this._request("get", "/appmesh/file/download", null, {
      headers,
      config: {
        responseType: "arraybuffer"
      }
    });

    if (response.status !== 200) {
      throw new AppMeshError(`Failed to download file: ${filePath}`, response.status, response.data);
    }

    if (ENV.isNode) {
      const fs = await import('fs/promises');

      try {
        await fs.writeFile(localFile, Buffer.from(response.data));

        if (applyAttrs && process.platform !== 'win32') {
          const respHeaders = response.headers; // avoid shadowing outer `headers`
          try {
            const mode = respHeaders["x-file-mode"];
            if (mode) {
              await fs.chmod(localFile, parseInt(mode, 10));
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
   * @param {string|File} localFile - Local file path/object
   * @param {string} [filePath=null] - Remote target path; defaults to the basename of localFile
   * @param {boolean} [applyAttrs] - In Node.js, send local permission bits; user/group metadata is
   * not currently populated by this SDK
   */
  async upload_file(localFile, filePath = null, applyAttrs = true) {
    if (!filePath) filePath = localFile.split(/[\\/]/).pop();
    const headers = { [CONSTANTS.HTTP_HEADER_KEY_X_FILE_PATH]: encodeURIComponent(filePath) };
    let formData;

    if (ENV.isNode) {
      // Node.js environment
      const FormData = (await import('form-data')).default;
      const fs = await import('fs');
      formData = new FormData();

      const filename = filePath.split('/').pop();
      formData.append("filename", filename);

      const stat = fs.statSync(localFile);
      if (stat.size < 10 * 1024 * 1024) {
        // For files < 10MB, use buffer
        const fileBuffer = fs.readFileSync(localFile);
        formData.append("file", fileBuffer, { filename: localFile.split('/').pop() });
      } else {
        // Stream for larger files
        formData.append("file", fs.createReadStream(localFile));
      }

      // Add file attributes
      if (applyAttrs) {
        headers["X-File-Mode"] = (stat.mode & 0o777).toString(); // Only permission bits
        // TODO: no user/group name in JS
        // headers["X-File-User"] = stat.uid.toString();
        // headers["X-File-Group"] = stat.gid.toString();
      }

      // Add form-data headers
      Object.assign(headers, formData.getHeaders());
    } else {
      // Browser environment
      formData = new FormData();

      // Get filename
      let filename;
      if (localFile instanceof File) {
        filename = localFile.name;
      } else if (localFile instanceof Blob) {
        filename = filePath.split('/').pop();
      } else {
        throw new AppMeshError('In browser, localFile must be File or Blob');
      }

      formData.append("filename", filename);
      formData.append("file", localFile);
    }

    await this._request("post", "/appmesh/file/upload", formData, {
      headers,
      config: {
        maxBodyLength: Infinity,
        maxContentLength: Infinity
      }
    });
  }

  /**
   * Get host resource usage
   * @returns {Object} Resource stats
   */
  async get_host_resources() {
    const response = await this._request("get", "/appmesh/resources");
    return response.data;
  }

  /**
   * Get current configuration
   * @returns {Promise<Object>} Config JSON
   */
  async get_config() {
    const response = await this._request("get", "/appmesh/config");
    return response.data;
  }

  /**
   * Apply a partial config update and return the merged server config.
   * @param {Object} config - Partial config document to POST to `/appmesh/config`
   * @returns {Object} Updated config
   */
  async set_config(config) {
    const response = await this._request("post", "/appmesh/config", config);
    return response.data;
  }

  /**
   * Set log level
   * @param {string} [level="DEBUG"] - Log level
   * @returns {string} Updated level
   */
  async set_log_level(level = "DEBUG") {
    const response = await this.set_config({ BaseConfig: { LogLevel: level } });
    return response.BaseConfig.LogLevel;
  }

  /**
   * Add label to server
   * @param {string} labelName - Label name
   * @param {string} labelValue - Label value
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async add_label(labelName, labelValue) {
    await this._request("put", `/appmesh/label/${labelName}`, null, { params: { value: labelValue } });
    return true;
  }


  /**
   * Delete label from server
   * @param {string} labelName - Label name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async delete_label(labelName) {
    await this._request("delete", `/appmesh/label/${labelName}`);
    return true;
  }


  /**
   * Get all server labels
   * @returns {Promise<Object>} All labels
   */
  async list_labels() {
    const response = await this._request("get", "/appmesh/labels");
    return response.data;
  }


  /**
   * Change user password
   * @param {string} oldPassword - Old password
   * @param {string} newPassword - New password
   * @param {string} [username="self"] - Username
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async update_password(oldPassword, newPassword, username = "self") {
    const body = {
      "old_password": base64Utils.encode(oldPassword),
      "new_password": base64Utils.encode(newPassword)
    };
    await this._request("post", `/appmesh/user/${username}/passwd`, body);
    return true;
  }

  /**
   * Add new user
   * @param {string} username - Username
   * @param {Object} userData - User definition
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async add_user(username, userData) {
    await this._request("put", `/appmesh/user/${username}`, userData);
    return true;
  }

  /**
   * Delete user
   * @param {string} username - Username
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async delete_user(username) {
    await this._request("delete", `/appmesh/user/${username}`);
    return true;
  }

  /**
   * Lock user account
   * @param {string} username - Username
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async lock_user(username) {
    await this._request("post", `/appmesh/user/${username}/lock`);
    return true;
  }

  /**
   * Unlock user account
   * @param {string} username - Username
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async unlock_user(username) {
    await this._request("post", `/appmesh/user/${username}/unlock`);
    return true;
  }

  /**
   * Get user list
   * @returns {Object[]} User array
   */
  async list_users() {
    const response = await this._request("get", "/appmesh/users");
    return response.data;
  }

  /**
   * Get current user info
   * @returns {Object} User properties
   */
  async get_current_user() {
    const response = await this._request("get", "/appmesh/user/self");
    return response.data;
  }

  /**
   * Get all user groups
   * @returns {Object[]} Group array
   */
  async list_groups() {
    const response = await this._request("get", "/appmesh/user/groups");
    return response.data;
  }

  /**
   * Get available permissions
   * @returns {Object[]} Permission list
   */
  async list_permissions() {
    const response = await this._request("get", "/appmesh/permissions");
    return response.data;
  }

  /**
   * Get user permissions
   * @returns {Object[]} Permission array
   */
  async get_user_permissions() {
    const response = await this._request("get", "/appmesh/user/permissions");
    return response.data;
  }

  /**
   * Get all roles and permissions
   * @returns {Object[]} Role array
   */
  async list_roles() {
    const response = await this._request("get", "/appmesh/roles");
    return response.data;
  }

  /**
   * Update or add role
   * @param {string} roleName - Role name
   * @param {Object} rolePermissionJson - Permission IDs
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async update_role(roleName, rolePermissionJson) {
    await this._request("post", `/appmesh/role/${roleName}`, rolePermissionJson);
    return true;
  }

  /**
   * Delete role
   * @param {string} roleName - Role name
   * @returns {Promise<boolean>} true on success; failures throw AppMeshError
   */
  async delete_role(roleName) {
    await this._request("delete", `/appmesh/role/${roleName}`);
    return true;
  }

  /**
   * Get raw Prometheus metrics text from the server.
   * @returns {Promise<string>} Metrics text
   */
  async get_metrics() {
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
    throw new AppMeshError("subscribe requires the TCP client (AppMeshClientTCP, imported from 'appmesh/tcp'); the HTTP client does not support event subscriptions");
  }

  /**
   * Event subscription is only available over the TCP transport.
   * @throws {AppMeshError} Always — use AppMeshClientTCP for event subscriptions.
   */
  async unsubscribe() {
    throw new AppMeshError("unsubscribe requires the TCP client (AppMeshClientTCP, imported from 'appmesh/tcp'); the HTTP client does not support event subscriptions");
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
   * @returns {Object} Headers object
   */
  _commonHeaders() {
    const headers = {};
    // Add user agent in Node.js
    if (ENV.isNode) {
      headers[CONSTANTS.HTTP_USER_AGENT_HEADER_NAME] = CONSTANTS.HTTP_USER_AGENT;
    }

    // Add forwarding host if specified
    if (this.forwardingHost) {
      if (this.forwardingHost.includes(":")) {
        headers[CONSTANTS.HTTP_HEADER_KEY_X_TARGET_HOST] = this.forwardingHost;
      } else {
        const parsedUrl = new URL(this.baseURL);
        const defaultPort = parsedUrl.protocol === 'https:' ? '443' : '80';
        const port = parsedUrl.port || defaultPort;
        headers[CONSTANTS.HTTP_HEADER_KEY_X_TARGET_HOST] = `${this.forwardingHost}:${port}`;
      }
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

    const { headers = {}, params = {}, config = {} } = options;

    try {
      const requestConfig = {
        method,
        url: path,
        withCredentials: true,  // for browser send cookie
        ...config,
        headers: { ...headers },
        params: { ...params }
      };

      if (body !== null) {
        requestConfig.data = body;
      }

      const response = await this._client(requestConfig);
      if (response.status !== 200) {
        const errMsg = this._extractErrorMessage(response.data);
        if (response.status === CONSTANTS.HTTP_STATUS_PRECONDITION_REQUIRED) {
          throw new TotpRequiredError(errMsg, response.data);
        }
        throw new AppMeshError(errMsg, response.status, response.data);
      }

      // axios response header use lower case
      if (ENV.isNode && response.headers['Set-Cookie'.toLowerCase()]) {
        // Handle array of cookies or single cookie
        const cookies = Array.isArray(response.headers['Set-Cookie'.toLowerCase()]) ?
          response.headers['Set-Cookie'.toLowerCase()] :
          [response.headers['Set-Cookie'.toLowerCase()]];

        // Join all cookies with semicolon separator
        this._client.defaults.headers.Cookie = cookies.join('; ');

        // Keep the in-memory token store in sync with the server-issued cookie
        // (login, renew, authenticate, TOTP setup/validate)
        const authCookie = cookies
          .map(c => c.split(';')[0].trim())
          .find(c => c.startsWith('appmesh_auth_token='));
        if (authCookie) {
          this._handleTokenUpdate(authCookie.substring('appmesh_auth_token='.length));
        }
      }

      return response;
    } catch (error) {
      if (error instanceof AppMeshError && error.statusCode === CONSTANTS.HTTP_STATUS_PRECONDITION_REQUIRED) {
        throw error;
      }
      throw this.onError(error);
    }
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
   * Comprehensive error handler for all client errors
   * @protected
   * @param {Error} error - The caught error
   * @returns {AppMeshError} Standardized AppMeshError
   */
  onError(error) {
    console.log("AppMeshClient error:", error);
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
  async with_forwarding_host(callback) {
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
    return this.with_forwarding_host(() =>
      this._client.wait_for_async_run(this, stdoutHandler, timeout)
    );
  }
}

// Export the main classes
export { AppMeshClient, AppOutput, AppRun, AppMeshError, TotpRequiredError, AppRemovedError, TransportDisconnectedError, DEFAULT_CA_FILE };
export default AppMeshClient;
