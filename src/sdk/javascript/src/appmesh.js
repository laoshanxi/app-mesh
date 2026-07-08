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
 * Decode the `exp` field from a JWT without signature verification.
 * @param {string} token - JWT string (header.payload.signature)
 * @returns {number|null} Expiry timestamp in seconds, or null
 * @private
 */
function _decodeJwtExp(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(base64Utils.decode(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
    return typeof payload.exp === 'number' ? payload.exp : null;
  } catch (_) {
    return null;
  }
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
   * @example
   * const sslConfig = {
   *   cert: fs.readFileSync("client.pem"),
   *   key: fs.readFileSync("client-key.pem"),
   *   ca: fs.readFileSync("ca.pem"),
   *   rejectUnauthorized: true
   * };
   */
  constructor(baseURL = ENV.isNode ? 'https://127.0.0.1:6060' : window.location.origin, sslConfig = null) {
    // Base URL for API requests
    this.baseURL = baseURL;

    // Host to forward requests to
    this.forwardingHost = null;

    // Current JWT token known to this client (single token store; transports
    // sync from it via _handleTokenUpdate/_getAccessToken)
    this._token = null;

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
    if (totpCode) headers["X-Totp-Code"] = totpCode;
    if (tokenExpire) headers["X-Expire-Seconds"] = parseDuration(tokenExpire);
    if (audience) headers["X-Audience"] = audience;

    await this._request("post", "/appmesh/login", null, { headers });
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
   * Logout from the current session.
   */
  async logout() {
    try {
      await this._request("post", "/appmesh/self/logoff");
    } catch (error) {
      console.error("Failed to logoff:", error.message);
    } finally {
      // Clean up keepAlive connections
      if (ENV.isNode && this._client.defaults.httpsAgent) {
        this._client.defaults.httpsAgent.destroy();
      }

      this._stopAutoRefresh();
      this._token = null;

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

  /** @private */
  _stopAutoRefresh() {
    this._autoRefreshEnabled = false;
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }
  }

  /** @private */
  _scheduleTokenRefresh() {
    if (!this._autoRefreshEnabled) return;

    // Replace any pending timer so re-scheduling (e.g. from _handleTokenUpdate) never stacks timers
    if (this._refreshTimer) {
      clearTimeout(this._refreshTimer);
      this._refreshTimer = null;
    }

    const REFRESH_INTERVAL = 300; // 5 min default check
    const REFRESH_MARGIN = 30;    // refresh 30s before expiry

    let delaySec = REFRESH_INTERVAL;

    // Try to compute precise delay from JWT exp
    const token = this._autoRefreshJwt || this._getAccessToken();
    if (token) {
      const exp = _decodeJwtExp(token);
      if (exp) {
        const now = Math.floor(Date.now() / 1000);
        const timeToExpiry = exp - now;
        if (timeToExpiry <= REFRESH_MARGIN) {
          delaySec = 1; // almost expired, refresh immediately
        } else {
          delaySec = Math.min(timeToExpiry - REFRESH_MARGIN, REFRESH_INTERVAL);
        }
      }
    }

    this._refreshTimer = setTimeout(async () => {
      if (!this._autoRefreshEnabled) return;
      try {
        // _request captures the renewed token cookie and routes it through
        // _handleTokenUpdate, which updates _autoRefreshJwt for precise delays
        await this.renew_token();
      } catch (err) {
        console.warn("Auto-refresh: token renewal failed:", err.message);
      }
      this._scheduleTokenRefresh(); // re-schedule
    }, delaySec * 1000);

    // Don't block Node.js process exit
    if (this._refreshTimer.unref) {
      this._refreshTimer.unref();
    }
  }

  /**
   * Renew the current JWT token.
   * @param {string|number} [tokenExpire] - Token expiry (integer seconds or ISO 8601 string)
   */
  async renew_token(tokenExpire = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const headers = {};
    if (tokenExpire) {
      headers["X-Expire-Seconds"] = parseDuration(tokenExpire);
    }
    await this._request("post", "/appmesh/token/renew", null, { headers });
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

    await this._request("post", "/appmesh/totp/validate", body, { headers });
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
   * @returns {boolean} True if healthy
   */
  async check_app_health(name) {
    try {
      const response = await this._request("get", `/appmesh/app/${name}/health`);
      return parseInt(response.data, 10) === 0;
    } catch (_) {
      return false; // non-200 or missing app → not healthy
    }
  }

  /**
   * Add or update application
   * @param {string} name - App name
   * @param {Object} appJson - App configuration
   * @example
  * {
   *  "name": "",
   *  "command": "",
   *  "shell": false,
   *  "session_login": false,
   *  "description": "",
   *  "metadata": "",
   *  "working_dir": "",
   *  "status": 1,
   *  "docker_image": "",
   *  "stdout_cache_num": 3,
   *  "start_time": "",
   *  "end_time": "",
   *  "interval": null,
   *  "cron": false,
   *  "daily_limitation": {
   *      "daily_start": "",
   *      "daily_end": ""
   *  },
   *  "retention": null,
   *  "health_check_cmd": null,
   *  "permission": null,
   *  "envs": [],
   *  "sec_env": [],
   *  "pid": null,
   *  "resource_limit": {
   *      "cpu_shares": null,
   *      "memory_mb": null,
   *      "memory_virt_mb": null
   *  },
   *  "behavior": {
   *      "exit": "standby",
   *      "control": {
   *          "0": "keepalive"
   *      }
   *  }
   * @returns {Promise<Object>} Registered app
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
   * @param {string} localFile - Local file path (Node.js) or suggested filename (browser)
   * @param {boolean} [applyAttrs=true] - Node.js only: apply returned mode and best-effort
   * owner/group metadata on non-Windows platforms
   */
  async download_file(filePath, localFile, applyAttrs = true) {
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
   * @param {string} filePath - Remote target path
   * @param {boolean} [applyAttrs] - In Node.js, send local permission bits; user/group metadata is
   * not currently populated by this SDK
   */
  async upload_file(localFile, filePath, applyAttrs = true) {
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
