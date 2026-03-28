// appmesh.js
import axios from 'axios';

// Lazy-resolved Node.js https module (null in browser)
let _https = null;
let _httpsReady = null; // Promise that resolves when https is loaded

// Constants using Object.freeze to prevent modifications
const CONSTANTS = Object.freeze({
  HTTP_USER_AGENT_HEADER_NAME: "User-Agent",
  HTTP_USER_AGENT: "appmesh/javascript",
  HTTP_STATUS_PRECONDITION_REQUIRED: 428,
  DEFAULT_TOKEN_EXPIRE_SECONDS: "P1W",
  DEFAULT_RUN_APP_TIMEOUT_SECONDS: "P2D",
  DEFAULT_RUN_APP_LIFECYCLE_SECONDS: "P2DT12H",
  DEFAULT_JWT_AUDIENCE: "appmesh-service",
  HTTP_HEADER_NAME_CSRF_TOKEN: "X-CSRF-Token",
  HTTP_COOKIE_NAME_CSRF_TOKEN: "appmesh_csrf_token",
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
   */
  constructor(message, statusCode = null, responseData = null) {
    super(message);
    this.name = 'AppMeshError';
    this.statusCode = statusCode;
    this.responseData = responseData;
    this.timestamp = new Date().toISOString();
  }
}

// Default output handler
const defaultOutputHandler = (output) => {
  console.log(output);
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

/**
 * AppMesh REST Service client
 */
class AppMeshClient {
  /**
   * Initialize AppMesh client
   * @param {string} baseURL - Service URL
   * @param {Object} [sslConfig] - SSL config 
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

    // Configure axios instance
    const axiosConfig = {
      baseURL,
      timeout: 300000, // 5 minutes
      validateStatus: status => true
    };

    // Store SSL config for deferred agent setup
    this._sslConfig = sslConfig;
    this._client = axios.create(axiosConfig);

    // Node.js only: start loading https module (resolved before first request)
    if (ENV.isNode && !_httpsReady) {
      _httpsReady = import('https').then(mod => {
        _https = mod.default || mod;
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
        // Handle response errors
        const err = new AppMeshError('Request failed: ' + (error.message || 'Unknown error'), error.response?.status, error.response?.data);
        return Promise.resolve(err);
      }
    );
  }

  /**
   * Login with username/password and let the server attach the session token cookie.
   * @param {string} username
   * @param {string} password
   * @param {string} [totpCode] - TOTP code if 2FA is enabled
   * @param {string|number} [expireSeconds] - Token expiry (integer seconds or ISO 8601 string)
   * @param {string} [audience] - JWT audience
   * @returns {Promise<void>} Resolves when login succeeds. If the server requires TOTP and no
   * valid code is supplied, `_request()` rejects with the HTTP 428 response details.
   */
  async login(username, password, totpCode = null, expireSeconds = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS, audience = CONSTANTS.DEFAULT_JWT_AUDIENCE) {
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
    if (expireSeconds) headers["X-Expire-Seconds"] = parseDuration(expireSeconds);
    if (audience) headers["X-Audience"] = audience;

    await this._request("post", "/appmesh/login", null, { headers });
  }

  /**
   * Verify the token currently attached to this client/session and optionally check permission.
   * @param {string} [permission] - Permission to check
   * @param {string} [audience] - JWT audience
   * @returns {Promise<{success: boolean, responseText: string}>} Verification result with success flag and response text.
   * @throws {AppMeshError} If the server rejects the token or permission check fails.
   */
  async authenticate(permission = null, audience = CONSTANTS.DEFAULT_JWT_AUDIENCE) {
    const headers = {};
    if (permission) headers["X-Permission"] = permission;
    if (audience) headers["X-Audience"] = audience;
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
    const COOKIE_NAME = 'appmesh_auth_token';
    if (ENV.isNode) {
      const existingCookies = this._client.defaults.headers.Cookie || '';
      const cookies = existingCookies.split('; ').filter(c =>
        c && !c.startsWith(COOKIE_NAME + '=')
      );
      cookies.push(`${COOKIE_NAME}=${token}`);
      this._client.defaults.headers.Cookie = cookies.join('; ');
      this._autoRefreshJwt = token;
      if (this._autoRefreshEnabled) {
        this._stopAutoRefresh();
        this._autoRefreshEnabled = true;
        this._scheduleTokenRefresh();
      }
    } else {
      // Browser: auth token is HttpOnly (set by server via Set-Cookie),
      // document.cookie cannot access or override HttpOnly cookies.
      // Use authenticate() for browser-based token verification instead.
      console.warn('set_token() is not supported in browser mode (auth cookie is HttpOnly). Use authenticate() instead.');
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

      // Remove CSRF token and cookies
      if (ENV.isNode) {
        this._client.defaults.headers.Cookie = null;
      } else {
        document.cookie = `${CONSTANTS.HTTP_COOKIE_NAME_CSRF_TOKEN}=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/; SameSite=Strict; Secure`;
      }
    }
  }

  /**
   * Enable or disable background token auto-refresh.
   * @param {boolean} enable - true to start, false to stop
   * @param {string} [jwtToken] - Optional token used only to calculate the first refresh delay
   */
  setAutoRefreshToken(enable, jwtToken = null) {
    this._stopAutoRefresh();
    this._autoRefreshEnabled = enable;
    if (enable) {
      this._autoRefreshJwt = jwtToken || this._getAccessToken?.() || null;
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

    const REFRESH_INTERVAL = 300; // 5 min default check
    const REFRESH_MARGIN = 30;    // refresh 30s before expiry

    let delaySec = REFRESH_INTERVAL;

    // Try to compute precise delay from JWT exp
    const token = this._autoRefreshJwt || this._getAccessToken?.();
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
        await this.renew_token();
        // Update stored token from cookie for precise delay calculation (Node.js only;
        // in browsers the auth cookie is HttpOnly and not accessible via JS)
        if (ENV.isNode) {
          const cookieStr = this._client?.defaults?.headers?.Cookie || '';
          const match = cookieStr.split('; ').find(c => c.startsWith('appmesh_auth_token='));
          if (match) this._autoRefreshJwt = match.split('=').slice(1).join('=');
        }
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
   * @param {string|number} [expireSeconds] - Token expiry (integer seconds or ISO 8601 string)
   */
  async renew_token(expireSeconds = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const headers = {};
    if (expireSeconds) {
      headers["X-Expire-Seconds"] = parseDuration(expireSeconds);
    }
    await this._request("post", "/appmesh/token/renew", null, { headers });
  }

  /**
   * Get the decoded OTP provisioning URI for the current user.
   * @returns {Promise<string>} Decoded `otpauth://...` URI, not just the raw secret field
   */
  async get_totp_secret() {
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
   * @param {string|number} [expireSeconds] - Token expiry in seconds or ISO8601 duration (e.g. "P1DT12H", 604800)
   */
  async validate_totp(username, totpChallenge, totpCode, expireSeconds = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const body = {
      "user_name": username,
      "totp_code": totpCode,
      "totp_challenge": totpChallenge,
      "expire_seconds": parseDuration(expireSeconds)
    };
    // Set cookie header for browser
    const headers = { "X-Set-Cookie": "true" };

    await this._request("post", "/appmesh/totp/validate", body, { headers });
  }

  /**
   * Disable TOTP for user
   * @param {string} [user='self'] - Username
   * @returns {boolean} Success status
   */
  async disable_totp(user = "self") {
    const response = await this._request("post", `/appmesh/totp/${user}/disable`);
    return response.status === 200;
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
   * @returns {Promise<boolean>} Success status
   */
  async enable_app(name) {
    const response = await this._request("post", `/appmesh/app/${name}/enable`);
    return response.status === 200;
  }

  /**
   * Disable application
   * @param {string} name - App name
   * @returns {Promise<boolean>} Success status
   */
  async disable_app(name) {
    const response = await this._request("post", `/appmesh/app/${name}/disable`);
    return response.status === 200;
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
    // axios response header use lower case
    const outPosition = response.headers["X-Output-Position".toLowerCase()] ? parseInt(response.headers["X-Output-Position".toLowerCase()], 10) : null;
    const exitCode = response.headers["X-Exit-Code".toLowerCase()] ? parseInt(response.headers["X-Exit-Code".toLowerCase()], 10) : null;
    return new AppOutput(response.status, response.data, outPosition, exitCode);
  }

  /**
   * Run an app synchronously and stream the returned stdout body to `outputHandler`.
   * @param {Object} app - App configuration
   * @param {Function} [outputHandler=defaultOutputHandler] - Output handler
   * @param {number|string} [maxTimeSeconds] - Max runtime
   * @param {number|string} [lifeCycleSeconds] - Lifecycle time
   * @returns {Promise<number|null>} Exit code parsed from `X-Exit-Code`, or `null` when absent
   */
  async run_app_sync(app, outputHandler = defaultOutputHandler, maxTimeSeconds = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifeCycleSeconds = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = {
      timeout: parseDuration(maxTimeSeconds),
      lifecycle: parseDuration(lifeCycleSeconds)
    };

    const response = await this._request("post", "/appmesh/app/syncrun", app, { params });
    let exitCode = null;

    if (response.status === 200) {
      if (outputHandler) {
        outputHandler(response.data);
      }
      // axios response header use lower case
      if (response.headers["X-Exit-Code".toLowerCase()]) {
        exitCode = parseInt(response.headers["X-Exit-Code".toLowerCase()], 10);
      }
    } else if (outputHandler) {
      outputHandler(response.data);
    }

    return exitCode;
  }

  /**
   * Run an app asynchronously and return a handle for later polling.
   * @param {Object} app - App config
   * @param {string|number} [maxTimeSeconds] - Max runtime
   * @param {string|number} [lifeCycleSeconds] - Lifecycle time
   * @returns {AppRun} Running app handle that also snapshots the current forwarding host
   */
  async run_app_async(app, maxTimeSeconds = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifeCycleSeconds = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = {
      timeout: parseDuration(maxTimeSeconds),
      lifecycle: parseDuration(lifeCycleSeconds)
    };

    const response = await this._request("post", "/appmesh/app/run", app, { params });
    return new AppRun(this, response.data.name, response.data.process_uuid);
  }

  /**
   * Wait for an async app to complete, optionally streaming incremental output.
   * @param {AppRun} run - AppRun object
   * @param {Function} [outputHandler] - Output handler
   * @param {number} [timeout=0] - Max wait time
   * @returns {Promise<number|null>} Exit code, or `null` on timeout/polling failure. On success
   * the SDK also attempts to delete the temporary run app.
   */
  async wait_for_async_run(run, outputHandler = defaultOutputHandler, timeout = 0) {
    if (run) {
      let lastOutputPosition = 0;
      const start = new Date();
      const interval = 1;

      while (run.procUid.length > 0) {
        try {
          const appOut = await this.get_app_output(run.appName, lastOutputPosition, 0, 20480, run.procUid, interval);
          if (appOut.output && outputHandler) {
            outputHandler(appOut.output);
          }

          if (appOut.outPosition !== null) {
            lastOutputPosition = appOut.outPosition;
          }

          if (appOut.exitCode !== null) {
            // Process finished
            await this.delete_app(run.appName);
            return appOut.exitCode;
          }

          if (appOut.statusCode !== 200) {
            // Request failed
            break;
          }

          if (timeout > 0 && (new Date() - start) / 1000 > timeout) {
            // Timeout reached
            break;
          }
          // Small delay to prevent tight looping
          await new Promise((resolve) => setTimeout(resolve, 100));
        } catch (error) {
          console.error(error);
          break;
        }
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
    const response = await this._request("post", `/appmesh/app/${appName}/task`, data, {
      params: { timeout: timeout.toString() }
    });
    return response.data;
  }

  /**
   * Cancel running task
   * @param {string} appName - App name
   * @returns {Promise<boolean>} Success status
   */
  async cancel_task(appName) {
    const response = await this._request("delete", `/appmesh/app/${appName}/task`);
    return response.status === 200;
  }

  /**
   * Download a remote file.
   * @param {string} filePath - Remote file path
   * @param {string} localFile - Local file path
   * @param {boolean} [applyAttrs=true] - In Node.js, apply returned mode and best-effort owner/group
   * metadata on non-Windows platforms
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
            const userName = respHeaders["x-file-user"];
            const groupName = respHeaders["x-file-group"];
            if (userName && groupName) {
              const uid = await _resolveUid(userName);
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
   * @param {Object} configJsonSection - Partial config document to POST to `/appmesh/config`
   * @returns {Object} Updated config
   */
  async set_config(configJsonSection) {
    const response = await this._request("post", "/appmesh/config", configJsonSection);
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
   * @returns {boolean} Success status
   */
  async add_label(labelName, labelValue) {
    const response = await this._request("put", `/appmesh/label/${labelName}`, null, { params: { value: labelValue } });
    return response.status === 200;
  }


  /**
   * Delete label from server
   * @param {string} labelName - Label name
   * @returns {boolean} Success status
   */
  async delete_label(labelName) {
    const response = await this._request("delete", `/appmesh/label/${labelName}`);
    return response.status === 200;
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
   * @param {string} [userName="self"] - Username
   * @returns {Promise<boolean>} Success status
   */
  async update_password(oldPassword, newPassword, userName = "self") {
    const body = {
      "old_password": base64Utils.encode(oldPassword),
      "new_password": base64Utils.encode(newPassword)
    };
    const response = await this._request("post", `/appmesh/user/${userName}/passwd`, body);
    return response.status === 200;
  }

  /**
   * Add new user
   * @param {string} userName - Username
   * @param {Object} userJson - User definition
   * @returns {Promise<boolean>} Success status
   */
  async add_user(userName, userJson) {
    const response = await this._request("put", `/appmesh/user/${userName}`, userJson);
    return response.status === 200;
  }

  /**
   * Delete user
   * @param {string} userName - Username
   * @returns {Promise<boolean>} Success status
   */
  async delete_user(userName) {
    const response = await this._request("delete", `/appmesh/user/${userName}`);
    return response.status === 200;
  }

  /**
   * Lock user account
   * @param {string} userName - Username
   * @returns {Promise<boolean>} Success status
   */
  async lock_user(userName) {
    const response = await this._request("post", `/appmesh/user/${userName}/lock`);
    return response.status === 200;
  }

  /**
   * Unlock user account
   * @param {string} userName - Username
   * @returns {Promise<boolean>} Success status
   */
  async unlock_user(userName) {
    const response = await this._request("post", `/appmesh/user/${userName}/unlock`);
    return response.status === 200;
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
   * @returns {Promise<boolean>} Success status
   */
  async update_role(roleName, rolePermissionJson) {
    const response = await this._request("post", `/appmesh/role/${roleName}`, rolePermissionJson);
    return response.status === 200;
  }

  /**
   * Delete role
   * @param {string} roleName - Role name
   * @returns {boolean} Success status
   */
  async delete_role(roleName) {
    const response = await this._request("delete", `/appmesh/role/${roleName}`);
    return response.status === 200;
  }

  /**
   * Get raw Prometheus metrics text from the server.
   * @returns {Promise<string>} Metrics text
   */
  async metrics() {
    const response = await this._request("get", "/appmesh/metrics", null, {
      config: { responseType: "text" }
    });
    return response.data;
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

    // Add CSRF token from cookies to headers
    const getCsrfToken = (cookieStr) => {
      if (!cookieStr) return null;
      const match = cookieStr.split('; ').find(c => c.startsWith(CONSTANTS.HTTP_COOKIE_NAME_CSRF_TOKEN + '='));
      return match ? match.split('=')[1] : null;
    };
    if (ENV.isNode) {
      const token = getCsrfToken(this._client.defaults.headers.Cookie);
      if (token) headers[CONSTANTS.HTTP_HEADER_NAME_CSRF_TOKEN] = token;
    } else {
      const token = getCsrfToken(document.cookie);
      if (token) headers[CONSTANTS.HTTP_HEADER_NAME_CSRF_TOKEN] = token;
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
          ...(this._sslConfig || { rejectUnauthorized: false }),
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
        if (path === "/appmesh/self/logoff") {
          return response;  // Allow logoff to "fail" gracefully
        }
        const errMsg = this._extractErrorMessage(response.data);
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
      }

      return response;
    } catch (error) {
      if (error instanceof AppMeshError && error.statusCode === CONSTANTS.HTTP_STATUS_PRECONDITION_REQUIRED) {
        throw error;
      }
      if (path === "/appmesh/self/logoff") {
        // console.log("Logoff error:", error.message);
        return;
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
   * Context manager for forward host override to self._client
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
   * @param {function} [outputHandler=defaultOutputHandler] - Print remote stdout function
   * @param {number} [timeout=0] - Wait max timeout seconds and return if not finished, 0 means wait until finished
   * @returns {Promise<number|null>} Return exit code if process finished, return null for timeout or exception
   */
  async wait(outputHandler = defaultOutputHandler, timeout = 0) {
    return this.withForwardingHost(() =>
      this._client.wait_for_async_run(this, outputHandler, timeout)
    );
  }
}

// Export the main classes
export { AppMeshClient, AppOutput, AppRun, AppMeshError };
export default AppMeshClient;
