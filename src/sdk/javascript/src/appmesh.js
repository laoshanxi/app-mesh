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
  DEFAULT_RUN_APP_TIMEOUT_SECONDS: "P2D",
  DEFAULT_RUN_APP_LIFECYCLE_SECONDS: "P2DT12H",
  HTTP_HEADER_KEY_AUTH: "Authorization",
  HTTP_HEADER_KEY_X_TARGET_HOST: "X-Target-Host",
  HTTP_HEADER_KEY_X_FILE_PATH: "X-File-Path",
});

// Environment detection
const ENV = Object.freeze({
  isNode: !(typeof window !== 'undefined' && typeof window.document !== 'undefined')
});

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

  /** Attach a caller-owned Dex access token in memory. */
  set_bearer_token(token) {
    const value = typeof token === 'string' ? token.trim() : '';
    this._handleTokenUpdate(value || null);
  }

  /** Source-compatible alias for set_bearer_token(). */
  set_token(token) {
    this.set_bearer_token(token);
  }

  /** Remove the locally attached bearer without contacting Engine or Dex. */
  clear_bearer_token() {
    this._handleTokenUpdate(null);
  }

  /** Return the current in-memory Dex access token. */
  _getAccessToken() {
    return this._token || null;
  }

  /** Store only the in-memory access token; never synthesize a Cookie header. */
  _handleTokenUpdate(token) {
    this._token = token || null;
  }

  /** Return Engine's public Dex/OIDC configuration. */
  async get_auth_config() {
    return (await this._request("get", "/appmesh/auth/config")).data;
  }

  /** Return the verified Dex principal represented by the current bearer. */
  async get_current_principal() {
    return (await this._request("get", "/appmesh/principal/self")).data;
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


  /** List Engine authorization overlays keyed by immutable Dex principal ID. */
  async list_principals() {
    return (await this._request("get", "/appmesh/principals")).data;
  }

  /** Update an Engine authorization overlay; never mutate IdP account data. */
  async update_principal(principalId, policy) {
    await this._request("post", `/appmesh/principal/${encodeURIComponent(principalId)}`, policy);
    return true;
  }

  /** Delete only an Engine authorization overlay. */
  async delete_principal(principalId) {
    await this._request("delete", `/appmesh/principal/${encodeURIComponent(principalId)}`);
    return true;
  }

  /** Safe compatibility alias returning a Principal, not an IdP user. */
  async get_current_user() {
    return this.get_current_principal();
  }

  /**
   * Get available permissions
   * @returns {Object[]} Permission list
   */
  async list_permissions() {
    const response = await this._request("get", "/appmesh/permissions");
    return response.data;
  }

  /** Get effective permissions for the current verified principal. */
  async get_principal_permissions() {
    const response = await this._request("get", "/appmesh/principal/self/permissions");
    return response.data;
  }

  /** Safe compatibility alias for get_principal_permissions(). */
  async get_user_permissions() {
    return this.get_principal_permissions();
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

    const token = this._getAccessToken();
    if (token) {
      headers[CONSTANTS.HTTP_HEADER_KEY_AUTH] = `Bearer ${token}`;
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
        withCredentials: false,
        ...config,
        headers: { ...headers },
        params: { ...params }
      };

      if (body !== null) {
        requestConfig.data = body;
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
export { AppMeshClient, AppOutput, AppRun, AppMeshError, AppRemovedError, TransportDisconnectedError, DEFAULT_CA_FILE };
export default AppMeshClient;
