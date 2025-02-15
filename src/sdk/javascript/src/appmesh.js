import axios from 'axios';
import https from 'https';

// Constants definitions using Object.freeze to prevent modifications
const CONSTANTS = Object.freeze({
  HTTP_USER_AGENT_HEADER_NAME: "User-Agent",
  HTTP_USER_AGENT: "appmesh/javascript",
  DEFAULT_TOKEN_EXPIRE_SECONDS: "P1W",
  DEFAULT_RUN_APP_TIMEOUT_SECONDS: "P2D",
  DEFAULT_RUN_APP_LIFECYCLE_SECONDS: "P2DT12H",
  DEFAULT_JWT_AUDIENCE: "appmesh-service"
});

// Environment detection utilities
const ENV = Object.freeze({
  isNode: !(typeof window !== 'undefined' && typeof window.document !== 'undefined')
});

// Base64 utilities optimized for both Node.js and browser environments
const base64Utils = ENV.isNode ? {
  encode: str => Buffer.from(str).toString('base64'),
  decode: str => Buffer.from(str, 'base64').toString()
} : {
  encode: str => btoa(encodeURIComponent(str)),
  decode: str => decodeURIComponent(atob(str))
};

// Custom error class for AppMesh specific errors
class AppMeshError extends Error {
  constructor(message, statusCode = null, responseData = null) {
    super(message);
    this.name = 'AppMeshError';
    this.statusCode = statusCode;
    this.responseData = responseData;
  }
}

// Default output handler if none is provided
const defaultOutputHandler = (output) => {
  console.log(output);
};

/**
 * Parse ISO8601 duration to seconds, supports: P[n]Y[n]M[n]DT[n]H[n]M[n]S or P[n]W
 * @param {string} {string|number} duration - ISO8601 duration string or number of seconds (e.g., "P1Y2M3DT4H5M6S").
 * @returns {number} The total duration in seconds.
 * @throws {RangeError} If the duration string is invalid.
 */
function parseDuration(duration) {
  // If duration is already a number, return it
  if (typeof duration === "number") {
    return duration;
  }

  if (typeof duration !== 'string') {
    throw new Error("Invalid input type. Expected number or ISO 8601 duration string.");
  }

  // Handle empty string
  if (!duration.trim()) {
    throw new Error('Duration string cannot be empty');
  }

  // Check if string starts with P (mandatory for ISO8601)
  if (!duration.startsWith('P')) {
    throw new Error('Invalid ISO8601 duration: must start with P');
  }

  // Define the regular expression pattern for matching ISO8601 duration format.
  const numbers = "\\d+";
  const fractionalNumbers = `${numbers}(?:[\\.,]${numbers})?`;
  const datePattern = `(${numbers}Y)?(${numbers}M)?(${numbers}W)?(${numbers}D)?`;
  const timePattern = `T(${fractionalNumbers}H)?(${fractionalNumbers}M)?(${fractionalNumbers}S)?`;
  const iso8601 = `P(?:${datePattern}(?:${timePattern})?)`;
  const objMap = [
    "years", "months", "weeks", "days", "hours", "minutes", "seconds",
  ];

  // Parse the duration string using the regex pattern.
  const matches = duration.replace(/,/g, ".").match(new RegExp(iso8601));
  if (!matches) {
    throw new RangeError("invalid duration: " + duration);
  }

  // Slice away the first match (the full matched string).
  const slicedMatches = matches.slice(1);

  // If there are no valid matches, throw an error.
  if (slicedMatches.filter(v => v != null).length === 0) {
    throw new RangeError("invalid duration: " + duration);
  }

  // Check if only one fractional unit is used (for example, no fractional seconds allowed alongside minutes).
  if (slicedMatches.filter(v => /\./.test(v || "")).length > 1) {
    throw new RangeError("only the smallest unit can be fractional");
  }

  // Reduce the parsed duration into an object of units.
  const durationObject = slicedMatches.reduce((prev, next, idx) => {
    prev[objMap[idx]] = parseFloat(next || "0") || 0;
    return prev;
  }, {});

  // Convert the parsed duration object into total seconds.
  let seconds = 0;

  // Convert years, months, weeks, and days into seconds.
  seconds += durationObject.years * 31536000; // 365 days * 24 hours * 60 minutes * 60 seconds
  seconds += durationObject.months * 2592000; // 30 days * 24 hours * 60 minutes * 60 seconds (approximate)
  seconds += durationObject.weeks * 604800; // 7 days * 24 hours * 60 minutes * 60 seconds
  // Convert hours, minutes, and seconds into seconds.
  seconds += durationObject.days * 86400;  // 24 hours * 60 minutes * 60 seconds
  seconds += durationObject.hours * 3600; // 60 minutes * 60 seconds
  seconds += durationObject.minutes * 60;
  seconds += durationObject.seconds;

  return seconds;
}

/**
 * Main AppMesh client class
 * Provides interface to interact with AppMesh REST Service
 */
class AppMeshClient {
  /**
   * Creates an instance of AppMeshClient.
   * This client object is used to access the App Mesh REST Service.
   *
   * @param {string} baseURL - The base URL of the App Mesh REST Service.
   * @param {Object} [sslConfig=null] - sslConfig definition. Default is null to disable SSL verify.
   * const sslConfig = {
   *   cert: fs.readFileSync("/opt/appmesh/ssl/client.pem"),
   *   key: fs.readFileSync("/opt/appmesh/ssl/client-key.pem"),
   *   ca: fs.readFileSync("/opt/appmesh/ssl/ca.pem"),  // Optional: if using a custom CA
   *   rejectUnauthorized: true,                        // Set to false if you want to ignore unauthorized SSL certificates
   * };
   * @param {string} jwtToken - Authentication JWT token for API requests.
   */
  constructor(baseURL = ENV.isNode ? 'https://127.0.0.1:6060' : window.location.origin, sslConfig = null, jwtToken = null) {
    /**
     * @property {string} baseURL - The base URL of the App Mesh REST Service.
     */
    this.baseURL = baseURL;
    /**
     * @property {string|null} _jwtToken - Authentication JWT token for API requests. Initially null.
     */
    this._jwtToken = jwtToken;
    /**
     * @property {string|null} forwardingHost - The host to forward requests to, if any. Initially null.
     */
    this.forwardingHost = null;

    // Optimize axios configuration
    const axiosConfig = {
      baseURL,
      timeout: 120000, // Default timeout to 120 seconds
      httpsAgent: ENV.isNode && (sslConfig ?
        new https.Agent(sslConfig) :
        new https.Agent({ rejectUnauthorized: false })),
      validateStatus: status => status >= 200 && status < 500 // Custom status validation
    };

    this._client = axios.create(axiosConfig);
    // Add request interceptor
    this._client.interceptors.request.use(
      config => {
        config.headers = { ...config.headers, ...this._commonHeaders() };
        return config;
      },
      error => Promise.reject(new AppMeshError(error.message))
    );

    // Add response interceptor
    this._client.interceptors.response.use(
      response => response,
      error => Promise.reject(this._handleError(error))
    );
  }

  /**
   * Authenticates the user with the App Mesh service.
   *
   * @async
   * @param {string} username - The username for authentication.
   * @param {string} password - The password for authentication.
   * @param {string|null} [totpCode=null] - Time-based One-Time Password for two-factor authentication. Optional.
   * @param {number|string} [expireSeconds=CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS] - The number of seconds until the token expires.
   *                                                                       Can be a number or an ISO 8601 duration string.
   * @param {string} [audience=CONSTANTS.DEFAULT_JWT_AUDIENCE] - The audience of the JWT token.
   * @returns {Promise<string>} A promise that resolves to the JWT token if login is successful.
   * @throws {Error} If the login fails or if there's a network error.
   */
  async login(username, password, totpCode = null, expireSeconds = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS, audience = CONSTANTS.DEFAULT_JWT_AUDIENCE) {
    const auth = base64Utils.encode(`${username}:${password}`);
    const headers = { Authorization: `Basic ${auth}` };
    if (totpCode) headers["Totp"] = totpCode;
    if (expireSeconds) headers["Expire-Seconds"] = parseDuration(expireSeconds);
    if (audience) headers["Audience"] = audience;

    try {
      this._jwtToken = null;
      const response = await this._request("post", "/appmesh/login", null, { headers });
      if (response.status !== 200) throw new Error(response.data);
      this._jwtToken = response.data["Access-Token"];
      return this._jwtToken;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  /**
   * Authenticates a token and optionally checks for a specific permission.
   *
   * @async
   * @param {string} token - The JWT token to authenticate.
   * @param {string|null} [permission=null] - The specific permission to verify. Optional.
   * @param {string} [audience=CONSTANTS.DEFAULT_JWT_AUDIENCE] - The audience to verify the token against.
   * @returns {Promise<boolean>} A promise that resolves to true if authentication is successful.
   * @throws {Error} If there's a network error or other issues during authentication.
   */
  async authenticate(token, permission = null, audience = CONSTANTS.DEFAULT_JWT_AUDIENCE) {
    const headers = {};
    if (permission) headers["Auth-Permission"] = permission;
    if (audience) headers["Audience"] = audience;
    this._jwtToken = token;
    const response = await this._request("post", "/appmesh/auth", null, { headers });
    return response.status === 200;
  }

  /**
   * Logs out the current user, invalidating their JWT token.
   *
   * @async
   * @returns {Promise<boolean>} A promise that resolves to true if logout is successful, false otherwise.
   * @throws {Error} If there's a network error or other issues during logout.
   */
  async logoff() {
    const response = await this._request("post", "/appmesh/self/logoff");
    return response.status === 200;
  }

  /**
   * Renews the current JWT token, optionally specifying a new expiration time.
   *
   * @async
   * @param {number|string} [expireSeconds=CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS] - The number of seconds until the new token expires.
   *                                                                       Can be a number or an ISO 8601 duration string.
   * @returns {Promise<string>} A promise that resolves to the new JWT token if renewal is successful.
   * @throws {Error} If token renewal fails or if there's a network error.
   */
  async renew_token(expireSeconds = CONSTANTS.DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const headers = {};
    if (expireSeconds) {
      headers["Expire-Seconds"] = parseDuration(expireSeconds);
    }
    const response = await this._request("post", "/appmesh/token/renew", null, { headers });
    this._jwtToken = response.data["Access-Token"];
    return this._jwtToken;
  }

  /**
   * Retrieves the TOTP secret for the current user.
   *
   * @async
   * @returns {Promise<string>} A promise that resolves to the TOTP secret.
   * @throws {Error} If retrieval fails or if there's a network error.
   */
  async get_totp_secret() {
    const response = await this._request("post", "/appmesh/totp/secret");
    return base64Utils.decode(response.data["Mfa-Uri"]);
  }

  /**
   * Sets up TOTP (Two-Factor Authentication) for the current user.
   *
   * @async
   * @param {string} totpCode - The TOTP code to verify and complete setup.
   * @returns {Promise<boolean>} A promise that resolves to true if setup is successful.
   * @throws {Error} If setup fails or if there's a network error.
   */
  async setup_totp(totpCode) {
    const headers = { Totp: totpCode };
    const response = await this._request("post", "/appmesh/totp/setup", null, { headers });
    return response.status === 200;
  }

  /**
   * Disables TOTP (Two-Factor Authentication) for a user.
   *
   * @async
   * @param {string} [user='self'] - The user to disable TOTP for. Defaults to 'self' (the current user).
   * @returns {Promise<boolean>} A promise that resolves to true if TOTP is successfully disabled.
   * @throws {Error} If disabling fails or if there's a network error.
   */
  async disable_totp(user = "self") {
    const response = await this._request("post", `/appmesh/totp/${user}/disable`);
    return response.status === 200;
  }

  /**
   * Retrieves information about all applications.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to an object containing information about all applications.
   * @throws {Error} If there's a network error or other issues during retrieval.
   */
  async view_all_apps() {
    const response = await this._request("get", "/appmesh/applications");
    return response.data;
  }

  /**
   * Retrieves information about a specific application.
   *
   * @async
   * @param {string} name - The name of the application to view.
   * @returns {Promise<Object>} A promise that resolves to an object containing information about the specified application.
   * @throws {Error} If there's a network error or other issues during retrieval.
   */
  async view_app(name) {
    const response = await this._request("get", `/appmesh/app/${name}`);
    return response.data;
  }

  /**
   * Checks the health status of a specific application.
   *
   * @async
   * @param {string} name - The name of the application to check.
   * @returns {Promise<boolean>} A promise that resolves to true if the application is healthy, false otherwise.
   * @throws {Error} If there's a network error or other issues during the health check.
   */
  async check_app_health(name) {
    const response = await this._request("get", `/appmesh/app/${name}/health`);
    return response.data === 0;
  }

  /**
   * Adds a new application or updates an existing one.
   *
   * @async
   * @param {string} name - The name of the application to add or update.
   * @param {Object} appJson - The application configuration in JSON format:
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
   * @returns {Promise<Object>} The resigtered application json object.
   * @throws {Error} If there's a network error or other issues during the operation.
   */
  async add_app(name, appJson) {
    const response = await this._request("put", `/appmesh/app/${name}`, appJson);
    return response.data;
  }

  /**
   * Deletes a specific application.
   *
   * @async
   * @param {string} name - The name of the application to delete.
   * @returns {Promise<boolean>} A promise that resolves to true if the deletion is successful.
   * @throws {Error} If there's a network error or other issues during the deletion.
   */
  async delete_app(name) {
    const response = await this._request("delete", `/appmesh/app/${name}`);
    return response.status === 200;
  }

  /**
   * Enables a specific application.
   *
   * @async
   * @param {string} name - The name of the application to enable.
   * @returns {Promise<boolean>} A promise that resolves to true if the application is successfully enabled.
   * @throws {Error} If there's a network error or other issues during the operation.
   */
  async enable_app(name) {
    const response = await this._request("post", `/appmesh/app/${name}/enable`);
    return response.status === 200;
  }

  /**
   * Disables a specific application.
   *
   * @async
   * @param {string} name - The name of the application to disable.
   * @returns {Promise<boolean>} A promise that resolves to true if the application is successfully disabled, false if not found.
   * @throws {Error} If there's a network error or other issues during the operation.
   */
  async disable_app(name) {
    const response = await this._request("post", `/appmesh/app/${name}/disable`);
    return response.status === 200;
  }

  /**
   * Retrieves the output of a running application.
   *
   * @async
   * @param {string} app_name - The name of the application.
   * @param {number} [stdout_position=0] - The starting position of the stdout to retrieve.
   * @param {number} [stdout_index=0] - The index of the stdout to retrieve.
   * @param {number} [stdout_maxsize=10240] - The maximum size of stdout to retrieve.
   * @param {string} [process_uuid=""] - The UUID of the process.
   * @param {number} [timeout=0] - The timeout for the request.
   * @returns {Promise<AppOutput>} A promise that resolves to an AppOutput object containing the application's output.
   * @throws {Error} If there's a network error or other issues during retrieval.
   */
  async get_app_output(app_name, stdout_position = 0, stdout_index = 0, stdout_maxsize = 10240, process_uuid = "", timeout = 0) {
    try {
      const params = {
        stdout_position: stdout_position.toString(),
        stdout_index: stdout_index.toString(),
        stdout_maxsize: stdout_maxsize.toString(),
        process_uuid: process_uuid,
        timeout: parseDuration(timeout)
      };

      const response = await this._request("get", `/appmesh/app/${app_name}/output`, null, { params });
      const outPosition = response.headers["output-position"] ? parseInt(response.headers["output-position"]) : null;
      const exitCode = response.headers["exit-code"] ? parseInt(response.headers["exit-code"]) : null;
      return new AppOutput(response.status, response.data, outPosition, exitCode);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  /**
   * Runs an application synchronously.
   *
   * @async
   * @param {Object} app - The application configuration.
   * @param {Function} [outputHandler=defaultOutputHandler] - A function to handle the application's output.
   * @param {number|string} [maxTimeSeconds=CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS] - The maximum time to run the application.
   * @param {number|string} [lifeCycleSeconds=CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS] - The lifecycle time for the application.
   * @returns {Promise<number|null>} A promise that resolves to the exit code of the application, or null if not available.
   * @throws {Error} If there's a network error or other issues during execution.
   */
  async run_app_sync(app, outputHandler = defaultOutputHandler, maxTimeSeconds = CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifeCycleSeconds = CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = {
      timeout: parseDuration(maxTimeSeconds),
      lifecycle: parseDuration(lifeCycleSeconds)
    };

    try {
      const response = await this._request("post", "/appmesh/app/syncrun", app, { params });
      let exitCode = null;

      if (response.status === 200) {
        if (outputHandler) {
          outputHandler(response.data);
        }
        if (response.headers["exit-code"]) {
          exitCode = parseInt(response.headers["exit-code"]);
        }
      } else if (outputHandler) {
        outputHandler(response.data);
      }

      return exitCode;
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

  /**
   * Runs an application asynchronously.
   *
   * @async
   * @param {Object} app - The application configuration.
   * @param {number|string} [maxTimeSeconds=CONSTANTS.DEFAULT_RUN_APP_TIMEOUT_SECONDS] - The maximum time to run the application.
   * @param {number|string} [lifeCycleSeconds=CONSTANTS.DEFAULT_RUN_APP_LIFECYCLE_SECONDS] - The lifecycle time for the application.
   * @returns {Promise<AppRun>} A promise that resolves to an AppRun object representing the running application.
   * @throws {Error} If there's a network error or other issues during execution.
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
   * Waits for an asynchronously running application to complete and retrieves its output.
   *
   * @async
   * @param {AppRun} run - The AppRun object representing the running application.
   * @param {Function} [outputHandler=defaultOutputHandler] - A function to handle the application's output.
   * @param {number} [timeout=0] - The maximum time to wait for the application to complete.
   * @returns {Promise<number|null>} A promise that resolves to the exit code of the application, or null if not available.
   * @throws {Error} If there's a network error or other issues during execution.
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
            // success
            await this.delete_app(run.appName);
            return appOut.exitCode;
          }

          if (appOut.statusCode !== 200) {
            // failed
            break;
          }

          if (timeout > 0 && (new Date() - start) / 1000 > timeout) {
            // timeout
            break;
          }
          // Add a small delay to prevent tight looping
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
   * Copy a remote file to local. Optionally apply the same permissions as the remote file.
   * @param {string} filePath - The remote file path.
   * @param {string} localFile - The local file path to be downloaded.
   * @param {boolean} [applyFileAttributes=true] - Whether to apply the file permissions (mode, owner, group) 
   *                                               from the remote file to the local file. Default is true.
   * @throws {AppMeshError} If there's a network error or other issues during execution.
   */
  async download_file(filePath, localFile, applyFileAttributes = true) {
    try {
      const headers = { "File-Path": filePath };
      const response = await this._request("get", "/appmesh/file/download", null, {
        headers,
        config: {
          responseType: "arraybuffer"
        }
      });

      if (response.status !== 200) {
        throw new Error(new TextDecoder().decode(response.data));
      }

      if (ENV.isNode) {
        const fs = await import('fs/promises');
        await fs.writeFile(localFile, Buffer.from(response.data));

        if (applyFileAttributes) {
          const { headers } = response;
          try {
            if (headers["file-mode"]) {
              await fs.chmod(localFile, parseInt(headers["file-mode"]));
            }
            if (headers["file-user"] && headers["file-group"]) {
              await fs.chown(
                localFile,
                parseInt(headers["file-user"]),
                parseInt(headers["file-group"])
              );
            }
          } catch (ex) {
            console.warn("Failed to apply file attributes:", ex.message);
          }
        }
      } else {
        // Browser environment
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
    } catch (error) {
      throw new AppMeshError(`Download failed: ${error.message}`);
    }
  }

  /**
   * Upload a local file to the remote server. Optionally apply the same permissions as the local file.
   * 
   * @param {string|File} localFile - The local file path or File object.
   * @param {string} filePath - The target remote file to be uploaded.
   * @param {boolean} [applyFileAttributes=true] - Whether to apply the file permissions (mode, owner, group) 
   *                                               from the local file to the remote file. Default is true.
   * @throws {AppMeshError} If there's a network error or other issues during execution.
   */
  async upload_file(localFile, filePath, applyFileAttributes = true) {
    try {
      const headers = { "File-Path": filePath };
      let formData;

      if (ENV.isNode) {
        // Only load modules in Node.js environment
        const FormData = (await import('form-data')).default;
        const fs = await import('fs');
        formData = new FormData();

        const filename = filePath.split('/').pop();
        formData.append("filename", filename);

        const stat = fs.statSync(localFile);
        if (stat.size < 10 * 1024 * 1024) {
          // For files smaller than 10MB, read into buffer for better performance
          const fileBuffer = fs.readFileSync(localFile);
          formData.append("file", fileBuffer, { filename: localFile.split('/').pop() });
        } else {
          // Use stream for larger files
          formData.append("file", fs.createReadStream(localFile));
        }

        // Add file attributes if requested
        if (applyFileAttributes) {
          headers["File-Mode"] = stat.mode.toString();
          headers["File-User"] = stat.uid.toString();
          headers["File-Group"] = stat.gid.toString();
        }

        // Merge with form-data headers for Node.js
        Object.assign(headers, formData.getHeaders());
      } else {
        formData = new FormData();
        formData.append("filename", filePath.split('/').pop());
        formData.append("file", localFile instanceof File ? localFile : new File([localFile], filePath.split('/').pop()));
      }

      const response = await this._request("post", "/appmesh/file/upload", formData, {
        headers,
        config: {
          maxBodyLength: Infinity,
          maxContentLength: Infinity
        }
      });

      if (response.status !== 200) {
        throw new AppMeshError(`Upload failed: ${response.data}`, response.status);
      }
    } catch (error) {
      throw new AppMeshError(`Upload failed: ${error.message}`);
    }
  }

  /**
   * Gets the App Mesh host resource report including CPU, memory, and disk usage.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to the host resource JSON.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_host_resources() {
    const response = await this._request("get", "/appmesh/resources");
    return response.data;
  }

  /**
   * Retrieves the current App Mesh configuration.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to the configuration JSON.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_config() {
    const response = await this._request("get", "/appmesh/config");
    return response.data;
  }

  /**
   * Updates the App Mesh configuration. Supports partial updates.
   *
   * @async
   * @param {Object} configJsonSection - The new configuration JSON. Format should follow 'config.yaml'.
   * @returns {Promise<Object>} A promise that resolves to the updated configuration JSON.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async set_config(configJsonSection) {
    const response = await this._request("post", "/appmesh/config", configJsonSection);
    return response.data;
  }

  /**
   * Updates the App Mesh log level. This is a wrapper around configSet().
   *
   * @async
   * @param {string} [level="DEBUG"] - The new log level. Can be "DEBUG", "INFO", "NOTICE", "WARN", or "ERROR".
   * @returns {Promise<string>} A promise that resolves to the updated log level.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async set_log_level(level = "DEBUG") {
    const response = await this.set_config({ BaseConfig: { LogLevel: level } });
    return response.BaseConfig.LogLevel;
  }

  /**
   * Adds a new label (tag) to the server.
   *
   * @async
   * @param {string} tagName - The name of the label to add.
   * @param {string} tagValue - The value of the label to add.
   * @returns {Promise<boolean>} A promise that resolves to true if the label was added successfully, false otherwise.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async add_tag(tagName, tagValue) {
    const response = await this._request("put", `/appmesh/label/${tagName}`, null, { params: { value: tagValue } });
    return response.status === 200;
  }

  /**
   * Deletes a label (tag) from the server.
   *
   * @async
   * @param {string} tagName - The name of the label to delete.
   * @returns {Promise<boolean>} A promise that resolves to true if the label was deleted successfully, false otherwise.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async delete_tag(tagName) {
    const response = await this._request("delete", `/appmesh/label/${tagName}`);
    return response.status === 200;
  }

  /**
   * Retrieves all labels (tags) from the server.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to an object containing all server labels.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_tags() {
    const response = await this._request("get", "/appmesh/labels");
    return response.data;
  }

  /**
   * Changes a user's password.
   *
   * @async
   * @param {string} newPassword - The new password.
   * @param {string} [userName="self"] - The username of the account to update. Defaults to "self".
   * @returns {Promise<boolean>} A promise that resolves to true if the password was updated successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async update_user_password(newPassword, userName = "self") {
    const headers = { "New-Password": base64Utils.encode(newPassword) };
    const response = await this._request("post", `/appmesh/user/${userName}/passwd`, null, { headers });
    return response.status === 200;
  }

  /**
   * Adds a new user. Not available for LDAP users.
   *
   * @async
   * @param {string} userName - The username of the new account.
   * @param {Object} userJson - User definition, following the same user format from security.yaml.
   * @returns {Promise<boolean>} A promise that resolves to true if the user was added successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async add_user(userName, userJson) {
    const response = await this._request("put", `/appmesh/user/${userName}`, userJson);
    return response.status === 200;
  }

  /**
   * Deletes a user.
   *
   * @async
   * @param {string} userName - The username of the account to delete.
   * @returns {Promise<boolean>} A promise that resolves to true if the user was deleted successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async delete_user(userName) {
    const response = await this._request("delete", `/appmesh/user/${userName}`);
    return response.status === 200;
  }

  /**
   * Locks a user account.
   *
   * @async
   * @param {string} userName - The username of the account to lock.
   * @returns {Promise<boolean>} A promise that resolves to true if the user was locked successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async lock_user(userName) {
    const response = await this._request("post", `/appmesh/user/${userName}/lock`);
    return response.status === 200;
  }

  /**
   * Unlocks a user account.
   *
   * @async
   * @param {string} userName - The username of the account to unlock.
   * @returns {Promise<boolean>} A promise that resolves to true if the user was unlocked successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async unlock_user(userName) {
    const response = await this._request("post", `/appmesh/user/${userName}/unlock`);
    return response.status === 200;
  }

  /**
   * Retrieves all user definitions.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to an object containing all user definitions.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_users() {
    const response = await this._request("get", "/appmesh/users");
    return response.data;
  }

  /**
   * Retrieves current user information.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to an object containing the current user's definition.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_self() {
    const response = await this._request("get", "/appmesh/user/self");
    return response.data;
  }

  /**
   * Retrieves all user groups.
   *
   * @async
   * @returns {Promise<Array>} A promise that resolves to an array of user groups.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_groups() {
    const response = await this._request("get", "/appmesh/user/groups");
    return response.data;
  }

  /**
   * Retrieves all available permissions.
   *
   * @async
   * @returns {Promise<Array>} A promise that resolves to an array of all available permissions.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_permissions() {
    const response = await this._request("get", "/appmesh/permissions");
    return response.data;
  }

  /**
   * Retrieves current user permissions.
   *
   * @async
   * @returns {Promise<Array>} A promise that resolves to an array of the current user's permissions.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_user_permissions() {
    const response = await this._request("get", "/appmesh/user/permissions");
    return response.data;
  }

  /**
   * Retrieves all roles with permission definitions.
   *
   * @async
   * @returns {Promise<Array>} A promise that resolves to an array of all role definitions.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async view_roles() {
    const response = await this._request("get", "/appmesh/roles");
    return response.data;
  }

  /**
   * Updates (or adds) a role with defined permissions.
   *
   * @async
   * @param {string} roleName - The name of the role to update or add.
   * @param {Object} rolePermissionJson - An array of permission IDs for the role.
   * @returns {Promise<boolean>} A promise that resolves to true if the role was updated successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async update_role(roleName, rolePermissionJson) {
    const response = await this._request("post", `/appmesh/role/${roleName}`, rolePermissionJson);
    return response.status === 200;
  }

  /**
   * Deletes a user role.
   *
   * @async
   * @param {string} roleName - The name of the role to delete.
   * @returns {Promise<boolean>} A promise that resolves to true if the role was deleted successfully.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async delete_role(roleName) {
    const response = await this._request("delete", `/appmesh/role/${roleName}`);
    return response.status === 200;
  }

  /**
   * Retrieves Prometheus metrics data.
   *
   * This method does not call the Prometheus API /metrics directly,
   * but instead retrieves a copy of the same metrics data from App Mesh.
   *
   * @async
   * @returns {Promise<string>} A promise that resolves to the Prometheus metrics text.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async metrics() {
    const response = await this._request("get", "/appmesh/metrics", { responseType: "text" });
    return response.data;
  }

  _commonHeaders() {
    const headers = { [CONSTANTS.HTTP_USER_AGENT_HEADER_NAME]: CONSTANTS.HTTP_USER_AGENT };
    if (this._jwtToken) {
      headers["Authorization"] = `Bearer ${this._jwtToken}`;
    }
    if (this.forwardingHost) {
      if (this.forwardingHost.includes(":")) {
        headers["X-Target-Host"] = this.forwardingHost;
      } else {
        const parsedUrl = new URL(this.baseURL);
        headers["X-Target-Host"] = `${this.forwardingHost}:${parsedUrl.port}`;
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
   * @param {Object} [options.headers={}] - Additional headers to include
   * @param {Object} [options.params={}] - Query parameters to include
   * @param {Object} [options.config={}] - Additional Axios config options
   * @returns {Promise<any>} The http response object
   * @throws {Error} If the request fails or returns a non-200 status
   */
  async _request(method, path, body = null, options = {}) {
    const { headers = {}, params = {}, config = {} } = options;

    try {
      const requestConfig = {
        method,
        url: path,
        ...config,
        headers: { ...headers },
        params: { ...params }
      };

      if (body !== null) {
        requestConfig.data = body;
      }

      const response = await this._client(requestConfig);
      return response;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  // Optimized error handling
  _handleError(error) {
    if (error.response) {
      const { status, data } = error.response;
      return new AppMeshError(
        `HTTP ${status}: ${typeof data === 'object' ? JSON.stringify(data) : data}`,
        status,
        data
      );
    }
    if (error.request) {
      return new AppMeshError('No response received from server');
    }
    return new AppMeshError(error.message);
  }
}

/**
 * Class representing output from an AppMesh application
 * Immutable after creation
 */
class AppOutput {
  /**
   * App output object for app_output() method
   * @param {number} statusCode - HTTP status code
   * @param {string} output - HTTP response text
   * @param {number|null} outPosition - Current read position (number or null)
   * @param {number|null} exitCode - Process exit code (number or null)
   */
  constructor(statusCode, output, outPosition, exitCode) {
    Object.assign(this, {
      statusCode: Number(statusCode),
      output: String(output),
      outPosition: outPosition !== null ? Number(outPosition) : null,
      exitCode: exitCode !== null ? Number(exitCode) : null
    });
    Object.freeze(this); // Make instance immutable
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
   * Wait for an async run to be finished
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
export { AppMeshClient, AppOutput, AppRun };
export default AppMeshClient;
