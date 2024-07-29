// appmesh.js
const axios = require("axios");
const https = require("https");
const base64 = require("base-64");
const { parse, toSeconds } = require("iso8601-duration");
const validate_params = require("./validate_params");

const HTTP_USER_AGENT_HEADER_NAME = "User-Agent";
const HTTP_USER_AGENT = "appmesh/javascript";
const DEFAULT_TOKEN_EXPIRE_SECONDS = "P1W"; // default 7 day(s)
const DEFAULT_RUN_APP_TIMEOUT_SECONDS = "P2D"; // 2 days
const DEFAULT_RUN_APP_LIFECYCLE_SECONDS = "P2DT12H"; // 2.5 days

// Default output handler if none is provided
const defaultOutputHandler = (output) => {
  if (typeof process !== "undefined" && process.stdout) {
    process.stdout.write(output);
  } else {
    console.log(output);
  }
};

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
  constructor(baseURL, sslConfig = null, jwtToken = null) {
    /**
     * @property {string} baseURL - The base URL of the App Mesh REST Service.
     */
    this.baseURL = baseURL;
    /**
     * @property {string|null} _jwtToken - Authentication JWT token for API requests. Initially null.
     */
    this._jwtToken = jwtToken;
    /**
     * @property {string|null} delegateHost - The host to delegate requests to, if any. Initially null.
     */
    this.delegateHost = null;
    /**
     * @property {AxiosInstance} _client - Axios instance for making HTTP requests.
     * Configured with the base URL and custom HTTPS agent for SSL verification.
     */
    this._client = axios.create({
      baseURL,
      httpsAgent: sslConfig ? new https.Agent(sslConfig) : new https.Agent({ rejectUnauthorized: false }),
    });
  }

  /**
   * Authenticates the user with the App Mesh service.
   *
   * @async
   * @param {string} username - The username for authentication.
   * @param {string} password - The password for authentication.
   * @param {string|null} [totpCode=null] - Time-based One-Time Password for two-factor authentication. Optional.
   * @param {number|string} [expireSeconds=DEFAULT_TOKEN_EXPIRE_SECONDS] - The number of seconds until the token expires.
   *                                                                       Can be a number or an ISO 8601 duration string.
   * @returns {Promise<string>} A promise that resolves to the JWT token if login is successful.
   * @throws {Error} If the login fails or if there's a network error.
   */
  @validate_params({
    username: [["isValidName", "User name must be a non-empty string"]],
    password: [["isValidString", "User password must be a non-empty string"]],
    totpCode: [
      ["isTOTP", "TOTP code must be a 6-digit string or number"],
      ["isOptional", "TOTP is optional"],
    ],
    expireSeconds: [["isTimeoutValue", "expireSeconds must be a positive number or a valid ISO 8601 duration string"]],
  })
  async login(username, password, totpCode = null, expireSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const auth = base64.encode(`${username}:${password}`);
    const headers = { Authorization: `Basic ${auth}` };
    if (totpCode) {
      headers["Totp"] = totpCode;
    }
    if (expireSeconds) {
      headers["Expire-Seconds"] = this._toSeconds(expireSeconds);
    }

    try {
      this._jwtToken = null;
      const response = await this._request("post", "/appmesh/login", null, { headers: headers });
      if (response.status !== 200) {
        throw new Error(response.data);
      }
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
   * @returns {Promise<boolean>} A promise that resolves to true if authentication is successful, false otherwise.
   * @throws {Error} If there's a network error or other issues during authentication.
   */
  @validate_params({
    token: [["isValidName", "Token must be a non-empty string"]],
    permission: [
      ["permission", "Permission must be a non-empty string"],
      ["isOptional", "Permission is optional"],
    ],
  })
  async authentication(token, permission = null) {
    const headers = {};
    if (permission) {
      headers["Auth-Permission"] = permission;
    }
    this._jwtToken = token;
    const response = await this._request("post", "/appmesh/auth", null, { headers: headers });
    return response.status === 200;
  }

  /**
   * Logs out the current user, invalidating their JWT token.
   *
   * @async
   * @returns {Promise<boolean>} A promise that resolves to true if logout is successful, false otherwise.
   * @throws {Error} If there's a network error or other issues during logout.
   */
  async logout() {
    const response = await this._request("post", "/appmesh/self/logoff");
    return response.status === 200;
  }

  /**
   * Renews the current JWT token, optionally specifying a new expiration time.
   *
   * @async
   * @param {number|string} [expireSeconds=DEFAULT_TOKEN_EXPIRE_SECONDS] - The number of seconds until the new token expires.
   *                                                                       Can be a number or an ISO 8601 duration string.
   * @returns {Promise<string>} A promise that resolves to the new JWT token if renewal is successful.
   * @throws {Error} If token renewal fails or if there's a network error.
   */
  @validate_params({ expireSeconds: [["isTimeoutValue", "expireSeconds must be a positive number or a valid ISO 8601 duration string"]] })
  async renew(expireSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const headers = { "New-Password": base64.encode(newPassword) };
    if (expireSeconds) {
      headers["Expire-Seconds"] = this._toSeconds(expireSeconds);
    }
    const response = await this._request("post", "/appmesh/token/renew", null, { headers: headers });
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
  async totp_secret() {
    const response = await this._request("post", "/appmesh/totp/secret");
    return base64.decode(response.data["Mfa-Uri"]);
  }

  /**
   * Sets up TOTP (Two-Factor Authentication) for the current user.
   *
   * @async
   * @param {string} totpCode - The TOTP code to verify and complete setup.
   * @returns {Promise<boolean>} A promise that resolves to true if setup is successful.
   * @throws {Error} If setup fails or if there's a network error.
   */
  @validate_params({ totpCode: [["isTOTP", "TOTP code must be a 6-digit string or number"]] })
  async totp_setup(totpCode) {
    const headers = { Totp: totpCode };
    const response = await this._request("post", "/appmesh/totp/setup", null, { headers: headers });
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
  @validate_params({ user: [["isValidName", "User name must be a non-empty string"]] })
  async totp_disable(user = "self") {
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
  async app_view_all() {
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
  @validate_params({ name: [["isValidName", "Application name must be a non-empty string"]] })
  async app_view(name) {
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
  @validate_params({ name: [["isValidName", "Application name must be a non-empty string"]] })
  async app_health(name) {
    const response = await this._request("get", `/appmesh/app/${name}/health`);
    return response.data === "0";
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
  @validate_params({
    name: [["isValidName", "Application name must be a non-empty string"]],
    appJson: [["isObject", "Application definition must be an object"]],
  })
  async app_add(name, appJson) {
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
  @validate_params({ name: [["isValidName", "Application name must be a non-empty string"]] })
  async app_delete(name) {
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
  @validate_params({ name: [["isValidName", "Application name must be a non-empty string"]] })
  async app_enable(name) {
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
  @validate_params({ name: [["isValidName", "Application name must be a non-empty string"]] })
  async app_disable(name) {
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
  @validate_params({
    name: [["isValidName", "Application name must be a non-empty string"]],
    stdout_position: [["isNumber", "stdout_position must be a positive number"]],
    stdout_index: [["isNumber", "stdout_index must be a positive number"]],
    stdout_maxsize: [["isNumber", "stdout_maxsize must be a positive number"]],
    process_uuid: [["isString", "process_uuid must be a non-empty string"]],
    timeout: [["isTimeoutValue", "timeout must be a positive number or a valid ISO 8601 duration string"]],
  })
  async app_output(app_name, stdout_position = 0, stdout_index = 0, stdout_maxsize = 10240, process_uuid = "", timeout = 0) {
    try {
      const params = {};
      params.stdout_position = stdout_position.toString();
      params.stdout_index = stdout_index.toString();
      params.stdout_maxsize = stdout_maxsize.toString();
      params.process_uuid = process_uuid;
      params.timeout = this._toSeconds(timeout);

      const response = await this._request("get", `/appmesh/app/${app_name}/output`, null, { params: params });
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
   * @param {number|string} [maxTimeSeconds=DEFAULT_RUN_APP_TIMEOUT_SECONDS] - The maximum time to run the application.
   * @param {number|string} [lifeCycleSeconds=DEFAULT_RUN_APP_LIFECYCLE_SECONDS] - The lifecycle time for the application.
   * @returns {Promise<number|null>} A promise that resolves to the exit code of the application, or null if not available.
   * @throws {Error} If there's a network error or other issues during execution.
   */
  @validate_params({
    app: [["isObject", "Application definition must be an object"]],
    outputHandler: [["isFunction", "outputHandler must be a function used to accept output string"]],
    maxTimeSeconds: [["isTimeoutValue", "maxTimeSeconds must be a positive number or a valid ISO 8601 duration string"]],
    lifeCycleSeconds: [["isTimeoutValue", "lifeCycleSeconds must be a positive number or a valid ISO 8601 duration string"]],
  })
  async run_sync(
    app,
    outputHandler = defaultOutputHandler,
    maxTimeSeconds = DEFAULT_RUN_APP_TIMEOUT_SECONDS,
    lifeCycleSeconds = DEFAULT_RUN_APP_LIFECYCLE_SECONDS
  ) {
    const params = { timeout: this._toSeconds(maxTimeSeconds), lifecycle: this._toSeconds(lifeCycleSeconds) };
    try {
      const response = await this._request("post", "/appmesh/app/syncrun", app, { params: params });
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
   * @param {number|string} [maxTimeSeconds=DEFAULT_RUN_APP_TIMEOUT_SECONDS] - The maximum time to run the application.
   * @param {number|string} [lifeCycleSeconds=DEFAULT_RUN_APP_LIFECYCLE_SECONDS] - The lifecycle time for the application.
   * @returns {Promise<AppRun>} A promise that resolves to an AppRun object representing the running application.
   * @throws {Error} If there's a network error or other issues during execution.
   */
  @validate_params({
    app: [["isObject", "Application definition must be an object"]],
    maxTimeSeconds: [["isTimeoutValue", "maxTimeSeconds must be a positive number or a valid ISO 8601 duration string"]],
    lifeCycleSeconds: [["isTimeoutValue", "lifeCycleSeconds must be a positive number or a valid ISO 8601 duration string"]],
  })
  async run_async(app, maxTimeSeconds = DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifeCycleSeconds = DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const params = { timeout: this._toSeconds(maxTimeSeconds), lifecycle: this._toSeconds(lifeCycleSeconds) };

    const response = await this._request("post", "/appmesh/app/run", app, { params: params });
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
  async run_async_wait(run, outputHandler = defaultOutputHandler, timeout = 0) {
    if (run) {
      let lastOutputPosition = 0;
      const start = new Date();
      const interval = 1;

      while (run.procUid.length > 0) {
        try {
          const appOut = await this.app_output(run.appName, lastOutputPosition, 0, 20480, run.procUid, interval);
          if (appOut.output && outputHandler) {
            outputHandler(appOut.output);
          }

          if (appOut.outPosition !== null) {
            lastOutputPosition = appOut.outPosition;
          }

          if (appOut.exitCode !== null) {
            // success
            await this.app_delete(run.appName);
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
   * Copy a remote file to local, the local file will have the same permission as the remote file
   * @param {string} filePath - The remote file path.
   * @param {string} localFile - The local file path to be downloaded.
   * @returns {Promise<boolean>} Success or failure.
   */
  async file_download(filePath, localFile) {
    try {
      const headers = { "File-Path": filePath };
      const response = await this._request("get", "/appmesh/file/download", null, {
        headers: headers,
        config: {
          responseType: "arraybuffer", // This is crucial for binary files
        },
      });

      if (response.status !== 200) {
        throw new Error(new TextDecoder().decode(response.data));
      }

      if (typeof window === "undefined") {
        // Node.js environment
        const fs = require("fs").promises;
        await fs.writeFile(localFile, Buffer.from(response.data));

        if (response.headers["file-mode"]) {
          await fs.chmod(localFile, parseInt(response.headers["file-mode"]));
        }

        if (response.headers["file-user"] && response.headers["file-group"]) {
          const fileUid = parseInt(response.headers["file-user"]);
          const fileGid = parseInt(response.headers["file-group"]);
          try {
            await fs.chown(localFile, fileUid, fileGid);
          } catch (ex) {
            console.log("Failed to change file ownership:", ex);
          }
        }
      } else {
        // Web browser environment
        const blob = new Blob([response.data]); // response.data is already an ArrayBuffer
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.style.display = "none";
        a.href = url;
        a.download = localFile.split("/").pop(); // Use just the filename
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
      }

      return true;
    } catch (error) {
      console.error("Download failed:", error);
      return false;
    }
  }
  /**
   * Upload a local file to the remote server, the remote file will have the same permission as the local file
   * @param {string|File} localFile - The local file path or File object.
   * @param {string} filePath - The target remote file to be uploaded.
   * @returns {Promise<boolean>} Success or failure.
   */
  async file_upload(localFile, filePath) {
    try {
      const headers = this._commonHeaders();
      headers["File-Path"] = filePath;
      let formData;

      if (typeof window === "undefined") {
        // Node.js environment
        const fs = require("fs");
        const path = require("path");
        const FormData = require("form-data");

        formData = new FormData();
        formData.append("filename", path.basename(filePath));

        const stat = fs.statSync(localFile);
        if (stat.size < 10 * 1024 * 1024) {
          // If file is smaller than 10MB
          // Read file into buffer for small files
          const fileBuffer = fs.readFileSync(localFile);
          formData.append("file", fileBuffer, { filename: path.basename(localFile) });
        } else {
          // Use stream for larger files
          formData.append("file", fs.createReadStream(localFile));
        }

        headers["File-Mode"] = stat.mode.toString();
        headers["File-User"] = stat.uid.toString();
        headers["File-Group"] = stat.gid.toString();

        // When using form-data, we need to set the content type manually for Axios
        headers["Content-Type"] = `multipart/form-data; boundary=${formData.getBoundary()}`;
      } else {
        // Web browser environment
        formData = new FormData();
        formData.append("filename", filePath.split("/").pop());
        formData.append("file", localFile instanceof File ? localFile : new File([localFile], filePath.split("/").pop()));

        // In browser, Axios will set the correct Content-Type header automatically
      }

      const response = await this._request("post", "/appmesh/file/upload", formData, {
        headers: headers,
        config: {
          maxBodyLength: Infinity, // Allow for large file uploads
          maxContentLength: Infinity,
        },
      });

      if (response.status !== 200) {
        throw new Error(response.data);
      }

      return true;
    } catch (error) {
      console.error("Upload failed:", error);
      return false;
    }
  }

  /**
   * Gets the App Mesh host resource report including CPU, memory, and disk usage.
   *
   * @async
   * @returns {Promise<Object>} A promise that resolves to the host resource JSON.
   * @throws {Error} If there's a network error or the server responds with a non-200 status.
   */
  async host_resource() {
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
  async config_view() {
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
  @validate_params({ configJsonSection: [["isObject", "Configuration definition must be an object"]] })
  async config_set(configJsonSection) {
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
  async log_level_set(level = "DEBUG") {
    const response = await this.config_set({ BaseConfig: { LogLevel: level } });
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
  @validate_params({ tagName: [["isValidName", "Tag name must be a non-empty string"]] })
  async tag_add(tagName, tagValue) {
    const response = await this._request("put", `/appmesh/label/${tagName}`, null, { params: { value: tagValue }, headers: headers });
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
  @validate_params({ tagName: [["isValidName", "Tag name must be a non-empty string"]] })
  async tag_delete(tagName) {
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
  async tag_view() {
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
  @validate_params({
    newPassword: [["isValidString", "New password must be a non-empty string"]],
    userName: [["isValidName", "User name must be a non-empty string"]],
  })
  async user_passwd_update(newPassword, userName = "self") {
    const headers = { "New-Password": base64.encode(newPassword) };
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
  @validate_params({ userName: [["isValidName", "User name must be a non-empty string"]] })
  async user_add(userName, userJson) {
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
  @validate_params({ userName: [["isValidName", "User name must be a non-empty string"]] })
  async user_delete(userName) {
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
  @validate_params({ userName: [["isValidName", "User name must be a non-empty string"]] })
  async user_lock(userName) {
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
  @validate_params({ userName: [["isValidName", "User name must be a non-empty string"]] })
  async user_unlock(userName) {
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
  async users_view() {
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
  async user_self() {
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
  async groups_view() {
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
  async permissions_view() {
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
  async permissions_for_user() {
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
  async roles_view() {
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
  @validate_params({ roleName: [["isValidName", "Role name must be a non-empty string"]] })
  async role_update(roleName, rolePermissionJson) {
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
  @validate_params({ roleName: [["isValidName", "Role name must be a non-empty string"]] })
  async role_delete(roleName) {
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
    // TODO: metric no need auth key
    const response = await this._request("get", "/appmesh/metrics", { responseType: "text" });
    return response.data;
  }

  // Common function to create headers
  _commonHeaders() {
    const headers = { HTTP_USER_AGENT_HEADER_NAME: HTTP_USER_AGENT };
    if (this._jwtToken) {
      headers["Authorization"] = `Bearer ${this._jwtToken}`;
    }
    if (this.delegateHost) {
      if (this.delegateHost.includes(":")) {
        headers["X-Target-Host"] = this.delegateHost;
      } else {
        const parsedUrl = new URL(this.baseURL);
        headers["X-Target-Host"] = `${this.delegateHost}:${parsedUrl.port}`;
      }
    }
    return headers;
  }

  _toSeconds(input) {
    if (typeof input === "number") {
      return input;
    }

    if (typeof input === "string") {
      try {
        return toSeconds(parse(input));
      } catch (error) {
        throw new Error("Invalid ISO 8601 duration string");
      }
    }
    throw new Error("Invalid input type. Expected number or ISO 8601 duration string.");
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
      let response;
      const mergedConfig = {
        ...config,
        headers: { ...this._commonHeaders(), ...headers },
        params: { ...params },
      };

      switch (method.toLowerCase()) {
        case "get":
        case "delete":
          response = await this._client[method](path, mergedConfig);
          break;
        case "post":
        case "put":
        case "patch":
          response = await this._client[method](path, body, mergedConfig);
          break;
        default:
          throw new Error(`Unsupported HTTP method: ${method}`);
      }

      return response;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  // Error handling
  _handleError(error) {
    if (error.response) {
      const { status, data } = error.response;
      return new Error(`HTTP ${status}: ${JSON.stringify(data)}`);
    }
    return error;
  }
}

class AppOutput {
  /**
   * App output object for app_output() method
   * @param {number} statusCode - HTTP status code
   * @param {string} output - HTTP response text
   * @param {number|null} outPosition - Current read position (number or null)
   * @param {number|null} exitCode - Process exit code (number or null)
   */
  constructor(statusCode, output, outPosition, exitCode) {
    /**
     * HTTP status code
     * @type {number}
     */
    this.statusCode = statusCode;

    /**
     * HTTP response text
     * @type {string}
     */
    this.output = output;

    /**
     * Current read position (number or null)
     * @type {number|null}
     */
    this.outPosition = outPosition;

    /**
     * Process exit code (number or null)
     * @type {number|null}
     */
    this.exitCode = exitCode;
  }
}

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
    this._delegateHost = client.delegateHost;
  }

  /**
   * Context manager for delegate host override to self._client
   * @param {function} callback - Function to execute within the delegate host context
   * @returns {Promise<*>} Result of the callback function
   */
  async withDelegateHost(callback) {
    const originalValue = this._client.delegateHost;
    this._client.delegateHost = this._delegateHost;
    try {
      return await callback();
    } finally {
      this._client.delegateHost = originalValue;
    }
  }

  /**
   * Wait for an async run to be finished
   * @param {function} [outputHandler=defaultOutputHandler] - Print remote stdout function
   * @param {number} [timeout=0] - Wait max timeout seconds and return if not finished, 0 means wait until finished
   * @returns {Promise<number|null>} Return exit code if process finished, return null for timeout or exception
   */
  async wait(outputHandler = defaultOutputHandler, timeout = 0) {
    return this.withDelegateHost(() => this._client.run_async_wait(this, outputHandler, timeout));
  }
}

module.exports = { AppMeshClient, AppOutput, AppRun };
