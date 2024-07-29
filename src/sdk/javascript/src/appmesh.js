// appmesh.js

const axios = require("axios");
const https = require("https");
const base64 = require("base-64");
const url = require("url");
const querystring = require("querystring");
const { parse, toSeconds } = require("iso8601-duration");

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
  constructor(baseURL, verifySSL = false) {
    this.baseURL = baseURL;
    this.token = null;
    this.delegateHost = null;
    this.client = axios.create({
      baseURL,
      httpsAgent: new https.Agent({
        rejectUnauthorized: verifySSL,
      }),
    });
  }

  delegate_host(hostName) {
    this.delegateHost = hostName;
  }

  // Login
  async login(username, password, totp = null, expireSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const auth = Buffer.from(`${username}:${password}`).toString("base64");
    const headers = { Authorization: `Basic ${auth}` };
    if (totp) {
      headers["Totp"] = totp;
    }
    if (expireSeconds) {
      headers["Expire-Seconds"] = this._toSeconds(expireSeconds);
    }

    try {
      this.token = null;
      const response = await this.client.post("/appmesh/login", null, { headers });
      if (response.status !== 200) {
        throw new Error(response.data);
      }
      this.token = response.data["Access-Token"];
      return this.token;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async authentication(token, permission = null) {
    try {
      const headers = this._createHeaders();
      if (permission) {
        headers["Auth-Permission"] = permission;
      }
      const response = await this.client.post("/appmesh/auth", null, { headers: headers });

      if (response.status === 200) {
        this.token = token;
        return true;
      }
      return false;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async logout() {
    try {
      const headers = this._createHeaders();
      const response = await this.client.post("/appmesh/self/logoff", null, { headers: headers });
      this.token = null;
      return response.status === 200;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async renew(expireSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS) {
    const headers = this._createHeaders();
    if (expireSeconds) {
      headers["Expire-Seconds"] = this._toSeconds(expireSeconds);
    }

    try {
      const response = await this.client.post("/appmesh/token/renew", null, { headers: headers });
      if (response.status === 200) {
        this.token = response.data["Access-Token"];
        return this.token;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async totp_secret() {
    try {
      const headers = this._createHeaders();
      const response = await this.client.post("/appmesh/totp/secret", null, { headers: headers });
      if (response.status === 200) {
        const totpUri = base64.decode(response.data["Mfa-Uri"]);
        return querystring.parse(url.parse(totpUri).query).secret;
      } else {
        throw new Error(response.data);
      }
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async totp_setup(totpCode) {
    try {
      const headers = this._createHeaders();
      headers["Totp"] = totpCode;
      const response = await this.client.post("/appmesh/totp/setup", null, { headers: headers });
      if (response.status === 200) {
        return true;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async totp_disable(user = "self") {
    try {
      const headers = this._createHeaders();
      const response = await this.client.post(`/appmesh/totp/${user}/disable`, null, { headers: headers });
      if (response.status === 200) {
        return true;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  // Applications
  async app_view_all() {
    try {
      const headers = this._createHeaders();
      const response = await this.client.get("/appmesh/applications", { headers: headers });
      return response.data;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_view(name) {
    try {
      const headers = this._createHeaders();
      const response = await this.client.get(`/appmesh/app/${name}`, { headers: headers });
      return response.data;
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_health(name) {
    try {
      const headers = this._createHeaders();
      const response = await this.client.get(`/appmesh/app/${name}/health`, { headers: headers });
      if (response.status === 200) {
        return response.data === "0";
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_add(name, appJson) {
    try {
      const headers = this._createHeaders();
      const response = await this.client.put(`/appmesh/app/${name}`, appJson, { headers: headers });
      if (response.status === 200) {
        return response.data;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_delete(name) {
    try {
      const headers = this._createHeaders();
      const response = await this.client.delete(`/appmesh/app/${name}`, { headers: headers });
      if (response.status === 200) {
        return true;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_enable(name) {
    try {
      const headers = this._createHeaders();
      const response = await this.client.post(`/appmesh/app/${name}/enable`, null, { headers: headers });
      if (response.status === 200) {
        return true;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_disable(name) {
    try {
      const headers = this._createHeaders();
      const response = await this.client.post(`/appmesh/app/${name}/disable`, null, { headers: headers });
      if (response.status === 200) {
        return true;
      } else if (response.status === 404) {
        return false;
      }
      throw new Error(response.data);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async app_output(app_name, stdout_position = 0, stdout_index = 0, stdout_maxsize = 10240, process_uuid = "", timeout = 0) {
    try {
      const headers = this._createHeaders();

      const params = {};
      params.stdout_position = stdout_position.toString();
      params.stdout_index = stdout_index.toString();
      params.stdout_maxsize = stdout_maxsize.toString();
      params.process_uuid = process_uuid;
      params.timeout = timeout.toString();

      const response = await this.client.get(`/appmesh/app/${app_name}/output`, { headers: headers, params: params });
      const outPosition = response.headers["output-position"] ? parseInt(response.headers["output-position"]) : null;
      const exitCode = response.headers["exit-code"] ? parseInt(response.headers["exit-code"]) : null;
      return new AppOutput(response.status, response.data, outPosition, exitCode);
    } catch (error) {
      throw this._handleError(error);
    }
  }

  async run_sync(
    app,
    outputHandler = defaultOutputHandler,
    maxTimeSeconds = DEFAULT_RUN_APP_TIMEOUT_SECONDS,
    lifeCycleSeconds = DEFAULT_RUN_APP_LIFECYCLE_SECONDS
  ) {
    const headers = this._createHeaders();
    const params = { timeout: this._toSeconds(maxTimeSeconds), lifecycle: this._toSeconds(lifeCycleSeconds) };

    try {
      const response = await this.client.post(`/appmesh/app/syncrun`, app, { headers: headers, params: params });
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

  async run_async(app, maxTimeSeconds = DEFAULT_RUN_APP_TIMEOUT_SECONDS, lifeCycleSeconds = DEFAULT_RUN_APP_LIFECYCLE_SECONDS) {
    const headers = this._createHeaders();
    const params = { timeout: this._toSeconds(maxTimeSeconds), lifecycle: this._toSeconds(lifeCycleSeconds) };

    try {
      const response = await this.client.post("/appmesh/app/run", app, { headers: headers, params: params });

      if (response.status !== 200) {
        throw new Error(response.data);
      }
      return new AppRun(this, response.data.name, response.data.process_uuid);
    } catch (error) {
      console.error(error);
      throw error;
    }
  }

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

  // Common function to create headers
  _createHeaders() {
    const headers = {
      Authorization: `Bearer ${this.token}`,
      "User-Agent": "APPMESH_JS_SDK",
    };
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
    this._client.delegate_host(this._delegateHost);
    try {
      return await callback();
    } finally {
      this._client.delegate_host(originalValue);
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
