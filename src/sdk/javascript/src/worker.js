// worker.js - App Mesh Worker SDK for Node.js
// This is a Node.js-only module - not included in browser builds

// Environment check - only works in Node.js
if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
  throw new Error('AppMeshWorker is only available in Node.js environment. Use AppMeshClient for browser applications.')
}

import AppMeshClient, { AppMeshError } from './appmesh.js'

/**
 * Error thrown when the daemon reports HTTP 412: this process key was superseded
 * by a newer process instance and the caller should stop serving.
 *
 * Subclasses AppMeshError with `statusCode` fixed to 412, so existing catch-based
 * callers keep working. Counterpart of Python `AppMeshProcessSupersededError`,
 * Go `ErrProcessSuperseded` and Rust `AppMeshError::ProcessSuperseded`.
 */
class ProcessSupersededError extends AppMeshError {
  /**
   * @param {string} message - Error message
   * @param {any} responseData - Raw 412 response body
   */
  constructor (message, responseData = null) {
    super(message, 412, responseData, 'PROCESS_SUPERSEDED')
    this.name = 'ProcessSupersededError'
  }
}

/** Permanent worker request rejection (HTTP 400); retrying cannot recover. */
class WorkerRejectedError extends AppMeshError {
  /** @param {string} message @param {any} responseData */
  constructor (message, responseData = null) {
    super(message, 400, responseData, 'WORKER_REJECTED')
    this.name = 'WorkerRejectedError'
  }
}

/**
 * True when `value` looks like a {host, port} address object rather than an SSL config.
 * Mirrors the acceptance logic in appmesh_tcp.js (kept local: appmesh_tcp.js is lazy-imported).
 * @private
 */
function _isTcpAddressObject (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value) &&
    ('host' in value || 'port' in value) &&
    !('ca' in value) && !('cert' in value) && !('key' in value) && !('rejectUnauthorized' in value)
}

/**
 * Internal sentinel: AppMeshWorkerTCP passes this as `options.client` to tell the base
 * constructor to skip building a default HTTP client (the TCP client is created lazily
 * by _ensureClient()). Callers passing `client: null`/`undefined` still get the default.
 * @private
 */
const _DEFER_CLIENT = Symbol('appmesh.deferClient')

/**
 * Worker SDK for App Mesh application interacting with the local App Mesh REST service over HTTPS.
 *
 * Build-in runtime environment variables required:
 *   - APP_MESH_PROCESS_KEY
 *   - APP_MESH_APPLICATION_NAME
 *
 * @example
 * // HTTP Worker Example
 * import { AppMeshWorker } from 'appmesh/worker';
 *
 * const worker = new AppMeshWorker();
 * const payload = await worker.fetchTask();
 * const result = processPayload(payload);
 * await worker.sendTaskResult(result);
 *
 * @example
 * // TCP Worker Example
 * import { AppMeshWorkerTCP } from 'appmesh/worker';
 *
 * const worker = new AppMeshWorkerTCP();
 * try {
 *   const payload = await worker.fetchTask();
 *   const result = processPayload(payload);
 *   await worker.sendTaskResult(result);
 * } finally {
 *   worker.close();
 * }
 */
class AppMeshWorker {
  /**
   * Initialize an App Mesh HTTP Worker for interacting with the App Mesh service via secure HTTPS.
   *
   * @param {string} [baseURL='https://127.0.0.1:6060'] - The server's base URI
   * @param {Object} [sslConfig=null] - SSL configuration object
   * @param {Buffer|string} [sslConfig.ca] - CA certificate
   * @param {Buffer|string} [sslConfig.cert] - Client certificate
   * @param {Buffer|string} [sslConfig.key] - Client key
   * @param {boolean} [sslConfig.rejectUnauthorized=true] - Whether to verify SSL
   * @param {Object} [options={}] - Additional options
   * @param {Object} [options.logger=console] - Logger instance
   * @param {AppMeshClient} [options.client] - Optional pre-built `AppMeshClient` instance to reuse.
   *   When supplied, `baseURL` and `sslConfig` are ignored and the worker shares the caller's
   *   client (and therefore its caller-owned bearer). Use this when a single process needs both
   *   client (outbound calls like `AddApp`) and worker (`fetchTask`/`sendTaskResult`) roles.
   *
   * @example
   * import fs from 'fs';
   * const sslConfig = {
   *   cert: fs.readFileSync('/opt/appmesh/ssl/client.pem'),
   *   key: fs.readFileSync('/opt/appmesh/ssl/client-key.pem'),
   *   ca: fs.readFileSync('/opt/appmesh/ssl/ca.pem'),
   *   rejectUnauthorized: true
   * };
   * const worker = new AppMeshWorker('https://127.0.0.1:6060', sslConfig);
   *
   * @example
   * // Share a single client between client-role and worker-role usage:
   * const client = new AppMeshClient('https://127.0.0.1:6060', sslConfig);
   * client.setBearerToken(process.env.APPMESH_BEARER_TOKEN);
   * const worker = new AppMeshWorker('https://127.0.0.1:6060', sslConfig, { client });
   */
  constructor (
    baseURL = 'https://127.0.0.1:6060',
    sslConfig = null,
    options = {}
  ) {
    if (options.client === _DEFER_CLIENT) {
      // Subclass (AppMeshWorkerTCP) creates its own client lazily — do not build a
      // throwaway HTTP client here.
      this._client = null
    } else if (options.client) {
      this._client = options.client
    } else {
      this._client = new AppMeshClient(baseURL, sslConfig)
    }
    this._logger = options.logger || console
    this._stopped = false
  }

  /**
   * Request cancellation of the fetchTask retry loop (safe to call at any time);
   * a pending fetchTask resolves `null` at its next retry iteration.
   */
  stop () {
    this._stopped = true
  }

  /**
   * Read and validate required runtime environment variables.
   * @private
   * @returns {{processKey: string, appName: string}} Environment variables
   * @throws {Error} If required environment variables are missing
   */
  _getRuntimeEnv () {
    const processKey = process.env.APP_MESH_PROCESS_KEY
    const appName = process.env.APP_MESH_APPLICATION_NAME

    if (!processKey) {
      throw new Error('Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.')
    }
    if (!appName) {
      throw new Error('Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.')
    }

    return { processKey, appName }
  }

  /**
   * Fetch task data in the currently running App Mesh application process.
   *
   * Used by App Mesh application process to obtain the payload from App Mesh service
   * that a client pushed to it. This method retries transient failures indefinitely
   * until successful or cancelled via {@link AppMeshWorker#stop}; HTTP 400/412 stop
   * the loop. Cancellation resolves `null`.
   *
   * @async
   * @returns {Promise<string|Buffer|null>} The raw payload bytes/body provided by the
   *   invoking client, or `null` when the fetch loop was cancelled via stop()
   * @throws {ProcessSupersededError} The daemon reported HTTP 412 — this process key was
   *   superseded by a newer process instance.
   * @throws {WorkerRejectedError} The daemon reported a permanent HTTP 400; an app entry
   *   point should stop serving and exit.
   */
  async fetchTask() {
    const { processKey, appName } = this._getRuntimeEnv()
    const path = `/appmesh/app/${appName}/task`

    const retryDelay = 100

    while (!this._stopped) {
      const attemptStart = Date.now()
      try {
        const response = await this._client.request('get', path, null, {
          headers: { 'X-AppMesh-Process-Key': processKey }
        })

        if (response.status === 200) {
          return response.data
        }

        // request() throws on non-200; this branch only guards injected clients
        // that resolve with non-200 responses.
        if (response.status === 412) {
          throw new ProcessSupersededError(
            'Process key mismatch (412): this process has been superseded by a newer instance',
            response.data
          )
        }
        if (response.status === 400) {
          throw new WorkerRejectedError('fetchTask permanently rejected with status 400', response.data)
        }

        this._logger.warn(`fetchTask failed with status ${response.status}: ${response.data}, retrying...`)
      } catch (error) {
        // ProcessSupersededError fixes statusCode to 412, so this covers both the
        // branch above and 412 AppMeshErrors thrown by request().
        if (error.statusCode === 412) {
          this._logger.error('Process key mismatch (412): this process has been superseded')
          throw error instanceof ProcessSupersededError
            ? error
            : new ProcessSupersededError('Process key mismatch (412): this process has been superseded by a newer instance',
              error.responseData
            )
        }
        if (error.statusCode === 400) {
          this._logger.error(`fetchTask permanently rejected: ${error.message}`)
          throw error instanceof WorkerRejectedError
            ? error
            : new WorkerRejectedError(error.message, error.responseData)
        }
        this._logger.warn(`fetchTask error: ${error.message}, retrying...`)
      }

      const remainingDelay = retryDelay - (Date.now() - attemptStart)
      if (remainingDelay > 0) {
        await this._sleep(remainingDelay)
      }
    }
    return null // cancelled via stop()
  }

  /**
   * Return the result of a server-side invocation back to the original client.
   *
   * Used by App Mesh application process to post the result to App Mesh service
   * after processing payload data so the invoking client can retrieve it.
   *
   * @async
   * @param {string|Buffer} result - Result payload to be delivered back to the client as-is
   * @returns {Promise<void>}
   * @throws {Error} If the task return fails
   */
  async sendTaskResult(result) {
    const { processKey, appName } = this._getRuntimeEnv()
    const path = `/appmesh/app/${appName}/task`

    let response
    try {
      response = await this._client.request('put', path, result, {
        headers: { 'X-AppMesh-Process-Key': processKey }
      })
    } catch (error) {
      // request() throws AppMeshError on non-200
      this._logger.error(`sendTaskResult failed with status ${error.statusCode}: ${error.message}`)
      throw error
    }

    if (response.status !== 200) {
      const msg = `sendTaskResult failed with status ${response.status}: ${response.data}`
      this._logger.error(msg)
      throw new Error(msg)
    }
  }

  /**
   * Sleep utility for retry logic
   * @private
   * @param {number} ms - Milliseconds to sleep
   * @returns {Promise<void>}
   */
  async _sleep (ms) {
    return new Promise(resolve => setTimeout(resolve, ms))
  }
}

/**
 * Worker SDK for interacting with the local App Mesh service over TCP (TLS).
 *
 * This class extends AppMeshWorker to use TCP transport instead of HTTP.
 * Requires the AppMeshClientTCP implementation.
 *
 * @extends AppMeshWorker
 *
 * @example
 * import { AppMeshWorkerTCP } from 'appmesh/worker';
 *
 * const worker = new AppMeshWorkerTCP();
 * try {
 *   const payload = await worker.fetchTask();
 *   const result = await processPayload(payload);
 *   await worker.sendTaskResult(result);
 * } finally {
 *   worker.close();
 * }
 */
class AppMeshWorkerTCP extends AppMeshWorker {
  /**
   * Construct an App Mesh worker TCP object to communicate securely with an App Mesh server over TLS.
   *
   * Like AppMeshClientTCP, the TCP address may be given as a legacy `[host, port]` array or an
   * explicit `{host, port}` object, in either of the first two positions:
   * `new AppMeshWorkerTCP(sslConfig, [host, port])` or `new AppMeshWorkerTCP({host, port}, sslConfig)`.
   *
   * @param {Object} [sslConfig=null] - SSL configuration (or `{host, port}` address)
   * @param {Buffer|string} [sslConfig.ca] - CA certificate for verification
   * @param {Buffer|string} [sslConfig.cert] - Client certificate
   * @param {Buffer|string} [sslConfig.key] - Client key
   * @param {boolean} [sslConfig.rejectUnauthorized=true] - Whether to verify SSL
   * @param {Array<string, number>|{host: string, port: number}} [tcpAddress=['127.0.0.1', 6059]] - TCP server address
   * @param {Object} [options={}] - Additional options
   * @param {Object} [options.logger=console] - Logger instance
   * @param {AppMeshClientTCP} [options.client] - Pre-built client to reuse (shares its caller-owned bearer);
   * when set, sslConfig/tcpAddress are ignored.
   *
   * @example
   * import fs from 'fs';
   * const sslConfig = {
   *   ca: fs.readFileSync('/opt/appmesh/ssl/ca.pem'),
   *   cert: fs.readFileSync('/opt/appmesh/ssl/client.pem'),
   *   key: fs.readFileSync('/opt/appmesh/ssl/client-key.pem')
   * };
   * const worker = new AppMeshWorkerTCP(sslConfig, ['127.0.0.1', 6059]);
   *
   * @example
   * // Share a single TCP client between client-role and worker-role usage:
   * import { AppMeshClientTCP } from 'appmesh/tcp';
   * const client = new AppMeshClientTCP(sslConfig, ['127.0.0.1', 6059]);
   * client.setBearerToken(process.env.APPMESH_BEARER_TOKEN);
   * const worker = new AppMeshWorkerTCP(sslConfig, ['127.0.0.1', 6059], { client });
   */
  constructor (
    sslConfig = null,
    tcpAddress = ['127.0.0.1', 6059],
    options = {}
  ) {
    // Accept the address-first object form: new AppMeshWorkerTCP({host, port}, sslConfig)
    if (_isTcpAddressObject(sslConfig)) {
      const addr = sslConfig
      sslConfig = (Array.isArray(tcpAddress) || _isTcpAddressObject(tcpAddress)) ? null : tcpAddress
      tcpAddress = addr
    }
    // The TCP client is created lazily by _ensureClient(); the sentinel tells the
    // parent not to construct a throwaway HTTP client.
    super(undefined, sslConfig, { ...options, client: options.client || _DEFER_CLIENT })
    this._sslConfig = sslConfig
    this._tcpAddress = tcpAddress
  }

  /**
   * Initialize TCP client (lazy loading to avoid circular dependencies)
   * @private
   */
  async _ensureClient () {
    if (!this._client) {
      const { AppMeshClientTCP } = await import('./appmesh_tcp.js')
      this._client = new AppMeshClientTCP(this._sslConfig, this._tcpAddress)
    }
    return this._client
  }

  /**
   * Fetch task data (overrides parent to ensure TCP client is initialized)
   */
  async fetchTask() {
    await this._ensureClient()
    return super.fetchTask()
  }

  /**
   * Return task result (overrides parent to ensure TCP client is initialized)
   */
  async sendTaskResult(result) {
    await this._ensureClient()
    return super.sendTaskResult(result)
  }

  /**
   * Close the TCP connection and release resources.
   * Should be called when done using the server.
   */
  close () {
    if (this._client && typeof this._client.close === 'function') {
      this._client.close()
    }
  }
}

/**
 * Context manager helper for AppMeshWorker
 * Provides automatic resource cleanup
 *
 * @param {Function} serverFactory - Function that creates a worker instance
 * @param {Function} callback - Async function to execute with the worker
 * @returns {Promise<any>} Result from callback
 *
 * @example
 * import { withServer, AppMeshWorkerTCP } from 'appmesh/worker';
 *
 * await withServer(
 *   () => new AppMeshWorkerTCP(),
 *   async (worker) => {
 *     const payload = await worker.fetchTask();
 *     const result = process(payload);
 *     await worker.sendTaskResult(result);
 *   }
 * );
 */
async function withServer (serverFactory, callback) {
  const server = serverFactory()
  try {
    return await callback(server)
  } finally {
    if (server && typeof server.close === 'function') {
      server.close()
    }
  }
}

export {
  AppMeshWorker,
  AppMeshWorkerTCP,
  ProcessSupersededError,
  WorkerRejectedError,
  withServer
}
export default AppMeshWorker

// ---------------------------------------------------------------------------
// Deprecated snake_case aliases kept for backward compatibility (the API used
// to mirror the Python SDK). They forward through `this` so subclass overrides
// still apply. Will be removed in the next major version.
// ---------------------------------------------------------------------------
const _snakeAliases = {
  fetch_task: 'fetchTask',
  send_task_result: 'sendTaskResult',
}
for (const cls of [AppMeshWorker]) {
  for (const [snake, camel] of Object.entries(_snakeAliases)) {
    if (!cls.prototype[camel]) continue
    cls.prototype[snake] = function (...args) { return this[camel](...args) }
  }
}
