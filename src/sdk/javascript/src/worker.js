// worker.js - App Mesh Worker SDK for Node.js
// This is a Node.js-only module - not included in browser builds

// Environment check - only works in Node.js
if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
  throw new Error(
    'AppMeshWorker is only available in Node.js environment. Use AppMeshClient for browser applications.'
  )
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
 * const payload = await worker.fetch_task();
 * const result = processPayload(payload);
 * await worker.send_task_result(result);
 *
 * @example
 * // TCP Worker Example
 * import { AppMeshWorkerTCP } from 'appmesh/worker';
 *
 * const worker = new AppMeshWorkerTCP();
 * try {
 *   const payload = await worker.fetch_task();
 *   const result = processPayload(payload);
 *   await worker.send_task_result(result);
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
   *   client (and therefore its token-refresh state). Use this when a single process needs both
   *   client (outbound calls like `AddApp`) and worker (`fetch_task`/`send_task_result`) roles to
   *   avoid two independent `/token/renew` loops fighting each other — the daemon blacklists
   *   the previous token on every renew, so the slower refresher gets 401 "Token has been revoked".
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
   * await client.login('user', 'pass');
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
      this._client.set_auto_refresh_token(false) // Task endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
    }
    this._logger = options.logger || console
    this._stopped = false
  }

  /**
   * Request cancellation of the fetch_task retry loop (safe to call at any time);
   * a pending fetch_task resolves `null` at its next retry iteration.
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
      throw new Error(
        'Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.'
      )
    }
    if (!appName) {
      throw new Error(
        'Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.'
      )
    }

    return { processKey, appName }
  }

  /**
   * Fetch task data in the currently running App Mesh application process.
   *
   * Used by App Mesh application process to obtain the payload from App Mesh service
   * that a client pushed to it. This method will retry indefinitely until successful
   * or cancelled via {@link AppMeshWorker#stop}, in which case `null` is resolved.
   *
   * @async
   * @returns {Promise<string|Buffer|null>} The raw payload bytes/body provided by the
   *   invoking client, or `null` when the fetch loop was cancelled via stop()
   * @throws {ProcessSupersededError} The daemon reported HTTP 412 — this process key was
   *   superseded by a newer process instance; the caller should stop serving (an app
   *   entry point typically catches this and exits).
   *
   * @example
   * const worker = new AppMeshWorker();
   * const payload = await worker.fetch_task();
   * console.log('Received payload:', payload);
   */
  async fetch_task () {
    const { processKey, appName } = this._getRuntimeEnv()
    const path = `/appmesh/app/${appName}/task`

    const RETRY_DELAY = 100

    while (!this._stopped) {
      const attemptStart = Date.now()
      try {
        const response = await this._client.request('get', path, null, {
          params: { process_key: processKey }
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

        this._logger.warn(
          `fetch_task failed with status ${response.status}: ${response.data}, retrying...`
        )
      } catch (error) {
        // ProcessSupersededError fixes statusCode to 412, so this covers both the
        // branch above and 412 AppMeshErrors thrown by request().
        if (error.statusCode === 412) {
          this._logger.error('Process key mismatch (412): this process has been superseded')
          throw error instanceof ProcessSupersededError
            ? error
            : new ProcessSupersededError(
              'Process key mismatch (412): this process has been superseded by a newer instance',
              error.responseData
            )
        }
        this._logger.warn(`fetch_task error: ${error.message}, retrying...`)
      }

      const remainingDelay = RETRY_DELAY - (Date.now() - attemptStart)
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
   *
   * @example
   * const worker = new AppMeshWorker();
   * const result = { status: 'success', data: processedData };
   * await worker.send_task_result(JSON.stringify(result));
   */
  async send_task_result (result) {
    const { processKey, appName } = this._getRuntimeEnv()
    const path = `/appmesh/app/${appName}/task`

    let response
    try {
      response = await this._client.request('put', path, result, {
        params: { process_key: processKey }
      })
    } catch (error) {
      // request() throws AppMeshError on non-200
      this._logger.error(`send_task_result failed with status ${error.statusCode}: ${error.message}`)
      throw error
    }

    if (response.status !== 200) {
      const msg = `send_task_result failed with status ${response.status}: ${response.data}`
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
 *   const payload = await worker.fetch_task();
 *   const result = await processPayload(payload);
 *   await worker.send_task_result(result);
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
   * @param {AppMeshClientTCP} [options.client] - Optional pre-built `AppMeshClientTCP` instance to reuse.
   *   When supplied, `sslConfig` and `tcpAddress` are ignored and the worker shares the caller's
   *   client (and therefore its token-refresh state). Use this when a single process needs both
   *   client and worker roles to avoid two independent `/token/renew` loops fighting each other —
   *   the daemon blacklists the previous token on every renew, so the slower refresher gets
   *   401 "Token has been revoked".
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
   * await client.login('user', 'pass');
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
      this._client.set_auto_refresh_token(false) // Task endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
    }
    return this._client
  }

  /**
   * Fetch task data (overrides parent to ensure TCP client is initialized)
   */
  async fetch_task () {
    await this._ensureClient()
    return super.fetch_task()
  }

  /**
   * Return task result (overrides parent to ensure TCP client is initialized)
   */
  async send_task_result (result) {
    await this._ensureClient()
    return super.send_task_result(result)
  }

  /**
   * Close the TCP connection and release resources.
   * Should be called when done using the server.
   *
   * @example
   * const worker = new AppMeshWorkerTCP();
   * try {
   *   // Use worker...
   * } finally {
   *   worker.close();
   * }
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
 *     const payload = await worker.fetch_task();
 *     const result = process(payload);
 *     await worker.send_task_result(result);
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
  withServer
}
export default AppMeshWorker
