// server.js - App Mesh Server SDK for Node.js
// This is a Node.js-only module - not included in browser builds

// Environment check - only works in Node.js
if (typeof window !== 'undefined' && typeof window.document !== 'undefined') {
  throw new Error(
    'AppMeshServer is only available in Node.js environment. Use AppMeshClient for browser applications.'
  )
}

import AppMeshClient from './appmesh.js'

/**
 * Server SDK for App Mesh application interacting with the local App Mesh REST service over HTTPS.
 *
 * Build-in runtime environment variables required:
 *   - APP_MESH_PROCESS_KEY
 *   - APP_MESH_APPLICATION_NAME
 *
 * @example
 * // HTTP Server Example
 * import { AppMeshServer } from 'appmesh/server';
 *
 * const server = new AppMeshServer();
 * const payload = await server.task_fetch();
 * const result = processPayload(payload);
 * await server.task_return(result);
 *
 * @example
 * // TCP Server Example
 * import { AppMeshServerTCP } from 'appmesh/server';
 *
 * const server = new AppMeshServerTCP();
 * try {
 *   const payload = await server.task_fetch();
 *   const result = processPayload(payload);
 *   await server.task_return(result);
 * } finally {
 *   server.close();
 * }
 */
class AppMeshServer {
  /**
   * Initialize an App Mesh HTTP Server for interacting with the App Mesh service via secure HTTPS.
   *
   * @param {string} [baseURL='https://127.0.0.1:6060'] - The server's base URI
   * @param {Object} [sslConfig=null] - SSL configuration object
   * @param {Buffer|string} [sslConfig.ca] - CA certificate
   * @param {Buffer|string} [sslConfig.cert] - Client certificate
   * @param {Buffer|string} [sslConfig.key] - Client key
   * @param {boolean} [sslConfig.rejectUnauthorized=true] - Whether to verify SSL
   * @param {Object} [options={}] - Additional options
   * @param {Object} [options.logger=console] - Logger instance
   *
   * @example
   * import fs from 'fs';
   * const sslConfig = {
   *   cert: fs.readFileSync('/opt/appmesh/ssl/client.pem'),
   *   key: fs.readFileSync('/opt/appmesh/ssl/client-key.pem'),
   *   ca: fs.readFileSync('/opt/appmesh/ssl/ca.pem'),
   *   rejectUnauthorized: true
   * };
   * const server = new AppMeshServer('https://127.0.0.1:6060', sslConfig);
   */
  constructor (
    baseURL = 'https://127.0.0.1:6060',
    sslConfig = null,
    options = {}
  ) {
    this._client = new AppMeshClient(baseURL, sslConfig)
    this._logger = options.logger || console
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
   * that a client pushed to it. This method will retry indefinitely until successful.
   *
   * @async
   * @returns {Promise<string|Buffer>} The payload provided by the client
   *
   * @example
   * const server = new AppMeshServer();
   * const payload = await server.task_fetch();
   * console.log('Received payload:', payload);
   */
  async task_fetch () {
    const { processKey, appName } = this._getRuntimeEnv()
    const path = `/appmesh/app/${appName}/task`

    while (true) {
      try {
        const response = await this._client._request('get', path, null, {
          params: { process_key: processKey }
        })

        if (response.status !== 200) {
          this._logger.warn(
            `task_fetch failed with status ${response.status}: ${response.data}, retrying...`
          )
          await this._sleep(100)
          continue
        }

        return response.data
      } catch (error) {
        this._logger.warn(`task_fetch error: ${error.message}, retrying...`)
        await this._sleep(100)
      }
    }
  }

  /**
   * Return the result of a server-side invocation back to the original client.
   *
   * Used by App Mesh application process to post the result to App Mesh service
   * after processing payload data so the invoking client can retrieve it.
   *
   * @async
   * @param {string|Buffer} result - Result payload to be delivered back to the client
   * @returns {Promise<void>}
   * @throws {Error} If the task return fails
   *
   * @example
   * const server = new AppMeshServer();
   * const result = { status: 'success', data: processedData };
   * await server.task_return(JSON.stringify(result));
   */
  async task_return (result) {
    const { processKey, appName } = this._getRuntimeEnv()
    const path = `/appmesh/app/${appName}/task`

    const response = await this._client._request('put', path, result, {
      params: { process_key: processKey }
    })

    if (response.status !== 200) {
      const msg = `task_return failed with status ${response.status}: ${response.data}`
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
 * Server SDK for interacting with the local App Mesh service over TCP (TLS).
 *
 * This class extends AppMeshServer to use TCP transport instead of HTTP.
 * Requires the AppMeshClientTCP implementation.
 *
 * @extends AppMeshServer
 *
 * @example
 * import { AppMeshServerTCP } from 'appmesh/server';
 *
 * const server = new AppMeshServerTCP();
 * try {
 *   const payload = await server.task_fetch();
 *   const result = await processPayload(payload);
 *   await server.task_return(result);
 * } finally {
 *   server.close();
 * }
 */
class AppMeshServerTCP extends AppMeshServer {
  /**
   * Construct an App Mesh server TCP object to communicate securely with an App Mesh server over TLS.
   *
   * @param {Object} [sslConfig=null] - SSL configuration
   * @param {Buffer|string} [sslConfig.ca] - CA certificate for verification
   * @param {Buffer|string} [sslConfig.cert] - Client certificate
   * @param {Buffer|string} [sslConfig.key] - Client key
   * @param {boolean} [sslConfig.rejectUnauthorized=true] - Whether to verify SSL
   * @param {Array<string, number>} [tcpAddress=['127.0.0.1', 6059]] - TCP server address [host, port]
   * @param {Object} [options={}] - Additional options
   * @param {Object} [options.logger=console] - Logger instance
   *
   * @example
   * import fs from 'fs';
   * const sslConfig = {
   *   ca: fs.readFileSync('/opt/appmesh/ssl/ca.pem'),
   *   cert: fs.readFileSync('/opt/appmesh/ssl/client.pem'),
   *   key: fs.readFileSync('/opt/appmesh/ssl/client-key.pem')
   * };
   * const server = new AppMeshServerTCP(sslConfig, ['127.0.0.1', 6059]);
   */
  constructor (
    sslConfig = null,
    tcpAddress = ['127.0.0.1', 6059],
    options = {}
  ) {
    // Don't call super() to avoid creating HTTP client
    // Initialize base properties manually
    this._logger = options.logger || console
    this._sslConfig = sslConfig
    this._tcpAddress = tcpAddress
    this._client = null
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
  async task_fetch () {
    await this._ensureClient()
    return super.task_fetch()
  }

  /**
   * Return task result (overrides parent to ensure TCP client is initialized)
   */
  async task_return (result) {
    await this._ensureClient()
    return super.task_return(result)
  }

  /**
   * Close the TCP connection and release resources.
   * Should be called when done using the server.
   *
   * @example
   * const server = new AppMeshServerTCP();
   * try {
   *   // Use server...
   * } finally {
   *   server.close();
   * }
   */
  close () {
    if (this._client && typeof this._client.close === 'function') {
      this._client.close()
    }
  }
}

/**
 * Context manager helper for AppMeshServer
 * Provides automatic resource cleanup
 *
 * @param {Function} serverFactory - Function that creates a server instance
 * @param {Function} callback - Async function to execute with the server
 * @returns {Promise<any>} Result from callback
 *
 * @example
 * import { withServer, AppMeshServerTCP } from 'appmesh/server';
 *
 * await withServer(
 *   () => new AppMeshServerTCP(),
 *   async (server) => {
 *     const payload = await server.task_fetch();
 *     const result = process(payload);
 *     await server.task_return(result);
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

export { AppMeshServer, AppMeshServerTCP, withServer }
export default AppMeshServer
