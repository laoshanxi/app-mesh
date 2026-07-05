// appmesh_tcp.js - App Mesh TCP Client SDK for Node.js
// This module provides TCP-based communication for improved performance with large file transfers

import tls from 'tls'
import fs from 'fs'
import os from 'os'
import { v1 as uuidv1 } from 'uuid'
import msgpack from 'msgpack-lite'
import AppMeshClient, { AppMeshError, TotpRequiredError, AppRemovedError, TransportDisconnectedError, DEFAULT_CA_FILE } from './appmesh.js'

// Constants
const TCP_BLOCK_SIZE = 16 * 1024 - 128 // TLS-optimized chunk size
const TCP_MESSAGE_MAGIC = 0x07C707F8 // must match TCP_MESSAGE_MAGIC in src/common/Utility.h
const TCP_MESSAGE_HEADER_LENGTH = 8 // 4-byte magic + 4-byte body length, big-endian
const ENCODING_UTF8 = 'utf-8'
const HTTP_USER_AGENT_TCP = 'appmesh/nodejs/tcp'
const HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = 'X-Send-File-Socket'
const HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = 'X-Recv-File-Socket'
const HTTP_HEADER_KEY_USER_AGENT = 'User-Agent'
const HTTP_HEADER_KEY_X_FILE_PATH = 'X-File-Path'
const HTTP_HEADER_KEY_AUTH = 'Authorization'

// Auth endpoints returning a new access_token in the JSON body (allowlist per
// docs/source/SDKContract.md "Auth Token Synchronization").
// Login/auth/totp_validate: apply token only when the request carried X-Set-Cookie: true
const AUTH_SET_COOKIE_PATHS = new Set(['/appmesh/login', '/appmesh/auth', '/appmesh/totp/validate'])
// Renew/setup: always apply (client already has an active session)
const AUTH_RENEW_PATHS = new Set(['/appmesh/token/renew', '/appmesh/totp/setup'])
const LOGOFF_PATH = '/appmesh/self/logoff'

/**
 * TCP transport for secure TLS connections and framed App Mesh messages.
 *
 * `sslConfig` is a tri-state:
 * - `null`/`undefined` (default): verify the server certificate against the App Mesh default
 *   CA (/opt/appmesh/ssl/ca.pem) if installed, otherwise the system CAs.
 * - object: custom TLS material — `ca`/`cert`/`key` (Buffer or file path) with an optional
 *   `rejectUnauthorized` flag (defaults to `true`). An unreadable CA/cert/key path is a hard
 *   error (`fs.readFileSync` throws), never a silent fallback to no-verification.
 * - `false`: explicit insecure mode — server certificate verification is disabled.
 *   This is the only way to disable verification besides `rejectUnauthorized: false`.
 */
class TCPTransport {
  /**
   * @param {Array<string, number>} [address=['127.0.0.1', 6059]] - Server address [host, port]
   * @param {Object|false|null} [sslConfig=null] - TLS tri-state (see class doc)
   */
  constructor (address = ['127.0.0.1', 6059], sslConfig = null) {
    this.address = address
    this.sslConfig = sslConfig
    this.socket = null
    this.receiveBuffer = Buffer.alloc(0)
  }

  /**
   * Establish a TLS connection to the server if one is not already open.
   * @returns {Promise<void>} Always a Promise, resolved immediately when already connected.
   */
  connect () {
    if (this.connected()) {
      return Promise.resolve()
    }

    const options = {
      host: this.address[0],
      port: this.address[1],
      rejectUnauthorized: true
    }

    // Handle SSL configuration
    if (this.sslConfig === false) {
      // Explicit insecure mode
      options.rejectUnauthorized = false
    } else if (this.sslConfig) {
      // Handle rejectUnauthorized
      if (typeof this.sslConfig.rejectUnauthorized === 'boolean') {
        options.rejectUnauthorized = this.sslConfig.rejectUnauthorized
      }

      // Handle CA certificate
      if (this.sslConfig.ca) {
        options.ca = Buffer.isBuffer(this.sslConfig.ca)
          ? this.sslConfig.ca
          : fs.readFileSync(this.sslConfig.ca)
      }

      // Handle client certificate
      if (this.sslConfig.cert) {
        options.cert = Buffer.isBuffer(this.sslConfig.cert)
          ? this.sslConfig.cert
          : fs.readFileSync(this.sslConfig.cert)
      }

      // Handle client key
      if (this.sslConfig.key) {
        options.key = Buffer.isBuffer(this.sslConfig.key)
          ? this.sslConfig.key
          : fs.readFileSync(this.sslConfig.key)
      }
    } else if (fs.existsSync(DEFAULT_CA_FILE)) {
      // Auto default: prefer the App Mesh default CA; absent → system CAs, verification stays on
      options.ca = fs.readFileSync(DEFAULT_CA_FILE)
    }

    this.socket = tls.connect(options)
    this.socket.setKeepAlive(true)

    // Handle connection errors
    return new Promise((resolve, reject) => {
      this.socket.once('secureConnect', () => {
        this.socket.removeListener('error', reject)
        resolve()
      })
      this.socket.once('error', reject)
    })
  }

  /**
   * Check if socket is connected
   */
  connected () {
    return this.socket && !this.socket.destroyed
  }

  /**
   * Close the connection
   */
  close () {
    if (this.socket) {
      this.socket.destroy()
      this.socket = null
    }
    this.receiveBuffer = Buffer.alloc(0)
  }

  /**
   * Send a message over the socket, framed as 4-byte magic + 4-byte length header
   * (big-endian), matching the daemon wire protocol.
   * @param {Buffer|Array} data - Data to send (empty array signals EOF: magic + zero length)
   */
  sendMessage (data) {
    if (!this.connected()) {
      throw new Error('Socket not connected')
    }

    const msgData = (Array.isArray(data) && data.length === 0)
      ? Buffer.alloc(0) // EOF signal
      : (Buffer.isBuffer(data) ? data : Buffer.from(data))

    const payload = Buffer.alloc(TCP_MESSAGE_HEADER_LENGTH + msgData.length)
    payload.writeUInt32BE(TCP_MESSAGE_MAGIC, 0)
    payload.writeUInt32BE(msgData.length, 4)
    msgData.copy(payload, TCP_MESSAGE_HEADER_LENGTH)

    this.socket.write(payload)
  }

  /**
   * Receive a message framed as 4-byte magic + 4-byte length header (big-endian).
   * @returns {Promise<Buffer|null>} Received data, empty Buffer for EOF signal, or null when
   * the connection closed
   * @throws {Error} If the header magic number does not match the daemon protocol
   */
  async receiveMessage () {
    if (!this.connected()) {
      return null
    }

    // Read message header (magic + length)
    while (this.receiveBuffer.length < TCP_MESSAGE_HEADER_LENGTH) {
      const chunk = await this._readChunk()
      if (!chunk) return null
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])
    }

    const magic = this.receiveBuffer.readUInt32BE(0)
    if (magic !== TCP_MESSAGE_MAGIC) {
      this.close()
      throw new Error(`Invalid TCP message magic number: 0x${magic.toString(16).toUpperCase()}`)
    }
    const length = this.receiveBuffer.readUInt32BE(4)

    // EOF signal
    if (length === 0) {
      this.receiveBuffer = this.receiveBuffer.slice(TCP_MESSAGE_HEADER_LENGTH)
      return Buffer.alloc(0)
    }

    // Read message body
    while (this.receiveBuffer.length < TCP_MESSAGE_HEADER_LENGTH + length) {
      const chunk = await this._readChunk()
      if (!chunk) return null
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])
    }

    const message = this.receiveBuffer.slice(TCP_MESSAGE_HEADER_LENGTH, TCP_MESSAGE_HEADER_LENGTH + length)
    this.receiveBuffer = this.receiveBuffer.slice(TCP_MESSAGE_HEADER_LENGTH + length)
    return message
  }

  /**
   * Read a chunk from the socket
   * @private
   */
  _readChunk () {
    return new Promise((resolve, reject) => {
      const onData = data => {
        this.socket.removeListener('data', onData)
        this.socket.removeListener('end', onEnd)
        this.socket.removeListener('error', onError)
        resolve(data)
      }

      const onEnd = () => {
        this.socket.removeListener('data', onData)
        this.socket.removeListener('end', onEnd)
        this.socket.removeListener('error', onError)
        resolve(null)
      }

      const onError = err => {
        this.socket.removeListener('data', onData)
        this.socket.removeListener('end', onEnd)
        this.socket.removeListener('error', onError)
        reject(err)
      }

      this.socket.once('data', onData)
      this.socket.once('end', onEnd)
      this.socket.once('error', onError)
    })
  }
}

/**
 * Request message for TCP protocol
 */
class RequestMessage {
  constructor () {
    this.uuid = ''
    this.httpMethod = 'GET'
    this.requestUri = ''
    this.clientAddr = ''
    this.headers = {}
    this.query = {}
    this.body = Buffer.alloc(0)
  }

  /**
   * Serialize message to msgpack format
   */
  serialize () {
    const data = {
      uuid: this.uuid,
      http_method: this.httpMethod,
      request_uri: this.requestUri,
      client_addr: this.clientAddr,
      headers: this.headers,
      query: this.query,
      body: this.body
    }
    return msgpack.encode(data)
  }
}

/**
 * Response message for TCP protocol
 */
class ResponseMessage {
  constructor () {
    this.uuid = ''
    this.requestUri = ''
    this.httpStatus = 0
    this.bodyMsgType = ''
    this.headers = {}
    this.body = Buffer.alloc(0)
  }

  /**
   * Deserialize message from msgpack format
   */
  deserialize (data) {
    const decoded = msgpack.decode(data)
    this.uuid = decoded.uuid || ''
    this.requestUri = decoded.request_uri || ''
    this.httpStatus = decoded.http_status || 0
    this.bodyMsgType = decoded.body_msg_type || ''
    this.headers = decoded.headers || {}
    this.body = decoded.body || Buffer.alloc(0)
    return this
  }
}

/**
 * True when `value` looks like a {host, port} address object rather than an SSL config.
 * @private
 */
function _isAddressObject (value) {
  return !!value && typeof value === 'object' && !Array.isArray(value) && !Buffer.isBuffer(value) &&
    ('host' in value || 'port' in value) &&
    !('ca' in value) && !('cert' in value) && !('key' in value) && !('rejectUnauthorized' in value)
}

/**
 * Normalize a TCP address given as [host, port] (legacy) or {host, port} to [host, port].
 * @private
 */
function _normalizeTcpAddress (address) {
  if (_isAddressObject(address)) {
    return [address.host ?? '127.0.0.1', address.port ?? 6059]
  }
  return address
}

/**
 * TCP-based App Mesh client with optimized file transfer support.
 *
 * Extends AppMeshClient to use TCP transport for better performance
 * with large file transfers while maintaining API compatibility.
 *
 * @extends AppMeshClient
 */
class AppMeshClientTCP extends AppMeshClient {
  /**
   * Create a TCP-based App Mesh client.
   *
   * Two constructor forms are accepted:
   * - `new AppMeshClientTCP(sslConfig, [host, port])` — legacy positional form; the address
   *   is a `[host, port]` array.
   * - `new AppMeshClientTCP({host, port}, sslConfig)` or
   *   `new AppMeshClientTCP(sslConfig, {host, port})` — the address may be an explicit
   *   `{host, port}` object in either position.
   *
   * `sslConfig` is a tri-state: `null`/`undefined` verifies the server certificate against the
   * App Mesh default CA (/opt/appmesh/ssl/ca.pem) if installed, otherwise the system CAs; an
   * object supplies custom TLS material (an unreadable ca/cert/key path is a hard error, never
   * a silent no-verify fallback); `false` is the explicit insecure no-verification mode.
   *
   * @param {Object|false|null} [sslConfig=null] - SSL configuration (or `{host, port}` address)
   * @param {Buffer|string} [sslConfig.ca] - CA certificate
   * @param {Buffer|string} [sslConfig.cert] - Client certificate
   * @param {Buffer|string} [sslConfig.key] - Client key
   * @param {boolean} [sslConfig.rejectUnauthorized=true] - Whether to verify SSL
   * @param {Array<string, number>|{host: string, port: number}} [tcpAddress=['127.0.0.1', 6059]] - TCP server address
   */
  constructor (sslConfig = null, tcpAddress = ['127.0.0.1', 6059]) {
    // Accept the address-first object form: new AppMeshClientTCP({host, port}, sslConfig)
    if (_isAddressObject(sslConfig)) {
      const addr = sslConfig
      sslConfig = (Array.isArray(tcpAddress) || _isAddressObject(tcpAddress)) ? null : tcpAddress
      tcpAddress = addr
    }
    tcpAddress = _normalizeTcpAddress(tcpAddress)

    // Pass dummy baseURL to parent - not used for TCP communication
    super('https://127.0.0.1:6060', sslConfig)
    this.tcpTransport = new TCPTransport(tcpAddress, sslConfig)

    // Store JWT token explicitly since cookies don't work with TCP
    this._token = ''
  }

  /**
   * Close the TCP transport and release local resources.
   */
  close () {
    if (this._demuxer) {
      this._demuxer.stop()
      this._demuxer = null
    }
    if (this.tcpTransport) {
      this.tcpTransport.close()
      this.tcpTransport = null
    }
  }

  /**
   * Get the current access token.
   * @returns {string} Current JWT token
   * @private
   * @override
   */
  _getAccessToken () {
    return this._token
  }

  /**
   * Handle token updates for transports that cannot rely on cookies.
   *
   * This method is called after login, renew_token, and authenticate operations.
   * Since TCP doesn't support cookies, we store the token explicitly.
   *
   * @param {string} token - New JWT token
   * @private
   * @override
   */
  _handleTokenUpdate (token) {
    // Base implementation stores the token and handles refresh scheduling
    super._handleTokenUpdate(token)
    this._token = token || ''
  }

  /**
   * Extract and apply a token from auth endpoint responses. TCP has no Set-Cookie,
   * so the token comes from the JSON body — only on HTTP 200 and only for the
   * SDKContract.md auth endpoint allowlist.
   * @param {Object} response - Normalized response object from _request
   * @param {string} path - Request URI path
   * @param {Object} requestHeaders - Headers sent with the request
   * @private
   */
  _syncTransportToken (response, path, requestHeaders) {
    if (response.status !== 200) return

    if (path === LOGOFF_PATH) {
      this._handleTokenUpdate(null)
      return
    }

    // Login/auth/totp_validate: apply only when client requested cookie mode
    if (AUTH_SET_COOKIE_PATHS.has(path)) {
      if (!requestHeaders || requestHeaders['X-Set-Cookie'] !== 'true') return
    } else if (!AUTH_RENEW_PATHS.has(path)) {
      return
    }

    let data = response.data
    // Parse if it's a Buffer containing JSON
    if (Buffer.isBuffer(data)) {
      try {
        data = JSON.parse(data.toString(ENCODING_UTF8))
      } catch (e) {
        return // Not JSON, ignore
      }
    }
    if (data && data.access_token) {
      this._handleTokenUpdate(data.access_token)
    }
  }

  /**
   * Send an App Mesh request over TCP transport and normalize the response shape.
   * @private
   * @override
   */
  async _request (method, path, body = null, options = {}) {
    if (!this.tcpTransport.connected()) {
      await this.tcpTransport.connect()
    }

    // Build request message
    const request = new RequestMessage()
    request.uuid = uuidv1()
    request.httpMethod = method.toUpperCase()
    request.requestUri = path
    request.clientAddr = os.hostname()

    // Set headers from options
    request.headers[HTTP_HEADER_KEY_USER_AGENT] = HTTP_USER_AGENT_TCP

    // Add authentication token if available
    const token = this._getAccessToken()
    if (token) {
      request.headers[HTTP_HEADER_KEY_AUTH] = token
    }

    if (options.headers) {
      Object.assign(request.headers, options.headers)
    }

    // Set query parameters
    if (options.params) {
      Object.assign(request.query, options.params)
    }

    // Set body
    if (body !== null) {
      if (typeof body === 'object' && !Buffer.isBuffer(body)) {
        request.body = Buffer.from(JSON.stringify(body, null, 2), ENCODING_UTF8)
      } else if (typeof body === 'string') {
        request.body = Buffer.from(body, ENCODING_UTF8)
      } else if (Buffer.isBuffer(body)) {
        request.body = body
      }
    }

    // Send request
    const serialized = request.serialize()

    let response
    if (this._demuxer && this._demuxer._running) {
      // Live demuxer: route response by UUID. A stopped demuxer can never resolve
      // waiters, so fall back to the direct read below. Contract S7: register the
      // waiter BEFORE writing request bytes so a fast response can't be dropped.
      const respPromise = this._demuxer.registerRequest(request.uuid)
      try {
        this.tcpTransport.sendMessage(serialized)
      } catch (e) {
        respPromise.catch(() => {}) // never dispatched; silence a later stop() rejection
        this._demuxer.unregisterRequest(request.uuid)
        throw e
      }
      response = await respPromise
    } else {
      // Legacy synchronous mode: read directly.
      this.tcpTransport.sendMessage(serialized)
      const respData = await this.tcpTransport.receiveMessage()
      if (!respData || respData.length === 0) {
        this.tcpTransport.close()
        throw new Error('Socket connection broken')
      }
      response = new ResponseMessage().deserialize(respData)
    }

    // Convert to standard response format matching axios structure
    const result = {
      status: response.httpStatus,
      statusText: this._getStatusText(response.httpStatus),
      headers: response.headers,
      data: this._decodeBody(response, options),
      config: options
    }

    // Sync token from auth endpoint responses (login, authenticate, renew_token, logoff)
    this._syncTransportToken(result, path, request.headers)

    // Mirror the HTTP transport: never swallow a non-200 into a success value
    if (result.status !== 200) {
      const errMsg = this._extractErrorMessage(result.data)
      if (result.status === 428) {
        throw new TotpRequiredError(errMsg, result.data)
      }
      throw new AppMeshError(errMsg, result.status, result.data)
    }

    return result
  }

  /**
   * Decode a raw msgpack body Buffer to the same shape axios produces over HTTP:
   * parsed JSON object for JSON payloads, string for text, Buffer only for binary
   * responses (responseType 'arraybuffer'/'stream').
   * @private
   */
  _decodeBody (response, options) {
    const data = response.body
    if (!Buffer.isBuffer(data)) {
      return data
    }

    const responseType = options.config?.responseType
    if (responseType === 'arraybuffer' || responseType === 'stream') {
      return data
    }

    const headers = response.headers || {}
    const ctKey = Object.keys(headers).find(k => k.toLowerCase() === 'content-type')
    const contentType = (ctKey ? String(headers[ctKey]) : '').toLowerCase()
    if (!responseType && contentType.includes('application/octet-stream')) {
      return data
    }

    const text = data.toString(ENCODING_UTF8)
    if (responseType === 'text' || contentType.startsWith('text/')) {
      return text
    }
    try {
      return JSON.parse(text)
    } catch (_) {
      return text // not JSON, keep raw text (axios does the same)
    }
  }

  /**
   * Get HTTP status text
   * @private
   */
  _getStatusText (code) {
    const statusTexts = {
      200: 'OK',
      201: 'Created',
      204: 'No Content',
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      428: 'Precondition Required',
      500: 'Internal Server Error'
    }
    return statusTexts[code] || 'Unknown'
  }

  /**
   * Download a file through the TCP file-socket side channel.
   *
   * @param {string} filePath - Remote file path
   * @param {string} localFile - Local destination path
   * @param {boolean} [applyAttrs=true] - Apply returned mode and best-effort owner/group metadata
   * on non-Windows Node.js hosts
   * @override
   */
  async download_file (filePath, localFile, applyAttrs = true) {
    const headers = {
      [HTTP_HEADER_KEY_X_FILE_PATH]: encodeURIComponent(filePath),
      [HTTP_HEADER_KEY_X_RECV_FILE_SOCKET]: 'true'
    }

    const response = await this._request(
      'get',
      '/appmesh/file/download',
      null,
      {
        headers
      }
    )

    if (!response.headers[HTTP_HEADER_KEY_X_RECV_FILE_SOCKET]) {
      throw new Error(
        `Server did not respond with socket transfer option: ${HTTP_HEADER_KEY_X_RECV_FILE_SOCKET}`
      )
    }

    // Receive file chunks
    const writeStream = fs.createWriteStream(localFile)
    try {
      while (true) {
        const chunk = await this.tcpTransport.receiveMessage()
        if (!chunk || chunk.length === 0) {
          break
        }
        writeStream.write(chunk)
      }
    } finally {
      writeStream.end()
    }

    // Apply file attributes on Unix systems
    if (applyAttrs && process.platform !== 'win32') {
      // Mode is sent as a decimal string (matches the HTTP transport and Python SDK)
      if (response.headers['X-File-Mode']) {
        fs.chmodSync(localFile, parseInt(response.headers['X-File-Mode'], 10))
      }
      if (response.headers['X-File-User'] && response.headers['X-File-Group']) {
        try {
          fs.chownSync(
            localFile,
            parseInt(response.headers['X-File-User']),
            parseInt(response.headers['X-File-Group'])
          )
        } catch (err) {
          console.warn(
            `Warning: Unable to change owner/group of ${localFile}. Operation requires elevated privileges.`
          )
        }
      }
    }
  }

  /**
   * Upload a file through the TCP file-socket side channel.
   *
   * @param {string} localFile - Local file path
   * @param {string} filePath - Remote destination path
   * @param {boolean} [applyAttrs=true] - Send local mode/uid/gid metadata so the server can
   * recreate permissions and ownership when supported
   * @override
   */
  async upload_file (localFile, filePath, applyAttrs = true) {
    if (!fs.existsSync(localFile)) {
      throw new Error(`Local file not found: ${localFile}`)
    }

    const headers = {
      [HTTP_HEADER_KEY_X_FILE_PATH]: encodeURIComponent(filePath),
      'Content-Type': 'text/plain',
      [HTTP_HEADER_KEY_X_SEND_FILE_SOCKET]: 'true'
    }

    // Add file attributes
    if (applyAttrs) {
      const stats = fs.statSync(localFile)
      headers['X-File-Mode'] = (stats.mode & 0o777).toString()
      headers['X-File-User'] = stats.uid.toString()
      headers['X-File-Group'] = stats.gid.toString()
    }

    const response = await this._request('post', '/appmesh/file/upload', null, {
      headers
    })

    if (!response.headers[HTTP_HEADER_KEY_X_SEND_FILE_SOCKET]) {
      throw new Error(
        `Server did not respond with socket transfer option: ${HTTP_HEADER_KEY_X_SEND_FILE_SOCKET}`
      )
    }

    // Send file chunks
    const readStream = fs.createReadStream(localFile, {
      highWaterMark: TCP_BLOCK_SIZE
    })

    for await (const chunk of readStream) {
      this.tcpTransport.sendMessage(chunk)
    }

    // Send EOF signal
    this.tcpTransport.sendMessage([])
  }

  /**
   * Subscribe to app events over TCP.
   *
   * @param {string} appName - Application name, or "*" for all apps.
   * @param {string[]} [events] - Event types: "START", "EXIT", "STDOUT", etc.
   * @param {function} callback - Called with event object for each received event.
   * @returns {Promise<Object>} Subscription result with subscription_id, app_name, events.
   */
  async subscribe (appName, events, callback) {
    this._enableDemuxer()

    let path = '/appmesh/subscribe'
    if (appName && appName !== '*') {
      path = `/appmesh/app/${appName}/subscribe`
    }

    const params = {}
    if (events && events.length > 0) {
      params.events = events.join(',')
    }

    const response = await this._request('post', path, null, { params })
    const result = response.data

    if (callback && result.subscription_id) {
      this._demuxer.registerEventCallback(result.subscription_id, callback)
    }

    return result
  }

  /**
   * Unsubscribe from app events.
   *
   * @param {string} subscriptionId - The subscription ID to remove.
   * @returns {Promise<void>}
   */
  async unsubscribe (subscriptionId) {
    await this._request('delete', '/appmesh/subscribe', null, {
      params: { subscription_id: subscriptionId }
    })

    if (this._demuxer) {
      this._demuxer.unregisterEventCallback(subscriptionId)
    }
  }

  /**
   * Register an app with optional atomic event subscription.
   *
   * @param {string} name - Application name.
   * @param {Object} appJson - Application definition.
   * @param {string[]} [subscribeEvents] - Event types to subscribe atomically.
   * @param {function} [callback] - Event callback (required when subscribeEvents is set).
   * @returns {Promise<Object>} Registered app (includes subscription_id when subscribed).
   */
  async add_app (name, appJson, subscribeEvents, callback) {
    const options = {}
    if (subscribeEvents && subscribeEvents.length > 0) {
      this._enableDemuxer()
      options.params = { subscribe_events: subscribeEvents.join(',') }
    }

    const response = await this._request('put', `/appmesh/app/${name}`, appJson, options)
    const result = response.data

    if (callback && result.subscription_id && this._demuxer) {
      this._demuxer.registerEventCallback(result.subscription_id, callback)
    }

    return result
  }

  /**
   * Enable demuxer for concurrent request-response and event routing.
   * @private
   */
  _enableDemuxer () {
    if (this._demuxer) return
    this._demuxer = new MessageDemuxer(this.tcpTransport)
    this._demuxer.start()
  }

  /**
   * Subscribe-based wait for async run (TCP override).
   *
   * Instead of polling get_app_output in a loop, subscribes to STDOUT/EXIT/REMOVED
   * events and does a one-shot backfill to cover output emitted before the subscribe
   * took effect.  Deduplicates by byte-position offset.
   *
   * No sentinel exit codes (real exit codes may be negative for signal kills):
   * non-EXIT terminations throw typed errors; null means caller-side timeout only.
   *
   * @param {AppRun} run - AppRun object
   * @param {Function} [stdoutHandler] - Stdout handler callback(data, position)
   * @param {number} [timeout=0] - Max wait time in seconds (0 = unlimited)
   * @returns {Promise<number|null>} Exit code, or null on timeout
   * @throws {AppRemovedError} If the app was removed before its exit was observed.
   * @throws {TransportDisconnectedError} If the demuxer disconnected while waiting,
   *   or the daemon delivered an unparseable exit code.
   */
  async wait_for_async_run (run, stdoutHandler, timeout = 0) {
    if (!run || !run.appName) return null

    let exitCode = null
    let failure = null
    let deliveredUntil = 0 // next-byte offset already delivered
    let done = false
    let resolveWait

    const waitPromise = new Promise(resolve => { resolveWait = resolve })

    const deliver = (chunk, pos) => {
      if (!chunk) return
      const buf = typeof chunk === 'string' ? Buffer.from(chunk, 'utf-8') : Buffer.from(chunk)
      const end = pos + buf.length
      if (end <= deliveredUntil) return
      let output = buf
      let startPos = pos
      if (pos < deliveredUntil) {
        output = buf.slice(deliveredUntil - pos)
        startPos = deliveredUntil
      }
      deliveredUntil = end
      if (stdoutHandler) {
        try { stdoutHandler(output.toString('utf-8'), startPos) } catch (_) { /* ignore */ }
      }
    }

    const onEvent = (event) => {
      if (event.event_type === 'STDOUT') {
        const pos = parseInt(event.data?.position ?? 0, 10) || 0
        deliver(event.data?.output ?? '', pos)
      } else if (event.event_type === 'EXIT') {
        const parsed = parseInt(event.data?.exit_code, 10)
        if (isNaN(parsed)) {
          failure = new TransportDisconnectedError(
            `EXIT event for '${run.appName}' carried an unparseable exit_code: ${event.data?.exit_code}`)
        } else {
          exitCode = parsed
        }
        done = true
        resolveWait()
      } else if (event.event_type === 'REMOVED') {
        if (exitCode === null && failure === null) {
          failure = new AppRemovedError(`app '${run.appName}' was removed before its exit was observed`)
        }
        done = true
        resolveWait()
      } else if (event.event_type === EVENT_TYPE_DISCONNECTED) {
        if (exitCode === null && failure === null) {
          failure = new TransportDisconnectedError(`transport disconnected while waiting for '${run.appName}' to exit`)
        }
        done = true
        resolveWait()
      }
    }

    const sub = await this.subscribe(run.appName, ['STDOUT', 'EXIT', 'REMOVED'], onEvent)

    try {
      // Backfill output emitted before subscribe took effect
      try {
        const backfill = await this.get_app_output(run.appName, 0, 0, 0, run.procUid, 0)
        if (backfill.output) {
          deliver(backfill.output, 0)
        }
        if (backfill.exitCode !== null && exitCode === null) {
          exitCode = backfill.exitCode
          done = true
          resolveWait()
        }
      } catch (_) {
        // backfill is best-effort
      }

      if (!done) {
        if (timeout > 0) {
          await Promise.race([
            waitPromise,
            new Promise(resolve => setTimeout(resolve, timeout * 1000))
          ])
        } else {
          await waitPromise
        }
      }
    } finally {
      try {
        if (sub && sub.subscription_id) {
          await this.unsubscribe(sub.subscription_id)
        }
      } catch (_) { /* ignore */ }

      // Best-effort delete on a real exit; on REMOVED/disconnect the app is already gone.
      if (exitCode !== null && failure === null) {
        try {
          await this.delete_app(run.appName)
        } catch (_) { /* ignore */ }
      }
    }

    if (failure !== null) throw failure
    return exitCode
  }
}

const EVENT_URI = '/appmesh/event'

/**
 * Synthetic event_type pushed to every registered callback when the demuxer
 * stops or the underlying transport disconnects. Lets long-running waits
 * (e.g. wait_for_async_run) unblock instead of hanging forever.
 */
const EVENT_TYPE_DISCONNECTED = '__disconnected__'

/**
 * Routes incoming messages to either pending request promises (by UUID) or
 * event subscription callbacks. Replaces the broken dual-reader pattern.
 * Events are dispatched to subscription callbacks synchronously from the single
 * read loop, in arrival order (matches the other SDK demuxers).
 */
class MessageDemuxer {
  // Bound the pre-registration event buffer (atomic-subscribe race window) so a
  // subscription whose callback never registers cannot grow memory without limit.
  static _MAX_BUFFERED_SUBS = 64
  static _MAX_BUFFERED_EVENTS_PER_SUB = 1000

  constructor (transport) {
    this._transport = transport
    this._pending = new Map()
    this._eventCallbacks = new Map()
    // Events that arrive between server-side subscription and the client
    // registering its callback (e.g. atomic add_app(subscribe_events) on a fast
    // app, whose output is pushed before add_app returns). Held per subId and
    // flushed on registerEventCallback so no events are lost.
    this._eventBuffers = new Map()
    this._running = false
  }

  start () {
    if (this._running) return
    this._running = true
    this._readLoop()
  }

  stop () {
    // Idempotent: _readLoop calls stop() again when it exits after an explicit
    // stop — don't broadcast a second synthetic DISCONNECTED event.
    if (!this._running) return
    this._running = false
    // Broadcast a synthetic disconnect event to all registered event callbacks
    // so long-running waits can unblock cleanly.
    this._broadcastDisconnect()
    for (const [, entry] of this._pending) {
      entry.reject(new TransportDisconnectedError('connection lost while waiting for response'))
    }
    this._pending.clear()
    this._eventBuffers.clear() // drop events buffered for never-registered subs
  }

  registerRequest (uuid) {
    return new Promise((resolve, reject) => {
      this._pending.set(uuid, { resolve, reject })
    })
  }

  unregisterRequest (uuid) {
    this._pending.delete(uuid)
  }

  registerEventCallback (subId, callback) {
    this._eventCallbacks.set(subId, callback)
    // Flush events that arrived before this callback registered (atomic-subscribe
    // race). Buffered events precede later live events: this runs synchronously at
    // register time, before any subsequent live event for subId can be dispatched.
    const buffered = this._eventBuffers.get(subId)
    if (buffered) {
      this._eventBuffers.delete(subId)
      for (const event of buffered) {
        try { callback(event) } catch (e) { console.error('Event callback error:', e) }
      }
    }
  }

  unregisterEventCallback (subId) {
    this._eventCallbacks.delete(subId)
    this._eventBuffers.delete(subId)
  }

  async _readLoop () {
    while (this._running && this._transport && this._transport.connected()) {
      try {
        const data = await this._transport.receiveMessage()
        if (!data || data.length === 0) break

        const resp = new ResponseMessage().deserialize(data)

        if (resp.requestUri === EVENT_URI) {
          this._dispatchEvent(resp)
        } else {
          this._dispatchResponse(resp)
        }
      } catch (e) {
        break
      }
    }
    // Connection lost — stop() handles broadcast + pending cleanup
    this.stop()
  }

  _broadcastDisconnect () {
    for (const [subId, cb] of this._eventCallbacks) {
      try {
        cb({
          subscription_id: subId,
          event_type: EVENT_TYPE_DISCONNECTED,
          app_name: '',
          timestamp: 0,
          sequence: 0,
          data: {}
        })
      } catch (e) {
        console.error('Disconnect callback error:', e)
      }
    }
  }

  _dispatchEvent (resp) {
    try {
      const bodyStr = typeof resp.body === 'string' ? resp.body : resp.body.toString('utf-8')
      const event = JSON.parse(bodyStr)
      const subId = event.subscription_id || (resp.headers && resp.headers['X-Subscription-Id'])
      const cb = this._eventCallbacks.get(subId)
      if (cb) {
        try { cb(event) } catch (e) { console.error('Event callback error:', e) }
      } else if (subId) {
        this._bufferEvent(subId, event)
      }
    } catch (e) {
      console.error('Failed to dispatch event:', e)
    }
  }

  /**
   * Hold an event whose callback has not registered yet, bounded to avoid
   * unbounded growth when a callback never registers.
   * @private
   */
  _bufferEvent (subId, event) {
    let buf = this._eventBuffers.get(subId)
    if (!buf) {
      if (this._eventBuffers.size >= MessageDemuxer._MAX_BUFFERED_SUBS) {
        return // cap distinct unregistered subs to bound memory
      }
      buf = []
      this._eventBuffers.set(subId, buf)
    }
    if (buf.length >= MessageDemuxer._MAX_BUFFERED_EVENTS_PER_SUB) {
      buf.shift() // drop-oldest
    }
    buf.push(event)
  }

  _dispatchResponse (resp) {
    const entry = this._pending.get(resp.uuid)
    if (entry) {
      this._pending.delete(resp.uuid)
      entry.resolve(resp)
    }
  }
}

export { AppMeshClientTCP, TCPTransport, RequestMessage, ResponseMessage, MessageDemuxer, EVENT_TYPE_DISCONNECTED }
export default AppMeshClientTCP
