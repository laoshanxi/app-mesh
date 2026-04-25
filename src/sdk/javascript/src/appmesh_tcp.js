// appmesh_tcp.js - App Mesh TCP Client SDK for Node.js
// This module provides TCP-based communication for improved performance with large file transfers

import tls from 'tls'
import fs from 'fs'
import os from 'os'
import { v1 as uuidv1 } from 'uuid'
import msgpack from 'msgpack-lite'
import AppMeshClient from './appmesh.js'

// Constants
const TCP_BLOCK_SIZE = 16 * 1024 - 128 // TLS-optimized chunk size
const ENCODING_UTF8 = 'utf-8'
const HTTP_USER_AGENT_TCP = 'appmesh/nodejs/tcp'
const HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = 'X-Send-File-Socket'
const HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = 'X-Recv-File-Socket'
const HTTP_HEADER_KEY_USER_AGENT = 'User-Agent'
const HTTP_HEADER_KEY_X_FILE_PATH = 'X-File-Path'
const HTTP_HEADER_KEY_AUTH = 'Authorization'

/**
 * TCP transport for secure TLS connections and framed App Mesh messages.
 */
class TCPTransport {
  constructor (address = ['127.0.0.1', 6059], sslConfig = null) {
    this.address = address
    this.sslConfig = sslConfig
    this.socket = null
    this.receiveBuffer = Buffer.alloc(0)
  }

  /**
   * Establish a TLS connection to the server if one is not already open.
   */
  connect () {
    if (this.connected()) {
      return
    }

    const options = {
      host: this.address[0],
      port: this.address[1],
      rejectUnauthorized: true
    }

    // Handle SSL configuration
    if (this.sslConfig) {
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
    } else if (this.sslConfig === false) {
      options.rejectUnauthorized = false
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
   * Send a message over the socket
   * @param {Buffer|Array} data - Data to send (empty array signals EOF)
   */
  sendMessage (data) {
    if (!this.connected()) {
      throw new Error('Socket not connected')
    }

    let payload
    if (Array.isArray(data) && data.length === 0) {
      // EOF signal
      payload = Buffer.alloc(4)
      payload.writeUInt32BE(0, 0)
    } else {
      const msgData = Buffer.isBuffer(data) ? data : Buffer.from(data)
      const length = msgData.length
      payload = Buffer.alloc(4 + length)
      payload.writeUInt32BE(length, 0)
      msgData.copy(payload, 4)
    }

    this.socket.write(payload)
  }

  /**
   * Receive a message from the socket
   * @returns {Promise<Buffer|null>} Received data or null for EOF
   */
  async receiveMessage () {
    if (!this.connected()) {
      return null
    }

    // Read message length (4 bytes)
    while (this.receiveBuffer.length < 4) {
      const chunk = await this._readChunk()
      if (!chunk) return null
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])
    }

    const length = this.receiveBuffer.readUInt32BE(0)

    // EOF signal
    if (length === 0) {
      this.receiveBuffer = this.receiveBuffer.slice(4)
      return Buffer.alloc(0)
    }

    // Read message body
    while (this.receiveBuffer.length < 4 + length) {
      const chunk = await this._readChunk()
      if (!chunk) return null
      this.receiveBuffer = Buffer.concat([this.receiveBuffer, chunk])
    }

    const message = this.receiveBuffer.slice(4, 4 + length)
    this.receiveBuffer = this.receiveBuffer.slice(4 + length)
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
   * @param {Object} [sslConfig=null] - SSL configuration object
   * @param {Buffer|string} [sslConfig.ca] - CA certificate
   * @param {Buffer|string} [sslConfig.cert] - Client certificate
   * @param {Buffer|string} [sslConfig.key] - Client key
   * @param {boolean} [sslConfig.rejectUnauthorized=true] - Whether to verify SSL
   * @param {Array<string, number>} [tcpAddress=['127.0.0.1', 6059]] - TCP server address [host, port]
   */
  constructor (sslConfig = null, tcpAddress = ['127.0.0.1', 6059]) {
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
    this._token = token || ''
    // Call parent implementation if it exists (for token refresh scheduling, etc.)
    if (super._handleTokenUpdate) {
      super._handleTokenUpdate(token)
    }
  }

  /**
   * Extract and store a token from a login/renew response body.
   *
   * Since TCP doesn't support Set-Cookie headers, we need to extract
   * the token from response body after login/authenticate operations.
   *
   * @param {Object} response - Response object from _request
   * @private
   */
  _extractTokenFromResponse (response) {
    // Check if response contains access_token (from login/renew)
    if (response.data) {
      let data = response.data

      // Parse if it's a Buffer containing JSON
      if (Buffer.isBuffer(data)) {
        try {
          data = JSON.parse(data.toString(ENCODING_UTF8))
        } catch (e) {
          // Not JSON, ignore
          return
        }
      }

      // Extract and store token
      if (data.access_token) {
        this._handleTokenUpdate(data.access_token)
      }
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
    this.tcpTransport.sendMessage(serialized)

    let response
    if (this._demuxer) {
      // Demuxer active: route response back via UUID matching.
      const resp = await this._demuxer.registerRequest(request.uuid)
      response = resp
    } else {
      // Legacy synchronous mode: read directly.
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
      data: response.body,
      config: options
    }

    // Extract token from response if present (for login, authenticate, renew_token)
    this._extractTokenFromResponse(result)

    return result
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

    if (response.status !== 200) {
      throw new Error(`Download failed: ${response.statusText}`)
    }

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
      if (response.headers['X-File-Mode']) {
        fs.chmodSync(localFile, parseInt(response.headers['X-File-Mode'], 8))
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

    if (response.status !== 200) {
      throw new Error(`Upload failed: ${response.statusText}`)
    }

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
 */
class MessageDemuxer {
  constructor (transport) {
    this._transport = transport
    this._pending = new Map()
    this._eventCallbacks = new Map()
    this._running = false
  }

  start () {
    if (this._running) return
    this._running = true
    this._readLoop()
  }

  stop () {
    this._running = false
    // Broadcast a synthetic disconnect event to all registered event callbacks
    // so long-running waits can unblock cleanly.
    this._broadcastDisconnect()
    for (const [, entry] of this._pending) {
      entry.reject(new Error('Demuxer stopped'))
    }
    this._pending.clear()
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
  }

  unregisterEventCallback (subId) {
    this._eventCallbacks.delete(subId)
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
      }
    } catch (e) {
      console.error('Failed to dispatch event:', e)
    }
  }

  _dispatchResponse (resp) {
    const entry = this._pending.get(resp.uuid)
    if (entry) {
      this._pending.delete(resp.uuid)
      entry.resolve(resp)
    }
  }
}

/**
 * Subscribe to app events over TCP.
 *
 * @param {string} appName - Application name, or "*" for all apps.
 * @param {string[]} [events] - Event types: "START", "EXIT", "STDOUT", etc.
 * @param {function} callback - Called with event object for each received event.
 * @returns {Promise<Object>} Subscription result with subscription_id, app_name, events.
 */
AppMeshClientTCP.prototype.subscribe = async function (appName, events, callback) {
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
  if (response.status !== 200) {
    throw new Error(`Subscribe failed: ${response.statusText}`)
  }

  const result = typeof response.data === 'string' ? JSON.parse(response.data) : response.data

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
AppMeshClientTCP.prototype.unsubscribe = async function (subscriptionId) {
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
AppMeshClientTCP.prototype.add_app = async function (name, appJson, subscribeEvents, callback) {
  const options = {}
  if (subscribeEvents && subscribeEvents.length > 0) {
    this._enableDemuxer()
    options.params = { subscribe_events: subscribeEvents.join(',') }
  }

  const response = await this._request('put', `/appmesh/app/${name}`, appJson, options)
  const result = typeof response.data === 'string' ? JSON.parse(response.data) : response.data

  if (callback && result.subscription_id && this._demuxer) {
    this._demuxer.registerEventCallback(result.subscription_id, callback)
  }

  return result
}

/**
 * Enable demuxer for concurrent request-response and event routing.
 * @private
 */
AppMeshClientTCP.prototype._enableDemuxer = function () {
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
 * Sentinel exit codes:
 *   null  — caller-side timeout
 *   -1    — REMOVED before EXIT observed
 *   -2    — demuxer disconnected (transport failure)
 *
 * @param {AppRun} run - AppRun object
 * @param {Function} [outputHandler] - Output handler
 * @param {number} [timeout=0] - Max wait time in seconds (0 = unlimited)
 * @returns {Promise<number|null>} Exit code, or null on timeout
 */
AppMeshClientTCP.prototype.wait_for_async_run = async function (run, outputHandler, timeout = 0) {
  if (!run || !run.appName) return null

  let exitCode = null
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
    if (pos < deliveredUntil) {
      output = buf.slice(deliveredUntil - pos)
    }
    deliveredUntil = end
    if (outputHandler) {
      try { outputHandler(output.toString('utf-8')) } catch (_) { /* ignore */ }
    }
  }

  const onEvent = (event) => {
    if (event.event_type === 'STDOUT') {
      const pos = parseInt(event.data?.position ?? 0, 10) || 0
      deliver(event.data?.output ?? '', pos)
    } else if (event.event_type === 'EXIT') {
      exitCode = parseInt(event.data?.exit_code ?? -1, 10)
      if (isNaN(exitCode)) exitCode = -1
      done = true
      resolveWait()
    } else if (event.event_type === 'REMOVED') {
      if (exitCode === null) exitCode = -1
      done = true
      resolveWait()
    } else if (event.event_type === EVENT_TYPE_DISCONNECTED) {
      if (exitCode === null) exitCode = -2
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

    // Best-effort delete on a real exit (>=0).
    // Sentinels (-1 REMOVED, -2 disconnected) mean the app is already gone.
    if (exitCode !== null && exitCode >= 0) {
      try {
        await this.delete_app(run.appName)
      } catch (_) { /* ignore */ }
    }
  }

  return exitCode
}

export { AppMeshClientTCP, TCPTransport, RequestMessage, ResponseMessage, MessageDemuxer, EVENT_TYPE_DISCONNECTED }
export default AppMeshClientTCP
