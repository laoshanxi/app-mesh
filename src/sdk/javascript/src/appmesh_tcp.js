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

/**
 * TCP Transport handler for secure TLS connections
 */
class TCPTransport {
  constructor (address = ['127.0.0.1', 6059], sslConfig = null) {
    this.address = address
    this.sslConfig = sslConfig
    this.socket = null
    this.receiveBuffer = Buffer.alloc(0)
  }

  /**
   * Establish TLS connection to the server
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
    this.httpStatus = decoded.http_status || 0
    this.bodyMsgType = decoded.body_msg_type || ''
    this.headers = decoded.headers || {}
    this.body = decoded.body || Buffer.alloc(0)
    return this
  }
}

/**
 * TCP-based App Mesh Client with optimized file transfer support
 *
 * Extends AppMeshClient to use TCP transport for better performance
 * with large file transfers while maintaining API compatibility.
 *
 * @extends AppMeshClient
 */
class AppMeshClientTCP extends AppMeshClient {
  /**
   * Create a TCP-based App Mesh client
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
  }

  /**
   * Close connections and release resources
   */
  close () {
    if (this.tcpTransport) {
      this.tcpTransport.close()
      this.tcpTransport = null
    }
  }

  /**
   * Send HTTP request over TCP transport
   * @private
   * @override
   */
  async _request (method, path, body = null, options = {}) {
    if (!this.tcpTransport.connected()) {
      this.tcpTransport.connect()
    }

    // Build request message
    const request = new RequestMessage()
    request.uuid = uuidv1()
    request.httpMethod = method.toUpperCase()
    request.requestUri = path
    request.clientAddr = os.hostname()

    // Set headers from options
    request.headers[HTTP_HEADER_KEY_USER_AGENT] = HTTP_USER_AGENT_TCP

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

    // Receive response
    const respData = await this.tcpTransport.receiveMessage()
    if (!respData || respData.length === 0) {
      this.tcpTransport.close()
      throw new Error('Socket connection broken')
    }

    const response = new ResponseMessage().deserialize(respData)

    // Convert to standard response format matching axios structure
    return {
      status: response.httpStatus,
      statusText: this._getStatusText(response.httpStatus),
      headers: response.headers,
      data: response.body,
      config: options
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
      500: 'Internal Server Error'
    }
    return statusTexts[code] || 'Unknown'
  }

  /**
   * Download file from remote server via optimized TCP transfer
   *
   * @param {string} filePath - Remote file path
   * @param {string} localFile - Local destination path
   * @param {boolean} [applyAttrs=true] - Apply remote file permissions locally
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
   * Upload file to remote server via optimized TCP transfer
   *
   * @param {string} localFile - Local file path
   * @param {string} filePath - Remote destination path
   * @param {boolean} [applyAttrs=true] - Upload file permissions metadata
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

export { AppMeshClientTCP, TCPTransport, RequestMessage, ResponseMessage }
export default AppMeshClientTCP
