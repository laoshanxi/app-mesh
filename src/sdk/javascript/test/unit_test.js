/**
 * Daemon-free unit tests for response decoding and error typing.
 *
 * - A-7a: a malformed JSON body must raise a typed AppMeshError, never silently
 *   degrade to a raw string (a string body later explodes far away, e.g. on
 *   `run.procUid.length`).
 * - B-5a: check_app_health maps only the daemon's verdict to false; auth/server
 *   errors must throw, not read as "unhealthy".
 * - A-9: JSON request bodies carry Content-Type: application/json on both transports.
 *
 * No daemon required — the HTTP tests use a local loopback mock server and the
 * TCP tests use a scripted transport.
 *
 * Run: node test/unit_test.js
 */

import http from 'http'
import nodeCrypto from 'node:crypto'
import { inspect as utilInspect } from 'node:util'
import msgpack from 'msgpack-lite'
import fs, { writeFileSync, unlinkSync } from 'fs'
import { tmpdir } from 'os'
import { join } from 'path'
import {
  AppMeshClient, AppMeshError, StaticAccessTokenProvider, RefreshTokenProvider, _resolveUserName, _resolveGroupName
} from '../src/appmesh.js'
import { AppMeshClientTCP } from '../src/appmesh_tcp.js'
import {
  RequestSigner, canonicalString, canonicalQuery, canonicalQueryFromEncoded, bodySha256Hex,
  canonicalSigningPath, isEmptyBodyExemptPath, EMPTY_BODY_SHA256
} from '../src/request_signature.js'

let passed = 0
let failed = 0

async function assert (name, fn) {
  try {
    await fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (error) {
    failed++
    console.error(`  FAIL: ${name} - ${error.message}`)
  }
}

// Reject with an AppMeshError and verify its type/code/status carry the failure cause
async function expectAppMeshError (promise, { errorCode, statusCode } = {}) {
  let thrown = null
  try {
    await promise
  } catch (error) {
    thrown = error
  }
  if (!(thrown instanceof AppMeshError)) {
    throw new Error(`expected AppMeshError, got ${thrown === null ? 'no error' : `${thrown.name}: ${thrown.message}`}`)
  }
  if (errorCode !== undefined && thrown.errorCode !== errorCode) {
    throw new Error(`expected errorCode ${errorCode}, got ${thrown.errorCode}`)
  }
  if (statusCode !== undefined && thrown.statusCode !== statusCode) {
    throw new Error(`expected statusCode ${statusCode}, got ${thrown.statusCode}`)
  }
  return thrown
}

// Headers the mock server last received on the upload route, so a test can assert
// what the SDK put on the wire.
let uploadHeaders = null

// Full wire snapshots (method, url, headers, body) of requests to /signed*,
// and of the /appmesh/refreshable attempts, for the request-signature tests.
const signedRequests = []
const signedRefreshRequests = []

// Authorization headers the mock server received on the refresh routes, in order,
// so a test can assert the 401 retry sequence.
let authRequests = []

// Bodies and Content-Types the mock server received on the token endpoint, in
// order, so a test can assert the refresh grant form fields.
let tokenRequests = []

function startMockServer () {
  const server = http.createServer((req, res) => {
    if (req.url === '/appmesh/file/upload') {
      uploadHeaders = req.headers
      // Drain the multipart body before answering, or the client sees a reset.
      req.resume()
      req.on('end', () => {
        res.writeHead(200, { 'Content-Type': 'text/plain' })
        res.end('ok')
      })
    } else if (req.url === '/appmesh/refreshable') {
      authRequests.push(req.headers.authorization || null)
      // Full header snapshots for the request-signature retry assertions.
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        signedRefreshRequests.push({ method: req.method, url: req.url, headers: req.headers, body })
        if (req.headers.authorization === 'Bearer new-token') {
          res.writeHead(200, { 'Content-Type': 'application/json' })
          res.end('{"ok": true}')
        } else {
          // An expired bearer carries the RFC 6750 invalid_token challenge; without it a signed 401 is terminal.
          res.writeHead(401, {
            'Content-Type': 'application/json',
            'WWW-Authenticate': 'Bearer error="invalid_token", error_description="token expired"'
          })
          res.end('{"message": "Unauthorized"}')
        }
      })
    } else if (req.url === '/appmesh/always-401') {
      authRequests.push(req.headers.authorization || null)
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end('{"message": "Unauthorized"}')
    } else if (req.url === '/oauth/token') {
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        tokenRequests.push({ contentType: req.headers['content-type'], body })
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end(JSON.stringify({ access_token: 'new-token', expires_in: 3600 }))
      })
    } else if (req.url === '/bad-json') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end('{"name": "x"')
    } else if (req.url === '/good-json') {
      res.writeHead(200, { 'Content-Type': 'application/json' })
      res.end('{"ok": true}')
    } else if (req.url === '/text-scalar') {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('0')
    } else if (req.url === '/appmesh/app/healthy/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('0')
    } else if (req.url === '/appmesh/app/sick/health') {
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end('1')
    } else if (req.url === '/appmesh/app/denied/health') {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end('{"message": "Unauthorized"}')
    } else if (req.url.startsWith('/signed') || req.url.startsWith('/pfx/signed') ||
               req.url === '/appmesh/file/download/ws') {
      // Capture the exact wire form (method, path, query, headers, body) so the
      // request-signature tests can verify like the daemon does.
      let body = ''
      req.on('data', chunk => { body += chunk })
      req.on('end', () => {
        signedRequests.push({
          method: req.method,
          url: req.url,
          headers: req.headers,
          body: Buffer.from(body, 'utf8')
        })
        res.writeHead(200, { 'Content-Type': 'application/json' })
        res.end('{"ok": true}')
      })
    } else {
      res.writeHead(404, { 'Content-Type': 'application/json' })
      res.end('{"message": "Not Found"}')
    }
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve(server)))
}

const server = await startMockServer()
const baseURL = `http://127.0.0.1:${server.address().port}`

console.log('=== JavaScript SDK Unit Tests (no daemon) ===\n')

// ---- HTTP transport: strict JSON decoding (A-7a) ----

await assert('HTTP malformed JSON raises typed JSON_PARSE error, not a string', async () => {
  const client = new AppMeshClient(baseURL)
  const err = await expectAppMeshError(client.request('get', '/bad-json'), { errorCode: 'JSON_PARSE', statusCode: 200 })
  if (typeof err.responseData !== 'string') throw new Error('responseData should keep the raw body for diagnostics')
})

await assert('HTTP valid JSON still parses to an object', async () => {
  const client = new AppMeshClient(baseURL)
  const response = await client.request('get', '/good-json')
  if (response.data.ok !== true) throw new Error(`expected parsed object, got ${JSON.stringify(response.data)}`)
})

await assert('HTTP text/plain scalar stays a string (health verdicts, stdout)', async () => {
  const client = new AppMeshClient(baseURL)
  const response = await client.request('get', '/text-scalar')
  if (response.data !== '0') throw new Error(`expected raw string "0", got ${JSON.stringify(response.data)}`)
})

// ---- HTTP transport: health check error semantics (B-5a) ----

await assert('check_app_health returns true on verdict 0', async () => {
  const client = new AppMeshClient(baseURL)
  if ((await client.checkAppHealth('healthy')) !== true) throw new Error('expected true')
})

await assert('check_app_health returns false only on an unhealthy verdict', async () => {
  const client = new AppMeshClient(baseURL)
  if ((await client.checkAppHealth('sick')) !== false) throw new Error('expected false')
})

await assert('check_app_health throws on 401 instead of reporting unhealthy', async () => {
  const client = new AppMeshClient(baseURL)
  await expectAppMeshError(client.checkAppHealth('denied'), { statusCode: 401 })
})

// ---- Token provider contract and 401 refresh retry ----

await assert('StaticAccessTokenProvider validates the token and clear() nulls it', async () => {
  const provider = new StaticAccessTokenProvider('  abc  ')
  if ((await provider.getAccessToken()) !== 'abc') throw new Error('expected trimmed token')
  if (provider.canRefresh() !== false) throw new Error('static provider must not refresh')
  for (const bad of ['', '   ', 42, null]) {
    let threw = false
    try { new StaticAccessTokenProvider(bad) } catch (_) { threw = true }
    if (!threw) throw new Error(`expected TypeError for ${JSON.stringify(bad)}`)
  }
  provider.clear()
  if ((await provider.getAccessToken()) !== null) throw new Error('clear() must null the token')
})

await assert('set_token_provider rejects non-provider objects', async () => {
  const client = new AppMeshClient(baseURL)
  let threw = false
  try { client.setTokenProvider({}) } catch (error) { threw = error instanceof TypeError }
  if (!threw) throw new Error('expected TypeError for a provider without getAccessToken')
})

// Fake refresh-capable provider: refreshAccessToken swaps old-token for new-token
// and records every rejected token it was called with.
function makeRefreshableProvider (calls) {
  return {
    token: 'old-token',
    async getAccessToken () { return this.token },
    canRefresh () { return true },
    async refreshAccessToken (rejectedToken) {
      calls.push(rejectedToken)
      this.token = 'new-token'
      return this.token
    }
  }
}

await assert('refreshable provider: 401 refreshes once and the retried request succeeds', async () => {
  const calls = []
  authRequests = []
  const client = new AppMeshClient(baseURL, null, makeRefreshableProvider(calls))
  const response = await client.request('get', '/appmesh/refreshable')
  if (response.data.ok !== true) throw new Error(`expected retried request to succeed, got status ${response.status}`)
  if (calls.length !== 1) throw new Error(`expected refreshAccessToken exactly once, got ${calls.length}`)
  if (calls[0] !== 'old-token') throw new Error(`expected rejected token "old-token", got ${JSON.stringify(calls[0])}`)
  const expected = 'Bearer old-token,Bearer new-token'
  if (authRequests.join(',') !== expected)
    throw new Error(`expected auth sequence ${expected}, got ${authRequests.join(',')}`)
})

await assert('static provider: 401 raises typed error without a retry', async () => {
  authRequests = []
  const client = new AppMeshClient(baseURL)
  client.setBearerToken('old-token')
  await expectAppMeshError(client.request('get', '/appmesh/refreshable'), { statusCode: 401 })
  if (authRequests.length !== 1) throw new Error(`expected exactly one request (no retry), got ${authRequests.length}`)
})

await assert('second 401 after refresh rejects with typed error, refresh still called once', async () => {
  const calls = []
  authRequests = []
  const client = new AppMeshClient(baseURL)
  client.setTokenProvider(makeRefreshableProvider(calls))
  await expectAppMeshError(client.request('get', '/appmesh/always-401'), { statusCode: 401 })
  if (calls.length !== 1) throw new Error(`expected refreshAccessToken exactly once, got ${calls.length}`)
  if (authRequests.length !== 2) throw new Error(`expected original + one retry, got ${authRequests.length} requests`)
})

await assert('setToken/clearBearerToken attach and detach through the provider', async () => {
  const client = new AppMeshClient(baseURL)
  client.setToken('alias-token')
  if ((await client._getAccessToken()) !== 'alias-token') throw new Error('setToken must attach the token')
  client.clearBearerToken()
  if ((await client._getAccessToken()) !== null) throw new Error('clear_bearer_token must detach the token')
  client.setBearerToken(null)
  if ((await client._getAccessToken()) !== null) throw new Error('setBearerToken(null) must clear')
})

await assert('TCP transport reads the token from the provider', async () => {
  const { client, sent } = makeScriptedTcpClient()
  client.setTokenProvider(makeRefreshableProvider([]))
  await client._request('get', '/appmesh/app/t')
  const request = msgpack.decode(sent[0])
  if (request.headers.Authorization !== 'Bearer old-token') {
    throw new Error(`expected Bearer old-token, got ${JSON.stringify(request.headers.Authorization)}`)
  }
})

// Scripted TCP transport answering 401 once, then 200: exercises the TCP
// refresh-and-retry path end to end.
function makeUnauthorizedThenOkTcpClient () {
  const client = new AppMeshClientTCP(false)
  const sent = []
  const statuses = [401, 200]
  client.tcpTransport = {
    connected: () => true,
    connect: async () => {},
    sendMessage: data => { sent.push(data) },
    receiveMessage: async () => msgpack.encode({
      uuid: 'resp-1',
      request_uri: '/appmesh/app/t',
      http_status: statuses.shift() ?? 200,
      body_msg_type: 'application/json',
      headers: {},
      body: Buffer.from('{}')
    })
  }
  return { client, sent }
}

await assert('TCP 401 refreshes once and retries with the new token', async () => {
  const calls = []
  const { client, sent } = makeUnauthorizedThenOkTcpClient()
  client.setTokenProvider(makeRefreshableProvider(calls))
  const response = await client._request('get', '/appmesh/app/t')
  if (response.status !== 200) throw new Error(`expected retried request to succeed, got status ${response.status}`)
  if (calls.length !== 1) throw new Error(`expected refreshAccessToken exactly once, got ${calls.length}`)
  if (calls[0] !== 'old-token') throw new Error(`expected rejected token "old-token", got ${JSON.stringify(calls[0])}`)
  if (sent.length !== 2) throw new Error(`expected original + one retry, got ${sent.length} requests`)
  const retry = msgpack.decode(sent[1])
  if (retry.headers.Authorization !== 'Bearer new-token') {
    throw new Error(`expected Bearer new-token on retry, got ${JSON.stringify(retry.headers.Authorization)}`)
  }
})

await assert('TCP static provider: 401 raises typed error without a retry', async () => {
  const { client, sent } = makeScriptedTcpClient({ http_status: 401 })
  client.setBearerToken('old-token')
  await expectAppMeshError(client._request('get', '/appmesh/app/t'), { statusCode: 401 })
  if (sent.length !== 1) throw new Error(`expected exactly one request (no retry), got ${sent.length}`)
})

// ---- RefreshTokenProvider ----

// Fake axios instance: records post(url, body, config) calls and delegates the
// response to `handler`, so provider tests never dial the network.
function makeFakeTokenHttp (handler, calls) {
  return {
    post: async (url, body, config) => {
      calls.push({ url, body, config })
      return handler({ url, body, config })
    }
  }
}

await assert('RefreshTokenProvider rejects non-loopback http and accepts https without dialing', async () => {
  for (const bad of ['http://example.com/token', 'http://192.168.1.10/token', 'ftp://127.0.0.1/token', 'not-a-url']) {
    let threw = false
    try {
      new RefreshTokenProvider({ tokenUrl: bad, accessToken: 'a', refreshToken: 'r' })
    } catch (error) { threw = error instanceof TypeError }
    if (!threw) throw new Error(`expected TypeError for ${JSON.stringify(bad)}`)
  }
  // https and loopback http must construct without any network access
  new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', refreshToken: 'r' })
  new RefreshTokenProvider({ tokenUrl: 'http://127.0.0.1:1/token', refreshToken: 'r' })
  new RefreshTokenProvider({ tokenUrl: 'http://localhost/token', refreshToken: 'r' })
  new RefreshTokenProvider({ tokenUrl: 'http://[::1]:1/token', refreshToken: 'r' })
})

await assert('RefreshTokenProvider proactively refreshes near expiry and single-flights concurrent calls', async () => {
  const calls = []
  const http = makeFakeTokenHttp(async () => {
    // Yield so concurrent getAccessToken callers overlap on the in-flight grant
    await new Promise(resolve => setTimeout(resolve, 10))
    return { status: 200, data: { access_token: 'fresh-token', expires_in: 3600 } }
  }, calls)
  const provider = new RefreshTokenProvider({
    tokenUrl: 'https://idp.example.com/token',
    accessToken: 'stale-token',
    refreshToken: 'rt-1',
    expiresIn: 20, // inside the 30s expiry margin -> expiring soon
    httpClient: http
  })
  const tokens = await Promise.all([provider.getAccessToken(), provider.getAccessToken(), provider.getAccessToken()])
  if (tokens.some(token => token !== 'fresh-token'))
    throw new Error(`expected all callers to get fresh-token, got ${JSON.stringify(tokens)}`)
  if (calls.length !== 1) throw new Error(`expected exactly one token request, got ${calls.length}`)
})

await assert('RefreshTokenProvider with unknown expiry does not refresh proactively', async () => {
  const calls = []
  const http = makeFakeTokenHttp(() => ({ status: 200, data: { access_token: 'x' } }), calls)
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', accessToken: 'at-1',
    refreshToken: 'rt-1', httpClient: http })
  if ((await provider.getAccessToken()) !== 'at-1') throw new Error('expected the current token without a refresh')
  if (calls.length !== 0) throw new Error(`expiresIn 0 must refresh only on 401, got ${calls.length} token requests`)
})

await assert('refreshAccessToken with a stale rejected token returns the current token without HTTP', async () => {
  const calls = []
  const http = makeFakeTokenHttp(() => ({ status: 200, data: { access_token: 'x' } }), calls)
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', accessToken: 'current-token',
    refreshToken: 'rt-1', httpClient: http })
  const token = await provider.refreshAccessToken('stale-token')
  if (token !== 'current-token') throw new Error(`expected current-token, got ${JSON.stringify(token)}`)
  if (calls.length !== 0)
    throw new Error(`a racing caller already refreshed; expected no token request, got ${calls.length}`)
})

await assert('grant sends form fields, stores a rotated refresh token, keeps the old one when omitted', async () => {
  const calls = []
  const http = makeFakeTokenHttp(({ body }) => {
    const refreshToken = new URLSearchParams(body).get('refresh_token')
    if (refreshToken === 'rt-1')
      return { status: 200, data: { access_token: 'at-2', refresh_token: 'rt-2', expires_in: 3600 } }
    return { status: 200, data: { access_token: 'at-3', expires_in: 3600 } } // no rotation
  }, calls)
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', accessToken: 'at-1',
    refreshToken: 'rt-1', httpClient: http })

  await provider.refreshAccessToken('at-1')
  if (calls.length !== 1) throw new Error(`expected one token request, got ${calls.length}`)
  const params = new URLSearchParams(calls[0].body)
  if (calls[0].config.headers['Content-Type'] !== 'application/x-www-form-urlencoded') {
    throw new Error(`expected form Content-Type, got ${JSON.stringify(calls[0].config.headers['Content-Type'])}`)
  }
  if (params.get('grant_type') !== 'refresh_token')
    throw new Error(`expected grant_type=refresh_token, got ${JSON.stringify(params.get('grant_type'))}`)
  if (params.get('client_id') !== 'appmesh-cli')
    throw new Error(`expected default client_id appmesh-cli, got ${JSON.stringify(params.get('client_id'))}`)
  if (params.get('refresh_token') !== 'rt-1')
    throw new Error(`expected refresh_token rt-1, got ${JSON.stringify(params.get('refresh_token'))}`)
  if ((await provider.getAccessToken()) !== 'at-2') throw new Error('expected the refreshed access token at-2')

  // The rotated refresh token rt-2 must be used on the next grant
  await provider.refreshAccessToken('at-2')
  if (new URLSearchParams(calls[1].body).get('refresh_token') !== 'rt-2')
    throw new Error('expected the rotated refresh token rt-2 on the second grant')
  if ((await provider.getAccessToken()) !== 'at-3') throw new Error('expected the refreshed access token at-3')

  // The response carried no refresh_token: the old rt-2 must be kept
  await provider.refreshAccessToken('at-3')
  if (new URLSearchParams(calls[2].body).get('refresh_token') !== 'rt-2')
    throw new Error('a response without refresh_token must keep the old one')
})

await assert('invalid_grant clears both tokens, canRefresh() turns false, getAccessToken rejects', async () => {
  const calls = []
  const http = makeFakeTokenHttp(() => ({ status: 400, data: { error: 'invalid_grant' } }), calls)
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', accessToken: 'at-1',
    refreshToken: 'rt-1', httpClient: http })
  let threw = false
  try { await provider.refreshAccessToken('at-1') } catch (_) { threw = true }
  if (!threw) throw new Error('expected invalid_grant to throw')
  if (provider.canRefresh() !== false) throw new Error('invalid_grant must drop the refresh token')
  threw = false
  try { await provider.getAccessToken() } catch (_) { threw = true }
  if (!threw) throw new Error('getAccessToken must reject once both tokens are cleared')
})

await assert('a transient grant failure throws but keeps the stored tokens', async () => {
  const http = makeFakeTokenHttp(() => ({ status: 500, data: { error: 'server_error' } }), [])
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', accessToken: 'at-1',
    refreshToken: 'rt-1', httpClient: http })
  let threw = false
  try { await provider.refreshAccessToken('at-1') } catch (_) { threw = true }
  if (!threw) throw new Error('expected a 500 grant response to throw')
  if (provider.canRefresh() !== true) throw new Error('a transient failure must keep the refresh token')
  if ((await provider.getAccessToken()) !== 'at-1') throw new Error('a transient failure must keep the access token')
})

await assert('a 400 without invalid_grant keeps the stored tokens', async () => {
  const http = makeFakeTokenHttp(() => ({ status: 400, data: { error: 'invalid_request' } }), [])
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token', accessToken: 'at-1',
    refreshToken: 'rt-1', httpClient: http })
  let threw = false
  try { await provider.refreshAccessToken('at-1') } catch (_) { threw = true }
  if (!threw) throw new Error('expected a 400 grant response to throw')
  if (provider.canRefresh() !== true) throw new Error('only invalid_grant may drop the refresh token')
  if ((await provider.getAccessToken()) !== 'at-1') throw new Error('only invalid_grant may drop the access token')
})

await assert('RefreshTokenProvider without an access token fetches one on first getAccessToken', async () => {
  const calls = []
  const http = makeFakeTokenHttp(() => ({ status: 200, data: { access_token: 'minted-token', expires_in: 3600 } }), calls)
  const provider = new RefreshTokenProvider({ tokenUrl: 'https://idp.example.com/token',
    refreshToken: 'rt-1', httpClient: http })
  if ((await provider.getAccessToken()) !== 'minted-token')
    throw new Error('expected a grant to mint the first access token')
  if (calls.length !== 1) throw new Error(`expected exactly one token request, got ${calls.length}`)
})

await assert('RefreshTokenProvider end-to-end: 401 drives the grant and the retried request succeeds', async () => {
  tokenRequests = []
  authRequests = []
  const provider = new RefreshTokenProvider({
    tokenUrl: `${baseURL}/oauth/token`,
    accessToken: 'old-token',
    refreshToken: 'rt-1'
  })
  const client = new AppMeshClient(baseURL, null, provider)
  const response = await client.request('get', '/appmesh/refreshable')
  if (response.data.ok !== true) throw new Error(`expected retried request to succeed, got status ${response.status}`)
  if (tokenRequests.length !== 1) throw new Error(`expected exactly one token grant, got ${tokenRequests.length}`)
  const params = new URLSearchParams(tokenRequests[0].body)
  if (params.get('grant_type') !== 'refresh_token' || params.get('client_id') !== 'appmesh-cli' ||
      params.get('refresh_token') !== 'rt-1') {
    throw new Error(`unexpected grant body ${JSON.stringify(tokenRequests[0].body)}`)
  }
  const expected = 'Bearer old-token,Bearer new-token'
  if (authRequests.join(',') !== expected)
    throw new Error(`expected auth sequence ${expected}, got ${authRequests.join(',')}`)
})

// ---- TCP transport: _decodeBody strictness (A-7a) ----

const tcpClient = new AppMeshClientTCP(false)

await assert('TCP malformed JSON body raises typed JSON_PARSE error', async () => {
  await expectAppMeshError(Promise.resolve().then(() => tcpClient._decodeBody({
    body: Buffer.from('{"broken"'),
    bodyMsgType: 'application/json',
    headers: {},
    httpStatus: 200
  }, {})), { errorCode: 'JSON_PARSE', statusCode: 200 })
})

await assert('TCP text/plain body (stdout) stays a string', () => {
  const text = tcpClient._decodeBody({
    body: Buffer.from('plain output line\n'),
    bodyMsgType: 'text/plain; charset=utf-8',
    headers: {},
    httpStatus: 200
  }, {})
  if (text !== 'plain output line\n') throw new Error(`expected raw text, got ${JSON.stringify(text)}`)
})

await assert('TCP empty body stays empty string', () => {
  const empty = tcpClient._decodeBody({ body: Buffer.alloc(0), bodyMsgType: 'text/plain', headers: {}, httpStatus: 200 }, {})
  if (empty !== '') throw new Error(`expected "", got ${JSON.stringify(empty)}`)
})

await assert('TCP octet-stream task reply decodes as UTF-8 text', () => {
  const text = tcpClient._decodeBody(
    { body: Buffer.from('task output'), bodyMsgType: 'application/octet-stream', headers: {}, httpStatus: 200 }, {})
  if (text !== 'task output') throw new Error(`expected text, got ${JSON.stringify(text)}`)
})

await assert('TCP binary responseType still returns a Buffer', () => {
  const buf = tcpClient._decodeBody(
    { body: Buffer.from([0x00, 0x01]), bodyMsgType: 'application/octet-stream', headers: {}, httpStatus: 200 },
    { config: { responseType: 'arraybuffer' } })
  if (!Buffer.isBuffer(buf)) throw new Error('expected Buffer passthrough')
})

await assert('TCP forwarded Content-Type header still selects text decoding', () => {
  const text = tcpClient._decodeBody({
    body: Buffer.from('forwarded body'),
    bodyMsgType: '',
    headers: { 'Content-Type': 'text/plain' },
    httpStatus: 200
  }, {})
  if (text !== 'forwarded body') throw new Error(`expected raw text, got ${JSON.stringify(text)}`)
})

// ---- TCP transport: request framing (A-9) ----

function makeScriptedTcpClient (responseFields) {
  const client = new AppMeshClientTCP(false)
  const sent = []
  client.tcpTransport = {
    connected: () => true,
    connect: async () => {},
    sendMessage: data => { sent.push(data) },
    receiveMessage: async () => msgpack.encode({
      uuid: 'resp-1',
      request_uri: '/appmesh/app/t',
      http_status: 200,
      body_msg_type: 'application/json',
      headers: {},
      body: Buffer.from('{}'),
      ...responseFields
    })
  }
  return { client, sent }
}

await assert('TCP JSON request body carries Content-Type: application/json', async () => {
  const { client, sent } = makeScriptedTcpClient()
  const response = await client._request('put', '/appmesh/app/t', { command: 'true' })
  if (response.data === null || typeof response.data !== 'object') throw new Error('expected parsed JSON body')
  const request = msgpack.decode(sent[0])
  if (request.headers['Content-Type'] !== 'application/json') {
    throw new Error(`expected Content-Type application/json, got ${request.headers['Content-Type']}`)
  }
  if (!request.body.toString('utf8').includes('"command"')) throw new Error('expected JSON payload in body')
})

await assert('TCP caller-supplied Content-Type header wins over the JSON default', async () => {
  const { client, sent } = makeScriptedTcpClient()
  await client._request('put', '/appmesh/app/t', { command: 'true' },
    { headers: { 'Content-Type': 'application/merge-patch+json' } })
  const request = msgpack.decode(sent[0])
  if (request.headers['Content-Type'] !== 'application/merge-patch+json') {
    throw new Error(`expected caller header to win, got ${request.headers['Content-Type']}`)
  }
})

await assert('TCP malformed JSON response raises typed error through _request', async () => {
  const { client } = makeScriptedTcpClient({ body: Buffer.from('{"broken"') })
  await expectAppMeshError(client._request('get', '/appmesh/app/t'), { errorCode: 'JSON_PARSE', statusCode: 200 })
})

// ---- File attributes: owner/group as names, numeric ids as fallback ----
//
// The daemon resolves X-File-User/X-File-Group by name (os::chown -> getUidByName)
// and accepts all-digit values as a numeric fallback, and its download side
// reports names (falling back to numeric strings for unknown ids), so a client
// that parseInt()s them hands NaN to chown. Both transports therefore resolve
// to names on upload (numeric ids when unresolvable) and from names on
// download, and skip the ownership step when a name does not resolve.

await assert('uid/gid resolve to names, and unknown ids resolve to null', async () => {
  const userName = await _resolveUserName(process.getuid())
  if (typeof userName !== 'string' || userName.length === 0) {
    throw new Error(`uid ${process.getuid()} must resolve to a user name, got ${JSON.stringify(userName)}`)
  }
  const groupName = await _resolveGroupName(process.getgid())
  if (typeof groupName !== 'string' || groupName.length === 0) {
    throw new Error(`gid ${process.getgid()} must resolve to a group name, got ${JSON.stringify(groupName)}`)
  }
  if ((await _resolveUserName(123456)) !== null) throw new Error('an unknown uid must resolve to null')
  if ((await _resolveGroupName(123456)) !== null) throw new Error('an unknown gid must resolve to null')
})

await assert('HTTP upload sends owner/group names, not numeric ids', async () => {
  const client = new AppMeshClient(baseURL)
  const localFile = join(tmpdir(), 'appmesh_unit_upload_attrs.txt')
  writeFileSync(localFile, 'attrs', 'utf8')
  try {
    uploadHeaders = null
    await client.uploadFile(localFile, '/tmp/appmesh_unit_target.txt', true)
    if (!uploadHeaders) throw new Error('the upload never reached the mock server')
    const userName = await _resolveUserName(process.getuid())
    const groupName = await _resolveGroupName(process.getgid())
    if (uploadHeaders['x-file-user'] !== userName) {
      throw new Error(`expected X-File-User ${JSON.stringify(userName)}, ` +
        `got ${JSON.stringify(uploadHeaders['x-file-user'])}`)
    }
    if (uploadHeaders['x-file-group'] !== groupName) {
      throw new Error(`expected X-File-Group ${JSON.stringify(groupName)}, ` +
        `got ${JSON.stringify(uploadHeaders['x-file-group'])}`)
    }
    if (!/^[0-7]+$/.test(uploadHeaders['x-file-mode'] || '')) {
      throw new Error(`expected numeric X-File-Mode, got ${JSON.stringify(uploadHeaders['x-file-mode'])}`)
    }
  } finally {
    try { unlinkSync(localFile) } catch (_) {}
  }
})

await assert('TCP upload sends owner/group names, not numeric ids', async () => {
  const client = new AppMeshClientTCP(false)
  const localFile = join(tmpdir(), 'appmesh_unit_tcp_upload_attrs.txt')
  writeFileSync(localFile, 'attrs', 'utf8')
  let sentHeaders = null
  client._request = async (method, path, body, options) => {
    sentHeaders = options.headers
    return { headers: { 'X-Send-File-Socket': 'true' }, httpStatus: 200 }
  }
  client.tcpTransport.sendMessage = () => {}
  try {
    await client.uploadFile(localFile, '/tmp/appmesh_unit_tcp_target.txt', true)
    const userName = await _resolveUserName(process.getuid())
    const groupName = await _resolveGroupName(process.getgid())
    if (sentHeaders['X-File-User'] !== userName) {
      throw new Error(`expected X-File-User ${JSON.stringify(userName)}, ` +
        `got ${JSON.stringify(sentHeaders['X-File-User'])}`)
    }
    if (sentHeaders['X-File-Group'] !== groupName) {
      throw new Error(`expected X-File-Group ${JSON.stringify(groupName)}, ` +
        `got ${JSON.stringify(sentHeaders['X-File-Group'])}`)
    }
    if (sentHeaders['X-File-User'] === String(process.getuid())) {
      throw new Error('a numeric uid must not be sent as the owner')
    }
  } finally {
    try { unlinkSync(localFile) } catch (_) {}
  }
})

await assert('TCP download resolves names before chown and skips unknown ones', async () => {
  const client = new AppMeshClientTCP(false)
  const localFile = join(tmpdir(), 'appmesh_unit_tcp_download_attrs.txt')
  const chowns = []
  const originalChownSync = fs.chownSync
  fs.chownSync = (path, uid, gid) => { chowns.push([uid, gid]) }
  const chunks = []
  client.tcpTransport.receiveMessage = async () => (chunks.length > 0 ? chunks.shift() : Buffer.alloc(0))
  try {
    client._request = async () => ({
      headers: {
        'X-Recv-File-Socket': 'true',
        'X-File-User': await _resolveUserName(process.getuid()),
        'X-File-Group': await _resolveGroupName(process.getgid())
      },
      httpStatus: 200
    })
    chunks.push(Buffer.from('download body'))
    await client.downloadFile('/remote/file.txt', localFile, true)
    if (chowns.length !== 1) {
      throw new Error(`expected exactly one chown, got ${JSON.stringify(chowns)}`)
    }
    if (chowns[0][0] !== process.getuid() || chowns[0][1] !== process.getgid()) {
      throw new Error(`expected chown to ${process.getuid()}:${process.getgid()}, got ${chowns[0].join(':')}`)
    }

    // A name the local host cannot resolve must skip ownership, not chown NaN.
    chowns.length = 0
    client._request = async () => ({
      headers: {
        'X-Recv-File-Socket': 'true',
        'X-File-User': 'appmesh-no-such-user',
        'X-File-Group': 'appmesh-no-such-group'
      },
      httpStatus: 200
    })
    chunks.push(Buffer.from('download body'))
    await client.downloadFile('/remote/file.txt', localFile, true)
    if (chowns.length !== 0) {
      throw new Error(`unresolvable names must not reach chown, got ${JSON.stringify(chowns)}`)
    }
  } finally {
    fs.chownSync = originalChownSync
    try { unlinkSync(localFile) } catch (_) {}
  }
})

// ---- Request signature (opt-in HMAC, REST.RequestSignature hardening) ----
//
// The canonical string must mirror src/daemon/security/RequestSignature.{h,cpp}
// byte-for-byte. The fixed vectors below were produced independently with
// `openssl dgst -sha256 -hmac`, so a drift in the canonical form (separator,
// order, body hash, hex case) fails the test instead of failing on the daemon.

const SIG_KEY_ID = 'ak-3f9c2a81b0d4'
const SIG_SECRET = 's3cret-key'
const VECTOR_GET_QUERY = '53f587f8c38267cbd15f7b5c846f21a1e00e8baedb8b901b3d1f0b802cc06cfe'
const VECTOR_POST_FILE = 'fa047e47d2b039c652e7029a41530cc8e3a0e81fe2fc71a7fcd145ea96f6ef80'
const hmacHex = (canonical) => nodeCrypto.createHmac('sha256', SIG_SECRET).update(canonical, 'utf8').digest('hex')

// Independent daemon-side verification: rebuild the canonical string from what
// the daemon would see (raw path, %-only decoded query, raw body bytes) using
// node:crypto directly, not the SDK signer.
function verifyCaptured (captured) {
  const url = new URL(captured.url, 'http://localhost')
  const canonical = canonicalString(
    captured.method,
    url.pathname,
    canonicalQueryFromEncoded(url.search ? url.search.slice(1) : ''),
    nodeCrypto.createHash('sha256').update(captured.body).digest('hex'),
    captured.headers['x-timestamp'],
    captured.headers['x-nonce']
  )
  return { canonical, signature: captured.headers['x-signature'], expected: hmacHex(canonical) }
}

await assert('signer known-answer vectors match the daemon canonical form', async () => {
  const signer = new RequestSigner(SIG_KEY_ID, SIG_SECRET)
  const canonical = canonicalString('GET', '/appmesh/app/demo', 'b=2&a=1', EMPTY_BODY_SHA256,
    '1700000000', 'n-12345')
  if (canonical !== `GET\n/appmesh/app/demo\nb=2&a=1\n${EMPTY_BODY_SHA256}\n1700000000\nn-12345`) {
    throw new Error(`unexpected canonical form: ${JSON.stringify(canonical)}`)
  }
  if (await signer.sign(canonical) !== VECTOR_GET_QUERY) {
    throw new Error(`GET+query vector mismatch: ${await signer.sign(canonical)}`)
  }
  const fileCanonical = canonicalString('POST', '/appmesh/file/upload', '', EMPTY_BODY_SHA256,
    '1700000001', 'abc')
  if (await signer.sign(fileCanonical) !== VECTOR_POST_FILE) {
    throw new Error(`POST file vector mismatch: ${await signer.sign(fileCanonical)}`)
  }
  if (signer.toString().includes(SIG_SECRET)) throw new Error('toString must redact the secret')
})

await assert('signer secret never surfaces in JSON.stringify or util.inspect', async () => {
  const signer = new RequestSigner(SIG_KEY_ID, SIG_SECRET)
  const dumped = JSON.stringify(signer)
  if (dumped.includes(SIG_SECRET)) throw new Error(`JSON.stringify leaked the secret: ${dumped}`)
  // Default options = what console.log renders; non-enumerable props stay hidden.
  const inspected = utilInspect(signer)
  if (inspected.includes(SIG_SECRET)) throw new Error(`util.inspect leaked the secret: ${inspected}`)
  // The hidden own property still backs signing.
  if (!Object.prototype.hasOwnProperty.call(signer, '_secret')) throw new Error('the _secret own property must exist')
  if (await signer.sign('canonical') !== hmacHex('canonical')) throw new Error('the hidden secret must still sign')
})

await assert('body hash: empty body, FIPS vector, and streamed-file exemption', async () => {
  if (await bodySha256Hex('/x', null) !== EMPTY_BODY_SHA256) throw new Error('null body must hash the empty string')
  if (await bodySha256Hex('/x', Buffer.alloc(0)) !== EMPTY_BODY_SHA256) throw new Error('empty body must hash the empty string')
  if (await bodySha256Hex('/x', Buffer.from('abc')) !==
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad') {
    throw new Error('sha256("abc") vector mismatch')
  }
  // Streamed file endpoints sign the empty-string hash even with a body present.
  if (await bodySha256Hex('/appmesh/file/upload', Buffer.from('streamed bytes')) !== EMPTY_BODY_SHA256) {
    throw new Error('file endpoint must sign the empty-string hash')
  }
  // The exemption is the exact daemon route set: subpaths hash their real body.
  if (!isEmptyBodyExemptPath('/appmesh/file/download')) throw new Error('the route itself is exempt')
  if (!isEmptyBodyExemptPath('/appmesh/file/download/ws')) throw new Error('the /ws channel is exempt')
  if (isEmptyBodyExemptPath('/appmesh/file/download/other')) throw new Error('subpaths are NOT exempt')
})

await assert('canonicalQuery sorts decoded pairs and skips null values', () => {
  if (canonicalQuery({ b: '2', a: '1', c: '3' }) !== 'a=1&b=2&c=3') throw new Error('pairs must sort by key')
  if (canonicalQuery({ k: 'y', j: 'z' }) !== 'j=z&k=y') throw new Error('sort by key then value')
  if (canonicalQuery({}) !== '') throw new Error('empty query must be the empty string')
  if (canonicalQuery(null) !== '') throw new Error('null query must be the empty string')
  if (canonicalQuery({ q: 'a b', skip: null }) !== 'q=a b') throw new Error('null values are skipped, values stay decoded')
  if (canonicalQuery({ k: 'é' }) !== 'k=é') throw new Error('decoded non-ASCII stays decoded')
})

await assert('canonicalQueryFromEncoded mirrors the daemon parser', () => {
  // %20 decodes to a space, '+' stays literal, %2F decodes to '/'; a duplicate
  // key keeps only its first occurrence (daemon std::map::emplace).
  if (canonicalQueryFromEncoded('b=2&a=%20&a=+&x=%2F') !== 'a= &b=2&x=/') {
    throw new Error(`got ${canonicalQueryFromEncoded('b=2&a=%20&a=+&x=%2F')}`)
  }
  if (canonicalQueryFromEncoded('k=%zz') !== 'k=%zz') throw new Error('malformed escape keeps the raw component')
  if (canonicalQueryFromEncoded('a=1&a=2') !== 'a=1') throw new Error('duplicate key keeps the first value')
  if (canonicalQueryFromEncoded('flag&a=1') !== 'a=1&flag=') throw new Error('a pair without = has an empty value')
  if (canonicalQueryFromEncoded('') !== '' || canonicalQueryFromEncoded(null) !== '') throw new Error('empty input')
  if (canonicalQueryFromEncoded('k=%C3%A9') !== 'k=é') throw new Error('UTF-8 percent escapes decode')
})

await assert('canonical query order is UTF-8 bytes, not UTF-16 code units', () => {
  // An emoji (U+1F600, UTF-16 surrogate pair) sorts BEFORE U+FFFD by UTF-16
  // code units but AFTER it by UTF-8 bytes; the daemon orders by UTF-8 bytes.
  const expected = '\uFFFD=2&\uD83D\uDE00=1'
  const encoded = canonicalQueryFromEncoded('%F0%9F%98%80=1&%EF%BF%BD=2')
  if (encoded !== expected) throw new Error(`encoded form got ${encoded}`)
  const mapped = canonicalQuery({ '\uD83D\uDE00': '1', '\uFFFD': '2' })
  if (mapped !== expected) throw new Error(`map form got ${mapped}`)
})

await assert('canonicalQueryFromEncoded treats prototype names as plain data (daemon std::map)', () => {
  // The daemon keeps every decoded key in a std::map, so a key named like an
  // Object prototype member is data. A plain object used to drop
  // toString/constructor/hasOwnProperty keys and lose __proto__ assignments.
  if (canonicalQueryFromEncoded('toString=1&constructor=2&hasOwnProperty=3&valueOf=4') !==
      'constructor=2&hasOwnProperty=3&toString=1&valueOf=4') {
    throw new Error(`prototype-named keys must survive: ${canonicalQueryFromEncoded('toString=1&constructor=2&hasOwnProperty=3&valueOf=4')}`)
  }
  // "__proto__" is a real entry, never the prototype trap.
  if (canonicalQueryFromEncoded('__proto__=x&a=1') !== '__proto__=x&a=1') {
    throw new Error(`__proto__ must stay data: ${canonicalQueryFromEncoded('__proto__=x&a=1')}`)
  }
  // Dedup is on the DECODED key (daemon decodes each component, then emplaces):
  // "%61" decodes to "a", so raw-key dedup used to keep both entries.
  if (canonicalQueryFromEncoded('a=1&%61=2') !== 'a=1') {
    throw new Error(`decoded-key first-wins: ${canonicalQueryFromEncoded('a=1&%61=2')}`)
  }
  // ... while two keys that merely LOOK alike encoded stay distinct entries.
  if (canonicalQueryFromEncoded('a=1&a%61=2') !== 'a=1&aa=2') {
    throw new Error(`distinct decoded keys both stay: ${canonicalQueryFromEncoded('a=1&a%61=2')}`)
  }
})

await assert('canonicalQueryFromEncoded keeps empty segments like the daemon', () => {
  // An empty segment inserts ("", "") and the canonical output keeps its "="
  // (the daemon Adaptor loop has no empty-segment skip); a trailing '&' adds
  // no segment because the loop ends at the string bounds.
  if (canonicalQueryFromEncoded('a=1&&b=2') !== '=&a=1&b=2') {
    throw new Error(`got ${canonicalQueryFromEncoded('a=1&&b=2')}`)
  }
  if (canonicalQueryFromEncoded('&&') !== '=') throw new Error(`got ${canonicalQueryFromEncoded('&&')}`)
  if (canonicalQueryFromEncoded('a=1&') !== 'a=1') throw new Error('a trailing & adds no segment')
})

await assert('cross-language golden signature vectors (fixed ts/nonce)', async () => {
  // The same five vectors are pinned by the daemon C++, Go, Java, Python, and
  // Rust test suites; path/query are the wire-encoded forms fed straight into
  // the canonical layer, so no time window is involved.
  const vectors = [
    { method: 'GET', path: '/appmesh/app/100%25', query: '', body: '',
      ts: '1700000000', nonce: 'nonce-golden-0001',
      sig: '1036298fce978dab3ca5393a17c8dbeafcd22e8394585a96ce5a60ad39694d8c' },
    { method: 'GET', path: '/appmesh/app/list', query: 'flag=true&name=dh-bot', body: '',
      ts: '1700000001', nonce: 'nonce-golden-0002',
      sig: '0c9287088c6ca609fad7436f3f4646451faa8e180733e28e10e4eee11f34a9c5' },
    { method: 'POST', path: '/appmesh/file/download', query: '', body: '',
      ts: '1700000002', nonce: 'nonce-golden-0003',
      sig: 'dea6aa318b1fc84f8ffaadc859e4b36a90a9d6c5619f737dd037c78e5d17ac7d' },
    { method: 'GET', path: '/appmesh/app/%E4%B8%AD%E6%96%87', query: 'a=1%26b%3D2', body: '',
      ts: '1700000003', nonce: 'nonce-golden-0004',
      sig: '6cf618bfb9264d61d5b23dbaa42d366f59054bce99b9addab3253f98aaadb0ab' },
    { method: 'POST', path: '/appmesh/appmesh/run', query: '', body: '{"command":"echo hi"}',
      ts: '1700000004', nonce: 'nonce-golden-0005',
      sig: '0a8de849eda2abf6389d40f11299aaf09e7b440615a6ee0c7e01012a92a1f876' }
  ]
  const signer = new RequestSigner('ak-golden', 'golden-secret')
  for (const v of vectors) {
    // bodySha256Hex with a non-exempt path hashes the given bytes verbatim.
    const canonical = canonicalString(v.method, v.path, v.query,
      await bodySha256Hex('/golden/vector', Buffer.from(v.body, 'utf8')), v.ts, v.nonce)
    const got = await signer.sign(canonical)
    if (got !== v.sig) throw new Error(`vector ${v.nonce} mismatch: ${got}`)
    if (canonical.split('\n').length !== 6) throw new Error('canonical must be six \\n-joined segments')
  }
})

await assert('HTTP transport attaches a verifiable signature (query, body, spaces)', async () => {
  const client = new AppMeshClient(baseURL)
  client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
  if (!client.isRequestSignatureEnabled()) throw new Error('signer must report enabled')

  await client.request('post', '/signed/echo', 'hello body', { params: { b: '2', a: '1' } })
  let captured = signedRequests[signedRequests.length - 1]
  if (captured.headers['x-request-key'] !== SIG_KEY_ID) throw new Error('X-Request-Key missing')
  if (!/^\d+$/.test(captured.headers['x-timestamp'] || '')) throw new Error('X-Timestamp must be unix seconds')
  if (!captured.headers['x-nonce']) throw new Error('X-Nonce missing')
  let verified = verifyCaptured(captured)
  if (verified.signature !== verified.expected) {
    throw new Error(`signature mismatch:\n  got      ${verified.signature}\n  expected ${verified.expected}`)
  }

  // A space in a query value must reach the daemon decodable (the signed client
  // forces pure percent encoding: %20, never '+'-for-space).
  await client.request('get', '/signed/spaces', null, { params: { q: 'a b', a: '1' } })
  captured = signedRequests[signedRequests.length - 1]
  if (!captured.url.includes('q=a%20b')) throw new Error(`space must be %20 on the wire: ${captured.url}`)
  verified = verifyCaptured(captured)
  if (verified.signature !== verified.expected) throw new Error('space-query signature mismatch')

  // Object bodies sign the JSON bytes axios actually writes.
  await client.request('put', '/signed/obj', { command: 'true' })
  captured = signedRequests[signedRequests.length - 1]
  if (captured.body.toString('utf8') !== '{"command":"true"}') {
    throw new Error(`unexpected wire body: ${captured.body.toString('utf8')}`)
  }
  verified = verifyCaptured(captured)
  if (verified.signature !== verified.expected) throw new Error('JSON body signature mismatch')

  // Opt-out removes the headers entirely.
  client.disableRequestSignature()
  if (client.isRequestSignatureEnabled()) throw new Error('signer must report disabled')
  await client.request('get', '/signed/off')
  captured = signedRequests[signedRequests.length - 1]
  if (captured.headers['x-signature'] !== undefined || captured.headers['x-request-key'] !== undefined) {
    throw new Error('signature must be opt-in')
  }
})

await assert('canonicalSigningPath strips the /ws data-channel suffix', () => {
  if (canonicalSigningPath('/appmesh/file/download/ws') !== '/appmesh/file/download') {
    throw new Error('download/ws must sign the route without /ws')
  }
  if (canonicalSigningPath('/appmesh/file/upload/ws') !== '/appmesh/file/upload') {
    throw new Error('upload/ws must sign the route without /ws')
  }
  if (canonicalSigningPath('/appmesh/file/delete') !== '/appmesh/file/delete') throw new Error('delete route passes through')
  if (canonicalSigningPath('/appmesh/applications') !== '/appmesh/applications') throw new Error('other paths pass through')
})

await assert('HTTP signature binds the wire path (space, baseURL prefix, /ws strip)', async () => {
  const client = new AppMeshClient(baseURL)
  client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)

  // A path with a space: axios percent-encodes it on the wire, so the signature
  // must be computed over the ENCODED wire path, not the caller's raw path.
  await client.request('get', '/signed/sp ace')
  let captured = signedRequests[signedRequests.length - 1]
  if (!captured.url.startsWith('/signed/sp%20ace')) {
    throw new Error(`wire path must be %20-encoded: ${captured.url}`)
  }
  let verified = verifyCaptured(captured)
  if (verified.signature !== verified.expected) {
    throw new Error('path-with-space signature mismatch (the raw path was signed, not the wire path)')
  }

  // A baseURL with a path prefix: the prefix is part of the wire path and must
  // be signed too.
  const prefixed = new AppMeshClient(`${baseURL}/pfx`)
  prefixed.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
  await prefixed.request('get', '/signed/prefixed')
  captured = signedRequests[signedRequests.length - 1]
  if (captured.url !== '/pfx/signed/prefixed') {
    throw new Error(`the baseURL path prefix must reach the wire: ${captured.url}`)
  }
  verified = verifyCaptured(captured)
  if (verified.signature !== verified.expected) {
    throw new Error('baseURL-prefix signature mismatch (the prefix was not signed)')
  }

  // The /ws data-channel route signs the route WITHOUT the trailing "/ws"
  // (daemon canonicalFileRoute) with the empty-string body hash.
  await client.request('get', '/appmesh/file/download/ws')
  captured = signedRequests[signedRequests.length - 1]
  if (captured.url !== '/appmesh/file/download/ws') throw new Error(`unexpected capture url: ${captured.url}`)
  const wsCanonical = canonicalString('GET', '/appmesh/file/download', '', EMPTY_BODY_SHA256,
    captured.headers['x-timestamp'], captured.headers['x-nonce'])
  if (captured.headers['x-signature'] !== hmacHex(wsCanonical)) {
    throw new Error('/ws route must sign the stripped path with the empty-body hash')
  }
})

await assert('HTTP 401 refresh retry re-signs with a fresh nonce', async () => {
  authRequests.length = 0
  signedRefreshRequests.length = 0
  const client = new AppMeshClient(baseURL, null, makeRefreshableProvider([]))
  client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
  const response = await client.request('post', '/appmesh/refreshable', { ok: true })
  if (response.status !== 200) throw new Error(`expected retried request to succeed, got ${response.status}`)
  if (signedRefreshRequests.length !== 2) throw new Error(`expected 2 wire requests, got ${signedRefreshRequests.length}`)
  const verifications = signedRefreshRequests.map(verifyCaptured)
  if (verifications.some(v => v.signature !== v.expected)) throw new Error('both attempts must verify')
  const [first, second] = signedRefreshRequests
  if (first.headers['x-nonce'] === second.headers['x-nonce']) {
    throw new Error('the retry must carry a fresh nonce (a replayed nonce is rejected by replay protection)')
  }
})

await assert('signed 401 without an invalid_token challenge never burns the refresh token', async () => {
  const calls = []
  const client = new AppMeshClient(baseURL, null, makeRefreshableProvider(calls))
  client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
  // /appmesh/always-401 answers 401 WITHOUT a WWW-Authenticate challenge: a
  // signature rejection, so the single-use refresh token must stay untouched
  // and the 401 surfaces as the terminal typed error.
  let status = null
  try {
    await client.request('get', '/appmesh/always-401')
  } catch (error) {
    status = error.statusCode ?? null
  }
  if (status !== 401) throw new Error(`expected the 401 to surface, got ${JSON.stringify(status)}`)
  if (calls.length !== 0) throw new Error(`refreshAccessToken must not run, got ${calls.length} call(s)`)
})

await assert('streamed file upload signs the empty-body hash (documented exemption)', async () => {
  const localFile = join(tmpdir(), `appmesh-sign-upload-${process.pid}.txt`)
  writeFileSync(localFile, 'file content bytes')
  try {
    const client = new AppMeshClient(baseURL)
    client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
    await client.uploadFile(localFile, '/remote/file.txt')
    if (!uploadHeaders) throw new Error('upload request was not captured')
    // The file bytes go on the wire, but the signature binds the empty hash.
    const canonical = canonicalString('POST', '/appmesh/file/upload', '', EMPTY_BODY_SHA256,
      uploadHeaders['x-timestamp'], uploadHeaders['x-nonce'])
    if (uploadHeaders['x-signature'] !== hmacHex(canonical)) {
      throw new Error('upload signature must verify with the empty-string body hash')
    }
  } finally {
    unlinkSync(localFile)
  }
})

await assert('TCP frame carries the four headers and verifies', async () => {
  const { client, sent } = makeScriptedTcpClient()
  client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
  await client._request('put', '/appmesh/app/t', { command: 'true' }, { params: { b: '2', a: '1' } })
  const frame = msgpack.decode(sent[0])
  if (frame.headers['X-Request-Key'] !== SIG_KEY_ID) throw new Error('X-Request-Key missing from frame headers')
  if (!/^\d+$/.test(frame.headers['X-Timestamp'] || '')) throw new Error('X-Timestamp must be unix seconds')
  if (!frame.headers['X-Nonce']) throw new Error('X-Nonce missing')
  const canonical = canonicalString(
    frame.http_method,
    frame.request_uri,
    canonicalQuery(frame.query),
    nodeCrypto.createHash('sha256').update(frame.body).digest('hex'),
    frame.headers['X-Timestamp'],
    frame.headers['X-Nonce']
  )
  if (frame.headers['X-Signature'] !== hmacHex(canonical)) {
    throw new Error(`TCP frame signature mismatch for canonical ${JSON.stringify(canonical)}`)
  }
})

await assert('TCP 401 retry re-signs with a fresh nonce', async () => {
  const { client, sent } = makeUnauthorizedThenOkTcpClient()
  client.setTokenProvider(makeRefreshableProvider([]))
  client.enableRequestSignature(SIG_KEY_ID, SIG_SECRET)
  const response = await client._request('get', '/appmesh/app/t')
  if (response.status !== 200) throw new Error(`expected retried request to succeed, got ${response.status}`)
  if (sent.length !== 2) throw new Error(`expected original + one retry, got ${sent.length}`)
  const frames = sent.map(data => msgpack.decode(data))
  for (const frame of frames) {
    const canonical = canonicalString(
      frame.http_method,
      frame.request_uri,
      canonicalQuery(frame.query),
      nodeCrypto.createHash('sha256').update(frame.body).digest('hex'),
      frame.headers['X-Timestamp'],
      frame.headers['X-Nonce']
    )
    if (frame.headers['X-Signature'] !== hmacHex(canonical)) throw new Error('each attempt must verify')
  }
  if (frames[0].headers['X-Nonce'] === frames[1].headers['X-Nonce']) {
    throw new Error('the retry must carry a fresh nonce')
  }
})

await assert('enableRequestSignature validates keyId and secret', () => {
  const client = new AppMeshClient(baseURL)
  for (const bad of [[null, 's'], ['', 's'], ['k', null], ['k', '']]) {
    let threw = false
    try {
      client.enableRequestSignature(bad[0], bad[1])
    } catch (error) {
      threw = error instanceof TypeError
    }
    if (!threw) throw new Error(`expected TypeError for ${JSON.stringify(bad)}`)
  }
})

// ---- Summary ----
server.close()
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
process.exit(failed > 0 ? 1 : 0)
