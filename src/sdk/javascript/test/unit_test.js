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
import msgpack from 'msgpack-lite'
import { AppMeshClient, AppMeshError } from '../src/appmesh.js'
import { AppMeshClientTCP } from '../src/appmesh_tcp.js'

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

function startMockServer () {
  const server = http.createServer((req, res) => {
    if (req.url === '/bad-json') {
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
  if ((await client.check_app_health('healthy')) !== true) throw new Error('expected true')
})

await assert('check_app_health returns false only on an unhealthy verdict', async () => {
  const client = new AppMeshClient(baseURL)
  if ((await client.check_app_health('sick')) !== false) throw new Error('expected false')
})

await assert('check_app_health throws on 401 instead of reporting unhealthy', async () => {
  const client = new AppMeshClient(baseURL)
  await expectAppMeshError(client.check_app_health('denied'), { statusCode: 401 })
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
  const text = tcpClient._decodeBody({ body: Buffer.from('task output'), bodyMsgType: 'application/octet-stream', headers: {}, httpStatus: 200 }, {})
  if (text !== 'task output') throw new Error(`expected text, got ${JSON.stringify(text)}`)
})

await assert('TCP binary responseType still returns a Buffer', () => {
  const buf = tcpClient._decodeBody({ body: Buffer.from([0x00, 0x01]), bodyMsgType: 'application/octet-stream', headers: {}, httpStatus: 200 }, { config: { responseType: 'arraybuffer' } })
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
  await client._request('put', '/appmesh/app/t', { command: 'true' }, { headers: { 'Content-Type': 'application/merge-patch+json' } })
  const request = msgpack.decode(sent[0])
  if (request.headers['Content-Type'] !== 'application/merge-patch+json') {
    throw new Error(`expected caller header to win, got ${request.headers['Content-Type']}`)
  }
})

await assert('TCP malformed JSON response raises typed error through _request', async () => {
  const { client } = makeScriptedTcpClient({ body: Buffer.from('{"broken"') })
  await expectAppMeshError(client._request('get', '/appmesh/app/t'), { errorCode: 'JSON_PARSE', statusCode: 200 })
})

// ---- Summary ----
server.close()
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
process.exit(failed > 0 ? 1 : 0)
