/**
 * Daemon-free tests for runAppSync output paging.
 *
 * A sync-run reply carries at most one page of output. When the reply fills a page the
 * daemon names the run instance (X-App-Name) and flags it (X-Output-Truncated); the
 * SDK pages the rest from the output endpoint in raw bytes, decodes once, then deletes
 * the run. These tests cover: the plain (untruncated) path, multi-page join with the
 * offset advancing by bytes, exactly one page, the maxOutputBytes ceiling and a failed
 * run deletion.
 *
 * No daemon required: the HTTP tests use a loopback mock server and the TCP tests a
 * scripted transport.
 *
 * Run: node test/syncrun_test.js
 */

import http from 'http'
import msgpack from 'msgpack-lite'
import { AppMeshClient, AppMeshRequestError, CONSTANTS } from '../src/appmesh.js'
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

// Taken from the client: the tests never assume a numeric page size.
const PAGE = CONSTANTS.SYNC_RUN_OUTPUT_PAGE_BYTES

// Page 1 ends with the first byte of U+4E2D (E4 B8 AD); page 2 completes it and
// ends with the first byte of U+00E9 (C3 A9); page 3 completes that one. Each page
// is exactly one full page, so the daemon would report all three as truncated.
const SPLIT_PAGE_1 = Buffer.concat([Buffer.alloc(PAGE - 1, 0x61), Buffer.from([0xe4])])
const SPLIT_PAGE_2 = Buffer.concat([Buffer.from([0xb8, 0xad]), Buffer.alloc(PAGE - 3, 0x62), Buffer.from([0xc3])])
const SPLIT_PAGE_3 = Buffer.concat([Buffer.from([0xa9]), Buffer.from('end')])

// A scripted daemon: POST syncrun answers with the first page, GET output serves the
// following pages in order, DELETE records the removal.
function startMockServer (script) {
  const log = []
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://127.0.0.1')
    req.resume()
    req.on('end', () => {
      if (req.method === 'POST' && url.pathname === '/appmesh/app/syncrun') {
        const first = script.first
        log.push({ method: 'POST', path: url.pathname })
        res.writeHead(200, {
          'Content-Type': `text/plain; charset=${first.charset || 'utf-8'}`,
          'X-Exit-Code': String(first.exitCode),
          ...first.headers
        })
        res.end(first.body)
      } else if (req.method === 'GET' && url.pathname === `/appmesh/app/${script.runName}/output`) {
        const position = Number(url.searchParams.get('stdout_position'))
        log.push({ method: 'GET', path: url.pathname, position })
        const page = script.pages.shift()
        res.writeHead(200, { 'Content-Type': 'text/plain' })
        res.end(page)
      } else if (req.method === 'DELETE' && url.pathname === `/appmesh/app/${script.runName}`) {
        log.push({ method: 'DELETE', path: url.pathname })
        res.writeHead(script.deleteStatus || 200, { 'Content-Type': 'application/json' })
        res.end('{}')
      } else {
        log.push({ method: req.method, path: url.pathname })
        res.writeHead(404, { 'Content-Type': 'application/json' })
        res.end('{"message": "Not Found"}')
      }
    })
  })
  return new Promise(resolve => server.listen(0, '127.0.0.1', () => resolve({ server, log })))
}

function makeHttpScriptedClient (script) {
  const first = script.first
  const responses = [
    {
      status: 200,
      headers: { 'content-type': `text/plain; charset=${first.charset || 'utf-8'}`, 'x-exit-code': String(first.exitCode), ...first.headers },
      data: first.body
    },
    ...script.pages.map(page => ({ status: 200, headers: { 'content-type': 'text/plain' }, data: page })),
    { status: script.deleteStatus || 200, headers: {}, data: {} }
  ]
  const client = new AppMeshClient('http://127.0.0.1:1')
  const log = []
  client._request = async (method, path, body, options) => {
    log.push({ method: method.toUpperCase(), path, position: options?.params?.stdout_position, responseType: options?.config?.responseType })
    const response = responses.shift()
    if (!response) throw new Error(`unexpected request ${method} ${path}`)
    // Like the real transport: a non-2xx reply rejects.
    if (response.status < 200 || response.status >= 300) throw new AppMeshError('failed', response.status, response.data)
    return response
  }
  return { client, log }
}

// Same scripted daemon over the TCP transport: every reply is one msgpack frame.
function makeScriptedTcpClient (script) {
  const first = script.first
  const frames = [
    {
      http_status: 200,
      body_msg_type: `text/plain; charset=${first.charset || 'utf-8'}`,
      headers: { 'X-Exit-Code': String(first.exitCode), ...first.headers },
      body: first.body
    },
    ...script.pages.map(page => ({ http_status: 200, body_msg_type: 'text/plain', headers: {}, body: page })),
    { http_status: script.deleteStatus || 200, body_msg_type: 'application/json', headers: {}, body: Buffer.from('{}') }
  ]
  const client = new AppMeshClientTCP(false)
  const log = []
  client.tcpTransport = {
    connected: () => true,
    connect: async () => {},
    sendMessage: data => {
      const frame = msgpack.decode(data)
      log.push({ method: frame.http_method, path: frame.request_uri, position: frame.query?.stdout_position })
    },
    receiveMessage: async () => msgpack.encode(frames.shift() || { http_status: 500, body: Buffer.from('{}') })
  }
  return { client, log }
}

console.log('=== runAppSync output paging (no daemon) ===\n')

const transports = [
  ['HTTP', makeHttpScriptedClient],
  ['TCP', makeScriptedTcpClient]
]

for (const [label, make] of transports) {
  const plain = {
    runName: 'run-plain',
    first: { body: Buffer.from('hello world'), exitCode: 3, headers: {} },
    pages: []
  }
  await assert(`${label}: untruncated output is returned unchanged and the run is not touched`, async () => {
    const { client, log } = make(plain)
    const calls = []
    const exitCode = await client.runAppSync({ command: 'echo hello world', shell: true }, (out, pos) => calls.push([out, pos]), 10, 20)
    if (exitCode !== 3) throw new Error(`expected exit code 3, got ${exitCode}`)
    if (calls.length !== 1 || calls[0][0] !== 'hello world' || calls[0][1] !== 0) {
      throw new Error(`expected one handler call with the body, got ${JSON.stringify(calls)}`)
    }
    if (log.length !== 1 || log[0].method !== 'POST') throw new Error(`expected only the syncrun request, got ${JSON.stringify(log)}`)
    if (label === 'HTTP' && log[0].responseType !== 'arraybuffer') {
      throw new Error(`expected the reply as raw bytes, got ${log[0].responseType}`)
    }
  })

  await assert(`${label}: untruncated output with no stdout handler still resolves the exit code`, async () => {
    const { client } = make(plain)
    const exitCode = await client.runAppSync({ command: 'echo hello world', shell: true }, null, 10, 20)
    if (exitCode !== 3) throw new Error(`expected exit code 3, got ${exitCode}`)
  })

  const multi = {
    runName: 'run-multi',
    first: {
      body: SPLIT_PAGE_1, exitCode: 0,
      headers: {
        'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-multi'
      }
    },
    pages: [SPLIT_PAGE_2, SPLIT_PAGE_3]
  }
  await assert(`${label}: multi-page output is joined as bytes, offsets advance by bytes, run deleted`, async () => {
    const { client, log } = make(multi)
    const calls = []
    const exitCode = await client.runAppSync({ command: 'x', shell: true }, (out, pos) => calls.push([out, pos]), 10, 20)
    if (exitCode !== 0) throw new Error(`expected exit code 0, got ${exitCode}`)
    if (calls.length !== 1 || calls[0][1] !== 0) throw new Error(`expected a single handler call at position 0, got ${JSON.stringify(calls)}`)
    const out = calls[0][0]
    // Every byte decodes to one character except the two split ones (5 bytes, 2 characters).
    const expectedLength = SPLIT_PAGE_1.length + SPLIT_PAGE_2.length + SPLIT_PAGE_3.length - 3
    if (out.length !== expectedLength) throw new Error(`expected ${expectedLength} characters, got ${out.length}`)
    if (!out.endsWith('éend')) throw new Error(`expected the split multi-byte characters to survive, got tail ${JSON.stringify(out.slice(-8))}`)
    if (out[PAGE - 1] !== '中') throw new Error(`expected U+4E2D right after page 1, got ${JSON.stringify(out[PAGE - 1])}`)
    if (out.includes('\uFFFD')) throw new Error('expected no replacement characters')
    const gets = log.filter(e => e.method === 'GET')
    const offsets = [SPLIT_PAGE_1.length, SPLIT_PAGE_1.length + SPLIT_PAGE_2.length]
    if (gets.map(e => e.position).join(',') !== offsets.join(',')) {
      throw new Error(`expected byte offsets ${offsets}, got ${JSON.stringify(gets)}`)
    }
    if (!log.some(e => e.method === 'DELETE' && e.path === `/appmesh/app/run-multi`)) throw new Error('expected the run to be deleted')
    if (log[log.length - 1].method !== 'DELETE') throw new Error('expected the delete to be the last request')
  })

  const exact = {
    runName: 'run-exact',
    first: {
      body: Buffer.alloc(PAGE, 0x63), exitCode: 7,
      headers: { 'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-exact' }
    },
    pages: [Buffer.alloc(0)]
  }
  await assert(`${label}: exactly one page reads an empty second page and still deletes the run`, async () => {
    const { client, log } = make(exact)
    const calls = []
    const exitCode = await client.runAppSync({ command: 'x', shell: true }, (out) => calls.push(out), 10, 20)
    if (exitCode !== 7) throw new Error(`expected exit code 7, got ${exitCode}`)
    if (calls.length !== 1 || calls[0].length !== PAGE) throw new Error(`expected one handler call with one page, got ${calls.length} calls`)
    if (log.filter(e => e.method === 'GET').length !== 1) throw new Error('expected exactly one output request')
    if (!log.some(e => e.method === 'DELETE')) throw new Error('expected the run to be deleted')
  })

  const over = {
    runName: 'run-over',
    first: {
      body: Buffer.alloc(PAGE, 0x64), exitCode: 0,
      headers: { 'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-over' }
    },
    pages: [Buffer.alloc(PAGE, 0x64), Buffer.alloc(PAGE, 0x64)]
  }
  await assert(`${label}: output past maxOutputBytes rejects and the run is kept`, async () => {
    const { client, log } = make(over)
    const calls = []
    let thrown = null
    try {
      await client.runAppSync({ command: 'x', shell: true }, (out) => calls.push(out), 10, 20, PAGE + 1024)
    } catch (error) {
      thrown = error
    }
    if (!(thrown instanceof AppMeshRequestError)) {
      throw new Error(`expected AppMeshRequestError, got ${thrown === null ? 'no error' : `${thrown.name}: ${thrown.message}`}`)
    }
    if (thrown.statusCode !== 200) throw new Error(`expected status 200 on the error, got ${thrown.statusCode}`)
    if (!thrown.message.includes('maxOutputBytes=' + (PAGE + 1024)) || !thrown.message.includes("'run-over'") ||
        !thrown.message.includes('600 seconds')) {
      throw new Error(`expected the message to name the ceiling, the run and the retention, got: ${thrown.message}`)
    }
    if (calls.length !== 0) throw new Error('expected the handler not to be called with a partial result')
    if (log.some(e => e.method === 'DELETE')) throw new Error('expected the run to be kept')
    if (!log.some(e => e.method === 'GET')) throw new Error(`expected paging to have started, got ${JSON.stringify(log)}`)
  })

  const ceilingBelowFirstPage = {
    runName: 'run-first',
    first: {
      body: Buffer.alloc(PAGE, 0x65), exitCode: 0,
      headers: { 'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-first' }
    },
    pages: []
  }
  await assert(`${label}: a ceiling below the first page rejects without paging or deleting`, async () => {
    const { client, log } = make(ceilingBelowFirstPage)
    let thrown = null
    try {
      await client.runAppSync({ command: 'x', shell: true }, null, 10, 20, 1024)
    } catch (error) {
      thrown = error
    }
    if (!(thrown instanceof AppMeshRequestError)) throw new Error(`expected AppMeshRequestError, got ${thrown}`)
    if (log.length !== 1) throw new Error(`expected only the syncrun request, got ${JSON.stringify(log)}`)
  })

  const overOnLastPage = {
    runName: 'run-tail',
    first: {
      body: Buffer.alloc(PAGE, 0x66), exitCode: 0,
      headers: { 'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-tail' }
    },
    pages: [Buffer.alloc(2048, 0x66)]
  }
  await assert(`${label}: the ceiling is checked on the short final page`, async () => {
    const { client, log } = make(overOnLastPage)
    let thrown = null
    try {
      await client.runAppSync({ command: 'x', shell: true }, null, 10, 20, PAGE + 1024)
    } catch (error) {
      thrown = error
    }
    if (!(thrown instanceof AppMeshRequestError)) throw new Error(`expected AppMeshRequestError, got ${thrown}`)
    if (log.some(e => e.method === 'DELETE')) throw new Error('expected the run to be kept')
  })

  const deleteFails = {
    runName: 'run-keep',
    deleteStatus: 500,
    first: {
      body: SPLIT_PAGE_1, exitCode: 1,
      headers: { 'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-keep' }
    },
    pages: [SPLIT_PAGE_3]
  }
  await assert(`${label}: a failed run deletion does not affect the result`, async () => {
    const { client, log } = make(deleteFails)
    const warnings = []
    const originalWarn = console.warn
    console.warn = (...args) => warnings.push(args.join(' '))
    let exitCode
    try {
      exitCode = await client.runAppSync({ command: 'x', shell: true }, null, 10, 20)
    } finally {
      console.warn = originalWarn
    }
    if (exitCode !== 1) throw new Error(`expected exit code 1, got ${exitCode}`)
    if (!log.some(e => e.method === 'DELETE')) throw new Error('expected the delete to have been attempted')
    if (warnings.length !== 1 || !warnings[0].includes("'run-keep'")) throw new Error(`expected one warning about the run, got ${JSON.stringify(warnings)}`)
  })

  const latin = {
    runName: 'run-latin',
    first: {
      body: Buffer.from('café', 'latin1'), charset: 'iso-8859-1', exitCode: 0,
      headers: { 'X-Output-Truncated': '1', 'X-Output-Position': '4', 'X-App-Name': 'run-latin' }
    },
    pages: [Buffer.from(' finé', 'latin1')]
  }
  await assert(`${label}: paged output is decoded in the charset of the first reply`, async () => {
    const { client } = make(latin)
    const calls = []
    await client.runAppSync({ command: 'x', shell: true }, (out) => calls.push(out), 10, 20)
    if (calls.length !== 1 || calls[0] !== 'café finé') throw new Error(`expected 'café finé', got ${JSON.stringify(calls)}`)
  })
}

// The real HTTP transport against a loopback server: raw bytes on the wire and the
// URL-encoded query.
const wire = await startMockServer({
  runName: 'run-wire',
  first: {
    body: Buffer.concat([Buffer.alloc(PAGE - 3, 0x61), Buffer.from('中')]), exitCode: 0,
    headers: { 'X-Output-Truncated': '1', 'X-Output-Position': String(PAGE), 'X-App-Name': 'run-wire' }
  },
  pages: [Buffer.from(' done')]
})
const wireClient = new AppMeshClient(`http://127.0.0.1:${wire.server.address().port}`)
const wireCalls = []
const wireExit = await wireClient.runAppSync({ command: 'x', shell: true }, (out) => wireCalls.push(out), 10, 20)
await assert('HTTP wire: paged run is joined, offset passed on the query and the run deleted', async () => {
  if (wireExit !== 0) throw new Error(`expected exit code 0, got ${wireExit}`)
  if (wireCalls.length !== 1 || !wireCalls[0].endsWith('a中 done')) throw new Error(`unexpected output tail ${JSON.stringify(wireCalls[0]?.slice(-8))}`)
  const gets = wire.log.filter(e => e.method === 'GET')
  if (gets.length !== 1 || gets[0].position !== PAGE || gets[0].path !== '/appmesh/app/run-wire/output') {
    throw new Error(`expected one GET at offset ${PAGE}, got ${JSON.stringify(wire.log)}`)
  }
  if (wire.log[wire.log.length - 1].method !== 'DELETE') throw new Error(`expected a delete, got ${JSON.stringify(wire.log)}`)
})
wire.server.close()

// ---- Summary ----
console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
process.exit(failed > 0 ? 1 : 0)
