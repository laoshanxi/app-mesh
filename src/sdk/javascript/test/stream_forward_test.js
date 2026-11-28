/**
 * Daemon-free tests for node forwarding on the streaming (SSE) path.
 *
 * A client with `forwardingHost` set must forward its streams (runTaskStream /
 * followOutput / streamRun) exactly like its other requests: the task runs on the target
 * node, never silently on the local one. The HTTP client carries X-Target-Host on the
 * stream request itself. AppMeshClientTCP streams over a direct HTTPS side channel; a
 * forwarded stream there must dial the agent REST listener (which relays streams through
 * node forwarding) with X-Target-Host, a local stream keeps the engine listener and sends
 * no target. A 400 from an engine listener must name the limitation.
 *
 * Run: node test/stream_forward_test.js
 */

import { Readable } from 'stream'
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

const SSE_TASK = 'event: final\ndata: {"result":"node-b"}\n\nevent: end\ndata: {"reason":"final"}\n\n'
const SSE_OUTPUT = 'event: stdout\ndata: {"output":"node-b\\n","position":0}\n\nevent: end\ndata: {"position":8,"reason":"eof"}\n\n'

// Replace the axios transport of a client with a recorder: interceptors (auth, forwarding
// header) still run, the network does not. Each recorder answers with one SSE wire text.
function recordRequests (client, wire) {
  const seen = []
  client._client.defaults.adapter = async config => {
    let body = null
    if (config.data != null) {
      body = typeof config.data.pipe === 'function'
        ? await new Promise((resolve, reject) => {
          const chunks = []
          config.data.on('data', c => chunks.push(c))
          config.data.on('end', () => resolve(Buffer.concat(chunks).toString()))
          config.data.on('error', reject)
        })
        : String(config.data)
    }
    seen.push({ url: config.baseURL + config.url, headers: config.headers, body })
    return {
      status: 200, statusText: 'OK', headers: {}, config,
      data: Readable.from([Buffer.from(wire)])
    }
  }
  return seen
}

async function drainTaskStream (client) {
  const stream = client.runTaskStream('worker', 'payload', { timeout: 30 })
  let next = await stream.next()
  while (!next.done) next = await stream.next()
  return next.value
}

async function drainFollowOutput (client) {
  const stream = client.followOutput('worker', { follow: false })
  let next = await stream.next()
  const out = []
  while (!next.done) {
    out.push(next.value)
    next = await stream.next()
  }
  return { out: out.join(''), end: next.value }
}

function header (request, name) {
  const key = Object.keys(request.headers).find(k => k.toLowerCase() === name.toLowerCase())
  return key ? request.headers[key] : undefined
}

const tests = [
  ['HTTP client: a forwarded task stream carries X-Target-Host', async () => {
    const client = new AppMeshClient('https://gateway.local:6060', false)
    client.setBearerToken('token')
    client.forwardingHost = 'appmesh_slave1'
    const seen = recordRequests(client, SSE_TASK)
    const end = await drainTaskStream(client)
    if (end.result !== 'node-b') throw new Error(`unexpected result ${end.result}`)
    if (seen.length !== 1) throw new Error(`expected one stream request, saw ${seen.length}`)
    if (header(seen[0], 'X-Target-Host') !== 'appmesh_slave1') throw new Error('stream request not forwarded')
    if (header(seen[0], 'Authorization') !== 'Bearer token') throw new Error('stream request not authenticated')
  }],

  ['HTTP client: without a forwarding host the stream carries no target', async () => {
    const client = new AppMeshClient('https://gateway.local:6060', false)
    client.setBearerToken('token')
    const seen = recordRequests(client, SSE_TASK)
    await drainTaskStream(client)
    if (header(seen[0], 'X-Target-Host') !== undefined) throw new Error('unexpected X-Target-Host')
  }],

  ['TCP client: a forwarded stream dials the agent REST port with X-Target-Host', async () => {
    const client = new AppMeshClientTCP(false, ['gateway.local', 6062])
    client.setBearerToken('token')
    client.forwardingHost = 'appmesh_slave1'
    const seen = recordRequests(client._ensureAgentChannel(), SSE_TASK)
    const end = await drainTaskStream(client)
    if (end.result !== 'node-b') throw new Error(`unexpected result ${end.result}`)
    if (seen.length !== 1) throw new Error(`expected one stream request, saw ${seen.length}`)
    if (!seen[0].url.startsWith('https://gateway.local:6060/appmesh/app/worker/task/stream')) {
      throw new Error(`forwarded stream dialled ${seen[0].url}`)
    }
    // Sent as given: an explicit TCP port would land the stream on the target's TCP listener.
    if (header(seen[0], 'X-Target-Host') !== 'appmesh_slave1') throw new Error('stream request not forwarded')
    if (header(seen[0], 'Authorization') !== 'Bearer token') throw new Error('stream request not authenticated')
    if (client._restChannelClient) throw new Error('the engine listener was built for a forwarded stream')
  }],

  ['TCP client: the agent hop gets the target as given, without the TCP port the frames append', async () => {
    const client = new AppMeshClientTCP(false, ['gateway.local', 6062])
    client.setBearerToken('token')
    client.forwardingHost = 'appmesh_slave1'
    const seen = recordRequests(client._ensureAgentChannel(), SSE_OUTPUT)
    const { out } = await drainFollowOutput(client)
    if (out !== 'node-b\n') throw new Error(`unexpected output ${JSON.stringify(out)}`)
    if (header(seen[0], 'X-Target-Host') !== 'appmesh_slave1') {
      throw new Error(`X-Target-Host is ${header(seen[0], 'X-Target-Host')}`)
    }
    if (client._forwardTargetHeader() !== 'appmesh_slave1:6062') throw new Error('framed requests changed')
  }],

  ['TCP client: a local stream keeps the engine listener and sends no target', async () => {
    const client = new AppMeshClientTCP(false, ['gateway.local', 6062])
    client.setBearerToken('token')
    const seen = recordRequests(client._ensureRestChannel(), SSE_TASK)
    await drainTaskStream(client)
    if (!seen[0].url.startsWith('https://gateway.local:6063/appmesh/app/worker/task/stream')) {
      throw new Error(`local stream dialled ${seen[0].url}`)
    }
    if (header(seen[0], 'X-Target-Host') !== undefined) throw new Error('unexpected X-Target-Host')
    if (client._agentChannelClient) throw new Error('the agent listener was built for a local stream')
  }],

  ['TCP client: agentPort is configurable', async () => {
    const client = new AppMeshClientTCP(false, { host: 'gateway.local', port: 6062, agentPort: 7060 })
    client.setBearerToken('token')
    client.forwardingHost = 'appmesh_slave1'
    const seen = recordRequests(client._ensureAgentChannel(), SSE_TASK)
    await drainTaskStream(client)
    if (!seen[0].url.startsWith('https://gateway.local:7060/')) throw new Error(`dialled ${seen[0].url}`)
  }],

  ['TCP client: a forwarded stream is signed when request signature is enabled', async () => {
    const client = new AppMeshClientTCP(false, ['gateway.local', 6062])
    client.setBearerToken('token')
    client.enableRequestSignature('key-id', 'key-secret')
    client.forwardingHost = 'appmesh_slave1'
    const seen = recordRequests(client._ensureAgentChannel(), SSE_TASK)
    await drainTaskStream(client)
    for (const name of ['X-Request-Key', 'X-Timestamp', 'X-Nonce', 'X-Signature']) {
      if (!header(seen[0], name)) throw new Error(`missing ${name} on the forwarded stream`)
    }
    if (header(seen[0], 'X-Request-Key') !== 'key-id') throw new Error('wrong signing key')
    if (header(seen[0], 'X-Target-Host') !== 'appmesh_slave1') throw new Error('stream request not forwarded')
  }],

  ['HTTP client: a 400 on a forwarded stream names the engine-listener limitation', async () => {
    const client = new AppMeshClient('https://gateway.local:6063', false)
    client.setBearerToken('token')
    client.forwardingHost = 'appmesh_slave1'
    client._client.defaults.adapter = async config => ({
      status: 400, statusText: 'Bad Request', headers: {}, config,
      data: Readable.from([Buffer.from('{"message":"Streaming is not supported through node forwarding"}')])
    })
    let caught = null
    try {
      await drainTaskStream(client)
    } catch (error) {
      caught = error
    }
    if (!(caught instanceof AppMeshError)) throw new Error(`expected AppMeshError, got ${caught}`)
    if (caught.statusCode !== 400) throw new Error(`expected status 400, got ${caught.statusCode}`)
    if (!/agent REST listener/.test(caught.message) || !/6060/.test(caught.message)) {
      throw new Error(`message does not name the limitation: ${caught.message}`)
    }
  }]
]

for (const [name, fn] of tests) await assert(name, fn)

console.log(`\n${passed} passed, ${failed} failed`)
process.exit(failed ? 1 : 0)
