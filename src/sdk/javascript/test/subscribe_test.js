/**
 * Unit tests for event subscription types and MessageDemuxer.
 * No server required — tests data model, serialization, and routing only.
 *
 * Run: node test/subscribe_test.js
 */

import {
  AppMeshClientTCP, ResponseMessage, MessageDemuxer, TCPTransport, EVENT_TYPE_DISCONNECTED,
} from '../src/appmesh_tcp.js'
import { TransportDisconnectedError } from '../src/appmesh.js'
import { EventEmitter } from 'events'
import msgpack from 'msgpack-lite'

let passed = 0
let failed = 0

function assert (name, fn) {
  try {
    fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (error) {
    failed++
    console.error(`  FAIL: ${name} - ${error.message}`)
  }
}

async function assertAsync (name, fn) {
  try {
    await fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (error) {
    failed++
    console.error(`  FAIL: ${name} - ${error.message}`)
  }
}

const EVENT_URI = '/appmesh/event'

console.log('Subscribe Unit Tests')
console.log('=' .repeat(50))

assert('EVENT_URI constant', () => {
  if (EVENT_URI !== '/appmesh/event') throw new Error('EVENT_URI mismatch')
})

assert('AppEvent JSON parsing', () => {
  const raw = '{"subscription_id":"sub123","event_type":"EXIT","app_name":"myapp","timestamp":1714000000,' +
    '"sequence":42,"data":{"exit_code":1,"pid":12345}}'
  const event = JSON.parse(raw)
  if (event.subscription_id !== 'sub123') throw new Error('subscription_id mismatch')
  if (event.event_type !== 'EXIT') throw new Error('event_type mismatch')
  if (event.app_name !== 'myapp') throw new Error('app_name mismatch')
  if (event.timestamp !== 1714000000) throw new Error('timestamp mismatch')
  if (event.sequence !== 42) throw new Error('sequence mismatch')
  if (event.data.exit_code !== 1) throw new Error('exit_code mismatch')
})

await assertAsync('event requests enable demuxer before send', async () => {
  const actions = []
  const stub = {
    _demuxer: null,
    async _enableDemuxer () {
      actions.push('demuxer')
      stub._demuxer = { registerEventCallback: () => actions.push('callback') }
    },
    async _request (method, path) {
      actions.push('request')
      return {
        data: path.endsWith('/subscribe')
          ? { subscription_id: 'sub-standalone' }
          : { subscription_id: 'sub-atomic' }
      }
    }
  }

  await AppMeshClientTCP.prototype.addApp.call(stub, 'test', { command: 'true' }, ['START'], () => {})
  if (actions.join(',') !== 'demuxer,request,callback') {
    throw new Error(`atomic add ordering mismatch: ${actions}`)
  }

  actions.length = 0
  await AppMeshClientTCP.prototype.subscribe.call(stub, 'test', ['START'], () => {})
  if (actions.join(',') !== 'demuxer,request,callback') {
    throw new Error(`subscribe ordering mismatch: ${actions}`)
  }
})

assert('Event type strings', () => {
  const validTypes = ['START', 'EXIT', 'STDOUT', 'HEALTH', 'STATUS', 'REMOVED']
  for (const t of validTypes) {
    const event = { subscription_id: 's', event_type: t, app_name: 'a', timestamp: 0, sequence: 0, data: {} }
    const json = JSON.stringify(event)
    if (!json.includes(t)) throw new Error(`Event type ${t} not in JSON`)
  }
})

assert('Subscribe result JSON parsing', () => {
  const raw = '{"subscription_id":"cqk8g7l4d","app_name":"myapp","events":["START","EXIT","STDOUT"]}'
  const result = JSON.parse(raw)
  if (result.subscription_id !== 'cqk8g7l4d') throw new Error('subscription_id mismatch')
  if (result.app_name !== 'myapp') throw new Error('app_name mismatch')
  if (result.events.length !== 3) throw new Error('events count mismatch')
  if (!result.events.includes('STDOUT')) throw new Error('stdout not in events')
})

assert('Event identification by request_uri', () => {
  const eventResp = { requestUri: EVENT_URI }
  const normalResp = { requestUri: '/appmesh/app/test' }
  if (eventResp.requestUri !== EVENT_URI) throw new Error('Event should match EVENT_URI')
  if (normalResp.requestUri === EVENT_URI) throw new Error('Normal should not match EVENT_URI')
})

assert('ResponseMessage has requestUri field', () => {
  const resp = new ResponseMessage()
  if (typeof resp.deserialize !== 'function') throw new Error('ResponseMessage.deserialize is not a function')
  if (resp.requestUri !== '') throw new Error('requestUri should default to empty string')
})

assert('MessageDemuxer routes event callbacks', () => {
  const demuxer = new MessageDemuxer(null)
  let received = null
  demuxer.registerEventCallback('sub1', (event) => { received = event })

  const fakeResp = { requestUri: EVENT_URI, body: Buffer.from(JSON.stringify({
    subscription_id: 'sub1', event_type: 'EXIT', app_name: 'test',
    timestamp: 0, sequence: 1, data: { exit_code: 0 }
  }))}
  demuxer._dispatchEvent(fakeResp)

  if (!received) throw new Error('Event callback not called')
  if (received.event_type !== 'EXIT') throw new Error('Wrong event_type')
  if (received.app_name !== 'test') throw new Error('Wrong app_name')
})

// Conformance S7 (partial, SDKContract.md): waiter registered before the response arrives is routed by UUID.
await assertAsync('MessageDemuxer routes responses by UUID', async () => {
  const demuxer = new MessageDemuxer(null)
  const uuid = 'test-uuid-123'

  const promise = demuxer.registerRequest(uuid)
  demuxer._dispatchResponse({ uuid, httpStatus: 200, body: Buffer.alloc(0), headers: {} })

  const resp = await promise
  if (resp.uuid !== uuid) throw new Error('UUID mismatch')
  if (resp.httpStatus !== 200) throw new Error('Status mismatch')
})

assert('MessageDemuxer ignores events for unknown subscriptions', () => {
  const demuxer = new MessageDemuxer(null)
  let called = false
  demuxer.registerEventCallback('sub1', () => { called = true })

  const fakeResp = { requestUri: EVENT_URI, body: Buffer.from(JSON.stringify({
    subscription_id: 'unknown_sub', event_type: 'EXIT', app_name: 'test',
    timestamp: 0, sequence: 1, data: {}
  }))}
  demuxer._dispatchEvent(fakeResp)

  if (called) throw new Error('Should not call callback for unknown subscription')
})

assert('MessageDemuxer unregister removes callback', () => {
  const demuxer = new MessageDemuxer(null)
  let callCount = 0
  demuxer.registerEventCallback('sub1', () => { callCount++ })

  const makeEvent = () => ({ requestUri: EVENT_URI, body: Buffer.from(JSON.stringify({
    subscription_id: 'sub1', event_type: 'START', app_name: 'a',
    timestamp: 0, sequence: 0, data: {}
  }))})

  demuxer._dispatchEvent(makeEvent())
  if (callCount !== 1) throw new Error('Expected 1 call')

  demuxer.unregisterEventCallback('sub1')
  demuxer._dispatchEvent(makeEvent())
  if (callCount !== 1) throw new Error('Should not call after unregister')
})

// Conformance S2 (demuxer, SDKContract.md): transport EOF broadcasts the synthetic
// __disconnected__ event to callbacks and rejects pending waiters instead of hanging.
await assertAsync('MessageDemuxer disconnect broadcast unblocks waiters', async () => {
  // Scripted mock transport: the only read fails, i.e. immediate EOF.
  const transport = {
    connected: () => true,
    receiveMessage: () => Promise.reject(new Error('connection closed'))
  }
  const demuxer = new MessageDemuxer(transport)

  let received = null
  demuxer.registerEventCallback('sub-s2', (event) => { received = event })
  const pending = demuxer.registerRequest('req-s2')
  demuxer.start()

  let rejection = null
  try {
    await pending
  } catch (e) {
    rejection = e
  }
  if (!(rejection instanceof TransportDisconnectedError)) {
    throw new Error(`pending waiter should reject with TransportDisconnectedError, got ${rejection}`)
  }
  if (!received || received.event_type !== EVENT_TYPE_DISCONNECTED) {
    throw new Error('registered callback did not receive the __disconnected__ broadcast')
  }
  if (received.subscription_id !== 'sub-s2') throw new Error('wrong subscription_id on disconnect event')
})

// Scripted client for the wait_for_async_run path (no network): injectEvent fires from
// the backfill call, after subscribe registered the callback (event arriving mid-wait).
function makeStubWaitClient () {
  const stub = {
    injectEvent: null,
    deleted: false,
    unsubscribed: false,
    _cb: null,
    async subscribe (name, events, cb) { stub._cb = cb; return { subscription_id: 'sub-1' } },
    async getAppOutput () {
      if (stub._cb && stub.injectEvent) stub._cb(stub.injectEvent)
      return { output: '', exitCode: null }
    },
    async unsubscribe () { stub.unsubscribed = true },
    async deleteApp () { stub.deleted = true }
  }
  return stub
}

// Conformance S6 (SDKContract.md): a negative exit code (signal kill, e.g. -2 = SIGINT)
// is returned as-is, never conflated with an error sentinel.
await assertAsync('wait_for_async_run returns negative exit code as-is', async () => {
  const stub = makeStubWaitClient()
  stub.injectEvent = { event_type: 'EXIT', data: { exit_code: -2 } }
  const code = await AppMeshClientTCP.prototype.waitForAsyncRun.call(
    stub, { appName: 'waitapp', procUid: 'proc-1' }, null, 5)
  if (code !== -2) throw new Error(`expected exit code -2, got ${code}`)
  if (!stub.unsubscribed) throw new Error('live transport must be unsubscribed after the wait')
  if (!stub.deleted) throw new Error('run app must be deleted after a real observed exit')
})

// Conformance S2 (SDKContract.md): transport disconnect mid-wait throws
// TransportDisconnectedError promptly instead of hanging, and skips cleanup
// requests on the dead transport (SDKContract cleanup policy).
await assertAsync('wait_for_async_run disconnect unblocks with typed error', async () => {
  const stub = makeStubWaitClient()
  stub.injectEvent = { event_type: EVENT_TYPE_DISCONNECTED }
  let thrown = null
  try {
    await AppMeshClientTCP.prototype.waitForAsyncRun.call(
      stub, { appName: 'waitapp', procUid: 'proc-1' }, null, 30)
  } catch (e) {
    thrown = e
  }
  if (!(thrown instanceof TransportDisconnectedError)) {
    throw new Error(`expected TransportDisconnectedError, got ${thrown}`)
  }
  if (stub.unsubscribed) throw new Error('must not send unsubscribe on a dead transport')
  if (stub.deleted) throw new Error('must not delete the run app after a disconnect')
})

// A file transfer must be rejected while the event demuxer owns the read side:
// the demuxer read loop would steal the raw (non-msgpack) chunk frames and
// corrupt the transfer (mirrors the Python SDK's _ensure_no_active_demuxer).
await assertAsync('file transfer rejected while demuxer active', async () => {
  const stub = {
    _demuxer: { _running: true },
    _ensureNoActiveDemuxer: AppMeshClientTCP.prototype._ensureNoActiveDemuxer,
    async _request () { throw new Error('request must not be sent') }
  }
  let thrown = null
  try { await AppMeshClientTCP.prototype.downloadFile.call(stub, '/remote/file') } catch (e) { thrown = e }
  if (!thrown || !thrown.message.includes('not supported')) throw new Error(`download not rejected: ${thrown}`)

  thrown = null
  try { await AppMeshClientTCP.prototype.uploadFile.call(stub, '/local/file') } catch (e) { thrown = e }
  if (!thrown || !thrown.message.includes('not supported')) throw new Error(`upload not rejected: ${thrown}`)
})

// A zero-length frame is not a message: the read loop skips it and keeps
// reading instead of tearing down every subscription (Python parity).
await assertAsync('read loop skips zero-length frames', async () => {
  const eventFrame = msgpack.encode({
    uuid: 'evt-1',
    request_uri: EVENT_URI,
    http_status: 200,
    body: Buffer.from(JSON.stringify({
      subscription_id: 'sub-zero', event_type: 'START', app_name: 'a',
      timestamp: 0, sequence: 0, data: {}
    })),
    headers: {}
  })
  const frames = [Buffer.alloc(0), eventFrame]
  const transport = {
    connected: () => true,
    receiveMessage: () => frames.length ? Promise.resolve(frames.shift()) : new Promise(() => {})
  }
  const demuxer = new MessageDemuxer(transport)
  const received = []
  demuxer.registerEventCallback('sub-zero', (e) => { if (e.event_type !== EVENT_TYPE_DISCONNECTED) received.push(e) })
  demuxer.start()

  await new Promise(resolve => setTimeout(resolve, 50))
  if (received.length !== 1 || received[0].event_type !== 'START') {
    demuxer.stop()
    throw new Error(`event after zero-length frame not delivered: ${received.length}`)
  }
  demuxer.stop()
})

// Concurrent subscribe() calls on an unconnected transport must create exactly
// one demuxer (no dual read loops competing for the socket).
await assertAsync('concurrent enableDemuxer creates a single demuxer', async () => {
  const client = new AppMeshClientTCP(false, ['127.0.0.1', 6059])
  let connects = 0
  client.tcpTransport = {
    connected: () => connects > 0,
    async connect () { connects++; await new Promise(r => setTimeout(r, 20)) },
    receiveMessage: () => new Promise(() => {}),
    close () {}
  }
  try {
    await Promise.all([client._enableDemuxer(), client._enableDemuxer(), client._enableDemuxer()])
    if (connects !== 1) throw new Error(`expected exactly 1 connect, got ${connects}`)
    if (!client._demuxer || !client._demuxer._running) throw new Error('demuxer not running')
  } finally {
    if (client._demuxer) client._demuxer.stop()
    client.close()
  }
})

// A hostile/corrupt 8-byte header (length near 4 GiB) must be rejected before
// the accumulation loop allocates, and the socket must be closed.
await assertAsync('oversized frame length rejected and socket closed', async () => {
  class FakeSocket extends EventEmitter {
    constructor () { super(); this.destroyed = false }
    destroy () { this.destroyed = true; this.emit('close') }
  }
  const transport = new TCPTransport(['127.0.0.1', 6059], null)
  const sock = new FakeSocket()
  transport.socket = sock

  const hostile = Buffer.alloc(8)
  hostile.writeUInt32BE(0x07C707F8, 0) // valid magic
  hostile.writeUInt32BE(0xFFFFFFFF, 4) // 4 GiB body length

  const pending = transport.receiveMessage()
  sock.emit('data', hostile)
  let thrown = null
  try { await pending } catch (e) { thrown = e }
  if (!thrown || !thrown.message.includes('exceeds maximum')) throw new Error(`oversized length not rejected: ${thrown}`)
  if (!sock.destroyed) throw new Error('socket must be closed after the framing error')
})

// The X-Subscription-Id fallback lookup is case-insensitive (header case is
// not contractual on the wire).
await assertAsync('event sub id fallback is case-insensitive', async () => {
  const demuxer = new MessageDemuxer(null)
  const fakeResp = {
    requestUri: EVENT_URI,
    headers: { 'x-subscription-id': 'sub-ci' },
    body: Buffer.from(JSON.stringify({
      event_type: 'EXIT', app_name: 'a', timestamp: 0, sequence: 0, data: { exit_code: 0 }
    }))
  }
  demuxer._dispatchEvent(fakeResp) // no subscription_id in body -> header fallback -> buffered

  const received = []
  demuxer.registerEventCallback('sub-ci', (e) => received.push(e))
  if (received.length !== 1 || received[0].event_type !== 'EXIT') {
    throw new Error('buffered event not flushed via case-insensitive header fallback')
  }
})

// Conformance S4 (SDKContract.md): events arriving before the callback
// registers (atomic-subscribe race) are buffered per sub_id and flushed in
// arrival order on registration, ahead of later live events.
await assertAsync('buffered events flush in order on registration (S4)', async () => {
  const demuxer = new MessageDemuxer(null)
  const mkEvent = (seq) => ({
    requestUri: EVENT_URI,
    body: Buffer.from(JSON.stringify({
      subscription_id: 'sub-s4', event_type: 'START', app_name: 'fast-app',
      timestamp: 0, sequence: seq, data: { pid: 1 }
    }))
  })

  // Two events arrive before any callback registers: they must be buffered.
  demuxer._dispatchEvent(mkEvent(1))
  demuxer._dispatchEvent(mkEvent(2))

  // Registration flushes the buffered events before later live ones.
  const order = []
  demuxer.registerEventCallback('sub-s4', (e) => {
    if (e.event_type !== EVENT_TYPE_DISCONNECTED) order.push(e.sequence)
  })
  demuxer._dispatchEvent(mkEvent(3))

  if (order.join(',') !== '1,2,3') {
    throw new Error(`expected buffered flush 1,2,3 — got ${order.join(',')}`)
  }
})

// The read pump keeps a single persistent 'data' listener: chunks arriving
// between reads (no waiter in flight) must be buffered and delivered to the
// next read instead of wedging the transfer. Regression test for the
// pause/resume churn that deadlocked large TCP downloads.
await assertAsync('chunks arriving between reads are buffered', async () => {
  class FakeSocket extends EventEmitter {
    constructor () { super(); this.destroyed = false }
    destroy () { this.destroyed = true; this.emit('close') }
  }
  const frame = (payload) => {
    const b = Buffer.alloc(8 + payload.length)
    b.writeUInt32BE(0x07C707F8, 0)
    b.writeUInt32BE(payload.length, 4)
    payload.copy(b, 8)
    return b
  }
  const transport = new TCPTransport(['127.0.0.1', 6059], null)
  const sock = new FakeSocket()
  transport.socket = sock

  const p1 = transport.receiveMessage()
  sock.emit('data', frame(Buffer.from('hello')))
  if ((await p1).toString() !== 'hello') throw new Error('first frame wrong')

  // Frame arrives while no read is in flight.
  sock.emit('data', frame(Buffer.from('world')))
  await new Promise(resolve => setTimeout(resolve, 10))
  const second = await transport.receiveMessage()
  if (second.toString() !== 'world') throw new Error('frame between reads was lost')

  // EOF after close resolves pending and future reads with null.
  transport.close()
  const eof = await transport.receiveMessage()
  if (eof !== null) throw new Error('closed transport must read as EOF')
})


// Read-pump error semantics: a socket error rejects the pending read (not a
// null resolve) and stays latched for later reads; close() drops the pump so a
// fresh socket re-arms clean state.
await assertAsync('read pump rejects on socket error, latches, and re-arms after close', async () => {
  class FakeSocket extends EventEmitter {
    constructor () { super(); this.destroyed = false }
    destroy () { this.destroyed = true; this.emit('close') }
  }
  const transport = new TCPTransport(['127.0.0.1', 6059], null)
  const sock = new FakeSocket()
  transport.socket = sock

  const pending = transport.receiveMessage()
  sock.emit('error', new Error('boom'))
  let rejected = null
  try { await pending } catch (e) { rejected = e }
  if (!rejected || rejected.message !== 'boom') throw new Error(`pending read must reject with the socket error, got ${rejected}`)

  let latched = null
  try { await transport.receiveMessage() } catch (e) { latched = e }
  if (!latched || latched.message !== 'boom') throw new Error('error must latch for later reads')

  transport.close()
  const fresh = new FakeSocket()
  transport.socket = fresh
  const frame = (payload) => {
    const b = Buffer.alloc(8 + payload.length)
    b.writeUInt32BE(0x07C707F8, 0)
    b.writeUInt32BE(payload.length, 4)
    payload.copy(b, 8)
    return b
  }
  const read = transport.receiveMessage()
  fresh.emit('data', frame(Buffer.from('rearmed')))
  if ((await read).toString() !== 'rearmed') throw new Error('pump must re-arm on a fresh socket after close()')
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
