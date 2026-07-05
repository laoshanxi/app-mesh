/**
 * Unit tests for event subscription types and MessageDemuxer.
 * No server required — tests data model, serialization, and routing only.
 *
 * Run: node test/subscribe_test.js
 */

import { AppMeshClientTCP, ResponseMessage, MessageDemuxer, EVENT_TYPE_DISCONNECTED } from '../src/appmesh_tcp.js'
import { TransportDisconnectedError } from '../src/appmesh.js'

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
  const raw = '{"subscription_id":"sub123","event_type":"EXIT","app_name":"myapp","timestamp":1714000000,"sequence":42,"data":{"exit_code":1,"pid":12345}}'
  const event = JSON.parse(raw)
  if (event.subscription_id !== 'sub123') throw new Error('subscription_id mismatch')
  if (event.event_type !== 'EXIT') throw new Error('event_type mismatch')
  if (event.app_name !== 'myapp') throw new Error('app_name mismatch')
  if (event.timestamp !== 1714000000) throw new Error('timestamp mismatch')
  if (event.sequence !== 42) throw new Error('sequence mismatch')
  if (event.data.exit_code !== 1) throw new Error('exit_code mismatch')
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
    _cb: null,
    async subscribe (name, events, cb) { stub._cb = cb; return { subscription_id: 'sub-1' } },
    async get_app_output () {
      if (stub._cb && stub.injectEvent) stub._cb(stub.injectEvent)
      return { output: '', exitCode: null }
    },
    async unsubscribe () {},
    async delete_app () { stub.deleted = true }
  }
  return stub
}

// Conformance S6 (SDKContract.md): a negative exit code (signal kill, e.g. -2 = SIGINT)
// is returned as-is, never conflated with an error sentinel.
await assertAsync('wait_for_async_run returns negative exit code as-is', async () => {
  const stub = makeStubWaitClient()
  stub.injectEvent = { event_type: 'EXIT', data: { exit_code: -2 } }
  const code = await AppMeshClientTCP.prototype.wait_for_async_run.call(
    stub, { appName: 'waitapp', procUid: 'proc-1' }, null, 5)
  if (code !== -2) throw new Error(`expected exit code -2, got ${code}`)
  if (!stub.deleted) throw new Error('run app must be deleted after a real observed exit')
})

// Conformance S2 (SDKContract.md): transport disconnect mid-wait throws
// TransportDisconnectedError promptly instead of hanging.
await assertAsync('wait_for_async_run disconnect unblocks with typed error', async () => {
  const stub = makeStubWaitClient()
  stub.injectEvent = { event_type: EVENT_TYPE_DISCONNECTED }
  let thrown = null
  try {
    await AppMeshClientTCP.prototype.wait_for_async_run.call(
      stub, { appName: 'waitapp', procUid: 'proc-1' }, null, 30)
  } catch (e) {
    thrown = e
  }
  if (!(thrown instanceof TransportDisconnectedError)) {
    throw new Error(`expected TransportDisconnectedError, got ${thrown}`)
  }
  if (stub.deleted) throw new Error('must not delete the run app after a disconnect')
})

console.log(`\nResults: ${passed} passed, ${failed} failed`)
process.exit(failed > 0 ? 1 : 0)
