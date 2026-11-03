/**
 * Live-daemon tests for the TCP sub/pub fixes.
 * No server required to import — every case skips unless APPMESH_BEARER_TOKEN is set.
 *
 * Run: APPMESH_BEARER_TOKEN=<dex-token> node test/subscribe_live.js
 */

import { AppMeshClientTCP } from '../src/appmesh_tcp.js'

let passed = 0
let failed = 0
let skipped = 0

async function assertLive (name, fn) {
  if (!process.env.APPMESH_BEARER_TOKEN) {
    skipped++
    console.log(`  SKIP: ${name} (APPMESH_BEARER_TOKEN not set)`)
    return
  }
  try {
    console.log(`  START: ${name} @${new Date().toISOString().slice(17, 23)}`)
    await fn()
    passed++
    console.log(`  PASS: ${name} @${new Date().toISOString().slice(17, 23)}`)
  } catch (error) {
    failed++
    console.error(`  FAIL: ${name} - ${error.message}`)
  }
}

const bearer = () => process.env.APPMESH_BEARER_TOKEN

function liveTCP () {
  const client = new AppMeshClientTCP(false, ['127.0.0.1', 6059])
  client.setBearerToken(bearer())
  return client
}

const unique = (prefix) => `${prefix}-${Date.now() % 1000000}`

console.log('Subscribe Live Tests')
console.log('='.repeat(50))

// Subscribe-based wait streams STDOUT and returns the exit code over TCP.
await assertLive('live TCP wait_for_async_run streams stdout', async () => {
  const client = liveTCP()
  try {
    const run = await client.runAppAsync(
      { name: unique('live-js-wait'), command: 'echo live-js-line-1; echo live-js-line-2', shell: true }, 10, 0)
    let out = ''
    const code = await client.waitForAsyncRun(run, (data) => { out += data }, 20)
    if (code !== 0) throw new Error(`expected exit 0, got ${code}`)
    if (!out.includes('live-js-line-1') || !out.includes('live-js-line-2')) {
      throw new Error(`stdout not streamed: ${out}`)
    }
  } finally {
    client.close()
  }
})

// F1: file transfers are rejected while the demuxer owns the read side;
// a separate client instance (its own connection) transfers fine.
await assertLive('live TCP file transfer guard', async () => {
  const client = liveTCP()
  try {
    await client.subscribe('*', ['START'], () => {})

    let err = null
    try { await client.downloadFile('/opt/appmesh/bin/appmesh', '/tmp/e2e-js-guarded') } catch (e) { err = e }
    if (!err || !err.message.includes('not supported')) throw new Error(`download not rejected: ${err}`)

    err = null
    try { await client.uploadFile('/etc/hosts', '/tmp/e2e-js-upload') } catch (e) { err = e }
    if (!err || !err.message.includes('not supported')) throw new Error(`upload not rejected: ${err}`)
  } finally {
    client.close()
  }

  const plain = liveTCP()
  try {
    await plain.downloadFile('/etc/hosts', '/tmp/e2e-js-plain')
  } finally {
    plain.close()
  }
})

// A stale bearer is rejected with 401, the provider rotates it once, and the
// replayed request succeeds over TCP.
await assertLive('live TCP 401 refresh retry', async () => {
  const client = new AppMeshClientTCP(false, ['127.0.0.1', 6059])
  let refreshed = 0
  client.setTokenProvider({
    getAccessToken: async () => (refreshed === 0 ? 'definitely-stale-token' : bearer()),
    canRefresh: () => true,
    refreshAccessToken: async () => { refreshed++; return bearer() }
  })
  try {
    const apps = await client.listApps()
    if (!Array.isArray(apps) || apps.length === 0) throw new Error('no apps visible after refresh replay')
    if (refreshed !== 1) throw new Error(`expected exactly 1 refresh, got ${refreshed}`)
  } finally {
    client.close()
  }
})

console.log(`\nResults: ${passed} passed, ${failed} failed, ${skipped} skipped`)
process.exit(failed > 0 ? 1 : 0)
