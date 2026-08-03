// Unit tests for token auto-refresh pacing and the refresh-token plumbing.
// No daemon required: the transport is stubbed out.
import { AppMeshClient, AppMeshError } from '../src/appmesh.js'

let passed = 0
let failed = 0

async function assert(name, fn) {
  try {
    await fn()
    passed++
    console.log(`  PASS: ${name}`)
  } catch (error) {
    failed++
    console.error(`  FAIL: ${name} - ${error.message}`)
  }
}

/** Build an unsigned JWT carrying iat/exp, which is all the pacing logic reads. */
function makeJwt(iat, exp, salt = '') {
  const claims = iat > 0 ? { iat, exp } : { exp }
  const payload = Buffer.from(JSON.stringify(claims)).toString('base64url')
  return `hdr.${payload}.sig${salt}`
}

// The transport is always stubbed below, so no TLS config is needed and no socket is opened.
function newClient() {
  return new AppMeshClient('https://127.0.0.1:6060')
}

/** Replace the transport with a recorder; returns the array of captured requests. */
function stubRequest(client, handler = null) {
  const calls = []
  client._request = async (method, path, body = null, options = {}) => {
    calls.push({ method, path, body, headers: options.headers || {} })
    if (handler) return handler({ method, path, body, options })
    return { status: 200, data: {} }
  }
  return calls
}

const now = () => Math.floor(Date.now() / 1000)

async function test() {
  console.log('=== JavaScript SDK Token Refresh Unit Tests ===\n')

  // ---- Margin: a fraction of the token's own lifetime ----
  await assert('margin is 40% of lifetime +/- 10% of that margin', () => {
    // [lifetime seconds, min, max]; the 60s case is floored at 30s (40% would be 24s)
    // and then clamped to half the lifetime.
    const cases = [
      [30 * 60, 648, 792],
      [7 * 24 * 3600, 217728, 266112],
      [60, 27, 30]
    ]
    for (const [lifetime, wantMin, wantMax] of cases) {
      const iat = now()
      const exp = iat + lifetime
      const got = AppMeshClient._refreshMargin(makeJwt(iat, exp), exp, iat)
      if (got < wantMin || got > wantMax) {
        throw new Error(`lifetime ${lifetime}s: margin ${got} outside [${wantMin}, ${wantMax}]`)
      }
    }
  })

  await assert('margin is stable for the same token', () => {
    const iat = now()
    const exp = iat + 3600
    const token = makeJwt(iat, exp)
    const first = AppMeshClient._refreshMargin(token, exp, iat)
    for (let i = 0; i < 10; i++) {
      const got = AppMeshClient._refreshMargin(token, exp, iat)
      if (got !== first) throw new Error(`jitter is not deterministic: ${first} then ${got}`)
    }
  })

  await assert('margin differs across tokens', () => {
    const iat = now()
    const exp = iat + 3600
    const seen = new Set()
    for (let i = 0; i < 20; i++) {
      // Same lifetime, different token bytes: the jitter must spread them.
      seen.add(AppMeshClient._refreshMargin(makeJwt(iat, exp, String(i)), exp, iat))
    }
    if (seen.size < 5) throw new Error(`expected jitter to spread renewals, got ${seen.size} distinct margins`)
  })

  // A 30s token must not renew every second: the margin is capped at half the lifetime
  // AFTER jitter, so the refresh point stays inside the token's own life.
  await assert('margin never exceeds half the lifetime', () => {
    for (const lifetime of [5, 30, 60, 120]) {
      const iat = now()
      const exp = iat + lifetime
      const got = AppMeshClient._refreshMargin(makeJwt(iat, exp), exp, iat)
      if (got > lifetime / 2) throw new Error(`lifetime ${lifetime}s: margin ${got} exceeds half-life ${lifetime / 2}`)
    }
  })

  await assert('margin falls back to remaining time when iat is absent', () => {
    const exp = now() + 30 * 60
    const got = AppMeshClient._refreshMargin(makeJwt(0, exp), exp, 0)
    if (got < 648 || got > 792) throw new Error(`margin ${got} outside [648, 792]`)
  })

  // ---- Plan: the 300s constant is a poll cap, not a renew interval ----
  // The regression this whole change exists for: a token that lives far longer than the
  // poll interval must not renew once per poll.
  await assert('plan does not renew once per poll', () => {
    const client = newClient()
    const iat = now()
    client._token = makeJwt(iat, iat + 30 * 60)
    const { delaySec, due } = client._computeRefreshPlan()
    if (due) throw new Error('a token with 30 minutes left must not be due for renewal')
    if (delaySec !== 300) throw new Error(`expected a poll-capped sleep of 300s, got ${delaySec}`)
  })

  await assert('plan renews at the refresh point', () => {
    const client = newClient()
    // Lifetime 30m, already 25m old: past the ~18m refresh point.
    client._token = makeJwt(now() - 25 * 60, now() + 5 * 60)
    const { delaySec, due } = client._computeRefreshPlan()
    if (!due) throw new Error('a token past its refresh point must be due')
    if (delaySec > 1) throw new Error(`expected an immediate renewal, got ${delaySec}`)
  })

  await assert('plan without any credential only polls', () => {
    const client = newClient()
    const { delaySec, due } = client._computeRefreshPlan()
    if (due) throw new Error('no credential means nothing to renew')
    if (delaySec !== 300) throw new Error(`expected the poll interval, got ${delaySec}`)
  })

  // An access token lost to an expired cookie is recoverable from the refresh token —
  // but only if the loop actually attempts a renewal.
  await assert('plan renews from a refresh token alone', () => {
    const client = newClient()
    client._refreshToken = 'rt'
    const { delaySec, due } = client._computeRefreshPlan()
    if (!due) throw new Error('a held refresh token can still mint an access token')
    if (delaySec > 1) throw new Error(`expected a prompt renewal, got ${delaySec}`)
  })

  // The browser case: the auth cookie is HttpOnly, so there is no readable token at all.
  // The daemon reports the lifetime in the login/renew body, and pacing must use it rather
  // than falling back to the fixed cadence this whole change exists to remove.
  await assert('browser paces off the server-reported lifetime, not a fixed cadence', () => {
    const client = newClient()
    const iat = now()
    client._captureRefreshToken({ data: { issued_at: iat, expire_time: iat + 30 * 60 } })
    const { delaySec, due } = client._computeRefreshPlan()
    if (due) throw new Error('a 30-minute session must not be due for renewal immediately')
    if (delaySec !== 300) throw new Error(`expected a poll-capped sleep of 300s, got ${delaySec}`)
  })

  await assert('browser renews at the refresh point of the reported lifetime', () => {
    const client = newClient()
    // Lifetime 30m, already 25m old: past the ~18m refresh point.
    client._captureRefreshToken({ data: { issued_at: now() - 25 * 60, expire_time: now() + 5 * 60 } })
    const { delaySec, due } = client._computeRefreshPlan()
    if (!due) throw new Error('a session past its refresh point must be due')
    if (delaySec > 1) throw new Error(`expected an immediate renewal, got ${delaySec}`)
  })

  // An opaque token keeps the legacy fixed cadence: the only safe fallback when the
  // lifetime cannot be read.
  await assert('plan falls back to the poll cadence for an undecodable token', () => {
    const client = newClient()
    client._token = 'not-a-jwt'
    const { delaySec, due } = client._computeRefreshPlan()
    if (!due) throw new Error('an undecodable token must fall back to renewing on the poll interval')
    if (delaySec !== 300) throw new Error(`expected the poll interval, got ${delaySec}`)
  })

  // ---- Backoff ----
  await assert('retry backoff is bounded at 60s', () => {
    const want = [5, 10, 20, 40, 60, 60, 60]
    want.forEach((w, i) => {
      const got = AppMeshClient._refreshRetryDelay(i + 1)
      if (got !== w) throw new Error(`failure ${i + 1}: expected ${w}, got ${got}`)
    })
  })

  await assert('a failed renewal does not disarm the loop', async () => {
    const client = newClient()
    client._computeRefreshPlan = () => ({ delaySec: 0, due: true })
    client.renew_token = async () => { throw new Error('daemon down') }
    client.set_auto_refresh_token(true)
    try {
      await new Promise(resolve => setTimeout(resolve, 50))
      if (client._refreshFailures !== 1) throw new Error(`expected 1 failure, got ${client._refreshFailures}`)
      if (!client._autoRefreshEnabled) throw new Error('auto-refresh was disabled by a failure')
      if (!client._refreshTimer) throw new Error('the loop was left without a pending timer')
    } finally {
      client.set_auto_refresh_token(false)
    }
  })

  // ---- Refresh-token plumbing ----
  await assert('login opts in to a refresh token and remembers the TTL', async () => {
    const client = newClient()
    client.set_use_refresh_token(true)
    const calls = stubRequest(client, () => ({ status: 200, data: { refresh_token: 'rt-login' } }))
    await client.login('u', 'p', null, 'P1D')
    if (calls[0].headers['X-Refresh-Token-Request'] !== 'true') throw new Error('missing opt-in header on login')
    if (client._refreshToken !== 'rt-login') throw new Error('refresh token was not captured from login')
    if (client._tokenExpireSeconds !== 86400) throw new Error(`expected 86400s remembered, got ${client._tokenExpireSeconds}`)
  })

  await assert('validate_totp does the same session setup as login', async () => {
    const client = newClient()
    client.set_use_refresh_token(true)
    const calls = stubRequest(client, () => ({ status: 200, data: { refresh_token: 'rt-totp' } }))
    await client.validate_totp('u', 'challenge', '123456', 'P1D')
    if (calls[0].headers['X-Refresh-Token-Request'] !== 'true') throw new Error('missing opt-in header on totp/validate')
    if (client._refreshToken !== 'rt-totp') throw new Error('refresh token was not captured from totp/validate')
    if (client._tokenExpireSeconds !== 86400) throw new Error(`expected 86400s remembered, got ${client._tokenExpireSeconds}`)
  })

  await assert('renew replays the login TTL and the refresh token', async () => {
    const client = newClient()
    client.set_use_refresh_token(true)
    const calls = stubRequest(client, () => ({ status: 200, data: { refresh_token: 'rt-2' } }))
    client._tokenExpireSeconds = 86400
    client._refreshToken = 'rt-1'
    await client.renew_token()
    const h = calls[0].headers
    if (h['X-Expire-Seconds'] !== 86400) throw new Error(`expected the login TTL replayed, got ${h['X-Expire-Seconds']}`)
    if (h['X-Refresh-Token'] !== 'rt-1') throw new Error('the held refresh token was not sent')
    if (h['X-Refresh-Token-Request'] !== 'true') throw new Error('missing opt-in header on renew')
    if (client._refreshToken !== 'rt-2') throw new Error('the rotated refresh token was not stored')
  })

  await assert('renew omits X-Expire-Seconds when the TTL is unknown', async () => {
    const client = newClient()
    const calls = stubRequest(client)
    await client.renew_token()
    if ('X-Expire-Seconds' in calls[0].headers) throw new Error('an unknown TTL must not be guessed')
    if ('X-Refresh-Token' in calls[0].headers) throw new Error('no refresh token held, none should be sent')
  })

  await assert('an explicit renew TTL overrides the remembered one', async () => {
    const client = newClient()
    const calls = stubRequest(client)
    client._tokenExpireSeconds = 86400
    await client.renew_token('P1W')
    if (calls[0].headers['X-Expire-Seconds'] !== 604800) throw new Error(`expected 604800, got ${calls[0].headers['X-Expire-Seconds']}`)
  })

  await assert('a 401 from renew clears the stored refresh token', async () => {
    const client = newClient()
    client._refreshToken = 'rt-dead'
    stubRequest(client, () => { throw new AppMeshError('unauthorized', 401) })
    let threw = false
    try { await client.renew_token() } catch (_) { threw = true }
    if (!threw) throw new Error('expected renew to reject')
    if (client._refreshToken !== null) throw new Error('a rejected refresh token must be dropped')
  })

  await assert('a 503 from renew keeps the refresh token', async () => {
    const client = newClient()
    client._refreshToken = 'rt-live'
    stubRequest(client, () => { throw new AppMeshError('unavailable', 503) })
    try { await client.renew_token() } catch (_) { /* expected */ }
    if (client._refreshToken !== 'rt-live') throw new Error('a transient failure must not drop the credential')
  })

  // Rotation makes a refresh token single-use, so two concurrent renewals would present
  // the same one and permanently wedge the client.
  await assert('renewals are single-flight', async () => {
    const client = newClient()
    let inFlight = 0
    let overlapped = false
    let completed = 0
    client._request = async () => {
      inFlight++
      if (inFlight > 1) overlapped = true
      await new Promise(resolve => setTimeout(resolve, 10))
      inFlight--
      completed++
      return { status: 200, data: {} }
    }
    await Promise.all([client.renew_token(), client.renew_token(), client.renew_token()])
    if (overlapped) throw new Error('two renewals ran concurrently')
    if (completed !== 3) throw new Error(`expected all 3 renewals to run, got ${completed}`)
  })

  await assert('a failed renewal does not break the single-flight queue', async () => {
    const client = newClient()
    let n = 0
    client._request = async () => {
      n++
      if (n === 1) throw new AppMeshError('boom', 500)
      return { status: 200, data: {} }
    }
    const results = await Promise.allSettled([client.renew_token(), client.renew_token()])
    if (results[0].status !== 'rejected') throw new Error('the first renewal should have failed')
    if (results[1].status !== 'fulfilled') throw new Error('a queued renewal must still run after a failure')
  })

  await assert('logoff presents and then clears the refresh token', async () => {
    const client = newClient()
    const calls = stubRequest(client)
    client._refreshToken = 'rt'
    await client.logout()
    const call = calls.find(c => c.path === '/appmesh/self/logoff')
    if (!call) throw new Error('no logoff request was sent')
    if (call.headers['X-Refresh-Token'] !== 'rt') throw new Error('the refresh token was not presented on logoff')
    if (client._refreshToken !== null) throw new Error('the refresh token must be cleared on logoff')
  })

  // ---- Refresh-token opt-in: tri-state ----
  // A refresh token is a multi-day credential. A one-shot script has nowhere to keep it and
  // never revokes it, so it must be asked for, not handed out.
  const HDR = 'X-Refresh-Token-Request'

  /** Drive login/totp-validate/renew and return whether each sent the opt-in header. */
  async function optInPerCall(client) {
    const calls = stubRequest(client)
    await client.login('u', 'p')
    await client.validate_totp('u', 'challenge', '123456')
    await client.renew_token()
    return calls.map(c => c.headers[HDR])
  }

  await assert('unset follows auto-refresh: off means no refresh token is requested', async () => {
    const sent = await optInPerCall(newClient())
    if (sent.some(v => v !== undefined)) throw new Error(`a one-shot client must not be issued one, got ${JSON.stringify(sent)}`)
  })

  await assert('unset follows auto-refresh: on means one is requested', async () => {
    const client = newClient()
    client.set_auto_refresh_token(true)
    try {
      const sent = await optInPerCall(client)
      if (sent.some(v => v !== 'true')) throw new Error(`a long-lived client should opt in everywhere, got ${JSON.stringify(sent)}`)
    } finally {
      client.set_auto_refresh_token(false)
    }
  })

  await assert('an explicit true overrides auto-refresh being off', async () => {
    const sent = await optInPerCall(new AppMeshClient('https://127.0.0.1:6060', null, true))
    if (sent.some(v => v !== 'true')) throw new Error(`the caller's choice must win, got ${JSON.stringify(sent)}`)
  })

  // Declining must omit the header: the daemon treats its mere presence as the opt-in, so
  // sending "false" would still mint the credential.
  await assert('an explicit false overrides auto-refresh being on, by omitting the header', async () => {
    const client = new AppMeshClient('https://127.0.0.1:6060', null, false)
    client.set_auto_refresh_token(true)
    try {
      const sent = await optInPerCall(client)
      if (sent.some(v => v !== undefined)) throw new Error(`declining must omit, never send "false", got ${JSON.stringify(sent)}`)
    } finally {
      client.set_auto_refresh_token(false)
    }
  })

  // ---- Browser asymmetry ----
  // The auth cookie is HttpOnly so XSS cannot reach it; a refresh token in JS memory would
  // hand that back to any injected script, for a longer window and with no need for it.
  // A fresh module instance is required: ENV.isNode is evaluated once, at import time.
  globalThis.window = { document: {}, location: { origin: 'https://x' } }
  const browser = await import('../src/appmesh.js?env=browser')
  delete globalThis.window

  await assert('a browser declines by default even with auto-refresh on', async () => {
    const client = new browser.AppMeshClient('https://127.0.0.1:6060')
    client.set_auto_refresh_token(true)
    try {
      const sent = await optInPerCall(client)
      if (sent.some(v => v !== undefined)) throw new Error(`a browser must not hold one implicitly, got ${JSON.stringify(sent)}`)
    } finally {
      client.set_auto_refresh_token(false)
    }
  })

  await assert('a browser still honours an explicit true', async () => {
    const client = new browser.AppMeshClient('https://127.0.0.1:6060')
    client.set_use_refresh_token(true)
    const sent = await optInPerCall(client)
    if (sent.some(v => v !== 'true')) throw new Error(`an explicit opt-in must be honoured, got ${JSON.stringify(sent)}`)
  })

  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
  if (failed > 0) process.exit(1)
}

test()
