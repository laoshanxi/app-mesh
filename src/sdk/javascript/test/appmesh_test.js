import { AppMeshClient } from '../src/appmesh.js'
import { tmpdir } from 'os'
import { join } from 'path'
import { writeFileSync, readFileSync, unlinkSync } from 'fs'

const baseURL = process.env.APPMESH_URL || 'https://127.0.0.1:6060'
const username = process.env.APPMESH_USER || 'admin'
const password = process.env.APPMESH_PASS || 'admin123'

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

async function test() {
  // No SSL verification (no certs on local dev)
  const client = new AppMeshClient(baseURL)

  console.log('=== JavaScript SDK Integration Tests ===\n')

  // ---- Authentication ----
  await assert('login', async () => {
    await client.login(username, password)
  })

  await assert('authenticate (apply=true)', async () => {
    const cookieStr = client._client?.defaults?.headers?.Cookie || ''
    const match = cookieStr.split('; ').find(c => c.startsWith('appmesh_auth_token='))
    const token = match ? match.split('=').slice(1).join('=') : null
    if (!token) throw new Error('expected token after login')
    const result = await client.authenticate(token)
    if (!result.success) throw new Error(`authenticate failed: ${result.responseText}`)
  })

  await assert('authenticate (apply=false)', async () => {
    const cookieStr = client._client?.defaults?.headers?.Cookie || ''
    const match = cookieStr.split('; ').find(c => c.startsWith('appmesh_auth_token='))
    const token = match ? match.split('=').slice(1).join('=') : null
    if (!token) throw new Error('expected token after login')
    const result = await client.authenticate(token, null, undefined, false)
    if (!result.success) throw new Error(`authenticate failed: ${result.responseText}`)
  })

  await assert('renew_token', async () => {
    await client.renew_token('P1D')
  })

  // ---- User / Roles ----
  await assert('get_user_permissions', async () => {
    const perms = await client.get_user_permissions()
    if (!Array.isArray(perms)) throw new Error('expected array')
  })

  await assert('get_current_user', async () => {
    const user = await client.get_current_user()
    if (!user) throw new Error('expected user object')
  })

  await assert('list_roles', async () => {
    const roles = await client.list_roles()
    if (!roles) throw new Error('expected roles object')
  })

  await assert('list_users', async () => {
    const users = await client.list_users()
    if (!users) throw new Error('expected users object')
  })

  // ---- Config / Resources ----
  await assert('get_config', async () => {
    const config = await client.get_config()
    if (!config) throw new Error('expected config')
  })

  await assert('get_host_resources', async () => {
    const res = await client.get_host_resources()
    if (!res) throw new Error('expected resources')
  })

  await assert('set_log_level', async () => {
    const level = await client.set_log_level('DEBUG')
    if (level !== 'DEBUG') throw new Error(`expected DEBUG, got ${level}`)
  })

  await assert('metrics', async () => {
    const m = await client.metrics()
    if (typeof m !== 'string' || m.length === 0) throw new Error('expected metrics text')
  })

  // ---- Applications ----
  await assert('list_apps', async () => {
    const apps = await client.list_apps()
    if (!Array.isArray(apps)) throw new Error('expected array')
  })

  await assert('add_app + get_app + delete_app', async () => {
    try { await client.delete_app('js_test_app') } catch (_) {}
    const app = await client.add_app('js_test_app', {
      name: 'js_test_app',
      command: 'echo hello_js',
      description: 'JS SDK test'
    })
    if (app.name !== 'js_test_app') throw new Error('name mismatch')

    const fetched = await client.get_app('js_test_app')
    if (fetched.name !== 'js_test_app') throw new Error('get_app mismatch')

    await client.delete_app('js_test_app')
  })

  await assert('enable_app + disable_app', async () => {
    await client.add_app('js_test_ed', { name: 'js_test_ed', command: 'sleep 60' })
    await client.disable_app('js_test_ed')
    await client.enable_app('js_test_ed')
    await client.delete_app('js_test_ed')
  })

  await assert('check_app_health (nonexistent → false)', async () => {
    const h = await client.check_app_health('nonexistent_xyz')
    if (h !== false) throw new Error('expected false for nonexistent app')
  })

  // ---- Sync / Async Run ----
  await assert('run_app_sync', async () => {
    const exitCode = await client.run_app_sync(
      { command: 'echo hello_sync_js', shell: true },
      null, 10, 20
    )
    // exitCode may be 0 or null depending on server
  })

  await assert('run_app_async + wait', async () => {
    const run = await client.run_app_async(
      { command: 'echo hello_async_js', shell: true },
      10, 20
    )
    if (!run || !run.procUid) throw new Error('expected AppRun with procUid')
    const code = await run.wait(null, 15)
    if (code !== 0) throw new Error(`expected exit 0, got ${code}`)
  })

  // ---- Labels ----
  await assert('add_label + list_labels + delete_label', async () => {
    await client.add_label('js_test_label', 'js_value')
    const labels = await client.list_labels()
    if (labels['js_test_label'] !== 'js_value') throw new Error('label not found')
    await client.delete_label('js_test_label')
    const labels2 = await client.list_labels()
    if (labels2['js_test_label']) throw new Error('label should be deleted')
  })

  // ---- Token Auto-Refresh ----
  await assert('setAutoRefreshToken', async () => {
    client.setAutoRefreshToken(true)
    if (!client._autoRefreshEnabled) throw new Error('expected enabled')
    if (!client._refreshTimer) throw new Error('expected timer')
    client.setAutoRefreshToken(false)
    if (client._autoRefreshEnabled) throw new Error('expected disabled')
    if (client._refreshTimer) throw new Error('expected no timer')
  })

  // ---- App Output ----
  await assert('get_app_output', async () => {
    const appName = 'js_test_output'
    try { await client.delete_app(appName) } catch (_) {}
    // Register a persistent app with output caching so output survives after run
    await client.add_app(appName, {
      name: appName,
      command: 'echo js_output_test',
      shell: true,
      stdout_cache_num: 3
    })
    // Allow the server time to execute the one-shot command
    await new Promise(resolve => setTimeout(resolve, 2000))
    try {
      const out = await client.get_app_output(appName)
      if (!out) throw new Error('expected AppOutput object')
      if (typeof out.statusCode !== 'number') throw new Error('expected numeric statusCode')
      if (out.statusCode !== 200) throw new Error(`expected status 200, got ${out.statusCode}`)
      if (typeof out.output !== 'string') throw new Error('expected string output')
      if (!out.output.includes('js_output_test')) {
        throw new Error(`expected output to contain "js_output_test", got: ${JSON.stringify(out.output)}`)
      }
    } finally {
      try { await client.delete_app(appName) } catch (_) {}
    }
  })

  // ---- File Upload / Download ----
  await assert('upload_file + download_file', async () => {
    const content = 'js_sdk_file_test_' + Date.now()
    const localUpload = join(tmpdir(), 'appmesh_js_upload.txt')
    const localDownload = join(tmpdir(), 'appmesh_js_download.txt')
    const remotePath = `/tmp/appmesh_js_test_${Date.now()}.txt`

    writeFileSync(localUpload, content, 'utf8')
    try {
      await client.upload_file(localUpload, remotePath)
      await client.download_file(remotePath, localDownload)
      const downloaded = readFileSync(localDownload, 'utf8')
      if (downloaded !== content) {
        throw new Error(`content mismatch: expected "${content}", got "${downloaded}"`)
      }
    } finally {
      try { unlinkSync(localUpload) } catch (_) {}
      try { unlinkSync(localDownload) } catch (_) {}
    }
  })

  // ---- Permissions / Groups ----
  await assert('list_permissions', async () => {
    const perms = await client.list_permissions()
    if (!Array.isArray(perms)) throw new Error('expected array')
    if (perms.length === 0) throw new Error('expected at least one permission')
  })

  await assert('list_groups', async () => {
    const groups = await client.list_groups()
    if (!Array.isArray(groups)) throw new Error('expected array')
  })

  // ---- Password Update ----
  await assert('update_password', async () => {
    const newPass = 'admin123_tmp_js'
    try {
      const ok1 = await client.update_password(password, newPass)
      if (!ok1) throw new Error('password change failed')
    } finally {
      // Always restore original password
      try { await client.update_password(newPass, password) } catch (_) {
        // If client token is invalid after password change, re-login with new password
        await client.login('admin', newPass)
        await client.update_password(newPass, password)
        await client.login('admin', password)
      }
    }
  })

  // ---- Set Config ----
  await assert('set_config', async () => {
    // Read current log level so we can restore it
    const before = await client.get_config()
    const originalLevel = before && before.BaseConfig && before.BaseConfig.LogLevel
      ? before.BaseConfig.LogLevel
      : 'INFO'

    const updated = await client.set_config({ BaseConfig: { LogLevel: 'INFO' } })
    if (!updated || !updated.BaseConfig) throw new Error('expected updated config with BaseConfig')
    if (updated.BaseConfig.LogLevel !== 'INFO') {
      throw new Error(`expected INFO, got ${updated.BaseConfig.LogLevel}`)
    }

    // Restore original level
    await client.set_config({ BaseConfig: { LogLevel: originalLevel } })
  })

  // ---- Logout ----
  await assert('logout', async () => {
    await client.logout()
  })

  // ---- Summary ----
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
  if (failed > 0) process.exit(1)
}

test()
