import { tmpdir } from 'os'
import { join } from 'path'
import { writeFileSync, readFileSync, unlinkSync } from 'fs'

import { AppMeshClient, AppMeshError } from '../src/appmesh.js'

const baseURL = process.env.APPMESH_URL || 'https://127.0.0.1:6060'
const accessToken = process.env.APPMESH_BEARER_TOKEN

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
  // Self-signed local daemon: explicitly disable server certificate verification
  const client = new AppMeshClient(baseURL, { rejectUnauthorized: false })
  if (!accessToken) throw new Error('APPMESH_BEARER_TOKEN is required; obtain it directly from Dex')
  client.setBearerToken(accessToken)

  console.log('=== JavaScript SDK Integration Tests ===\n')

  // ---- Principal / Roles ----
  await assert('get_user_permissions', async () => {
    const perms = await client.getUserPermissions()
    if (!Array.isArray(perms)) throw new Error('expected array')
  })

  await assert('get_current_user', async () => {
    const user = await client.getCurrentUser()
    if (!user) throw new Error('expected user object')
  })

  await assert('list_roles', async () => {
    const roles = await client.listRoles()
    if (!roles) throw new Error('expected roles object')
  })

  // ---- Config / Resources ----
  await assert('get_config', async () => {
    const config = await client.getConfig()
    if (!config) throw new Error('expected config')
  })

  await assert('get_host_resources', async () => {
    const res = await client.getHostResources()
    if (!res) throw new Error('expected resources')
  })

  await assert('set_log_level', async () => {
    const level = await client.setLogLevel('DEBUG')
    if (level !== 'DEBUG') throw new Error(`expected DEBUG, got ${level}`)
  })

  await assert('get_metrics', async () => {
    const m = await client.getMetrics()
    if (typeof m !== 'string' || m.length === 0) throw new Error('expected metrics text')
  })

  // ---- Applications ----
  await assert('list_apps', async () => {
    const apps = await client.listApps()
    if (!Array.isArray(apps)) throw new Error('expected array')
  })

  await assert('add_app + get_app + delete_app', async () => {
    try { await client.deleteApp('js_test_app') } catch (_) {}
    const app = await client.addApp('js_test_app', {
      name: 'js_test_app',
      command: 'echo hello_js',
      description: 'JS SDK test'
    })
    if (app.name !== 'js_test_app') throw new Error('name mismatch')

    const fetched = await client.getApp('js_test_app')
    if (fetched.name !== 'js_test_app') throw new Error('get_app mismatch')

    await client.deleteApp('js_test_app')
  })

  await assert('enable_app + disable_app', async () => {
    await client.addApp('js_test_ed', { name: 'js_test_ed', command: 'sleep 60' })
    await client.disableApp('js_test_ed')
    await client.enableApp('js_test_ed')
    await client.deleteApp('js_test_ed')
  })

  await assert('checkAppHealth(nonexistent → throws)', async () => {
    // A missing app is a 404 server verdict, not a health verdict: it must surface
    // as an error instead of reading as "unhealthy"
    let thrown = null
    try {
      await client.checkAppHealth('nonexistent_xyz')
    } catch (error) {
      thrown = error
    }
    if (!(thrown instanceof AppMeshError)) {
      throw new Error(`expected AppMeshError for missing app, got ${thrown === null ? 'no error' : thrown.name}`)
    }
  })

  // ---- Sync / Async Run ----
  await assert('run_app_sync', async () => {
    const exitCode = await client.runAppSync(
      { command: 'echo hello_sync_js', shell: true },
      null, 10, 20
    )
    // exitCode may be 0 or null depending on server
  })

  await assert('run_app_async + wait', async () => {
    const run = await client.runAppAsync(
      { command: 'echo hello_async_js', shell: true },
      10, 20
    )
    if (!run || !run.procUid) throw new Error('expected AppRun with procUid')
    const code = await run.wait(null, 15)
    if (code !== 0) throw new Error(`expected exit 0, got ${code}`)
  })

  // ---- Labels ----
  await assert('add_label + list_labels + delete_label', async () => {
    await client.addLabel('js_test_label', 'js_value')
    const labels = await client.listLabels()
    if (labels['js_test_label'] !== 'js_value') throw new Error('label not found')
    await client.deleteLabel('js_test_label')
    const labels2 = await client.listLabels()
    if (labels2['js_test_label']) throw new Error('label should be deleted')
  })

  // ---- App Output ----
  await assert('get_app_output', async () => {
    const appName = 'js_test_output'
    try { await client.deleteApp(appName) } catch (_) {}
    // Register a persistent app with output caching so output survives after run
    await client.addApp(appName, {
      name: appName,
      command: 'echo js_output_test',
      shell: true,
      stdout_backup_count: 3
    })
    // Allow the server time to execute the one-shot command
    await new Promise(resolve => setTimeout(resolve, 2000))
    try {
      const out = await client.getAppOutput(appName)
      if (!out) throw new Error('expected AppOutput object')
      if (typeof out.statusCode !== 'number') throw new Error('expected numeric statusCode')
      if (out.statusCode !== 200) throw new Error(`expected status 200, got ${out.statusCode}`)
      if (typeof out.output !== 'string') throw new Error('expected string output')
      if (!out.output.includes('js_output_test')) {
        throw new Error(`expected output to contain "js_output_test", got: ${JSON.stringify(out.output)}`)
      }
    } finally {
      try { await client.deleteApp(appName) } catch (_) {}
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
      await client.uploadFile(localUpload, remotePath)
      await client.downloadFile(remotePath, localDownload)
      const downloaded = readFileSync(localDownload, 'utf8')
      if (downloaded !== content) {
        throw new Error(`content mismatch: expected "${content}", got "${downloaded}"`)
      }
    } finally {
      try { unlinkSync(localUpload) } catch (_) {}
      try { unlinkSync(localDownload) } catch (_) {}
    }
  })

  // ---- Permissions ----
  await assert('list_permissions', async () => {
    const perms = await client.listPermissions()
    if (!Array.isArray(perms)) throw new Error('expected array')
    if (perms.length === 0) throw new Error('expected at least one permission')
  })

  // ---- Set Config ----
  await assert('set_config', async () => {
    // Read current log level so we can restore it
    const before = await client.getConfig()
    const originalLevel = before && before.BaseConfig && before.BaseConfig.LogLevel
      ? before.BaseConfig.LogLevel
      : 'INFO'

    const updated = await client.setConfig({ BaseConfig: { LogLevel: 'INFO' } })
    if (!updated || !updated.BaseConfig) throw new Error('expected updated config with BaseConfig')
    if (updated.BaseConfig.LogLevel !== 'INFO') {
      throw new Error(`expected INFO, got ${updated.BaseConfig.LogLevel}`)
    }

    // Restore original level
    await client.setConfig({ BaseConfig: { LogLevel: originalLevel } })
  })

  // ---- Summary ----
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`)
  if (failed > 0) process.exit(1)
}

test()
