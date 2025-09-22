import fs from 'fs'
import { AppMeshClient } from 'appmesh'

const baseURL = process.env.APPMESH_URL || 'https://127.0.0.1:6060'
const username = process.env.APPMESH_USER || 'admin'
const password = process.env.APPMESH_PASS || 'admin123'

async function test() {
  // SSL configuration
  const sslConfig = {
    cert: fs.readFileSync('/opt/appmesh/ssl/client.pem'),
    key: fs.readFileSync('/opt/appmesh/ssl/client-key.pem'),
    ca: fs.readFileSync('/opt/appmesh/ssl/ca.pem'),
    rejectUnauthorized: true
  }

  const client = new AppMeshClient(baseURL, sslConfig)
  try {
    // Login test
    console.log('Testing login...')
    await client.login(username, password)
    console.log('Login successful')

    // Authentication test
    await client.authenticate()
    console.log('Authentication')

    // User and Role tests
    console.log('\nTesting user permissions...')
    console.log('Permissions:', await client.view_user_permissions())
    console.log('Roles:', await client.view_roles())
    console.log('Users:', await client.view_users())
    console.log('Self:', await client.view_self())

    // View configuration test
    console.log('\nTesting view_config...')
    const config = await client.view_config()
    console.log('Configuration:', JSON.stringify(config, null, 2))

    // View resources test
    console.log('\nTesting view_host_resources...')
    const resources = await client.view_host_resources()
    console.log('Resources:', JSON.stringify(resources, null, 2))

    // Set log level test
    console.log('\nTesting set_log_level...')
    const logLevel = await client.set_log_level('DEBUG')
    console.log('Log level set:', logLevel)

    // Metrics test
    console.log('\nTesting metrics...')
    const metrics = await client.metrics()
    console.log('Metrics:', metrics)

    // File operations test
    await client.run_app_sync({
      name: 'pyexec',
      metadata:
        "import os; [os.remove('/tmp/2.log') if os.path.exists('/tmp/2.log') else None]"
    })

    try {
      await fs.promises.unlink('1.log')
    } catch (err) { }

    await client.download_file('/opt/appmesh/bin/appsvc', '1.log')
    await client.upload_file('1.log', '/tmp/2.log')

    // View applications test
    console.log('\nTesting view_all_apps...')
    const apps = await client.view_all_apps()
    console.log('Applications:', JSON.stringify(apps, null, 2))

    // View specific app
    const app_view = await client.view_app('ping')
    console.log('App view:', app_view)

    // Check app health
    const app_health = await client.check_app_health('ping')
    console.log('App health:', app_health)

    // Add, enable, disable, and delete app test
    const newApp = {
      name: 'test-ping',
      description: 'appmesh ping test',
      command: 'ping github.com -w 300',
      shell: true,
      behavior: {
        control: { 0: 'standby' },
        exit: 'standby'
      }
    }

    await client.add_app('test-ping', newApp)
    await client.enable_app('test-ping')
    await client.disable_app('test-ping')
    await client.delete_app('test-ping')

    // Get app output
    const app_output = await client.get_app_output('ping')
    console.log('App output:', app_output)

    // Run app tests
    try {
      await client.delete_app('test-run')
    } catch { }

    const runApp = {
      name: 'test-run',
      description: 'appmesh ping test',
      command: 'ping github.com -w 5',
      shell: true,
      behavior: {
        control: { 0: 'standby' },
        exit: 'standby'
      }
    }

    const nodeOutputHandler = output => process.stdout.write(output)

    const run_app_sync = await client.run_app_sync(runApp)
    console.log('Run app sync:', run_app_sync)

    const run_async = await client.run_app_async(runApp, 'PT20S', 'PT20S')
    await run_async.wait(nodeOutputHandler)

    // TOTP test
    /*
    const totp_secret = await client.get_totp_secret()
    console.log('totp_secret:', totp_secret)
    const code = node2fa.generateToken(totp_secret)
    console.log(code)
    //const totp_setup = await client.setup_totp(code);
    //console.log("totp_setup:", totp_setup);
    const totp_disable = await client.disable_totp()
    console.log('totp_disable:', totp_disable)
    */

    // Logout test
    await client.logoff()
    console.log('Logged out successfully')

    await client.login(username, password)
    console.log('Re-login successful')
  } catch (error) {
    console.error('Test failed:', error)
    process.exit(1)
  }
}

test()
