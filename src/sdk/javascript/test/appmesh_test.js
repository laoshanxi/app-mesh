const fs = require("fs");
const { AppMeshClient } = require("../src/appmesh");
// const { AppMeshClient } = require("appmesh");
// const twofactor = require("node-2fa");

async function userTest() {
  const sslConfig = {
    cert: fs.readFileSync("/opt/appmesh/ssl/client.pem"),
    key: fs.readFileSync("/opt/appmesh/ssl/client-key.pem"),
    ca: fs.readFileSync("/opt/appmesh/ssl/ca.pem"),
    rejectUnauthorized: true,
  };

  const appmesh = new AppMeshClient("https://localhost:6060", sslConfig);

  try {
    // Test login
    const token = await appmesh.login("admin", "admin123");
    console.log("login response:", token);
    //appmesh.forwardingHost = "localhost"
    const auth = await appmesh.authenticate(token);
    console.log("authentication response:", auth);

    console.log("permissions_for_user:", await appmesh.view_user_permissions());
    console.log("roles_view:", await appmesh.view_roles());
    console.log("users_view:", await appmesh.view_users());
    console.log("user_self:", await appmesh.view_self());

    const host_resource = await appmesh.view_host_resources();
    console.log("host_resource:", host_resource);

    const config_view = await appmesh.view_config();
    console.log("config_view:", config_view);

    const log_level_set = await appmesh.set_log_level("DEBUG");
    console.log("log_level_set:", log_level_set);

    const metrics = await appmesh.metrics();
    console.log("metrics:", metrics);

    appmesh.run_app_sync({
      name: "pyrun",
      metadata:
        "import os; [os.remove('/tmp/2.log') if os.path.exists('/tmp/2.log') else None]",
    });
    const fs = require("fs").promises;
    try {
      await fs.unlink("1.log");
    } catch (err) {}
    await appmesh.download_file("/opt/appmesh/bin/appsvc", "1.log");
    await appmesh.upload_file("1.log", "/tmp/2.log");

    /*
    const totp_secret = await appmesh.get_totp_secret();
    console.log("totp_secret:", totp_secret);
    const code = twofactor.generateToken(totp_secret);
    console.log(code);
    //const totp_setup = await appmesh.setup_totp(code);
    //console.log("totp_setup:", totp_setup);
    const totp_disable = await appmesh.disable_totp();
    console.log("totp_disable:", totp_disable);
    */

    // Test list applications
    const applications = await appmesh.view_all_apps();
    console.log("app_view_all:", applications);

    const app_view = await appmesh.view_app("ping");
    console.log("app_view:", app_view);

    const app_health = await appmesh.check_app_health("ping");
    console.log("app_view:", app_health);

    // Add a new application
    const newApp = {
      name: "test-ping",
      description: "appmesh ping test",
      command: "ping github.com -w 300",
      shell: true,
      behavior: {
        control: { 0: "standby" },
        exit: "standby",
      },
    };
    const app_add = await appmesh.add_app("test-ping", newApp);
    console.log("app_add:", app_add);

    const app_enable = await appmesh.enable_app("test-ping");
    console.log("app_enable:", app_enable);

    const app_disable = await appmesh.disable_app("test-ping");
    console.log("app_disable:", app_disable);

    const app_delete = await appmesh.delete_app("test-ping");
    console.log("app_delete:", app_delete);

    const app_output = await appmesh.get_app_output("ping");
    //console.log("app_output:", app_output);

    try {
      await appmesh.delete_app("test-run");
    } catch {}

    const runApp = {
      name: "test-run",
      description: "appmesh ping test",
      command: "ping github.com -w 5",
      shell: true,
      behavior: {
        control: { 0: "standby" },
        exit: "standby",
      },
    };

    console.log(runApp);
    // For Node.js backend:
    const nodeOutputHandler = (output) => process.stdout.write(output);
    // web frontend
    //const webOutputHandler = (output) => {
    //  // Append to a div, update state in React, etc.
    //  document.getElementById('output').textContent += output;
    //};

    const run_app_sync = await appmesh.run_app_sync(runApp);
    console.log("run_app_sync:", run_app_sync);

    const run_async = await appmesh.run_app_async(runApp, "PT20S", "PT20S");
    await run_async.wait(nodeOutputHandler);

    // Test logout
    await appmesh.logoff();
    console.log("Logged out successfully");
  } catch (error) {
    console.error("Error:", error.message);
  }
}

userTest();
