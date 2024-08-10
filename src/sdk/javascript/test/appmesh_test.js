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
    //appmesh.delegateHost = "localhost"
    const auth = await appmesh.authentication(token);
    console.log("authentication response:", auth);

    console.log("permissions_for_user:", await appmesh.permissions_for_user());
    console.log("roles_view:", await appmesh.roles_view());
    console.log("users_view:", await appmesh.users_view());
    console.log("user_self:", await appmesh.user_self());

    const host_resource = await appmesh.host_resource();
    console.log("host_resource:", host_resource);

    const config_view = await appmesh.config_view();
    console.log("config_view:", config_view);

    const log_level_set = await appmesh.log_level_set("DEBUG");
    console.log("log_level_set:", log_level_set);

    const metrics = await appmesh.metrics();
    console.log("metrics:", metrics);

    appmesh.run_sync({
      name: "pyrun",
      metadata: "import os; [os.remove('/tmp/2.log') if os.path.exists('/tmp/2.log') else None]",
    });
    const fs = require("fs").promises;
    try {
      await fs.unlink("1.log");
    } catch (err) {}
    await appmesh.file_download("/opt/appmesh/bin/appsvc", "1.log");
    await appmesh.file_upload("1.log", "/tmp/2.log");

    /*
    const totp_secret = await appmesh.totp_secret();
    console.log("totp_secret:", totp_secret);
    const code = twofactor.generateToken(totp_secret);
    console.log(code);
    //const totp_setup = await appmesh.totp_setup(code);
    //console.log("totp_setup:", totp_setup);
    const totp_disable = await appmesh.totp_disable();
    console.log("totp_disable:", totp_disable);
    */

    // Test list applications
    const applications = await appmesh.app_view_all();
    console.log("app_view_all:", applications);

    const app_view = await appmesh.app_view("ping");
    console.log("app_view:", app_view);

    const app_health = await appmesh.app_health("ping");
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
    const app_add = await appmesh.app_add("test-ping", newApp);
    console.log("app_add:", app_add);

    const app_enable = await appmesh.app_enable("test-ping");
    console.log("app_enable:", app_enable);

    const app_disable = await appmesh.app_disable("test-ping");
    console.log("app_disable:", app_disable);

    const app_delete = await appmesh.app_delete("test-ping");
    console.log("app_delete:", app_delete);

    const app_output = await appmesh.app_output("ping");
    //console.log("app_output:", app_output);

    try {
      await appmesh.app_delete("test-run");
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

    const run_sync = await appmesh.run_sync(runApp);
    console.log("run_sync:", run_sync);

    const run_async = await appmesh.run_async(runApp, "PT20S", "PT20S");
    await run_async.wait(nodeOutputHandler);

    // Test logout
    await appmesh.logout();
    console.log("Logged out successfully");
  } catch (error) {
    console.error("Error:", error.message);
  }
}

userTest();
