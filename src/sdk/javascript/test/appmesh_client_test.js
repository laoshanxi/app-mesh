const { AppMeshClient, AppOutput } = require("../src/appmesh.js");
//const otplib = require("otplib");

async function userTest() {
  const appmesh = new AppMeshClient("https://localhost:6060");

  try {
    // Test login
    const token = await appmesh.login("admin", "admin123");
    console.log("login response:", token);
    //appmesh.delegate_host("localhost")
    const auth = await appmesh.authentication(token);
    console.log("authentication response:", auth);
    // await appmesh.logout();

    /*
    const totp_secret = await appmesh.totp_secret();
    console.log("totp_secret:", totp_secret);

    const code = otplib.totp.generate(totp_secret);
    console.log(code);
    console.log(otplib.totp.check(code, totp_secret));
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
