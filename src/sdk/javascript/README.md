# App Mesh JavaScript SDK

> **Naming**: public methods use camelCase (`listApps`, `runAppSync`).

## Client SDK

### Build

```shell
npm run build
```

### Install

```shell
npm i appmesh
```

### Usage

#### Node.js

```js
import { AppMeshClient } from "appmesh";

const client = new AppMeshClient();
client.setBearerToken(process.env.APPMESH_BEARER_TOKEN);
```

#### Run an app synchronously

```js
// Resolves to the exit code (null when the daemon sent none); the stdout handler
// receives the complete output in one call.
const exitCode = await client.runAppSync({ command: "cat big.log", shell: true }, (output) => process.stdout.write(output));
// Optional 5th parameter: reject instead of returning when the output grows past a byte ceiling.
await client.runAppSync(app, (output) => process.stdout.write(output), 30, 60, 10 * 1024 * 1024);
```

One `runAppSync` reply carries at most 5 MiB of output. When the output fills a page,
the SDK pages the rest from the daemon (in raw bytes, decoded once in the charset of the
first reply) and only then calls the stdout handler, so the complete output is always
delivered. The same applies to `AppMeshClientTCP`. When the output grows past
`maxOutputBytes` the call rejects with `AppMeshRequestError` (the message names the run
instance that keeps the remaining output readable for 600 seconds) instead of returning a
partial result; the instance is left in place for the daemon to clean up.

#### Forwarding and streaming in a cluster

`client.forwardingHost` (the `X-Target-Host` header) applies to every call, the streaming
ones included (`runTaskStream`, `followOutput`, `streamRun`): the task runs on the target
node and its stream is served from there, and a target the gateway cannot reach rejects
the call with 502 like any other forwarded request. `AppMeshClientTCP` streams over a
direct HTTPS side channel: a forwarded stream on it dials the agent REST listener on the
same host (`agentPort`, default 6060), because the engine listener itself answers a
forwarded stream with 400. An `AppMeshClient` whose base URL points at the engine listener
(default port 6063) therefore cannot forward a stream: the call rejects with a 400 whose
message says so; use the agent REST listener (default port 6060) as the base URL.

#### Browser (VUE Example)

```js
import { AppMeshClient } from "appmesh";
import { Message } from "element-ui";

export class VueAppMeshClient extends AppMeshClient {
  constructor(options = {}) {
    super(options.baseURL, options.sslConfig);
  }

  /**
   * Override error handler
   * @protected
   * @param {Error} error - The caught error
   * @returns {AppMeshError} Standardized AppMeshError
   */
  onError(error) {
    const message = error.message;
    if (message) {
      Message({ message, type: "error", duration: 5 * 1000 });
    }
    return error;
  }
}
```

## Server SDK for Node.js

Server-side SDK for building App Mesh applications in Node.js. This SDK enables your Node.js applications to receive tasks from clients via the App Mesh service and return processed results.

### 📦 Package Structure

The `appmesh` package supports **both browser and Node.js** environments:

- **Client SDK** (`appmesh`) - Works in both browser and Node.js
- **Server SDK** (`appmesh/worker`) - **Node.js only** (not bundled for browser)

This ensures the browser build remains lightweight and doesn't include Node.js-specific server code.

### Features

- ✅ **HTTP Server Support** - Communicate with App Mesh REST service over HTTPS
- ✅ **TCP Server Support** - Use TCP transport for better performance (requires optional dependencies)
- ✅ **SSL/TLS Security** - Full support for client certificates and CA verification
- ✅ **Automatic Retry** - Built-in retry logic for task fetching
- ✅ **Context Manager** - Clean resource management with `withServer` helper
- ✅ **Custom Logging** - Pluggable logger support
- ✅ **Binary & Text Data** - Handle both text and binary payloads
- ✅ **Error Handling** - Comprehensive error handling and reporting
- ✅ **Browser Compatible** - Server SDK doesn't affect browser builds

### Installation

```bash
# Basic installation (HTTP server support only)
npm install appmesh

# For TCP server support, install optional dependencies:
npm install msgpack-lite uuid
```

### Quick Start

#### Basic HTTP Server

```javascript
import { AppMeshWorker, ProcessSupersededError, WorkerRejectedError } from "appmesh/worker";

const server = new AppMeshWorker();

try {
  // Fetch task from client
  const payload = await server.fetchTask();
  console.log("Received:", payload);

  // Process the task
  const result = processData(payload);

  // Return result to client
  await server.sendTaskResult(result);
} catch (error) {
  if (error instanceof ProcessSupersededError || error instanceof WorkerRejectedError) {
    // This process was replaced (412), or its request is permanently invalid (400).
    // Exiting is an app entry-point decision; the SDK only surfaces the error.
    console.error(error.message);
    process.exit(1);
  }
  throw error;
}
```

#### With SSL Configuration

```javascript
import { AppMeshWorker } from "appmesh/worker";
import fs from "fs";

const sslConfig = {
  cert: fs.readFileSync("/opt/appmesh/ssl/client.pem"),
  key: fs.readFileSync("/opt/appmesh/ssl/client-key.pem"),
  ca: fs.readFileSync("/opt/appmesh/ssl/ca.pem"),
  rejectUnauthorized: true,
};

const server = new AppMeshWorker("https://127.0.0.1:6060", sslConfig);
```

#### TCP Server (Better Performance)

**Dependencies:** `npm install msgpack-lite uuid`

```javascript
import { AppMeshWorkerTCP, withServer } from "appmesh/worker";
import fs from "fs";

const sslConfig = {
  ca: fs.readFileSync("/opt/appmesh/ssl/ca.pem"),
  cert: fs.readFileSync("/opt/appmesh/ssl/client.pem"),
  key: fs.readFileSync("/opt/appmesh/ssl/client-key.pem"),
};

// Auto-cleanup with context manager
await withServer(
  () => new AppMeshWorkerTCP(sslConfig, ["127.0.0.1", 6062]),
  async (server) => {
    const payload = await server.fetchTask();
    const result = processPayload(payload);
    await server.sendTaskResult(result);
  }
);
// Connection automatically closed
```

### Environment Variables

The App Mesh service automatically sets these environment variables:

- `APP_MESH_PROCESS_KEY` - Process authentication key
- `APP_MESH_APPLICATION_NAME` - Application name

These are **required** and set automatically by the App Mesh service when running your application.

### API Reference

#### AppMeshWorker

##### Constructor

```javascript
new AppMeshWorker(baseURL, sslConfig, options);
```

**Parameters:**

- `baseURL` (string, optional) - App Mesh service URL. Default: `'https://127.0.0.1:6060'`
- `sslConfig` (object, optional) - SSL configuration. `false` disables verification; `null`/`undefined` verifies against the bundled App Mesh CA or system roots
  - `ca` - CA certificate (Buffer or string path)
  - `cert` - Client certificate (Buffer or string path)
  - `key` - Client private key (Buffer or string path)
  - `rejectUnauthorized` (boolean) - Verify SSL certificate. Default: `true`
- `options` (object, optional)
  - `logger` - Custom logger instance. Default: `console`
  - `client` - Pre-built `AppMeshClient` instance to reuse. When supplied, `baseURL` and `sslConfig` are ignored, and the worker shares the caller's bearer.

##### Methods

###### `fetchTask()`

Fetch task payload from the App Mesh service. Automatically retries transient failures.

**Returns:** `Promise<string|Buffer|null>` - The payload sent by the client, or `null` when the fetch loop is cancelled via `stop()`

**Throws:** `ProcessSupersededError` for HTTP 412, or `WorkerRejectedError` for a permanent HTTP 400. The caller should stop serving; exit at the app entry point if appropriate.

**Example:**

```javascript
const payload = await server.fetchTask();
const data = JSON.parse(payload);
```

###### `sendTaskResult(result)`

Return processed result back to the client.

**Parameters:**

- `result` (string|Buffer) - Result to return to client

**Returns:** `Promise<void>`

**Throws:** Error if return fails

**Example:**

```javascript
const result = { status: "success", data: processedData };
await server.sendTaskResult(JSON.stringify(result));
```

###### `stop()`

Cancel the fetch loop. A running `fetchTask()` call resolves `null`.

```javascript
server.stop();
```

#### AppMeshWorkerTCP

TCP-based server for better performance with large data transfers.

##### Constructor

```javascript
new AppMeshWorkerTCP(sslConfig, tcpAddress, options);
```

**Parameters:**

- `sslConfig` (object, optional) - SSL configuration (same as AppMeshWorker)
- `tcpAddress` (array or object, optional) - `[host, port]` (legacy) or `{host, port}`. Default: `['127.0.0.1', 6062]`. The `{host, port}` object form is also accepted as the first argument: `new AppMeshWorkerTCP({host, port}, sslConfig)`
- `options` (object, optional) - Same as AppMeshWorker

##### Methods

Same as `AppMeshWorker`, plus:

###### `close()`

Close the TCP connection and release resources.

**Example:**

```javascript
const server = new AppMeshWorkerTCP();
try {
  // Use server...
} finally {
  server.close();
}
```

#### Helper Functions

##### `withServer(serverFactory, callback)`

Context manager for automatic resource cleanup.

**Parameters:**

- `serverFactory` (function) - Function that creates a server instance
- `callback` (async function) - Function to execute with the server

**Returns:** `Promise<any>` - Result from callback

**Example:**

```javascript
await withServer(
  () => new AppMeshWorkerTCP(),
  async (server) => {
    const payload = await server.fetchTask();
    await server.sendTaskResult(processData(payload));
  }
);
```

### Usage Examples

#### JSON Processing

```javascript
import { AppMeshWorker } from "appmesh/worker";

const server = new AppMeshWorker();

try {
  const payload = await server.fetchTask();
  const data = JSON.parse(payload);

  // Process JSON data
  const result = {
    status: "success",
    processed: data,
    timestamp: new Date().toISOString(),
  };

  await server.sendTaskResult(JSON.stringify(result));
} catch (error) {
  await server.sendTaskResult(
    JSON.stringify({
      status: "error",
      message: error.message,
    })
  );
}
```

#### Binary Data Processing

```javascript
import { AppMeshWorker } from "appmesh/worker";
import crypto from "crypto";

const server = new AppMeshWorker();

const binaryPayload = await server.fetchTask();
const hash = crypto.createHash("sha256");
hash.update(binaryPayload);

const result = {
  size: binaryPayload.length,
  checksum: hash.digest("hex"),
};

await server.sendTaskResult(JSON.stringify(result));
```

#### Long-Running Task

```javascript
import { AppMeshWorker } from "appmesh/worker";

const server = new AppMeshWorker();

const config = JSON.parse(await server.fetchTask());
const results = [];

for (let i = 0; i < config.steps; i++) {
  // Simulate work
  await new Promise((resolve) => setTimeout(resolve, 1000));
  results.push({ step: i + 1, status: "completed" });
  console.log(`Step ${i + 1}/${config.steps} completed`);
}

await server.sendTaskResult(
  JSON.stringify({
    status: "success",
    results: results,
  })
);
```

### Client-Server Workflow

#### 1. Client Sends Task

```javascript
// Client side
import { AppMeshClient } from "appmesh";

const client = new AppMeshClient();
client.setBearerToken(process.env.APPMESH_BEARER_TOKEN);

const result = await client.runTask(
  "my-app",
  JSON.stringify({
    action: "process",
    data: [1, 2, 3, 4, 5],
  })
);

console.log("Result:", result);
```

#### 2. Server Processes Task

```javascript
// Server side (running as App Mesh application)
import { AppMeshWorker } from "appmesh/worker";

const server = new AppMeshWorker();

const payload = await server.fetchTask();
const request = JSON.parse(payload);

const result = {
  action: request.action,
  sum: request.data.reduce((a, b) => a + b, 0),
};

await server.sendTaskResult(JSON.stringify(result));
```

## Behavioral contract

Cross-SDK client guarantees (event demuxer ordering, `__disconnected__` event, buffering caps, timeout/cleanup policy, and bearer authentication) are defined in [SDKContract.md](https://github.com/laoshanxi/app-mesh/blob/main/docs/source/interfaces/SDKContract.md).
