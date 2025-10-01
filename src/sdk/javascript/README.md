# App Mesh JavaScript SDK

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
await client.login("username", "password");
```

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
- **Server SDK** (`appmesh/server`) - **Node.js only** (not bundled for browser)

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
import { AppMeshServer } from "appmesh/server";

const server = new AppMeshServer();

// Fetch task from client
const payload = await server.task_fetch();
console.log("Received:", payload);

// Process the task
const result = processData(payload);

// Return result to client
await server.task_return(result);
```

#### With SSL Configuration

```javascript
import { AppMeshServer } from "appmesh/server";
import fs from "fs";

const sslConfig = {
  cert: fs.readFileSync("/opt/appmesh/ssl/client.pem"),
  key: fs.readFileSync("/opt/appmesh/ssl/client-key.pem"),
  ca: fs.readFileSync("/opt/appmesh/ssl/ca.pem"),
  rejectUnauthorized: true,
};

const server = new AppMeshServer("https://127.0.0.1:6060", sslConfig);
```

#### TCP Server (Better Performance)

**Dependencies:** `npm install msgpack-lite uuid`

```javascript
import { AppMeshServerTCP, withServer } from "appmesh/server";
import fs from "fs";

const sslConfig = {
  ca: fs.readFileSync("/opt/appmesh/ssl/ca.pem"),
  cert: fs.readFileSync("/opt/appmesh/ssl/client.pem"),
  key: fs.readFileSync("/opt/appmesh/ssl/client-key.pem"),
};

// Auto-cleanup with context manager
await withServer(
  () => new AppMeshServerTCP(sslConfig, ["127.0.0.1", 6059]),
  async (server) => {
    const payload = await server.task_fetch();
    const result = processPayload(payload);
    await server.task_return(result);
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

#### AppMeshServer

##### Constructor

```javascript
new AppMeshServer(baseURL, sslConfig, options);
```

**Parameters:**

- `baseURL` (string, optional) - App Mesh service URL. Default: `'https://127.0.0.1:6060'`
- `sslConfig` (object, optional) - SSL configuration
  - `ca` - CA certificate (Buffer or string path)
  - `cert` - Client certificate (Buffer or string path)
  - `key` - Client private key (Buffer or string path)
  - `rejectUnauthorized` (boolean) - Verify SSL certificate. Default: `true`
- `options` (object, optional)
  - `logger` - Custom logger instance. Default: `console`

##### Methods

###### `task_fetch()`

Fetch task payload from the App Mesh service. Automatically retries on failure.

**Returns:** `Promise<string|Buffer>` - The payload sent by the client

**Example:**

```javascript
const payload = await server.task_fetch();
const data = JSON.parse(payload);
```

###### `task_return(result)`

Return processed result back to the client.

**Parameters:**

- `result` (string|Buffer) - Result to return to client

**Returns:** `Promise<void>`

**Throws:** Error if return fails

**Example:**

```javascript
const result = { status: "success", data: processedData };
await server.task_return(JSON.stringify(result));
```

#### AppMeshServerTCP

TCP-based server for better performance with large data transfers.

##### Constructor

```javascript
new AppMeshServerTCP(sslConfig, tcpAddress, options);
```

**Parameters:**

- `sslConfig` (object, optional) - SSL configuration (same as AppMeshServer)
- `tcpAddress` (array, optional) - `[host, port]`. Default: `['127.0.0.1', 6059]`
- `options` (object, optional) - Same as AppMeshServer

##### Methods

Same as `AppMeshServer`, plus:

###### `close()`

Close the TCP connection and release resources.

**Example:**

```javascript
const server = new AppMeshServerTCP();
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
  () => new AppMeshServerTCP(),
  async (server) => {
    const payload = await server.task_fetch();
    await server.task_return(processData(payload));
  }
);
```

### Usage Examples

#### JSON Processing

```javascript
import { AppMeshServer } from "appmesh/server";

const server = new AppMeshServer();

try {
  const payload = await server.task_fetch();
  const data = JSON.parse(payload);

  // Process JSON data
  const result = {
    status: "success",
    processed: data,
    timestamp: new Date().toISOString(),
  };

  await server.task_return(JSON.stringify(result));
} catch (error) {
  await server.task_return(
    JSON.stringify({
      status: "error",
      message: error.message,
    })
  );
}
```

#### Binary Data Processing

```javascript
import { AppMeshServer } from "appmesh/server";
import crypto from "crypto";

const server = new AppMeshServer();

const binaryPayload = await server.task_fetch();
const hash = crypto.createHash("sha256");
hash.update(binaryPayload);

const result = {
  size: binaryPayload.length,
  checksum: hash.digest("hex"),
};

await server.task_return(JSON.stringify(result));
```

#### Long-Running Task

```javascript
import { AppMeshServer } from "appmesh/server";

const server = new AppMeshServer();

const config = JSON.parse(await server.task_fetch());
const results = [];

for (let i = 0; i < config.steps; i++) {
  // Simulate work
  await new Promise((resolve) => setTimeout(resolve, 1000));
  results.push({ step: i + 1, status: "completed" });
  console.log(`Step ${i + 1}/${config.steps} completed`);
}

await server.task_return(
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
await client.login("username", "password");

const result = await client.run_task(
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
import { AppMeshServer } from "appmesh/server";

const server = new AppMeshServer();

const payload = await server.task_fetch();
const request = JSON.parse(payload);

const result = {
  action: request.action,
  sum: request.data.reduce((a, b) => a + b, 0),
};

await server.task_return(JSON.stringify(result));
```
