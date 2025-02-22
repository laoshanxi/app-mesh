# AppMesh JavaScript SDK

## Build

```shell
npm run build
```

## Install

```shell
npm i appmesh
```

## Usage

### Node.js

```js
import { AppMeshClient } from 'appmesh'
const client = new AppMeshClient()
const token = await client.login(username, password)
```

### VUE

```js
import { AppMeshClient } from 'appmesh'
import { Message } from 'element-ui'

export class VueAppMeshClient extends AppMeshClient {
  constructor(options = {}) {
    super(options.baseURL, options.sslConfig, options.jwtToken);
  }

  /**
   * Override error handler
   * @protected
   * @param {Error} error - The caught error
   * @returns {AppMeshError} Standardized AppMeshError
   */
  onError(error) {
    let message = error.message;
    if (message) {
      Message({ message, type: 'error', duration: 5 * 1000 });
    }
    return error;
  }
}
```
