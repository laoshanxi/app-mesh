# App Mesh Go SDK

Go client for App Mesh. Package name: `appmesh`.

## Install

The Go SDK is part of the repository's root module. Install the root module:

```shell
go get github.com/laoshanxi/app-mesh@latest
```

The subdirectory `src/sdk/go` is a package inside that module, not a module of its own. `go get github.com/laoshanxi/app-mesh/src/sdk/go@latest` does not work.

Import the package with the full path:

```go
import appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
```

The repository publishes no Go tags, so `@latest` resolves to the latest commit on `main`. The SDK self-reports its version through the `appmesh.SDKVersion` constant.

## Usage

```go
package main

import (
	"fmt"
	"os"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

func main() {
	client, err := appmesh.NewHTTPClient(appmesh.Option{
		AppMeshURI: "https://127.0.0.1:6060",
		JWTToken:   os.Getenv("APPMESH_BEARER_TOKEN"),
	})
	if err != nil {
		panic(err)
	}
	defer client.Close()

	apps, err := client.ListApps()
	if err != nil {
		panic(err)
	}
	for _, app := range apps {
		fmt.Println(app.Name)
	}
}
```

`AppMeshClientTCP` and `AppMeshClientWSS` speak the TCP (port 6062) and WebSocket (port 6063) transports. `NewHTTPClient` accepts one `Option` struct with the endpoint, TLS material, forwarding target, and token provider.

## Test

Run the unit tests:

```shell
go test ./...
```

Live-daemon cases skip without `APPMESH_BEARER_TOKEN` in the environment.
