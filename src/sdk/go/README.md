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

## Run synchronously

`RunAppSync(app, maxTime, lifecycle)` returns `(exitCode, stdout, err)` and `RunAppSyncChecked` additionally reports whether the exit code came from the daemon. The daemon answers one page of at most 5 MiB per request; when the output fills the page the client reads the remaining pages of the run and removes it, so `stdout` is complete on every transport. `RunAppSyncWithContext` and `RunAppSyncCheckedContext` take a `context.Context` and `SyncRunOptions`:

```go
exit, out, err := client.RunAppSyncWithContext(ctx, app, 3600, 3660,
    appmesh.SyncRunOptions{MaxOutputBytes: 64 * 1024 * 1024})
```

`MaxOutputBytes <= 0` (the default) is unlimited. When the collected output exceeds the ceiling the call returns an error instead of a truncated result and leaves the run on the daemon, where the rest stays readable for 600 seconds through `GetAppOutput`.

`AppMeshClientTCP` and `AppMeshClientWSS` speak the TCP (port 6062) and WebSocket (port 6063) transports. `NewHTTPClient` accepts one `Option` struct with the endpoint, TLS material, forwarding target, and token provider.

`Option.ForwardTo` (the `X-Target-Host` header) applies to every call on every transport, including the streaming ones (`RunTaskStream`, `FollowOutput`, `StreamRun`): the task runs on the target node and its stream is served from there, and a target the gateway cannot reach fails with 502 like any other forwarded request. The TCP and WSS transports stream over a direct HTTPS side channel; a forwarded stream on them dials the agent REST listener on the same host (`Option.AgentPort`, default 6060), because the engine listener itself answers a forwarded stream with 400. An HTTP client whose `AppMeshURI` points at the engine listener (default port 6063) therefore cannot forward a stream: the call fails with a 400 whose message says so; use the agent REST listener (default port 6060) as `AppMeshURI` for forwarded streams.

## Test

Run the unit tests:

```shell
go test ./...
```

Live-daemon cases skip without `APPMESH_BEARER_TOKEN` in the environment.
