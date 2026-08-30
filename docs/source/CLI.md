# App Mesh CLI

`appm` manages an App Mesh Engine. All authenticated requests carry a Dex
access token; the CLI never accepts a local username or password.

## Authentication and target addresses

Engine and Dex addresses are independent:

| Setting | Purpose |
| --- | --- |
| `APPMESH_ENGINE_URL` | Engine endpoint selected with `appm -H`, including a local Engine. |
| `APPMESH_DEX_ACCESS_URL` | Optional client-reachable route used for Dex back-channel operations. |

`appm logon` reads the public issuer, audience, client ID, and scopes advertised
by the selected Engine. It uses Authorization Code with PKCE and an RFC 8252
loopback callback by default, or RFC 8628 Device Authorization with `--device`.
The canonical issuer is also the default Dex route. Set
`APPMESH_DEX_ACCESS_URL` or `--dex-access-url` only when this client needs a
different private route to that same issuer.

```bash
appm -H "$APPMESH_ENGINE_URL" logon
# Headless alternative:
appm -H "$APPMESH_ENGINE_URL" logon --device
appm -H "$APPMESH_ENGINE_URL" loginfo
appm -H "$APPMESH_ENGINE_URL" ls
appm -H "$APPMESH_ENGINE_URL" logoff
```

The CLI stores the Dex access/refresh token set and expiry in owner-only local
state bound to the Engine endpoint, issuer, client ID, and audience. The Rust SDK
refreshes directly at Dex and the CLI durably records token rotation. Only the
access token is sent to Engine, and neither token is printed. `logoff` attempts
Dex revocation when advertised and always clears local state; use `--local-only`
to skip the network attempt.

The removed `passwd`, `lock`, `user`, `mfa`, `appmgpwd`, and `appmginit` commands
have no Engine-side replacement.

## Commands

```text
Usage: appm [OPTIONS] <COMMAND>

Commands:
  logon      Sign in to Dex with a browser or device flow
  logoff     Revoke Dex tokens when supported and clear the local session
  loginfo    Show the current Dex session and Engine principal
  add        Register a new application
  rm         Remove an application
  view       List applications
  enable     Enable applications
  disable    Disable applications
  restart    Restart applications
  run        Run a command or application
  exec       Execute a single remote command
  shell      Open an interactive remote shell
  get        Download a remote file
  put        Upload a local file
  label      Manage host labels
  log        Set the Engine log level
  config     View Engine configuration
  resource   Show host resources
  metric     Show Prometheus metrics
  workflow   Manage workflows

Options:
  -H, --host-url <HOST_URL>      Engine host URL
  -F, --forward-to <FORWARD_TO>  Forward an Engine request to a target node
  -v, --verbose                  Enable debug logging
  -h, --help                     Print help
  -V, --version                  Print version
```

Aliases are available for `ls`/`list`, `reg`, `remove`/`unreg`, `logout`, and
`wf`.

## Common operations

```bash
appm -H "$APPMESH_ENGINE_URL" add --app ping --cmd 'ping example.com'
appm -H "$APPMESH_ENGINE_URL" view --app ping --show-output
appm -H "$APPMESH_ENGINE_URL" disable --app ping
appm -H "$APPMESH_ENGINE_URL" enable --app ping
appm -H "$APPMESH_ENGINE_URL" restart --app ping
appm -H "$APPMESH_ENGINE_URL" rm --app ping

appm -H "$APPMESH_ENGINE_URL" run --cmd 'uname -a' --shell
appm -H "$APPMESH_ENGINE_URL" exec -- uname -a
appm -H "$APPMESH_ENGINE_URL" shell

appm -H "$APPMESH_ENGINE_URL" get --remote /opt/appmesh/work/server.log --local ./server.log
appm -H "$APPMESH_ENGINE_URL" put --local ./input.txt --remote /tmp/input.txt
appm -H "$APPMESH_ENGINE_URL" label --view
appm -H "$APPMESH_ENGINE_URL" config
appm -H "$APPMESH_ENGINE_URL" resource
appm -H "$APPMESH_ENGINE_URL" metric

appm -H "$APPMESH_ENGINE_URL" workflow add --file workflow.yaml
appm -H "$APPMESH_ENGINE_URL" workflow list
appm -H "$APPMESH_ENGINE_URL" workflow run example
```

The Engine derives ownership and execution identity from the verified Dex
principal. Workflow commands use the same bearer; no second workflow login is
performed.

See [Security](Security.md) for issuer, access-route, TLS, and local-account details and
[SDK Contract](SDKContract.md) for the Python and Rust OAuth contracts.
