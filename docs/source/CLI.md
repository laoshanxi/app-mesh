# App Mesh CLI

Use `appm` to manage an App Mesh Engine. Run `appm logon` before you use a protected command.

## Sign-in methods

The CLI supports three interactive methods.

| Method | Command | Use |
| --- | --- | --- |
| Built-in password | `appm logon` | Use this method for the packaged administrator or viewer. The CLI reads the password from the terminal, or from standard input with `--password-stdin`. |
| Device authorization | `appm logon --device` | Use this method on a headless computer. Complete the approval on a second device. |
| Browser authorization | `appm logon --browser` | Use this method when the authentication service requires a browser. |

The default installation supports the built-in password method. This method does not open a browser. You can supply the non-secret username with `--username`. The CLI reads the password from the terminal prompt. Add `--password-stdin` to read the password from standard input instead. Use this option in a pipeline that has no terminal.

```bash
appm logon --username admin@appmesh.local
appm loginfo
appm ls
appm logoff

# Sign in without a terminal (Docker or CI)
sudo /opt/appmesh/script/appmesh-auth.sh print-initial-password \
  | appm logon --username admin@appmesh.local --password-stdin
```

Use `--auth-access-url` only when the client needs a different network route to the same authentication service. You can also set `APPMESH_AUTH_ACCESS_URL`.

```bash
appm logon --auth-access-url https://auth-route.example.com/auth
```

Use `--auth-allow-http` to allow a plain-HTTP authentication service on a non-loopback host. Use it on trusted networks only. You can also set `APPMESH_AUTH_ALLOW_HTTP`; the value `0`, `false`, or `no` disables it. `--login-timeout` sets the maximum wait for the browser callback. The default is 300 seconds.

The CLI gets the issuer, audience, client ID, scopes, and supported flows from the selected Engine. The CLI sends only the access token to the Engine. It does not send the password or refresh token to the Engine.

## First administrator

A new built-in installation has no active administrator role. Complete one sign-in on the authentication owner host:

```bash
appm logon --username admin@appmesh.local
```

This command assigns the first administrator role when all security checks pass. The assignment is automatic and can occur only once. It does not need a browser, `sudo`, or a second enrollment token.

Do not use `--forward-to` for this one-time assignment. A direct remote connection also cannot complete the assignment. After the local assignment succeeds, normal remote and forwarded sign-in work.

## Remote sign-in

Use `-H` to sign in to an Engine directly:

```bash
appm -H wss://node-a.example.com:6058 logon
appm -H wss://node-a.example.com:6058 ls
```

The session belongs to the selected Engine endpoint. The CLI verifies the authentication configuration before it reuses the session.

## Forwarded sign-in

Use `-F` when one Engine forwards requests to another Engine:

```bash
appm -H wss://gateway.example.com:6058 -F node-b.example.com logon
appm -H wss://gateway.example.com:6058 -F node-b.example.com ls
```

The gateway forwards authentication discovery to the target. The client then gets a token directly from the shared authentication service. The gateway validates the token before it connects to the target. The target Engine validates the token again.

The CLI connects over WSS only. SDK clients can also use HTTP and TCP for forwarded commands. A forwarded event subscription requires TCP or WSS.

The local session belongs to the gateway endpoint. You can use that session with another forwarded target only when the target advertises the same issuer, client ID, and audience. Include `-F` on each command that must run on the target. The CLI does not save a forwarding target as a default.

## Session storage

The CLI stores the token set in an owner-only local file. The session key includes the Engine endpoint, issuer, client ID, and audience. The CLI removes a session when the selected Engine advertises an incompatible authentication configuration.

`appm logoff` tries to revoke the tokens when the authentication service supports revocation. It always removes the local session. Use `--local-only` to skip the network request.

`appm loginfo` shows the Engine endpoint, principal, display name, and token expiry. It does not show provider details or tokens.

For scripts and CI, set the `APPMESH_BEARER_TOKEN` environment variable. The CLI uses this token as-is until it expires. There is no refresh token and no local session. Run `appm logon` for interactive use.

## Commands

```text
App Mesh CLI

Usage: appm [OPTIONS] <COMMAND>

Commands:
  logon     Sign in (built-in password login by default)
  logoff    Revoke tokens when supported and clear the local session
  loginfo   Show the current sign-in session and Engine principal
  add       Register a new application
  rm        Remove an application
  view      List applications
  enable    Enable applications
  disable   Disable applications
  restart   Restart applications (disable then enable)
  run       Run a command or application
  exec      Execute a single remote command
  shell     Interactive remote shell
  get       Download a remote file
  put       Upload a local file
  label     Manage host labels
  log       Set log level
  config    View server configuration
  resource  Show host resources
  metric    Show Prometheus metrics
  workflow  Manage workflows
  help      Print this message or the help of the given subcommand(s)

Options:
  -H, --host-url <HOST_URL>      Server host URL (default: last used or wss://127.0.0.1:6058)
  -F, --forward-to <FORWARD_TO>  Forward request to target host
  -v, --verbose                  Enable debug logging
  -h, --help                     Print help
  -V, --version                  Print version
```

Aliases are available for `ls` or `list`, `reg`, `remove` or `unreg`, `logout`, and `wf`. Within workflows, `ls` is an alias of `list` and `remove` is an alias of `rm`.

## Workflows

```bash
appm workflow add -f pipeline.yaml            # register a workflow from YAML
appm workflow list                            # list registered workflows
appm workflow get pipeline                    # show one definition
appm workflow inputs pipeline                 # show input parameters
appm workflow rm pipeline                     # remove a workflow

appm workflow run pipeline -e env=prod -f     # trigger a run and follow output
appm workflow runs pipeline                   # list run history
appm workflow detail -w pipeline <run-id>     # per-job and per-step status
appm workflow logs -w pipeline <run-id>       # view the run flow log
appm workflow output -w pipeline <run-id> -j build -s compile   # view one step stdout
appm workflow cancel -w pipeline <run-id>     # cancel a running workflow
appm workflow rerun -w pipeline <run-id>      # re-run with the same inputs
```

## Common operations

```bash
appm add --app ping --cmd 'ping example.com'
appm view --app ping --show-output
appm disable --app ping
appm enable --app ping
appm restart --app ping
appm rm --app ping

appm run --cmd 'uname -a' --shell
appm exec -- uname -a
appm shell

appm get --remote /opt/appmesh/work/server.log --local ./server.log
appm put --local ./input.txt --remote /tmp/input.txt
appm resource
appm metric
```

`get` and `put` transfer the file content only. Add `--apply-permissions` to apply the remote POSIX permissions and ownership on download, or to send the local permissions and ownership on upload.

See [Deployment](Install.md) for installation procedures. See [Security](Security.md) for the security model. See [SDK Behavioral Contract](SDKContract.md) for SDK behavior.
