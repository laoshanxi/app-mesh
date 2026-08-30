# App Mesh deployment

App Mesh supports native packages and containers. The default package includes an authentication service. You do not need an external identity system for the first start.

Use [CLI](CLI.md) for all sign-in methods and forwarding commands. Use [Security](Security.md) for the security model.

## Container installation

Run this command:

```shell
docker run -d -p 6060:6060 --restart=always --name appmesh \
  -v appmesh-work:/opt/appmesh/work \
  laoshanxi/appmesh:latest
```

The image runs as UID and GID `482`. A bind-mounted work directory must be writable by this identity. A named volume needs no additional permission setup.

Persist `/opt/appmesh/work`. Back up this directory as one unit. It contains authentication state, authorization data, application definitions, and the master key for secured environment values.

Mount `/var/run/docker.sock` only when App Mesh must manage Docker images. Grant the minimum required group access.

## Linux installation

### RPM

```shell
sudo rpm --import gpg_public.key
sudo yum install appmesh_3.0.0_gcc_9_glibc_2.31_x86_64.rpm
sudo systemctl enable --now appmesh
```

The RPM is signed. Use `zypper` instead of `yum` on SUSE.

### DEB

```shell
sudo -E apt install ./appmesh_3.0.0_gcc_7_glibc_2.27_x86_64.deb
sudo systemctl enable --now appmesh
```

The DEB is not signed. Verify it with the release checksums:

```shell
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c --ignore-missing SHA256SUMS
```

## macOS installation

```shell
sudo installer -pkg appmesh_3.0.0_clang_17_macos_15_arm64.pkg -target / -dumplog
sudo launchctl load -w /Library/LaunchDaemons/com.laoshanxi.appmesh.plist
```

## Windows installation

Run `appmesh_<version>_windows_x64.exe`. The default directory is `C:\local\appmesh`. The installer registers `AppMeshService`.

Use `/S` for a silent installation. Use Add or Remove Programs to uninstall App Mesh. Use `Uninstall.exe /PURGE` only when you also want to remove local CLI session data.

## Verify the installation

```shell
appm -V
```

On Linux, also check the service:

```shell
sudo systemctl status appmesh
```

## First sign-in

The first start creates two built-in identities.

| Identity | Username | Credential file |
| --- | --- | --- |
| Packaged administrator | `admin@appmesh.local` | `work/auth/secrets/initial-admin-credentials` |
| Read-only viewer | `guest@appmesh.local` | `work/auth/secrets/initial-viewer-credentials` |

The credential file is owner-only. Read its `password=` value on the authentication owner host, or print it with `sudo /opt/appmesh/script/appmesh-auth.sh print-initial-password`. Enter the value at the masked terminal prompt.

Run this command on the authentication owner host:

```shell
appm logon --username admin@appmesh.local
```

The command uses the built-in password method. It does not open a browser. The CLI assigns the first administrator role when the one-time checks pass.

After the assignment, remote and forwarded sign-in work. See [CLI](CLI.md#remote-sign-in) for the command forms.

You can remove the recoverable plaintext after you confirm sign-in:

```shell
sudo /opt/appmesh/script/appmesh-auth.sh forget-initial-password
```

This action does not remove the password hash. Use this command to create a replacement password:

```shell
sudo /opt/appmesh/script/appmesh-auth.sh rotate-initial-password
sudo systemctl restart appmesh
```

## Cluster authentication service

A cluster runs the bundled authentication service on one node and joins the
other nodes to it. The owner runs Dex and holds the identity state. A follower
runs no authentication service, creates no built-in credentials, and verifies
tokens against the owner's issuer.

Set the owner node:

```shell
sudo /opt/appmesh/script/setup.sh \
  --auth-mode builtin \
  --auth-role owner \
  --oidc-issuer https://owner.example.com:6060/auth
```

Join a follower node. The issuer must be the same string on every node;
`--oidc-access-url` defaults to the issuer:

```shell
sudo /opt/appmesh/script/setup.sh \
  --auth-mode builtin \
  --auth-role follower \
  --oidc-issuer https://owner.example.com:6060/auth
```

`--auth-role` accepts `standalone` (packaged default), `owner`, and
`follower`. A follower without an issuer is a setup error. A role selection
from a previous builtin installation is removed automatically when you switch
to external mode.

Package installation runs the same setup with the administrator environment.
A node can therefore join during `dpkg`/`rpm` installation:

```shell
sudo APPMESH_AUTH_ROLE=follower \
     APPMESH_AUTH_ISSUER=https://owner.example.com:6060/auth \
     dpkg -i appmesh_*.deb
```

See [Security](Security.md) for the forwarding authentication model and the
authorization-data consistency rule. A worked multi-node example is
`script/docker/docker-compose.yaml`.

## External authentication service

Use external mode when an operator manages the OpenID Connect issuer.

```shell
sudo /opt/appmesh/script/setup.sh \
  --auth-mode external \
  --oidc-issuer https://auth.example.com/oidc
```

Use these options when required:

- `--oidc-access-url` sets a private discovery and signing-key route.
- `--oidc-tls-verify` enables or disables TLS verification.
- `--oidc-ca-path` sets a private CA file or directory.
- `--clear-oidc-ca` removes the configured private CA path.

External mode does not create built-in identities. Provision the first principal and role binding in `work/config/authorization.yaml` before you use protected operations.

On Windows, use:

```powershell
powershell -ExecutionPolicy Bypass -File C:\local\appmesh\script\setup.ps1 `
  -Issuer https://auth.example.com/oidc
```

The Windows script also accepts `-AccessUrl`, `-TlsVerify`, `-CaPath`, `-ClearCa`, and `-NoRestart`.

## Configuration

The package installs read-only defaults in `/opt/appmesh/config`. Put operator overrides in `/opt/appmesh/work/config`.

The main files are:

- `config.yaml` for Engine and transport settings;
- `oidc.yaml` for issuer and access-route settings;
- `authorization.yaml` for principals, roles, and bindings;
- `auth-stack.yaml` for built-in service ownership and ports.

Use these environment variables for non-interactive authentication setup:

```text
APPMESH_AUTH_MODE
APPMESH_AUTH_ROLE
APPMESH_AUTH_ISSUER
APPMESH_AUTH_ACCESS_URL
APPMESH_AUTH_TLS_VERIFY
APPMESH_AUTH_CA_PATH
```

The setup interface does not accept a user password or client secret.

## Upgrade and reset

An ordinary upgrade preserves `work/auth`. Existing sessions remain usable while their tokens and issuer state remain valid.

Set `APPMESH_FRESH_INSTALL=Y` only when you want new runtime state. This action removes existing authentication state. Back up the work directory before you use it. Users must sign in again after the reset.

## Uninstall

### Linux

```shell
sudo systemctl disable --now appmesh
sudo yum remove appmesh
```

Use `apt remove appmesh` on a DEB system. Use `apt purge appmesh` only when you also want to remove package configuration.

### macOS

```shell
sudo launchctl unload -w /Library/LaunchDaemons/com.laoshanxi.appmesh.plist
sudo pkgutil --forget com.laoshanxi.appmesh
```

Remove `/opt/appmesh` only when you do not need its persisted state.

### Container

```shell
docker stop appmesh
docker rm appmesh
```

Delete the volume only when you do not need the persisted state.
