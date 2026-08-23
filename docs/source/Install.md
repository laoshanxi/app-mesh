# App Mesh Deployment Guide

App Mesh supports native systemd-managed service and Docker container deployments. This guide covers installation methods and common configurations.

Authentication is Dex-only: Dex is the single token issuer and App Mesh is a standard OAuth resource server. Linux and macOS packages bundle Dex and run it as a protected System App, so a default installation is self-contained and needs no external identity service. Windows packages always use an external issuer. For the trust model, cluster topology, external IdP connectors and authorization details, see [Security](Security.md), [ADR 0009](../adr/0009-dex-only-authentication.md) and the [auth design notes](../../auth.md).

## Installation Methods

### Docker Container (Quick Start)

Create an App Mesh container and expose the service port `6060`:

```shell
docker run -d -p 6060:6060 --restart=always --name=appmesh \
  -v appmesh-work:/opt/appmesh/work \
  laoshanxi/appmesh:latest
```

Configuration:

- Configuration Files Location:
  - Default: `/opt/appmesh/config` (read-only)
  - Override: `/opt/appmesh/work/config/`
  - Files: `config.yaml`, `oidc.yaml`, `authorization.yaml` (plus `auth-stack.yaml` and `dex.yaml` where the bundled Dex is packaged)

- Configuration override by Environment Variables:
  - Override defaults in `config.yaml` using environment variables with the format `APPMESH_${YAML_KEY_LEVEL1}_${YAML_KEY_LEVEL2}=NEW_VALUE`. For example:
    - `-e APPMESH_REST_RestListenAddress=0.0.0.0`: Enable listening on the LAN.
  - Authentication mode is selected with `-e APPMESH_AUTH_MODE=builtin|external` (default `builtin`). External mode also requires `-e APPMESH_DEX_ISSUER=<url>`; `APPMESH_DEX_ACCESS_URL`, `APPMESH_DEX_TLS_VERIFY` and `APPMESH_DEX_CA_PATH` cover private routing and TLS.

- Working data persists in `/opt/appmesh/work` - mount this directory for persistence.
  The image runs as UID/GID `482:482`; bind-mounted directories must be writable,
  and mounted or copied files must be readable by this identity. Docker named
  volumes work without additional permission setup.

- To run as root, add `--user 0:0`.

- Docker socket access is disabled by default. Mount `/var/run/docker.sock` and
  grant its group access only when `docker_image` management is required.

- Back up the whole `work` directory. `work/auth` holds the Dex database and the
  `sec_env` master key `work/auth/secrets/secret-master-key`; encrypted
  application definitions in `work/apps` cannot be restored without that key.

- The remote TLS connection related certification files are located in `/opt/appmesh/ssl` for native installations, and in `/opt/appmesh/work/ssl` for the container image.

### Native Installation on Linux / macOS

App Mesh can be installed as a systemd (Linux) or launchd (macOS) managed service. Import the GPG key first if needed for signature verification:

```shell
sudo rpm --import gpg_public.key   # RPM-based
sudo dpkg --import gpg_public.key  # DEB-based
```

#### RPM Package (CentOS / RHEL / SUSE)

```shell
# Install
sudo yum install appmesh_2.2.1_gcc_9_glibc_2.31_x86_64.rpm       # CentOS/RHEL
sudo zypper install appmesh_2.2.1_gcc_9_glibc_2.31_x86_64.rpm    # SUSE

# Start
sudo systemctl enable appmesh
sudo systemctl start appmesh

# Uninstall
sudo systemctl stop appmesh
sudo systemctl disable appmesh
sudo yum remove appmesh        # CentOS/RHEL
sudo zypper remove appmesh     # SUSE
```

#### DEB Package (Ubuntu / Debian)

```shell
# Install (use sudo -E to pass environment variables)
sudo -E apt install ./appmesh_2.2.1_gcc_7_glibc_2.27_x86_64.deb

# Start
sudo systemctl enable appmesh
sudo systemctl start appmesh

# Uninstall
sudo systemctl stop appmesh
sudo systemctl disable appmesh
sudo apt remove appmesh
sudo apt purge appmesh          # also remove config files
```

#### macOS Package (.pkg)

```shell
# Install
sudo installer -pkg appmesh_2.2.1_clang_17_macos_15_arm64.pkg -target /

# Start
sudo launchctl load -w /Library/LaunchDaemons/com.laoshanxi.appmesh.plist

# Stop
sudo launchctl unload /Library/LaunchDaemons/com.laoshanxi.appmesh.plist

# Uninstall
sudo launchctl unload /Library/LaunchDaemons/com.laoshanxi.appmesh.plist
sudo rm -rf /opt/appmesh
sudo rm /Library/LaunchDaemons/com.laoshanxi.appmesh.plist
sudo pkgutil --forget com.laoshanxi.appmesh
```

#### Docker Container

```shell
# Install & Start (see Quick Start above)
docker run -d -p 6060:6060 --restart=always --name=appmesh \
  -v appmesh-work:/opt/appmesh/work laoshanxi/appmesh:latest

# Stop
docker stop appmesh

# Uninstall
docker stop appmesh
docker rm appmesh
docker rmi laoshanxi/appmesh:latest   # optional: remove image
```

#### Verify Installation

```shell
# Check service status
sudo systemctl status appmesh          # Linux
sudo launchctl list | grep appmesh     # macOS
docker ps | grep appmesh               # Docker

# CLI quick test
appm ls
```

#### First Login

The bundled Dex creates two local identities on the first start, each with a random password stored in a mode-0600 file under `/opt/appmesh/work/auth/secrets`:

| Identity | Username | Credential file |
|---|---|---|
| Bootstrap administrator | `admin@appmesh.local` | `work/auth/secrets/dex-initial-admin-credentials` |
| Read-only viewer | `guest@appmesh.local` | `work/auth/secrets/dex-initial-guest-credentials` |

Read the `password=` line as root and enter it only on the Dex login page - App Mesh itself never accepts a password. The administrator holds no App Mesh role until it is enrolled once, locally on the Engine host:

```shell
sudo /opt/appmesh/bin/appm logon --enroll-first-admin
sudo /opt/appmesh/bin/appm logon --device --enroll-first-admin   # headless host
```

Afterwards, ordinary `appm logon` (browser or `--device`) is enough. Once enrolled, remove the recoverable plaintext - the bcrypt login keeps working - and rotate the password later when needed:

```shell
sudo /opt/appmesh/script/appmesh-auth.sh forget-initial-password
sudo /opt/appmesh/script/appmesh-auth.sh rotate-initial-password
sudo systemctl restart appmesh   # reload the rotated hash
```

To use an operator-managed Dex instead of the bundled one, select external mode at install time (`APPMESH_AUTH_MODE=external` plus `APPMESH_DEX_ISSUER=<url>`) or re-run setup afterwards:

```shell
sudo /opt/appmesh/script/setup.sh --auth-mode external --oidc-issuer https://auth.example.com/dex
```

`--oidc-access-url`, `--oidc-tls-verify`, `--oidc-ca-path` and `--clear-oidc-ca` configure a private discovery route and its TLS trust. External mode has no bootstrap credentials and no first-admin enrollment: provision the initial Principal binding in `work/config/authorization.yaml` as described in [Security](Security.md).

- Web UI Deployment: after logging on, deploy the UI and access it at https://{hostname}:

```shell
appm add -a appweb -p 11 -e APP_DOCKER_OPTS="--net=host -v /opt/appmesh/ssl/server.pem:/etc/nginx/conf.d/server.crt:ro -v /opt/appmesh/ssl/server-key.pem:/etc/nginx/conf.d/server.key:ro" -I laoshanxi/appmesh-ui:2.2.1 -f
```

### Windows

The NSIS installer `appmesh_<version>_windows_x64.exe` installs into `C:\local\appmesh` by default and registers the `AppMeshService` Windows service through the bundled `nssm.exe`. Use `/S` for a silent install; uninstall through *Add/Remove Programs* or `Uninstall.exe`, where `/PURGE` also removes the CLI session data under `%APPDATA%\AppMesh` and `%LOCALAPPDATA%\AppMesh`.

Windows packages contain no bundled Dex and always use an external issuer. Point the Engine at it after installing:

```powershell
powershell -ExecutionPolicy Bypass -File C:\local\appmesh\script\setup.ps1 `
  -Issuer https://auth.example.com/dex
```

`-AccessUrl`, `-TlsVerify`, `-CaPath`, `-ClearCa` and `-NoRestart` are accepted as well; the values are written to the operator override `work\config\oidc.yaml`. First-administrator enrollment is unavailable on Windows - provision the initial Principal binding in `work\config\authorization.yaml`; see [Security](Security.md).

### Docker Compose Installation with UI

For a full-featured deployment, including App Mesh and App Mesh UI, you can use Docker Compose.

- Install Docker Compose:

```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

- Download the [docker-compose.yaml](https://github.com/laoshanxi/app-mesh/raw/main/script/docker/docker-compose.yaml) and start the services:

```bash
mkdir appmesh
cd appmesh
wget -O docker-compose.yaml https://github.com/laoshanxi/app-mesh/raw/main/script/docker/docker-compose.yaml
docker-compose -f docker-compose.yaml up -d
```

- Verify Running Services:

```bash
docker-compose -f docker-compose.yaml ps
```

App Mesh UI is accessible at `https://<hostname>`; sign in with the bootstrap administrator described in [First Login](#first-login).

### Environment Variables and Additional Notes

- WSL Support: Use `service appmesh start` on Windows WSL Ubuntu environments.
- Fresh Installation: Set `export APPMESH_FRESH_INSTALL=Y` to enable a fresh installation (avoiding reuse of SSL and config files) and use sudo -E to pass environment variables. This also removes existing runtime state including `work/auth`, so back up that directory first.
- Authentication Mode: `APPMESH_AUTH_MODE=builtin|external` and `APPMESH_DEX_ISSUER` / `APPMESH_DEX_ACCESS_URL` / `APPMESH_DEX_TLS_VERIFY` / `APPMESH_DEX_CA_PATH` can be passed at package installation time; setup persists the selection and preserves it across upgrades.
- Custom Installation Path: Set `PROMPT_INSTALL_PATH=1` to specify a custom installation directory interactively during installation. Alternatively, set `PROMPT_INSTALL_PATH=/opt` to specify the installation directory directly without a prompt. After moving the home directory to a new location, you can re-run the script `script/pack/setup.sh` to complete the setup.
- Disable Custom Process User: Set `export APPMESH_BaseConfig_DisableExecUser=true` to disable custom process users. The Docker image sets this environment variable by default.
- Daemon User and Group: Use `APPMESH_DAEMON_EXEC_USER` and `APPMESH_DAEMON_EXEC_USER_GROUP` to specify daemon process user and group.
- Timezone Configuration: Use `APPMESH_BaseConfig_PosixTimezone` (e.g., `export APPMESH_BaseConfig_PosixTimezone="+08"`) for timezone setting.
- Default User: The installation creates an appmesh Linux user for app execution.
- CentOS Dependencies: On CentOS 8, install libnsl with `sudo yum install libnsl`

## Common Use Cases

App Mesh can be utilized in various scenarios, including but not limited to:

- Integrating RPM installation and managing startup behavior.
- Executing remote synchronous/asynchronous shell commands (e.g., via web SSH).
- Monitoring host and application resources.
- Functioning as a file server.
- Managing microservices.
- Deploying applications across clusters.

## Reference

- [Security](https://app-mesh.readthedocs.io/en/latest/Security.html)
- [ADR 0009: Dex-only authentication](../adr/0009-dex-only-authentication.md)
