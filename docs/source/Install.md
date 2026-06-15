# App Mesh Deployment Guide

App Mesh supports native systemd-managed service and Docker container deployments. This guide covers installation methods and common configurations.

## Installation Methods

### Docker Container (Quick Start)

Create an App Mesh container, expose the service port `6060`, and enable Docker access inside the container:

```shell
docker run -d -p 6060:6060 --restart=always --name=appmesh --net=host -v /var/run/docker.sock:/var/run/docker.sock laoshanxi/appmesh:latest
```

Configuration:

- Configuration Files Location:
  - Default: `/opt/appmesh/config` (read-only)
  - Override: `/opt/appmesh/work/config/`
  - Files: `config.yaml`, `security.yaml`, `consul.yaml`

- Configuration override by Environment Variables:
  - Override defaults in `config.yaml` & `consul.yaml` using environment variables with the format `APPMESH_${JSON_KEY_LEVEL1}_${JSON_KEY_LEVEL2}_${JSON_KEY_LEVEL3}=NEW_VALUE`. For example, to enable specific cluster configurations for request forwarding:
    - `-e APPMESH_REST_JWT_JWTSalt=PRODUCTION_SALT`: Specify the JWT salt at the cluster level in case of using HS256 sign algorithom (should share jwt-private.pem/jwt-private.pem in case of using RS256).
    - `-e APPMESH_REST_JWT_Issuer=PRODUCTION_SERVICE_NAME`: Specify the JWT issuer at the cluster level.
    - `-e APPMESH_REST_RestListenAddress=0.0.0.0`: Enable listening on the LAN.

- Working data persists in `/opt/appmesh/work` - mount this directory for persistence.

- Security plugin supports `local`/`consul`/`oauth2`, mount `/opt/appmesh/config/security.yaml` to override local security information.

- The remote TLS connection related certification files are located in `/opt/appmesh/ssl`.

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
sudo launchctl load -w /Library/LaunchDaemons/com.appmesh.appmesh.plist

# Stop
sudo launchctl unload /Library/LaunchDaemons/com.appmesh.appmesh.plist

# Uninstall
sudo launchctl unload /Library/LaunchDaemons/com.appmesh.appmesh.plist
sudo rm -rf /opt/appmesh
sudo rm /Library/LaunchDaemons/com.appmesh.appmesh.plist
sudo pkgutil --forget com.laoshanxi.appmesh
```

#### Docker Container

```shell
# Install & Start (see Quick Start above)
docker run -d -p 6060:6060 --restart=always --name=appmesh --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock laoshanxi/appmesh:latest

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

- Web UI Deployment: Access the Web UI at https://{hostname}:

```shell
appm logon -U admin # Input default password: admin123
appm add -n appweb --perm 11 -e APP_DOCKER_OPTS="--net=host -v /opt/appmesh/ssl/server.pem:/etc/nginx/conf.d/server.crt:ro -v /opt/appmesh/ssl/server-key.pem:/etc/nginx/conf.d/server.key:ro" -d laoshanxi/appmesh-ui:2.2.1 -f
```

### Docker Compose Installation with UI and Consul Service

For a full-featured deployment, including App Mesh, App Mesh UI, and Consul, you can use Docker Compose.

- Install Docker Compose:

```bash
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

- Download and Configure Docker Compose File:

- Obtain the [docker-compose.yaml](https://github.com/laoshanxi/app-mesh/raw/main/script/docker-compose.yaml).
- Configure the correct Consul bind IP address and network device name in the file.

- Start Services:

```bash
mkdir appmesh
cd appmesh
wget -O docker-compose.yaml https://github.com/laoshanxi/app-mesh/raw/main/script/docker-compose.yaml
docker-compose -f docker-compose.yaml up -d
```

- Verify Running Services:

```bash
docker-compose -f docker-compose.yaml ps
```

By default, App Mesh will connect to Consul via `https://127.0.0.1:443`. App Mesh UI is accessible at `https://<hostname>`, with admin as the username and admin123 as the default password.

### Environment Variables and Additional Notes

- WSL Support: Use `service appmesh start` on Windows WSL Ubuntu environments.
- Fresh Installation: Set `export APPMESH_FRESH_INSTALL=Y` to enable a fresh installation (avoiding reuse of SSL and config files) and use sudo -E to pass environment variables.
- Secure Installation: Set `export APPMESH_SECURE_INSTALLATION=Y` to generate an initial secure password for the admin user and enable password encryption.
- Custom Installation Path: Set `PROMPT_INSTALL_PATH=1` to specify a custom installation directory interactively during installation. Alternatively, set `PROMPT_INSTALL_PATH=/opt` to specify the installation directory directly without a prompt. After moving the home directory to a new location, you can re-run the script `script/setup.sh` to complete the setup.
- Disable Custom Process User: Set `export APPMESH_BaseConfig_DisableExecUser=true` to disable custom process users.
- Daemon User and Group: Use `APPMESH_DAEMON_EXEC_USER` and `APPMESH_DAEMON_EXEC_USER_GROUP` to specify daemon process user and group.
- Timezone Configuration: Use `APPMESH_BaseConfig_PosixTimezone` (e.g., `export APPMESH_BaseConfig_PosixTimezone="+08"`) for timezone setting.
- Default User: The installation creates an appmesh Linux user for app execution.
- CentOS Dependencies: On CentOS 8, install libnsl with `sudo yum install libnsl`

## Common Use Cases

App Mesh can be utilized in various scenarios, including but not limited to:

- Integrating RPM installation and managing startup behavior.
- Executing remote synchronous/asynchronous shell commands (e.g., via web SSH).
- Monitoring host and application resources.
- Running as a standalone JWT server.
- Functioning as a file server.
- Managing microservices.
- Deploying applications across clusters.

## Reference

- [Security](https://app-mesh.readthedocs.io/en/latest/Security.html)
