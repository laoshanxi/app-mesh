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
  - Default: `/opt/appmesh/` (read-only)
  - Override: `/opt/appmesh/work/config/`
  - Files: `config.yaml`, `security.yaml`, `consul.yaml`

- Configuration override by Environment Variables:
  - Override defaults in `config.yaml` & `consul.yaml` using environment variables with the format `APPMESH_${JSON_KEY_LEVEL1}_${JSON_KEY_LEVEL2}_${JSON_KEY_LEVEL3}=NEW_VALUE`. For example, to enable specific cluster configurations for request forwarding:
    - `-e APPMESH_REST_JWT_JWTSalt=PRODUCTION_SALT`: Specify the JWT salt at the cluster level in case of using HS256 sign algorithom (should share jwt-private.pem/jwt-private.pem in case of using RS256).
    - `-e APPMESH_REST_JWT_Issuer=PRODUCTION_SERVICE_NAME`: Specify the JWT issuer at the cluster level.
    - `-e APPMESH_REST_RestListenAddress=0.0.0.0`: Enable listening on the LAN.

- Working data persists in `/opt/appmesh/work` - mount this directory for persistence.

- Security plugin supports `local`/`consul`/`ldap`/`oauth2`, mount `/opt/appmesh/security.yaml` to override local security information.

- The remote TLS connection related certification files are located in `/opt/appmesh/ssl`.

### Native Installation on Linux

App Mesh can be installed as a systemd service on Linux systems. The following steps outline installation on macOS, CentOS, Ubuntu, and SUSE systems.

- Import the GPG Key (if needed for signature verification)

```shell
sudo rpm --import gpg_public.key
sudo dpkg --import gpg_public.key
```

- Install native package:

```shell
# centos
sudo yum install appmesh_2.1.1_gcc_9_glibc_2.31_x86_64.rpm
# ubuntu
sudo -E apt install appmesh_2.1.1_gcc_7_glibc_2.27_x86_64.deb
# SUSE
sudo zypper install appmesh_2.1.1_gcc_9_glibc_2.31_x86_64.rpm
# macOS
sudo installer -pkg appmesh_2.1.2_clang_16_macos_15_arm64.pkg -target /
# Note: use sudo -E to pass current environment variables
```

- Start and Enable the Service:

```shell
# Linux
sudo systemctl enable appmesh
sudo systemctl start appmesh
sudo systemctl status appmesh
● appmesh.service - App Mesh daemon service
   Loaded: loaded (/etc/systemd/system/appmesh.service; enabled; vendor preset: disabled)

# macOS
sudo launchctl load -w /Library/LaunchDaemons/com.appmesh.appmesh.plist
```

- Web UI Deployment: Access the Web UI at https://{hostname}:

```shell
appc logon -U admin # Input default password: admin123
appc add -n appweb --perm 11 -e APP_DOCKER_OPTS="--net=host -v /opt/appmesh/ssl/server.pem:/etc/nginx/conf.d/server.crt:ro -v /opt/appmesh/ssl/server-key.pem:/etc/nginx/conf.d/server.key:ro" -d laoshanxi/appmesh-ui:2.1.2 -f
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
- CORS Configuration: Set `APPMESH_CORS_DISABLE=true` to disable Cross-Origin Resource Sharing for the agent listen service.
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
