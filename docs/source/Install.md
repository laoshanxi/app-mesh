# App Mesh Deployment Guide

App Mesh can be deployed in various environments, either as a native systemd-managed service or within a Docker container. This guide provides detailed instructions for setting up App Mesh in several configurations, including standalone deployment, Docker-based deployment, and Docker Compose for multi-component setups.

## Installation Options

### Quick Installation via Docker Container

Deploy the App Mesh daemon as a Docker container with a memory limit:

```shell
docker run -d --memory=8g --restart=always --name=appmesh --net=host -v /var/run/docker.sock:/var/run/docker.sock laoshanxi/appmesh
```

You can override default configurations located at `/opt/appmesh/work/config/config.yaml` by using environment variables. Use the format `APPMESH_${BASE_JSON_KEY}_${SUB_JSON_KEY}_${SUB_JSON_KEY}=NEW_VALUE`. For example, to enable specific cluster configurations for request forwarding, you need set the following environment variables:

- Use `-e APPMESH_REST_JWT_JWTSalt=PRODUCTION_SALT` to specify the JWT salt at the cluster level.
- Use `-e APPMESH_REST_JWT_Issuer=PRODUCTION_SERVICE_NAME` to specify the JWT issuer at the cluster level.
- Use `-e APPMESH_REST_RestListenAddress=0.0.0.0` to enable listening on the LAN.

The `/opt/appmesh/work` directory stores all data. To ensure data persistence, you can mount this directory from the host.

### Native Installation on Linux

App Mesh can be installed as a standalone service on Linux systems. The following steps outline installation on CentOS, Ubuntu, and SUSE systems.

1. Import the GPG Key (if needed for signature verification)

```shell
sudo rpm --import gpg_public.key
sudo dpkg --import gpg_public.key
```

2. Install native package:

```shell
# centos
sudo yum install appmesh_2.1.1_gcc_9_glibc_2.31_x86_64.rpm
# ubuntu
sudo -E apt install appmesh_2.1.1_gcc_7_glibc_2.27_x86_64.deb
# SUSE
sudo zypper install appmesh_2.1.1_gcc_9_glibc_2.31_x86_64.rpm
# macOS
sudo mkdir -p /opt/appmesh
sudo tar zxvf appmesh_2.1.2_clang_15.0.0_macos_14.7.2_arm64.gz -C /opt/appmesh
sudo bash /opt/appmesh/script/setup.sh
# notes: use sudo -E to pass environment variables
```

3. Start and Enable the Service:

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

4. Web UI Deployment: Access the Web UI at https://<hostname>:

```shell
appc logon -u admin -x admin123
appc add -n appweb --perm 11 -e APP_DOCKER_OPTS="--net=host -v /opt/appmesh/ssl/server.pem:/etc/nginx/conf.d/server.crt:ro -v /opt/appmesh/ssl/server-key.pem:/etc/nginx/conf.d/server.key:ro" -d laoshanxi/appmesh-ui:2.1.2 -f
```

### Docker Compose Installation with UI and Consul Service

For a full-featured deployment, including App Mesh, App Mesh UI, and Consul, you can use Docker Compose.

1. Install Docker Compose:

```bash
sudo curl -L "https://github.com/docker/compose/releases/download/v2.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
```

2. Download and Configure Docker Compose File:

- Obtain the [docker-compose.yaml](https://github.com/laoshanxi/app-mesh/raw/main/script/docker-compose.yaml).
- Configure the correct Consul bind IP address and network device name in the file.

3. Start Services:

```bash
mkdir appmesh
cd appmesh
wget -O docker-compose.yaml https://github.com/laoshanxi/app-mesh/raw/main/script/docker-compose.yaml
docker-compose -f docker-compose.yaml up -d
```

4. Verify Running Services:

```bash
docker-compose -f docker-compose.yaml ps
```

By default, App Mesh will connect to Consul via `https://127.0.0.1:443`. App Mesh UI is accessible at `https://<hostname>`, with admin as the username and admin123 as the default password.

### Environment Variables and Additional Notes

- WSL Support: Use service appmesh start on Windows WSL Ubuntu environments.
- Fresh Installation: Set `export APPMESH_FRESH_INSTALL=Y` to enable a fresh installation (avoiding reuse of SSL and config files) and use sudo -E to pass environment variables.
- Secure Installation: Set `export APPMESH_SECURE_INSTALLATION=Y` to generate an initial secure password for the admin user and enable password encryption.
- Custom Installation Path: Set `PROMPT_INSTALL_PATH=1` to specify a custom installation directory interactively during installation. Alternatively, set `PROMPT_INSTALL_PATH=/opt` to specify the installation directory directly without a prompt. After moving the home directory to a new location, you can re-run the script `script/setup.sh` to complete the setup.
- Disable Custom Process User: Set `export APPMESH_BaseConfig_DisableExecUser=true` to disable custom process users.
- Daemon User and Group: Use `APPMESH_DAEMON_EXEC_USER` and `APPMESH_DAEMON_EXEC_USER_GROUP` to specify daemon process user and group.
- Timezone Configuration: Use `APPMESH_BaseConfig_PosixTimezone` (e.g., export APPMESH_BaseConfig_PosixTimezone="+08") for timezone setting.
- Default User: The installation creates an appmesh Linux user for app execution.
- CentOS Dependencies: On CentOS 8, install libnsl with`sudo yum install libnsl`

## Common Use Cases

App Mesh can be utilized in various scenarios, including but not limited to:

- Integrating RPM installation and managing startup behavior.
- Executing remote synchronous/asynchronous shell commands (e.g., via web SSH).
- Monitoring host and application resources.
- Running as a standalone JWT server.
- Functioning as a file server.
- Managing microservices.
- Deploying applications across clusters.
