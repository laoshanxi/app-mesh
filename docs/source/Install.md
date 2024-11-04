# App Mesh Deployment Guide

<div align=center><img src="https://github.com/laoshanxi/app-mesh/raw/main/docs/source/deploy.png"/></div>

App Mesh can be deployed in various environments, either as a native systemd-managed service or within a Docker container. This guide provides detailed instructions for setting up App Mesh in several configurations, including standalone deployment, Docker-based deployment, and Docker Compose for multi-component setups.

## Installation Options

### Quick Installation via Docker Container

Deploy the App Mesh daemon as a Docker container with a memory limit:

```shell
docker run -d --memory=8g --restart=always --name=appmesh --net=host -v /var/run/docker.sock:/var/run/docker.sock laoshanxi/appmesh
```

You can override default configurations using environment variables in the format `APPMESH_${BASE_JSON_KEY}_${SUB_JSON_KEY}=NEW_VALUE`. For example:

- `-e APPMESH_REST_HttpThreadPoolSize=10`
- `-e APPMESH_REST_SSL_VerifyPeer=true`
- `-e APPMESH_SECURE_INSTALLATION=Y`
- `-e APPMESH_REST_RestListenAddress=0.0.0.0`

The `/opt/appmesh/work` directory stores all data. To ensure data persistence, you can mount this directory from the host.

### Native Installation on Linux

App Mesh can be installed as a standalone service on Linux systems. The following steps outline installation on CentOS, Ubuntu, and SUSE systems.

1. Import the GPG Key (if needed for signature verification)

```shell
sudo rpm --import gpg_public.key
sudo dpkg --import gpg_public.key
```

2. Install App Mesh:

```shell
# centos
sudo yum install appmesh_2.1.1_gcc_9_glibc_2.31_x86_64.rpm
# ubuntu (use sudo -E to pass environment variables)
sudo -E apt install appmesh_2.1.1_gcc_7_glibc_2.27_x86_64.deb
# SUSE
sudo zypper install appmesh_2.1.1_gcc_9_glibc_2.31_x86_64.rpm
```

3. Start and Enable the Service:

```shell
sudo systemctl enable appmesh
sudo systemctl start appmesh
sudo systemctl status appmesh
● appmesh.service - App Mesh daemon service
   Loaded: loaded (/etc/systemd/system/appmesh.service; enabled; vendor preset: disabled)
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
- Fresh Installation: Set export APPMESH_FRESH_INSTALL=Y to enable a fresh installation (avoiding reuse of SSL and config files) and use sudo -E to pass environment variables.
- Secure Installation: Set export APPMESH_SECURE_INSTALLATION=Y to generate an initial secure password for the admin user and enable password encryption.
- Disable Custom Process User: Set export APPMESH_BaseConfig_DisableExecUser=true to disable custom process users.
- Daemon User and Group: Use APPMESH_DAEMON_EXEC_USER and APPMESH_DAEMON_EXEC_USER_GROUP to specify daemon process user and group.
- Timezone Configuration: Use APPMESH_PosixTimezone (e.g., export APPMESH_PosixTimezone="+08") for timezone setting.
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
