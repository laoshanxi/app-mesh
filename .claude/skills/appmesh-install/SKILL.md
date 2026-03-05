---
name: appmesh-install
description: Installation guide for App Mesh — package, Docker, and systemd
---

## Package Installation

```bash
# Ubuntu/Debian
sudo -E apt install appmesh_*.deb

# CentOS/RHEL (CentOS 8: also install libnsl)
sudo yum install appmesh_*.rpm

# SUSE
sudo zypper install appmesh_*.rpm
```

Use `sudo -E` to pass environment variables during install.

## Docker

```bash
# Basic
docker run -d --name appmesh laoshanxi/appmesh

# With root (for pip/apt inside container)
docker run -d --name appmesh -e APPMESH_RUN_AS_ROOT=true laoshanxi/appmesh

# Production: persistent data + Docker-in-Docker
docker run -d --name appmesh \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v appmesh-work:/opt/appmesh/work \
  -p 6060:6060 \
  laoshanxi/appmesh
```

## Systemd

```bash
sudo systemctl enable appmesh   # auto-start on boot
sudo systemctl start appmesh
sudo systemctl status appmesh
service appmesh start           # WSL
```

## Install-Time Environment Variables

Override config at install time. Saved in `/opt/appmesh/appmesh.default`.

```bash
APPMESH_FRESH_INSTALL=Y              # ignore existing SSL/config
APPMESH_SECURE_INSTALLATION=Y        # generate secure admin password
PROMPT_INSTALL_PATH=/opt              # custom install path
APPMESH_DAEMON_EXEC_USER=appmesh     # daemon process user
APPMESH_BaseConfig_PosixTimezone="+08"
APPMESH_REST_RestListenPort=6060
```

Runtime config overrides use the same `APPMESH_<Section>_<Key>=VALUE` format.

## Key Paths

| Path | Description |
|------|-------------|
| `/opt/appmesh/config/` | Read-only config (config.yaml, security.yaml) |
| `/opt/appmesh/work/config/` | Writable config overrides |
| `/opt/appmesh/work/` | Working data (mount for persistence) |
| `/opt/appmesh/ssl/` | SSL certificates |

## Verification

```bash
sudo systemctl status appmesh
appc logon -U admin
appc ls
```
