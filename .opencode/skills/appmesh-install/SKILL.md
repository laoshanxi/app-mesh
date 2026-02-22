---
name: appmesh-install
description: Linux package installation guide for appmesh with systemd service management
license: MIT
compatibility: opencode
metadata:
  audience: developers
  platform: linux
---

## Package Installation Guide

### Install Package

#### CentOS/RHEL
```bash
cd build/
sudo yum install appmesh_*.rpm
```

#### Ubuntu/Debian
```bash
cd build/
sudo -E apt install appmesh_*.deb
```

#### SUSE
```bash
cd build/
sudo zypper install appmesh_*.rpm
```

### Service Management

#### Start and Enable Service (systemd)
```bash
# Enable auto-start on boot
sudo systemctl enable appmesh

# Start service
sudo systemctl start appmesh

# Check service status
sudo systemctl status appmesh
```

#### WSL Environment
```bash
service appmesh start
```

### Environment Variables

Environment variables override config.yaml settings, saved in `/opt/appmesh/appmesh.default` using format `APPMESH_<JSON_KEY_LEVEL1>_<JSON_KEY_LEVEL2>_<JSON_KEY_LEVEL3>=VALUE`:

```bash
# Fresh installation (avoid reusing SSL and config files)
export APPMESH_FRESH_INSTALL=Y

# Secure installation (generate initial secure password for admin user)
export APPMESH_SECURE_INSTALLATION=Y

# Custom installation path (interactive)
export PROMPT_INSTALL_PATH=1

# Custom installation path (direct)
export PROMPT_INSTALL_PATH=/opt

# Disable custom process user
export APPMESH_BaseConfig_DisableExecUser=true

# Daemon process user and group
export APPMESH_DAEMON_EXEC_USER=appmesh
export APPMESH_DAEMON_EXEC_USER_GROUP=appmesh

# Timezone configuration
export APPMESH_BaseConfig_PosixTimezone="+08"
```

## Configuration Locations

- Config files: `/opt/appmesh/config` (read-only) or `/opt/appmesh/work/config/`
- Environment overrides: `/opt/appmesh/appmesh.default`
- Configuration files: `config.yaml`, `security.yaml`, `consul.yaml`
- Working data: `/opt/appmesh/work` (mount for persistence)
- SSL certificates: `/opt/appmesh/ssl`

## Service Configuration

### systemd Service File
Location: `/etc/systemd/system/appmesh.service`

Status verification:
```bash
sudo systemctl status appmesh
```

View server logs:
```bash
tail -f /opt/appmesh/work/server.log
```

## Common Use Cases

- RPM installation with startup behavior management
- Remote synchronous/asynchronous shell commands execution
- Host and application resource monitoring
- JWT server functionality
- File server operations
- Microservice management
- Cross-cluster application deployment

## Important Notes

- Use `sudo -E` for installing to pass current environment variables
- Package includes appmesh Linux user creation for app execution
- CentOS 8 requires: `sudo yum install libnsl`