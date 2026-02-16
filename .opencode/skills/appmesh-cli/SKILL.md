---
name: appmesh-cli
description: Complete CLI reference guide for appmesh using appc command
license: MIT
compatibility: opencode
metadata:
  audience: developers
  platform: linux
---

## CLI Overview

The `appc` command provides a CLI to interact with App Mesh daemon:

```bash
# View all commands
appc --help

# Remote connection (default: https://127.0.0.1:6060)
appc -H https://192.168.1.100:6060 [command]
```

## Authentication Commands

### Logon to App Mesh
```bash
# Basic login (interactive password)
appc logon -U admin

# Specify session duration (default: 7 days)
appc logon -U admin -t PT1D  # 1 day
appc logon -U admin -t 86400  # 86400 seconds

# Show authentication token
appc logon -U admin --show-token

# With custom audience
appc logon -U admin -a appmesh-service
```

### Session Management
```bash
# View current user
appc loginfo

# Logout
appc logoff

# Change password
appc passwd -U admin

# Lock/unlock user
appc lock -U admin --lock true
appc lock -U admin --lock false

# View user information
appc user -U admin

# Manage two-factor authentication
appc mfa -U admin
```

## Application Management

### View Applications
```bash
# List all applications
appc ls

# List with detailed information
appc ls -l

# View application output
appc ls -a appname -o

# Follow output in real-time
appc ls -a appname -o -f

# View process tree
appc ls -P

# JSON format output
appc ls -j
```

### Add Application
```bash
# Basic application
appc add -a myapp -c "/usr/bin/python script.py" -w /path/to/work

# Docker container
appc add -a myapp -d laoshanxi/appmesh-ui:2.2.1 \
  -e "APP_DOCKER_OPTS=--net=host -p 8080:8080"

# Cron scheduler
appc add -a myapp -c "/usr/bin/python script.py" -Ycron -i "*/5 * * * * *"

# Resource limits
appc add -a myapp -c "/usr/bin/python script.py" -M 512 -C 1024

# Permission control
appc add -a myapp -c "/usr/bin/python script.py" -p 23

# Environment variables
appc add -a myapp -c "/usr/bin/python script.py" \
  -e "ENV1=value1" -e "ENV2=value2"

# Health check
appc add -a myapp -c "/usr/bin/python script.py" -H "/usr/bin/curl http://localhost:8080"

# Exit behavior
appc add -a myapp -c "/usr/bin/python script.py" -Q standby
```

### Application Control
```bash
# Enable application
appc enable -a myapp

# Disable application
appc disable -a myapp

# Restart application
appc restart -a myapp

# Remove application
appc rm -a myapp
```

## Execution Commands

### Run Commands
```bash
# Execute command and retrieve output
appc run -a myapp "ls -la"

# Execute with shell context
appc shell -a myapp "ps aux"
```

## System Management

### Resources
```bash
# Show host resources
appc resource
```

### Labels
```bash
# View labels
appc label

# Add labels or use specific command for management
appc label -l key=value
```

### Configurations
```bash
# View configurations
appc config -a CONFIG_NAME

# Set log level
appc log
```

### Logs
```bash
# Set log level (debug, info, warn, error)
appc log -l debug
appc log -l info
```

## File Operations

### Download Files
```bash
appc get -a myapp -s /remote/path -d /local/path
```

### Upload Files
```bash
appc put -a myapp -s /local/path -d /remote/path
```

## Command Options Reference

### Connection Options
```
-H, --host-url      Server URL [default: https://127.0.0.1:6060]
-F, --forward-to    Forward requests to target host[:port]
-U, --user          User name
-X, --password      User password
```

### General Options
```
-v, --verbose       Enable verbose output
-h, --help          Display command usage and exit
-f, --force         Skip confirmation prompts
```

### Application Add Options
```
Basic:
  -a, --app              Application name (required)
  -c, --cmd              Command line with arguments (required)
  -w, --working-dir      Working directory path
  -d, --description      Application description
  -s, --status           Initial status [true|false] (default: true)

Runtime:
  -u, --shell            Enable shell mode
  -G, --session-login    Execute with session login context
  -H, --health-check     Health check command
  -I, --docker-image     Docker image
  -P, --pid              Attach to existing process ID

Schedule:
  -b, --begin-time       Start time (ISO8601)
  -x, --end-time         End time (ISO8601)
  -S, --daily-begin      Daily start time
  -E, --daily-end        Daily end time
  -i, --interval         Start interval
  -Y, --cron             Use cron expression

Resource Limits:
  -M, --memory-limit     Memory limit (MB)
  -V, --virtual-memory   Virtual memory limit (MB)
  -C, --cpu-shares       CPU shares
  -N, --log-cache-size   Number of stdout cache files (default: 3)

Advanced:
  -p, --permission       Permission bits (23=read/write, all bits)
  -m, --metadata         Metadata string/JSON
  -e, --env              Environment variables
  -z, --security-env     Encrypted environment variables
  -R, --stop-timeout     Process stop timeout
  -Q, --exit             Exit behavior [restart|standby|keepalive|remove]
  -T, --control          Exit code behaviors CODE:ACTION
  -D, --stdin            Read YAML from stdin or file
```

## Usage Patterns

### Interactive Session
```bash
# Login and work interactively
appc logon -U admin
appc ls
appc add -a test -c "sleep 300"
appc ls -a test -o -f
```

### Script Automation
```bash
# Non-interactive login for scripts
export APPC_TOKEN=$(appc logon -U admin -X 'password' --show-token --timeout PT1H)
appc -H https://server:6060 add -a myscript -c "./run.sh"
```

### Batch Operations
```bash
# Disable all applications
for app in $(appc ls -j | jq -r '.[].name'); do
  appc disable -a $app
done
```

### Docker Application Deployment
```bash
# Web UI with SSL
appc add -n appweb --perm 11 \
  -e "APP_DOCKER_OPTS=--net=host -v /opt/appmesh/ssl/server.pem:/etc/nginx/conf.d/server.crt:ro" \
  -d laoshanxi/appmesh-ui:2.2.1 \
  -f
```

## Common Tasks

### Create Docker Container App
```bash
appc add -a webserver \
  -I nginx:latest \
  -e "APP_DOCKER_OPTS=-p 80:80 -v /data:/usr/share/nginx/html" \
  -s true
```

### Create Scheduled Job
```bash
# Run every 5 minutes
appc add -a backup -c "/usr/bin/rsync -avz /data /backup" \
  -Y cron -i "*/5 * * * * *"

# Daily at 2AM
appc add -a nightly_job -c "/usr/bin/python /scripts/setup.py" \
  -S "02:00:00+08"
```

### Monitor Application Logs
```bash
# View application output
appc ls -a myapp -o -f
```

### Check Application Resources
```bash
# Resource usage
appc resource -a myapp
```