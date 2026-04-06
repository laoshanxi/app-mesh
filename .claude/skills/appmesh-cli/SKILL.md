---
name: appmesh-cli
description: Complete CLI reference for the appc command
---

## CLI Overview

```bash
appc --help
appc -H https://192.168.1.100:6060 [command]  # remote connection
```

## Authentication

```bash
appc logon -U admin                    # interactive password
appc logon -U admin -t PT1D            # 1-day session
appc logon -U admin --show-token       # show JWT token
appc loginfo                           # current user
appc logoff                            # logout
appc passwd                            # change own password
appc passwd -t admin                   # change another user's password
appc lock -t admin -k true             # lock user
appc mfa -U admin                      # manage 2FA
```

## Application Management

### View
```bash
appc ls                                # list all
appc ls -l                             # detailed
appc ls -a myapp -o                    # view stdout
appc ls -a myapp -o -f                 # follow stdout (tail -f)
appc ls -P                             # process tree
appc ls -j                             # JSON output
```

### Add
```bash
appc add -a myapp -c "./run.sh" -w /path/to/work          # basic
appc add -a myapp -c "./run.sh" -u                         # shell mode
appc add -a myapp -I nginx:latest \
  -e "APP_DOCKER_OPTS=-p 80:80"                            # docker
appc add -a myapp -c "./run.sh" -Y cron -i "*/5 * * * * *"  # cron
appc add -a myapp -c "./run.sh" -S "02:00:00+08"          # daily schedule
appc add -a myapp -c "./run.sh" -M 512 -C 1024            # resource limits
appc add -a myapp -c "./run.sh" -e "K=V" -e "K2=V2"       # env vars
appc add -a myapp -c "./run.sh" -K "/usr/bin/curl http://localhost:8080"  # health check
appc add -a myapp -c "./run.sh" -Q keepalive               # exit behavior
```

### Control
```bash
appc enable -a myapp
appc disable -a myapp
appc restart -a myapp
appc rm -a myapp
```

## Execution

```bash
appc run -c "ls -la"                          # sync command
appc run -c "echo hello | grep hello" -u      # shell mode
appc run -c "env" -e "KEY=value"              # with env vars
appc run -a myapp -m @input.json              # with metadata
appc shell                                    # interactive shell
appc shell ps aux                             # one-shot via shell
```

## System

```bash
appc resource                          # CPU, memory, disk
appc config                            # view config
appc log -L DEBUG                      # set log level (DEBUG/INFO/WARN/ERROR)
appc label -v                          # view labels
appc label -a -l key=value             # add label
appc label -d -l key                   # delete label
```

## File Transfer

```bash
appc get -r /remote/path -l /local/path   # download
appc put -r /remote/path -l /local/path   # upload
```

## Script Automation

```bash
# Non-interactive token for scripts
export APPC_TOKEN=$(appc logon -U admin -X 'password' --show-token --timeout PT1H)
appc -H https://server:6060 add -a myscript -c "./run.sh"

# Batch operations
for app in $(appc ls -j | jq -r '.[].name'); do
  appc disable -a $app
done
```

## Flag Context Sensitivity

Some short flags change meaning per command — use long-form (`--app`, `--target`) when ambiguous:
- `-a`: app name (`ls`/`add`/`run`), audience (`logon`), add mode (`label`), no-attr (`get`/`put`)
- `-t`: timeout (`run`/`shell`), target user (`passwd`/`lock`)
- `-v`: verbose (global), view (`label`/`config`)
- `-r`: remote path (`get`/`put`), retry (`shell`)
