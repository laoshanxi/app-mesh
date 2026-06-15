---
name: appmesh-cli
description: Complete CLI reference for the appm command
---

## CLI Overview

```bash
appm --help
appm -H https://192.168.1.100:6060 [command]  # remote connection
```

## Authentication

```bash
appm logon -U admin                    # interactive password
appm logon -U admin -t PT1D            # 1-day session
appm logon -U admin --show-token       # show JWT token
appm loginfo                           # current user
appm logoff                            # logout
appm passwd                            # change own password
appm passwd -t admin                   # change another user's password
appm lock -t admin -k true             # lock user
appm mfa -U admin                      # manage 2FA
```

## Application Management

### View
```bash
appm ls                                # list all
appm ls -l                             # detailed
appm ls -a myapp -o                    # view stdout
appm ls -a myapp -o -f                 # follow stdout (tail -f)
appm ls -P                             # process tree
appm ls -j                             # JSON output
```

### Add
```bash
appm add -a myapp -c "./run.sh" -w /path/to/work          # basic
appm add -a myapp -c "./run.sh" -u                         # shell mode
appm add -a myapp -I nginx:latest \
  -e "APP_DOCKER_OPTS=-p 80:80"                            # docker
appm add -a myapp -c "./run.sh" -Y cron -i "*/5 * * * * *"  # cron
appm add -a myapp -c "./run.sh" -S "02:00:00+08"          # daily schedule
appm add -a myapp -c "./run.sh" -M 512 -C 1024            # resource limits
appm add -a myapp -c "./run.sh" -e "K=V" -e "K2=V2"       # env vars
appm add -a myapp -c "./run.sh" -K "/usr/bin/curl http://localhost:8080"  # health check
appm add -a myapp -c "./run.sh" -Q keepalive               # exit behavior
```

### Control
```bash
appm enable -a myapp
appm disable -a myapp
appm restart -a myapp
appm rm -a myapp
```

## Execution

```bash
appm run -c "ls -la"                          # sync command
appm run -c "echo hello | grep hello" -u      # shell mode
appm run -c "env" -e "KEY=value"              # with env vars
appm run -a myapp -m @input.json              # with metadata
appm shell                                    # interactive shell
appm shell ps aux                             # one-shot via shell
```

## System

```bash
appm resource                          # CPU, memory, disk
appm config                            # view config
appm log -L DEBUG                      # set log level (DEBUG/INFO/WARN/ERROR)
appm label -v                          # view labels
appm label -a -l key=value             # add label
appm label -d -l key                   # delete label
```

## File Transfer

```bash
appm get -r /remote/path -l /local/path   # download
appm put -r /remote/path -l /local/path   # upload
```

## Script Automation

```bash
# Non-interactive token for scripts
export APPM_TOKEN=$(appm logon -U admin -X 'password' --show-token --timeout PT1H)
appm -H https://server:6060 add -a myscript -c "./run.sh"

# Batch operations
for app in $(appm ls -j | jq -r '.[].name'); do
  appm disable -a $app
done
```

## Flag Context Sensitivity

Some short flags change meaning per command — use long-form (`--app`, `--target`) when ambiguous:
- `-a`: app name (`ls`/`add`/`run`), audience (`logon`), add mode (`label`), no-attr (`get`/`put`)
- `-t`: timeout (`run`/`shell`), target user (`passwd`/`lock`)
- `-v`: verbose (global), view (`label`/`config`)
- `-r`: remote path (`get`/`put`), retry (`shell`)
