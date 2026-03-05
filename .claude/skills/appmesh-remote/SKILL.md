---
name: appmesh-remote
description: "Execute AI-generated Python/Bash/Node.js on remote servers via the appmesh Python SDK."
---

# Remote Execution Skill

Execute code on a remote server (container, VM, bare-metal) via the appmesh SDK. Async mode with real-time stdout streaming. See `CLAUDE.md` "Remote Execution Policy" for trigger rules and defaults.

Reference implementation: [example_remote_exec.py](example_remote_exec.py)

## Prerequisites

```bash
pip install appmesh
```

## Connection (use once per script)

```python
import os, warnings
warnings.filterwarnings("ignore", module="urllib3")
from appmesh import AppMeshClient, App

host = os.environ.get("APPMESH_HOST", "https://127.0.0.1:6060")
user = os.environ.get("APPMESH_USER", "admin")
password = os.environ.get("APPMESH_PASSWORD", "admin123")
ssl_verify_env = os.environ.get("APPMESH_SSL_VERIFY", "false")
ssl_verify = {"true": True, "false": False}.get(ssl_verify_env.lower(), ssl_verify_env)

client = AppMeshClient(rest_url=host, ssl_verify=ssl_verify, ssl_client_cert=None, auto_refresh_token=True)
client.login(user, password)
```

**Note**: Always pass `ssl_client_cert=None` when connecting from Mac (the SDK defaults to a server-side cert path that doesn't exist locally).

## Execution Patterns

### Pattern 1: Async Command (default for all execution)

```python
from contextlib import suppress

run = client.run_app_async(
    App({"command": "apt-get update", "shell": True}),
    max_time_seconds=300,
)
print(f"APP_NAME={run.app_name}")
try:
    exit_code = run.wait(stdout_print=True, timeout=300)
    print(f"\nExit code: {exit_code}")
except KeyboardInterrupt:
    with suppress(Exception):
        client.disable_app(run.app_name)
        client.delete_app(run.app_name)
    raise
```

### Pattern 2: Upload Script + Async Execute (primary for generated code)

```python
import tempfile, uuid
from contextlib import suppress

script_content = '''#!/usr/bin/env python3
import json, platform
result = {"hostname": platform.node(), "python": platform.python_version()}
print(json.dumps(result, indent=2))
'''

with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
    f.write(script_content)
    local_script = f.name

remote_script = f"/tmp/claude_{uuid.uuid4().hex}.py"

try:
    client.upload_file(local_script, remote_script)
    run = client.run_app_async(
        App({"command": f"python3 {remote_script}", "shell": True, "working_dir": "/tmp"}),
        max_time_seconds=300,
    )
    print(f"APP_NAME={run.app_name}")
    print(f"REMOTE_SCRIPT={remote_script}")
    try:
        exit_code = run.wait(stdout_print=True, timeout=300)
    except KeyboardInterrupt:
        with suppress(Exception):
            client.disable_app(run.app_name)
            client.delete_app(run.app_name)
        raise
finally:
    os.unlink(local_script)
    with suppress(Exception):
        client.run_app_sync(f"rm -f {remote_script}")
```

Works identically for other languages — change suffix and command accordingly:
- **Bash**: suffix `.sh`, command `bash {remote_script}`
- **Node.js**: suffix `.js`, command `node {remote_script}`

### Pattern 3: Deploy as Long-Running App

When user says "deploy", "register", "keep running", or "run as service". Upload to `/opt/appmesh/work/` (persistent, not `/tmp/`).

```python
# Upload script first (same as Pattern 2, but to persistent path)
client.upload_file(local_script, remote_script)

app = App()
app.name = "my_service"
app.command = f"python3 {remote_script}"
app.shell = True
app.working_dir = "/opt/appmesh/work"
app.status = 1  # enabled, starts immediately
app.behavior.set_exit_behavior(App.Behavior.Action.KEEPALIVE)

registered = client.add_app(app)
print(f"Deployed '{registered.name}'")
print(f"View stdout: appc ls -a {registered.name} -o -f")
```

View / follow stdout:
```python
output = client.get_app_output("my_service", stdout_position=0, timeout=3)
print(output.output)
```

Remove:
```python
client.disable_app("my_service")
client.delete_app("my_service")
```

### Pattern 4: Sync Command (cleanup/checks only)

```python
exit_code, output = client.run_app_sync("rm -f /tmp/claude_*.py", max_time_seconds=10)
```

## Best Practices

1. **Always clean up** remote temp files in `finally`
2. **Timeouts** — 60s simple commands, 300s builds, 600s+ installs
3. **Upload for multi-line** — prefer file upload over inline commands
