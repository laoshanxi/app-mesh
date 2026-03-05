#!/usr/bin/env python3
"""
Example: Remote code execution via appmesh Python SDK.

Demonstrates:
1. Async execution with real-time stdout streaming
2. Upload script → async execute → download results
3. Interrupt handling (Ctrl+C → stop + cleanup)
4. Deploy as long-running persistent app

Usage:
    export APPMESH_HOST=https://<remote-host>:6060
    export APPMESH_USER=admin
    export APPMESH_PASSWORD=<password>
    python3 example_remote_exec.py
"""

import json
import os
import sys
import tempfile
import time
import uuid
import warnings
from contextlib import suppress
from typing import Union

warnings.filterwarnings("ignore", module="urllib3")

from appmesh import App, AppMeshClient


def _parse_ssl_verify(value: str) -> Union[bool, str]:
    """Convert APPMESH_SSL_VERIFY env var to requests-compatible ssl_verify value."""
    lower = value.lower()
    if lower == "true":
        return True
    if lower == "false":
        return False
    return value  # CA cert path


def create_client() -> AppMeshClient:
    """Create and authenticate an App Mesh client from environment variables."""
    host = os.environ.get("APPMESH_HOST", "https://127.0.0.1:6060")
    user = os.environ.get("APPMESH_USER", "admin")
    password = os.environ.get("APPMESH_PASSWORD", "admin123")
    ssl_verify = _parse_ssl_verify(os.environ.get("APPMESH_SSL_VERIFY", "false"))

    client = AppMeshClient(rest_url=host, ssl_verify=ssl_verify, ssl_client_cert=None, auto_refresh_token=True)
    try:
        client.login(user, password)
    except Exception as exc:
        raise RuntimeError(f"Login to {host} failed: {exc}") from exc
    print(f"Connected to {host}")
    return client


def demo_async_command(client: AppMeshClient) -> None:
    """Demo 1: Async command with real-time stdout streaming + interrupt handling."""
    print("\n--- Demo 1: Async Command with Real-Time Stdout ---")

    run = client.run_app_async(
        App({"command": "for i in 1 2 3 4 5; do echo \"Step $i of 5\"; sleep 1; done; echo 'Done!'", "shell": True}),
        max_time_seconds=30,
    )
    try:
        exit_code = run.wait(stdout_print=True, timeout=60)
        print(f"\nExit code: {exit_code}")
    except KeyboardInterrupt:
        print("\nInterrupted — stopping remote app...")
        with suppress(Exception):
            client.disable_app(run.app_name)
            client.delete_app(run.app_name)
        raise


def demo_upload_and_execute(client: AppMeshClient) -> None:
    """Demo 2: Upload Python script, async execute with streaming, download results."""
    print("\n--- Demo 2: Upload → Async Execute → Download ---")

    script_content = """\
#!/usr/bin/env python3
import json
import platform
import datetime
import os

result = {
    "timestamp": datetime.datetime.now().isoformat(),
    "hostname": platform.node(),
    "python_version": platform.python_version(),
    "platform": platform.platform(),
    "architecture": platform.machine(),
    "cwd": os.getcwd(),
    "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
}

output_path = "/tmp/claude_result.json"
with open(output_path, "w") as f:
    json.dump(result, f, indent=2)

print(json.dumps(result, indent=2))
print(f"Results saved to {output_path}")
"""

    local_script = None
    remote_script = f"/tmp/claude_{uuid.uuid4().hex}.py"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script_content)
            local_script = f.name

        client.upload_file(local_script, remote_script)
        print(f"Uploaded script to remote:{remote_script}")

        # Async execute with real-time stdout
        run = client.run_app_async(
            App({"command": f"python3 {remote_script}", "shell": True, "working_dir": "/tmp"}),
            max_time_seconds=120,
        )
        try:
            exit_code = run.wait(stdout_print=True, timeout=120)
            print(f"\nExit code: {exit_code}")
        except KeyboardInterrupt:
            print("\nInterrupted — stopping remote app...")
            with suppress(Exception):
                client.disable_app(run.app_name)
                client.delete_app(run.app_name)
            raise

        if exit_code == 0:
            local_result = os.path.join(tempfile.gettempdir(), "claude_remote_result.json")
            client.download_file("/tmp/claude_result.json", local_result)
            with open(local_result, "r", encoding="utf-8") as f:
                data = json.load(f)
            print(f"\nDownloaded result: {json.dumps(data, indent=2)}")
            os.unlink(local_result)
    finally:
        if local_script and os.path.exists(local_script):
            os.unlink(local_script)
        with suppress(Exception):
            client.run_app_sync(f"rm -f {remote_script} /tmp/claude_result.json")
        print("Cleaned up temp files")


def demo_deploy_app(client: AppMeshClient) -> None:
    """Demo 3: Deploy as long-running persistent app with stdout viewing."""
    print("\n--- Demo 3: Deploy as Long-Running App ---")

    app_name = f"claude_demo_{uuid.uuid4().hex[:8]}"
    script_content = """\
#!/usr/bin/env python3
import time, datetime
while True:
    print(f"[{datetime.datetime.now().isoformat()}] Service running...")
    time.sleep(3)
"""

    local_script = None
    remote_script = f"/opt/appmesh/work/{app_name}.py"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write(script_content)
            local_script = f.name

        client.upload_file(local_script, remote_script)

        # Register as persistent app with auto-restart
        app = App()
        app.name = app_name
        app.command = f"python3 {remote_script}"
        app.shell = True
        app.working_dir = "/opt/appmesh/work"
        app.status = 1  # enabled, starts immediately
        app.behavior.set_exit_behavior(App.Behavior.Action.KEEPALIVE)

        registered = client.add_app(app)
        print(f"Deployed '{registered.name}' — PID: {registered.pid}")

        # Wait a moment then read stdout
        time.sleep(5)

        output = client.get_app_output(app_name, stdout_position=0, timeout=3)
        print(f"App stdout:\n{output.output}")

        # Follow stdout for a few seconds (like tail -f)
        print("Following stdout (5 seconds)...")
        position = output.out_position or 0
        end_time = time.time() + 5
        try:
            while time.time() < end_time:
                out = client.get_app_output(app_name, stdout_position=position, timeout=2)
                if out.output:
                    print(out.output, end="")
                position = out.out_position or position
        except KeyboardInterrupt:
            print(f"\nStopped following. App '{app_name}' still running.")
            return  # Don't clean up — leave it deployed

        # Clean up demo app
        print(f"\nCleaning up demo app '{app_name}'...")
        client.disable_app(app_name)
        client.delete_app(app_name)
        with suppress(Exception):
            client.run_app_sync(f"rm -f {remote_script}")
        print("Demo app removed.")
    finally:
        if local_script and os.path.exists(local_script):
            os.unlink(local_script)


def demo_bash_diagnostic(client: AppMeshClient) -> None:
    """Demo 4: Upload and run a bash diagnostic script (async with streaming)."""
    print("\n--- Demo 4: Bash Diagnostic Script (Async) ---")

    bash_script = """\
#!/bin/bash
set -euo pipefail
echo "=== System Information ==="
echo "Hostname: $(hostname)"
echo "OS: $(uname -s) $(uname -r)"
echo "Architecture: $(uname -m)"
echo ""
echo "=== Disk Usage ==="
df -h / 2>/dev/null || echo "df not available"
echo ""
echo "=== Process Count ==="
echo "Running processes: $(ps aux 2>/dev/null | wc -l || echo 'unknown')"
echo ""
echo "=== Service Status ==="
ls /opt/appmesh/ 2>/dev/null && echo "Service installed" || echo "Service path not found"
"""

    local_script = None
    remote_script = f"/tmp/claude_{uuid.uuid4().hex}.sh"
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".sh", delete=False) as f:
            f.write(bash_script)
            local_script = f.name

        client.upload_file(local_script, remote_script)
        run = client.run_app_async(
            App({"command": f"bash {remote_script}", "shell": True}),
            max_time_seconds=60,
        )
        try:
            exit_code = run.wait(stdout_print=True, timeout=60)
            print(f"\nExit code: {exit_code}")
        except KeyboardInterrupt:
            with suppress(Exception):
                client.disable_app(run.app_name)
                client.delete_app(run.app_name)
            raise
    finally:
        if local_script and os.path.exists(local_script):
            os.unlink(local_script)
        with suppress(Exception):
            client.run_app_sync(f"rm -f {remote_script}")


if __name__ == "__main__":
    client = create_client()
    demos = [demo_async_command, demo_upload_and_execute, demo_deploy_app, demo_bash_diagnostic]
    for demo in demos:
        try:
            demo(client)
        except KeyboardInterrupt:
            print("\nUser interrupted. Skipping remaining demos.")
            break
        except Exception as exc:
            print(f"[WARN] {demo.__name__} failed: {exc}", file=sys.stderr)
    print("\nAll demos completed!")
