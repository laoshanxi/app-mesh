#!/usr/bin/env python3
"""
Remote dev tool: tar-based sync + App Mesh execute.

Usage:
    remote.py sync                            Sync local files to remote
    remote.py exec <cmd> [--timeout N]        Execute on remote (no sync)
    remote.py sync-exec <cmd> [--timeout N]   Sync + execute
    remote.py run-script <file> [--timeout N] Upload + execute + cleanup
    remote.py deploy <name> <cmd>             Sync + register service
    remote.py output <app_name>              View app stdout via SDK
    remote.py cleanup <app_name>              Stop and remove remote app
"""

import argparse
import hashlib
import os
import shlex
import subprocess
import sys
import tempfile
import uuid
import warnings

warnings.filterwarnings("ignore", module="urllib3")

# --- Configuration ---

HOST = os.environ.get("APPMESH_HOST", "https://127.0.0.1:6060")
USER = os.environ.get("APPMESH_USER", "admin")
PASS = os.environ.get("APPMESH_PASSWORD", "admin123")
WORKSPACE = os.environ.get("APPMESH_WORKSPACE", "")
SSL_VERIFY_ENV = os.environ.get("APPMESH_SSL_VERIFY", "false")
SSL_VERIFY = {"true": True, "false": False}.get(SSL_VERIFY_ENV.lower(), SSL_VERIFY_ENV)

DEFAULT_EXCLUDES = [".git", "build", "node_modules", "__pycache__", ".claude", "*.o", "*.pyc", ".env", ".env.*", "*.pem", "*.key", "*.p12", "*.pfx"]
EXTRA = os.environ.get("APPMESH_SYNC_EXCLUDE", "")
if EXTRA:
    DEFAULT_EXCLUDES.extend(e.strip() for e in EXTRA.split(",") if e.strip())


def get_client():
    """Create and authenticate App Mesh client."""
    from appmesh import AppMeshClient

    client = AppMeshClient(base_url=HOST, ssl_verify=SSL_VERIFY, ssl_client_cert=None, auto_refresh_token=True)
    try:
        client.login(USER, PASS)
    except Exception as e:
        print(f"[error] Failed to connect to {HOST}: {e}")
        sys.exit(1)
    return client


# --- Core Functions ---


def _hash_file(path):
    """Compute SHA-256 hash of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _sync_marker_path():
    """Path to the local marker file that stores the last synced tar hash."""
    tag = hashlib.sha256(f"{HOST}:{WORKSPACE}".encode()).hexdigest()[:12]
    return os.path.join(tempfile.gettempdir(), f"_appmesh_sync_marker_{tag}")


def do_sync(client, force=False):
    """Sync local repo to remote workspace via tar + upload + extract.
    Skips upload if local files haven't changed since last successful sync."""
    if not WORKSPACE:
        print("[error] APPMESH_WORKSPACE not set.")
        sys.exit(1)

    try:
        local_root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"], text=True, stderr=subprocess.DEVNULL
        ).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        local_root = os.getcwd()

    # Build tar exclude args
    exclude_args = []
    for pattern in DEFAULT_EXCLUDES:
        exclude_args.extend(["--exclude", pattern])

    # Create compressed tar of the working tree
    tar_file = os.path.join(tempfile.gettempdir(), f"_appmesh_sync_{os.getpid()}.tar.gz")
    remote_tar = f"/tmp/_appmesh_sync_{uuid.uuid4().hex[:8]}.tar.gz"

    try:
        print(f"[sync] Packing {local_root} ...")
        result = subprocess.run(
            ["tar", "czf", tar_file, *exclude_args, "-C", local_root, "."],
            capture_output=True,
        )
        if result.returncode != 0:
            print(f"[error] tar failed: {result.stderr.decode()}")
            sys.exit(1)

        # Check if content changed since last sync
        tar_hash = _hash_file(tar_file)
        marker = _sync_marker_path()
        if not force and os.path.exists(marker):
            with open(marker) as f:
                last_hash = f.read().strip()
            if last_hash == tar_hash:
                print("[sync] No changes since last sync, skipping.")
                return

        tar_size = os.path.getsize(tar_file)
        print(f"[sync] Uploading {tar_size / 1024:.0f} KB ...")

        # Upload tar to remote
        client.upload_file(tar_file, remote_tar)

        # Extract on remote: ensure workspace exists, extract
        print(f"[sync] Extracting to {WORKSPACE} ...")
        ws_q = shlex.quote(WORKSPACE)
        tar_q = shlex.quote(remote_tar)
        exit_code, output = client.run_app_sync(
            f"mkdir -p {ws_q} && tar xzf {tar_q} -C {ws_q}",
            max_time=60,
        )
        # Always clean up remote tar, regardless of extract outcome
        try:
            client.run_app_sync(f"rm -f {tar_q}", max_time=10)
        except Exception as e:
            print(f"[warn] remote tar cleanup failed: {e}")
        if exit_code != 0:
            print(f"[error] Remote extract failed: {output}")
            sys.exit(1)

        # Save hash marker on success
        with open(marker, "w") as f:
            f.write(tar_hash)

        print("[sync] Done.")
    finally:
        if os.path.exists(tar_file):
            os.unlink(tar_file)


def do_exec(client, cmd, timeout=600, working_dir=None):
    """Execute command on remote with streaming stdout."""
    from appmesh import App

    print(f"[exec] {cmd}")
    app_dict = {"command": cmd, "shell": True}
    wd = working_dir or WORKSPACE
    if wd:
        app_dict["working_dir"] = wd
    run = client.run_app_async(
        App(app_dict),
        max_time=timeout,
    )
    print(f"[app] {run.app_name}")
    try:
        exit_code = run.wait(print_stdout=True, timeout=timeout)
    except KeyboardInterrupt:
        try:
            client.disable_app(run.app_name)
            client.delete_app(run.app_name)
        except Exception as e:
            print(f"\n[warn] cleanup failed for {run.app_name}: {e}")
        print("\n[interrupted]")
        sys.exit(130)
    print(f"[exit] {exit_code}")
    return exit_code


# --- Commands ---


def cmd_sync(args):
    if not WORKSPACE:
        print("[error] APPMESH_WORKSPACE not set.")
        sys.exit(1)
    client = get_client()
    do_sync(client, force=args.force)


def cmd_exec(args):
    client = get_client()
    wd = getattr(args, "working_dir", None)
    return do_exec(client, args.cmd, args.timeout, working_dir=wd)


def cmd_sync_exec(args):
    if not WORKSPACE:
        print("[error] APPMESH_WORKSPACE not set.")
        sys.exit(1)
    client = get_client()
    do_sync(client, force=args.force)
    return do_exec(client, args.cmd, args.timeout)


def cmd_run_script(args):
    client = get_client()
    remote_script = f"/tmp/claude_{uuid.uuid4().hex[:12]}"

    client.upload_file(args.script, remote_script)
    rs_q = shlex.quote(remote_script)
    client.run_app_sync(f"chmod +x {rs_q}", max_time=5)
    rc = 1
    try:
        rc = do_exec(client, remote_script, args.timeout)
    finally:
        try:
            client.run_app_sync(f"rm -f {rs_q}", max_time=5)
        except Exception as e:
            print(f"[warn] remote script cleanup failed: {e}")
    return rc


def cmd_deploy(args):
    from appmesh import App

    client = get_client()
    do_sync(client)

    app = App()
    app.name = args.name
    app.command = args.cmd
    app.shell = True
    app.working_dir = WORKSPACE
    app.status = 1
    app.behavior.set_exit_behavior(App.Behavior.Action.KEEPALIVE)

    try:
        registered = client.add_app(app)
        print(f"[deploy] Registered '{registered.name}' with keepalive.")
        output = client.get_app_output(registered.name, stdout_maxsize=2048, timeout=2)
        if output.output:
            print(f"[deploy] Initial output:\n{output.output}")
        print(f"[deploy] View stdout: python3 {__file__} output {shlex.quote(registered.name)}")
    except Exception as e:
        print(f"[error] deploy failed: {e}")
        return 1
    return 0


def cmd_output(args):
    client = get_client()
    try:
        result = client.get_app_output(
            args.app_name,
            stdout_position=0,
            stdout_maxsize=args.maxsize,
            timeout=args.timeout,
        )
        if result.output:
            print(result.output, end="")
        if result.exit_code is not None:
            print(f"\n[exit] {result.exit_code}")
    except Exception as e:
        print(f"[error] get output failed: {e}")
        return 1
    return 0


def cmd_cleanup(args):
    client = get_client()
    failed = False
    try:
        client.disable_app(args.app_name)
    except Exception as e:
        print(f"[warn] disable failed: {e}")
        failed = True
    try:
        client.delete_app(args.app_name)
    except Exception as e:
        print(f"[warn] delete failed: {e}")
        failed = True
    if failed:
        print(f"[cleanup] Partially removed {args.app_name}")
        return 1
    print(f"[cleanup] Removed {args.app_name}")
    return 0


# --- Entry Point ---


def main():
    parser = argparse.ArgumentParser(description="App Mesh remote dev tool: sync (tar) + remote execute")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("sync", help="Sync local files to remote workspace")
    p.add_argument("--force", action="store_true", help="Force sync even if no changes detected")

    p = sub.add_parser("exec", help="Execute on remote (no sync)")
    p.add_argument("cmd", help="Command to execute")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--working-dir", help="Override working directory")

    p = sub.add_parser("sync-exec", help="Sync + execute (main dev loop)")
    p.add_argument("cmd", help="Command to execute")
    p.add_argument("--timeout", type=int, default=600)
    p.add_argument("--force", action="store_true", help="Force sync even if no changes detected")

    p = sub.add_parser("run-script", help="Upload script + execute + cleanup")
    p.add_argument("script", help="Local script path")
    p.add_argument("--timeout", type=int, default=300)

    p = sub.add_parser("deploy", help="Sync + register as long-running service")
    p.add_argument("name", help="Service name")
    p.add_argument("cmd", help="Command to run")

    p = sub.add_parser("output", help="View stdout of a running/finished app")
    p.add_argument("app_name", help="App name")
    p.add_argument("--maxsize", type=int, default=10240, help="Max output bytes to read")
    p.add_argument("--timeout", type=int, default=2, help="Wait seconds for output")

    p = sub.add_parser("cleanup", help="Stop and remove a remote app")
    p.add_argument("app_name", help="App name to clean up")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    handler = {
        "sync": cmd_sync,
        "exec": cmd_exec,
        "sync-exec": cmd_sync_exec,
        "run-script": cmd_run_script,
        "deploy": cmd_deploy,
        "output": cmd_output,
        "cleanup": cmd_cleanup,
    }[args.command]

    rc = handler(args)
    sys.exit(rc if isinstance(rc, int) else 0)


if __name__ == "__main__":
    main()
