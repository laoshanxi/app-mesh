"""
Simple MCP stdio <-> WebSocket pipe with optional unified config.
Version: 0.2.0 (improved)

Usage (env):
    export MCP_ENDPOINT=<ws_endpoint>
    # Windows (PowerShell): $env:MCP_ENDPOINT = "<ws_endpoint>"

Start server process(es) from config:
Run all configured servers (default)
    python mcp_pipe.py

Run a single local server script (back-compat)
    python mcp_pipe.py path/to/server.py

Config discovery order:
    $MCP_CONFIG, then ./mcp_config.json

Env overrides:
    (none for proxy; uses current Python: python -m mcp_proxy)
"""

import asyncio
import subprocess
import logging
import os
import signal
import sys
import json
from typing import Tuple, Dict, Optional

import websockets
from websockets.exceptions import ConnectionClosed
from dotenv import load_dotenv

# Load env if .env exists
load_dotenv()

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger("MCP_PIPE")

# Reconnection settings
INITIAL_BACKOFF = 1  # Initial wait time in seconds
MAX_BACKOFF = 600  # Maximum wait time in seconds


async def connect_with_retry(uri: str, target: str) -> None:
    """
    Attempt to connect indefinitely. Uses exponential backoff on failure.
    """
    backoff = INITIAL_BACKOFF
    attempt = 0

    while True:
        if attempt:
            logger.info(f"[{target}] Reconnecting in {backoff}s (attempt {attempt})...")
            await asyncio.sleep(backoff)

        attempt += 1

        try:
            await connect_to_server(uri, target)
            backoff = INITIAL_BACKOFF  # reset after success
        except Exception as exc:
            logger.warning(f"[{target}] Connection lost: {exc}")
            backoff = min(backoff * 2, MAX_BACKOFF)


async def connect_to_server(uri: str, target: str) -> None:
    """
    Connect to WebSocket server and bridge IO to a local subprocess.
    """
    logger.info(f"[{target}] Connecting to WebSocket...")
    async with websockets.connect(uri) as websocket:
        logger.info(f"[{target}] Connected")

        cmd, env = build_server_command(target)
        process = subprocess.Popen(
            cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env
        )
        logger.info(f"[{target}] Started: {' '.join(cmd)}")

        try:
            await asyncio.gather(
                pipe_websocket_to_process(websocket, process, target),
                pipe_process_to_websocket(process, websocket, target),
                pipe_process_stderr_to_terminal(process, target),
            )
        except Exception:
            raise
        finally:
            terminate_process(process, target)


def terminate_process(process: subprocess.Popen, target: str) -> None:
    """Safely terminate a child process."""
    logger.info(f"[{target}] Terminating subprocess...")

    try:
        process.terminate()
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()

    logger.info(f"[{target}] Subprocess terminated")


async def pipe_websocket_to_process(websocket, process, target: str) -> None:
    """Forward messages from WebSocket → process stdin."""
    try:
        async for message in websocket:
            logger.debug(f"[{target}] << {message[:120]}")
            if process.stdin:
                process.stdin.write(message + "\n")
                process.stdin.flush()
    except Exception as exc:
        logger.error(f"[{target}] WS→Process pipe error: {exc}")
        raise
    finally:
        if process.stdin and not process.stdin.closed:
            process.stdin.close()


async def pipe_process_to_websocket(process, websocket, target: str) -> None:
    """Forward stdout lines from process → WebSocket."""
    try:
        while True:
            line = await asyncio.to_thread(process.stdout.readline)
            if not line:
                logger.info(f"[{target}] Process stdout ended")
                break
            logger.debug(f"[{target}] >> {line[:120]}")
            await websocket.send(line)
    except Exception as exc:
        logger.error(f"[{target}] Process→WS pipe error: {exc}")
        raise


async def pipe_process_stderr_to_terminal(process, target: str) -> None:
    """Forward stderr → local terminal."""
    try:
        while True:
            line = await asyncio.to_thread(process.stderr.readline)
            if not line:
                logger.info(f"[{target}] Process stderr ended")
                break
            sys.stderr.write(line)
    except Exception as exc:
        logger.error(f"[{target}] STDERR pipe error: {exc}")
        raise


def load_config() -> Dict:
    """
    Load config from $MCP_CONFIG or ./mcp_config.json.
    Returns {} if missing or invalid.
    """
    path = os.environ.get("MCP_CONFIG", os.path.join(os.getcwd(), "mcp_config.json"))
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f) or {}
    except Exception:
        return {}


def build_server_command(target: Optional[str]) -> Tuple[list, Dict[str, str]]:
    """
    Build and return (command_list, env) for starting a server.
    """
    if target is None:
        if len(sys.argv) < 2:
            raise RuntimeError("Missing server name or script path")
        target = sys.argv[1]

    cfg = load_config()
    servers = cfg.get("mcpServers", {})

    if target in servers:
        entry = servers[target] or {}
        if entry.get("disabled"):
            raise RuntimeError(f"Server '{target}' is disabled")

        env = os.environ.copy()
        env.update({str(k): str(v) for k, v in (entry.get("env") or {}).items()})
        typ = entry.get("type", entry.get("transportType", "stdio")).lower()

        if typ == "stdio":
            cmd = entry.get("command")
            if not cmd:
                raise RuntimeError(f"Server '{target}' missing command")
            return [cmd, *entry.get("args", [])], env

        if typ in {"http", "sse", "streamablehttp"}:
            url = entry.get("url")
            if not url:
                raise RuntimeError(f"'{target}' type={typ} missing url")

            cmd = [sys.executable, "-m", "mcp_proxy"]
            if typ in {"http", "streamablehttp"}:
                cmd += ["--transport", "streamablehttp"]
            for k, v in (entry.get("headers") or {}).items():
                cmd += ["-H", k, str(v)]
            cmd.append(url)
            return cmd, env

        raise RuntimeError(f"Unsupported server type: {typ}")

    # Fallback: treat target as script path
    if not os.path.exists(target):
        raise RuntimeError(f"'{target}' is not a configured server or a valid script path")
    return [sys.executable, target], os.environ.copy()


def signal_handler(*_):
    logger.info("Shutting down...")
    sys.exit(0)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)

    endpoint = os.environ.get("MCP_ENDPOINT")
    if not endpoint:
        logger.error("Missing environment variable: MCP_ENDPOINT")
        sys.exit(1)

    target = sys.argv[1] if len(sys.argv) > 1 else None

    async def main():
        if target is None:
            cfg = load_config().get("mcpServers", {})
            enabled = [k for k, v in cfg.items() if not (v or {}).get("disabled")]
            if not enabled:
                raise RuntimeError("No enabled servers in config")
            logger.info(f"Starting servers: {', '.join(enabled)}")
            await asyncio.gather(*(connect_with_retry(endpoint, t) for t in enabled))
        else:
            await connect_with_retry(endpoint, target)

    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Interrupted")
