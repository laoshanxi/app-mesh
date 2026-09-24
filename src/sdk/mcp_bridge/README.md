# AppMesh MCP Server

An MCP (Model Context Protocol) server for querying and managing AppMesh applications with LLM.

## Features of integrate AppMesh MCP to LLM client with prompt

- 📊 Application monitoring and management
- 📋 Application listing and filtering
- 📈 Application lifecycle and health summary
- 🔍 Application status filtering

## Quick Start

```bash
# Setup virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure MCP endpoint
export MCP_ENDPOINT="wss://xxxxxxx/mcp/?token=eyJxxxxxxx"

# Supply the App Mesh access token. The stdio server reads it from the
# environment and refuses to start a client without it.
export APPMESH_BEARER_TOKEN="eyJxxxxxxx"

# Start MCP Server
python3 mcp_pipe.py
```

The stdio server targets `https://127.0.0.1:6060` by default. Set `APPMESH_URL`
when the Engine listens elsewhere. See [Authentication](../../../docs/source/Authentication.md)
for token acquisition.

## LLM Client Prompt Demo

![MCP Client Demo](https://github.com/laoshanxi/picture/raw/master/appmesh/appmesh_mcp.png)
