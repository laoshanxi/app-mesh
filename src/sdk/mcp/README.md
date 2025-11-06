# AppMesh MCP Server

An MCP (Model Context Protocol) server for querying and managing AppMesh applications with LLM.

## Features of integrate AppMesh MCP to LLM client with prompt

- 📊 Application monitoring and management
- 📋 Application listing and filtering
- 📈 Detailed statistics and metrics collection
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

# Start MCP Server
python3 mcp_pipe.py
```

## LLM Client Prompt Demo

![MCP Client Demo](https://github.com/laoshanxi/picture/raw/master/appmesh/appmesh_mcp.png)
