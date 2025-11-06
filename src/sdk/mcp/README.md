# AppMesh MCP Server

An MCP (Model Context Protocol) server for querying and managing AppMesh applications.

## MCP Features

- 📊 Query individual application details
- 📋 List all applications
- 📈 Get application statistics and summary
- 🔍 Filter applications by status
- ⚡ Real-time application status monitoring

## Steps

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
export MCP_ENDPOINT="wss://xxxxxxx/mcp/?token=eyJxxxxxxx"
python3 mcp_pipe.py
```

## MCP Client demo

<div align=center><img src="https://github.com/laoshanxi/picture/raw/master/appmesh/appmesh_mcp.png" align=center /></div>