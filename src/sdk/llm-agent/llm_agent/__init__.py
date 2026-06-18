"""llm-agent — run a Claude agent on App Mesh.

A thin App Mesh wrapper around the official Claude Agent SDK (Claude Code-based): it routes
session turns over the App Mesh task RPC, persists just enough to resume the SDK
conversation, and streams to a worker App's stdout. The agent loop, tools, and history
are the SDK's; access control is the daemon's (RBAC + the worker App's permission).
"""

__version__ = "0.2.0"
