"""llm-agent — run LLM agents on App Mesh.

A thin App Mesh integration around an existing agent runtime: it owns the
platform concerns (multi-tenant, RBAC, App-Mesh-Apps-as-tools, per-tenant budget,
sessions, task transport) and delegates the LLM interaction (loop calls, streaming,
tool-calling format) to the official provider SDKs — no hand-rolled provider code.
"""

__version__ = "0.1.0"
