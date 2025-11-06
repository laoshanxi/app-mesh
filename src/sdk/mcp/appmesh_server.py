"""
AppMesh MCP Server
==================

This MCP (Model Context Protocol) server exposes AppMesh application management
capabilities as LLM-callable tools.

Purpose
-------
This server allows large language models and MCP-compatible clients to:
- Query a specific application's detailed configuration and runtime status
- List all applications, optionally filtered by status
- Generate summarized health and lifecycle statistics for all applications

Each exposed function is decorated as an MCP tool, allowing direct invocation
by LLMs or MCP clients.

Returned Data Model
-------------------
Application objects follow the schema defined in the AppMesh system (Go struct).
Fields include identity, configuration, runtime status, resource metrics,
health state, logs, and scheduling/behavior metadata.

Authentication
--------------
This demo logs into AppMesh using default admin credentials.
In production use, replace this with secure credential handling.

Transport
---------
The MCP server runs over STDIO so it can be launched as a subprocess by LLM runtimes.
"""

# pylint: disable=line-too-long,broad-exception-caught

import sys
import io
import os
import logging
from typing import Optional

from fastmcp import FastMCP
from appmesh import AppMeshClient

logging.basicConfig(
    filename="appmesh_mcp.log", level=logging.DEBUG, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("AppMesh-MCP")

# Ensure UTF-8 compatibility under Windows consoles
if sys.platform == "win32":
    os.environ["PYTHONIOENCODING"] = "utf-8"
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8")


# Create the MCP Server instance. The name will be shown to the client.
mcp = FastMCP("AppMesh")


@mcp.tool(description="Retrieve detailed information about a single application by name.")
def get_application(app_name: str) -> dict:
    """
    Get detailed configuration and runtime status of a specified application.

    Parameters
    ----------
    app_name : str
        The application name exactly as registered in AppMesh.

    Returns
    -------
    dict
        success : bool   - Indicates if the request succeeded
        application : dict (only on success)
            Full JSON representation of the application state
        error : str (only on failure)
        message: str (user-friendly explanation)
    """
    try:
        client = AppMeshClient()
        client.login("admin", "admin123")
        app = client.get_app(app_name)

        logger.info("Retrieved information for application: %s", app_name)
        return {"success": True, "application": app.json()}

    except RuntimeError as e:
        return {"success": False, "error": str(e), "message": "AppMesh client not initialized."}
    except Exception as e:
        logger.error("Failed to get application %s: %s", app_name, e)
        return {"success": False, "error": str(e), "message": f"Failed to retrieve application: {app_name}"}


@mcp.tool(description="List applications, optionally filtered by status (enabled/disabled).")
def list_applications(filter_status: Optional[str] = None) -> dict:
    """
    List all registered applications.

    Parameters
    ----------
    filter_status : str, optional
        If provided, filter applications by status:
        - "enabled" (status = running-capable)
        - "disabled" (status = inactive)

    Returns
    -------
    dict
        success : bool
        count : int
        applications : list[dict]
        error/message on failure
    """
    try:
        client = AppMeshClient()
        client.login("admin", "admin123")
        apps = client.list_apps()

        applications = []
        for app in apps:
            app_status = "enabled" if app.status == 1 else "disabled"
            if filter_status and app_status.lower() != filter_status.lower():
                continue
            applications.append(app.json())

        logger.info("Retrieved %d applications", len(applications))
        return {"success": True, "count": len(applications), "applications": applications}

    except RuntimeError as e:
        return {"success": False, "error": str(e), "message": "AppMesh client not initialized."}
    except Exception as e:
        logger.error("Failed to list applications: %s", e)
        return {"success": False, "error": str(e), "message": "Failed to retrieve application list"}


@mcp.tool(description="Compute a high-level summary of application lifecycle and health state.")
def get_application_summary() -> dict:
    """
    Generate system-wide application status statistics.

    Returns
    -------
    dict :
        success : bool
        summary :
            total_applications : int
            running : int
            stopped : int
            healthy : int
            unhealthy : int
            with_errors : int
        application_names : list[str]
    """
    try:
        client = AppMeshClient()
        client.login("admin", "admin123")
        apps = client.list_apps()

        total_count = len(apps)
        running_count = sum(1 for app in apps if app.pid and app.pid > 0)
        stopped_count = total_count - running_count
        healthy_count = sum(1 for app in apps if app.health == 0)
        unhealthy_count = sum(1 for app in apps if app.health == 1)
        error_count = sum(1 for app in apps if app.last_error)

        app_names = [app.name for app in apps]

        logger.info("Generated summary for %d applications", total_count)
        return {
            "success": True,
            "summary": {
                "total_applications": total_count,
                "running": running_count,
                "stopped": stopped_count,
                "healthy": healthy_count,
                "unhealthy": unhealthy_count,
                "with_errors": error_count,
            },
            "application_names": app_names,
        }

    except RuntimeError as e:
        return {"success": False, "error": str(e), "message": "AppMesh client not initialized."}
    except Exception as e:
        logger.error("Failed to generate summary: %s", e)
        return {"success": False, "error": str(e), "message": "Failed to generate application summary"}


if __name__ == "__main__":
    logger.info("Starting AppMesh MCP Server (stdio)...")
    mcp.run(transport="stdio")
