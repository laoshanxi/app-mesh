# ADR 0002 — Workflow Stored as Special App

## Status

Accepted — this is the implemented design.

ADR 0004 proposes a first-class Workflow resource instead; that redesign is not
implemented, so workflows are still stored as described here.

## Context

Workflow definitions need CRUD operations with RBAC. Three storage options were considered:

- **Pure local files**: CLI reads/writes `/opt/appmesh/work/workflow/` directly. No REST API for remote management, no permission control.
- **Dedicated daemon API**: Add workflow-specific REST endpoints to the C++ daemon. Full control, but requires daemon code changes.
- **Register as special App**: Workflow is registered as an App Mesh App with label `type=workflow`, storing only lightweight metadata (owner, permission, YAML file path). The actual YAML lives as a server-side file managed via the File API.

## Decision

Workflows are registered as **special Apps** (label `type=workflow`) for CRUD and RBAC. Each workflow has its own directory (`/opt/appmesh/work/workflow/{name}/`) containing the YAML definition, run history, checkpoints, and archived logs. The App's metadata holds only the YAML file path reference. Files are managed via the File API.

## Consequences

### Benefits

- **Zero daemon changes**: CRUD goes through existing App API + File API.
- **Ownership metadata stored**: each workflow App records `owner`/`permission`. Note this
  is **stored but not yet enforced** — workflow operations (run, cancel, view, CRUD) are
  invoked via `run_task` on the single workflow-engine App, so the daemon's only access
  check is the `app-run-task` permission on that engine App (ADR 0005); the per-workflow
  `owner`/`permission` fields are not consulted, and steps run under the engine's own
  identity. Per-workflow authorization (owner/actor/execution_identity) is the unimplemented
  ADR 0004 work.
- **Remote management**: any SDK or CLI can manage workflows via existing REST endpoints.

### Trade-offs

- **Mixed App list**: `appc app list` shows workflow pseudo-Apps alongside real Apps. Accepted — naming convention (`workflow-` prefix) is sufficient.
- **Two-step registration**: CLI must upload the YAML file and register the App in sequence, not atomically.
- **YAML size not in metadata**: avoids bloating the App metadata field, but means the trigger/engine must read the file separately.
