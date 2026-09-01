# ADR 0002 — Workflow Stored as Special App

## Status

Accepted — this is the implemented design.

ADR 0004 proposes a first-class Workflow resource instead; that redesign is not
implemented, so workflows are still stored as described here.

## Context

Workflow definitions need CRUD operations with RBAC. Three storage options were considered:

- **Pure local files**: CLI reads/writes `/opt/appmesh/work/workflow/` directly. No REST API for remote management, no permission control.
- **Dedicated daemon API**: Add workflow-specific REST endpoints to the C++ daemon. Full control, but requires daemon code changes.
- **Register as special App**: Workflow is registered as an App Mesh App with metadata `type=workflow`, storing only lightweight metadata (owner, YAML file path). The actual YAML lives as a server-side file written by the engine.

## Decision

Workflows are registered as **special Apps** (metadata `type=workflow`) for CRUD and RBAC. Each workflow has its own directory (`/opt/appmesh/work/workflow/{name}/`) containing the YAML definition, run history, checkpoints, and archived logs. The App's metadata holds the YAML file path and the owner. The YAML content travels inside the `workflow_add` run_task payload; the engine validates it (parse + DAG check) and writes the file itself — registration is a single client call, with App-registration-first ordering and rollback to avoid orphans.

## Consequences

### Benefits

- **Zero daemon changes**: CRUD goes through the existing App API + Task API.
- **Ownership enforced** (since ADR 0006 Phase 1+2): the engine records the authenticated
  registrant's immutable Principal ID as owner in the App metadata; YAML cannot declare an
  owner. Every workflow action authorizes against owner or `workflow-admin`, fail-closed.
  Manual runs use the caller's Engine-validated bearer. Automatic and recovered runs
  use a short-lived Engine-local capability bound to the workflow owner, run, current
  Workflow process, and allowed operations. Registering an automatic trigger requires
  `workflow-admin` (see ADR 0006 and ADR 0009).
- **Remote management**: any SDK or CLI can manage workflows via the existing `run_task` endpoint.

### Trade-offs

- **Mixed App list**: `appm view` shows workflow pseudo-Apps alongside real Apps. Accepted — naming convention (`workflow-` prefix) is sufficient.
- **YAML size not in metadata**: avoids bloating the App metadata field, but means the trigger/engine must read the file separately.
