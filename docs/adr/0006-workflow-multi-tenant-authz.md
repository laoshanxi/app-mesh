# ADR 0006 — Workflow Multi-Tenant Authorization

## Status

Accepted. Authentication and identity details were revised by ADR 0009.

## Context

The daemon sees the workflow engine as one App, while workflow names and actions are inside
the Task payload. Daemon RBAC can decide whether a Principal may call the engine, but the
engine must enforce ownership and action-specific policy for individual workflows.

## Decision

Authorization has three layers:

| Layer | Question | Enforcement |
|-------|----------|-------------|
| L1 | May the caller send a Task to the workflow engine? | App Mesh `app-run-task` permission |
| L2 | May the caller view, run, or manage this workflow? | workflow engine policy using immutable Principal IDs |
| L3 | What may a step do? | App Mesh RBAC for the caller or the run capability's bound owner |

### Caller authentication

Every workflow request carries the caller's access token. The workflow engine submits
that token to the Engine's Principal self endpoint. The Engine validates issuer, signature,
audience, and token time constraints, then returns the stable Principal ID and permissions.
The workflow engine does not decode an unverified token to establish identity.

The token is removed from request data immediately after validation and is never persisted
or logged.

### Ownership and administration

`workflow_add` derives the owner from the authenticated registrant. A YAML `owner` value is
ignored and must not influence authorization. Owner and actor values stored in workflow/run
state are immutable Principal IDs, not usernames.

The policy is:

```
canAccess(principal, workflow) =
    principal.id == workflow.owner_principal_id ||
    principal.permissions contains "workflow-admin"
```

The owner may operate on their workflow. A Principal with `workflow-admin` may operate on
all workflows. Listing filters out inaccessible workflows.

Registering a workflow with an automatic trigger requires `workflow-admin`, because those
runs execute without a human caller.

### Effective identity for steps

- Manual Run: use the validated caller's access token; record the caller Principal ID
  as `actor`.
- Automatic or recovered execution: the managed Workflow process proves its current
  `APP_MESH_PROCESS_KEY` over loopback TCP and asks Engine for an opaque capability bound to
  workflow ID, run ID, current owner Principal, allowed operations, process UUID, and a
  maximum five-minute lifetime. A newly automatic Run records `internal:workflow-trigger`
  as its actor marker; recovery preserves the original actor and trigger source.

Workflow definitions cannot select an arbitrary execution identity. The Engine has no local
password login, user credential map, impersonation, or token-minting path. The workflow
capability is not an OAuth/JWT identity token: Engine signs and validates it with a
daemon-only key, accepts it only on an actual loopback TCP peer, and intersects every
operation with the owner's current active RBAC. Principal disable, ownership changes, and
role removal therefore take effect immediately. Long runs renew before expiry using the
same local process proof; capabilities are never persisted or placed in message payloads.
The binding scopes the Run lifecycle, owner, process, routes, and operations rather than one
arbitrary existing App: App/message steps may target an existing App only through its normal
owner/RBAC/access checks. A command step may create only a reserved `wf-cmd-*` App whose
workflow/run/process metadata matches the capability, and subsequent operations on that
temporary App repeat the metadata check.

### Action policy

| Action | Required workflow policy |
|--------|--------------------------|
| add new manual-only workflow | authenticated Principal; owner derived from caller |
| add workflow with automatic trigger | `workflow-admin` |
| overwrite/remove/get/run/rerun/cancel/read logs | owner or `workflow-admin` |
| list | return owned workflows, or all for `workflow-admin` |

## Consequences

- Stable Principal IDs survive directory display-name and username changes.
- Manual steps have exactly the caller's App Mesh authority and fail closed when the access
  token is no longer valid.
- Automatic and recovered runs do not require stored human credentials.
- Automatic authority is run-scoped and cannot outlive owner/RBAC changes.
- Bearer tokens are ephemeral request material and cannot appear in durable run state.
- Node-local capabilities cannot be forwarded to a remote Engine; cluster delegation needs
  a future Engine-mediated protocol.

## References

- ADR 0002 — workflow storage and ownership metadata.
- ADR 0004 — proposed unified Run model.
- ADR 0009 — authentication service and Principal mapping.
