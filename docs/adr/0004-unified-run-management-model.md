# ADR 0004 — Unified Run Management Model

## Status

Proposed, with the identity portion superseded by ADR 0009. Step-result isolation and
cancel propagation are implemented; the unified Run API, single-mode engine, and external
trigger model remain proposals.

## Context

The engine has historically had separate CLI and long-running service execution paths.
Those paths differ in lifecycle management, logging, cancellation, and trigger handling.
The intended direction is to separate run creation from run execution, as GitHub Actions
separates platform scheduling from runners.

## Decision

All trigger sources should create the same Run resource. The workflow engine should only
pick up pending Runs, execute their DAGs, archive logs, and record terminal state. Cron and
event watchers should be ordinary App Mesh Apps that call the Run API.

The proposed lifecycle is:

```
pending -> running -> success | failure | cancelled
```

### Identity and authorization

ADR 0009 replaces this ADR's former user/password execution-identity design:

- `resource_owner` is the immutable App Mesh Principal ID that registered the workflow.
- `actor` is the immutable Principal ID that initiated the Run.
- A manual Run executes with the caller's Dex access token after the Engine validates it
  and resolves it to that Principal.
- An automatic or recovered Run executes with a short-lived Engine-local capability bound
  to its workflow, run, current owner, current Workflow process, and operation allow-list.
- Registering automatic triggers requires the `workflow-admin` permission.
- Workflow YAML cannot choose another user's identity. There is no stored username/password
  map, impersonation, or Engine-local login path.
- Tokens remain ephemeral and are never written to Run records, checkpoints, or logs.

Step authorization is enforced by App Mesh RBAC for the validated caller or, for an
automatic/recovered Run, the capability's current owner binding. Engine re-checks that
owner's active status, ownership, and permission for every operation. The Workflow process
is not a Dex client and holds no OAuth client secret. The capability is bound to the Run
lifecycle, owner, managed Workflow process, and operation set; it is not a single-target
credential. App and message steps may still address an existing application when the bound
owner's normal RBAC and application-access checks allow it. Newly created `wf-cmd-*`
applications and every later operation on them must carry metadata matching the capability's
workflow ID, run ID, and process UUID.

### Run Record

A future unified Run record replaces the split checkpoint and run index. Identity fields
contain stable Principal IDs, never usernames or credentials:

```json
{
  "run_id": "abc123",
  "workflow": "data-pipeline",
  "resource_owner_principal_id": "principal-owner-id",
  "actor_principal_id": "principal-caller-id",
  "source": "manual",
  "status": "running",
  "created_at": "2026-05-23T10:00:00Z",
  "started_at": "2026-05-23T10:00:01Z",
  "inputs": {"env": "prod"},
  "jobs": {
    "build": {"status": "success"},
    "test": {"status": "running"}
  }
}
```

For a newly automatic Run, the v1 audit record uses the non-Principal actor marker
`internal:workflow-trigger`; a recovered Run preserves the original Run's actor and source
while acquiring a new local capability. The owner Principal ID is recorded separately. A
future unified Run schema should represent this distinction explicitly rather than putting
an internal marker in a field named `actor_principal_id`.

### Step context isolation

Step results are job-scoped internally so parallel jobs cannot overwrite one another.
`${{ steps.compile.stdout }}` resolves in the current job; cross-job references use
`${{ jobs.build.steps.compile.stdout }}`.

### Cancel propagation

Cancellation marks the Run cancelled, deletes every active temporary step App, and records
each affected step as cancelled. The engine tracks `{run_id, job, step} -> app_name` for
this purpose.

## Consequences

- Run lifecycle and trigger sources can converge on one API and one execution path.
- Manual authorization expires with the caller's Dex token and fails closed.
- Automatic and recovered execution remains possible without retaining human credentials.
- The local capability issuer and the current managed Workflow process form a narrow trust
  boundary; capabilities are short-lived, route-bound, and re-evaluated against owner RBAC.
- Workflow registry discovery uses a private capability route that returns only
  `workflow-*` definitions; the synthetic controller cannot list arbitrary applications.
- Implementing the unified queue/API and external trigger wrappers remains future work.

## References

- ADR 0002 — workflow stored as a special App.
- ADR 0006 — workflow authorization policy.
- ADR 0009 — Dex-only authentication and immutable Principal identity.
