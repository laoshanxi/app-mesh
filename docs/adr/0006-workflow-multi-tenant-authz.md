# ADR 0006 — Workflow Multi-Tenant Authorization (Phase 1 + 2)

## Status

Accepted — implemented (Phase 1 + 2). The engine enforces per-workflow ownership and
runs steps under the triggering caller's identity; the Go SDK (`EnableConcurrency`),
the workflow engine, and the Rust CLI (`appc workflow`, all 14 actions) now carry the
caller token in the run_task payload. This is a concrete, simplified subset of the
identity model in ADR 0004; the full `execution_identity` / automatic-trigger model
(Phase 3 below) remains the longer-term target and is still Proposed in ADR 0004.

## Context

Today the workflow engine has effectively no authorization beyond one coarse gate
(see ADR 0005 and the corrected note in ADR 0002):

- The engine logs in once as a single fixed identity (`APPMESH_USER`, default
  `admin`) via `sec_env`, and **every** step and CRUD call uses that one JWT.
- The only access check is `app-run-task` + write-access on the single `workflow`
  engine App. Past that gate, `TaskHandler.dispatch` does **zero** per-action /
  per-workflow authorization — any reachable caller can run / cancel / delete / read
  logs of **any** workflow.
- `wf-<name>` Apps record `owner`/`permission`, but nothing reads them.
- Steps run as `admin`, so any user who can trigger a workflow gets admin-level
  command execution (privilege escalation / confused deputy).

Goal: support two roles —
- **user**: submit and manage **their own** workflows;
- **admin**: view and manage **all** workflows —
with steps executing under the **triggering caller's** authority, not admin's.

### Why not extend daemon RBAC for per-workflow rules

From the daemon's view the engine is a *single* App; `run_task` carries an opaque
body, so the daemon cannot see the `action`/`workflow` inside. Daemon RBAC can only
gate "may you talk to the engine at all." Per-workflow authorization therefore lives
**inside the engine** (the engine is its own Policy Decision Point); the daemon stays
the authenticator (IdP) and the step-execution substrate.

## Decision

Three authorization layers:

| Layer | Question | Enforced by |
|-------|----------|-------------|
| **L1** | May you send a task to the engine? | daemon RBAC `app-run-task` (already exists, ADR 0005) |
| **L2** | May you run/view/manage *this* workflow? | engine PDP — `owner == caller \|\| isAdmin` |
| **L3** | What may a step do? | the caller's own token runs the step → daemon's per-App ACL/RBAC applies naturally |

### Identity — token in the `run_task` payload (no daemon change, no new API)

Because Phase 2 already needs the caller's token to run steps, that same token is the
trusted identity source for Phase 1 — one token serves both, so **no C++ daemon change
and no new backend API are required**.

1. The client puts its JWT in the `run_task` payload: `Request.Token`.
2. On every request the engine validates it via the Go SDK
   `Authenticate(token, "", "", false)`. Invalid / expired / blacklisted → reject
   (fail-closed).
3. The verified caller username is taken from the token's `sub` claim (App Mesh sets
   `set_subject(userName)`, `JwtToken.cpp:46`).
4. The token is **stripped from `Request` immediately after authentication** and is
   **never written** to run records, checkpoints, `runs.json`, or logs.

### L2 authorization (Phase 1) — engine PDP

Predicate:

```
isAdmin(caller)        = caller ∈ APPMESH_WORKFLOW_ADMINS   // comma-separated username
                         // allowlist, default {"admin"}; evaluated in the engine (PDP)
canAccess(caller, wf)  = isAdmin(caller) || caller == wf.owner   // wf.owner from wf-<name> App Owner
```

The admin check is a **username allowlist** (`APPMESH_WORKFLOW_ADMINS`), chosen for
simplicity and zero RBAC setup (the default `admin` user is a workflow admin out of the
box, and the Python tests need no role wiring). Tradeoff: it is more brittle than an
RBAC permission — renaming a user loses admin, and admin cannot be granted via a role.
A future hardening is to switch `isAdmin` to an RBAC predicate
(`Authenticate(token, "workflow-manage")`) so admin is role-grantable; deferred.

Per-action matrix in `dispatch`:

| action | RBAC perm (L1 already passed) | ownership (L2) | note |
|--------|------|------|------|
| `workflow_add` | — | new: none; overwrite existing: `canAccess` | **owner forced = verified caller** (stop trusting YAML `owner`) |
| `workflow_rm` | — | `canAccess` | |
| `run` / `rerun` / `cancel` | — | `canAccess` | |
| `workflow_get` / `workflow_inputs` | — | `canAccess` | |
| `runs` / `run_detail` / `log` / `step_log` | — | `canAccess` | logs may contain secrets → owner-only |
| `workflow_list` | — | filter | user sees own; admin sees all |

Also record `actor = caller` in the run record for audit (the ADR 0004 `actor`).

### L3 execution (Phase 2) — invoker rights

Steps run as the **triggering caller**, not admin:

- The caller token is threaded `dispatch → TriggerManual → triggerRun → startRun →
  launchRun` (in-memory only; queued runs hold it in the in-memory queue entry).
- In `launchRun` the engine builds a **caller-scoped** `AppMeshClient` from the token
  and passes it as the existing `client` arg to `engine.RunWithContext`. The engine /
  executor are otherwise unchanged — they already use whatever client they are handed
  (`StepExecutor.Client`, `clientForTarget` forwards `client.GetToken()` to remote
  nodes). This keeps Phase 2 nearly zero-change in the execution path.
- The engine's **own** identity (`s.client`) is used **only for the control plane** —
  registry scan / `ListApps`, registering & removing `wf-<name>` Apps, orphan and
  cancel cleanup. It **no longer executes steps**. It should therefore be **downgraded
  from `admin` to a least-privilege service account** (only `app-reg`, `app-delete`,
  `app-view-all`, `app-run-task`), not the broad `admin` it defaults to today.

Result: a step can do exactly what the caller could do directly — privilege
escalation disappears, and the daemon's existing per-App owner/permission enforces it.

### Ownership is derived, not declared

`owner` is established from the **authenticated registrant** at `workflow_add`, not from
the YAML. Consequently the workflow YAML's `owner` field is **no longer needed and is
ignored** (trusting it was the spoofable-owner hole), and `permission` (rwx bits) is
unused in the own-vs-all model — access is `owner || isAdmin`. Both fields can be
dropped from workflow YAML; reintroduce `permission` only if/when group sharing
(read-only collaborators, etc.) is added.

Note: this is distinct from the engine App's `sec_env` login (`APPMESH_USER`/
`APPMESH_PASSWORD`), which still authenticates the engine to the daemon and stays
(downgraded to a service account, above).

### Token lifecycle — Plan A (chosen), expiry deferred

- **Plan A**: use the caller's current token as-is; a run is bounded by that token's
  validity. Token expiry / user disabled → remaining steps fail closed. This is the
  *desired* security semantic (a workflow must not keep acting after the caller's
  authorization lapses) and needs no long-lived stored credential.
- **Expiry handling is explicitly deferred** for now — long-running workflows that
  outlive the token are out of scope for the first implementation.
- **Known constraint (renew blacklists the prior token, `RestHandler.cpp:977`):** the
  trigger must use a **dedicated, non-renewing token** (e.g. a one-shot CLI login
  token), *not* an auto-refreshing session token — otherwise the caller's next session
  renew blacklists the token mid-run and kills the DAG.
- Rejected: auto-minting / passing around a long-lived token (largest credential-leak
  surface). Engine-side `RenewToken()` to extend long runs is a possible future
  enhancement (the old "Plan B"), out of scope here.

## Scope of change (as implemented)

| Component | File(s) | Change | Status |
|-----------|---------|--------|--------|
| Engine API | `internal/api/task_handler.go` | `Request.Token`; `authenticate()` + `authorize()`; strip token; `owner = caller` on add; `workflow_list` filter; `ownerOf` reads the registry (no per-action `GetApp`) | ✅ done |
| Engine service | `internal/trigger/service.go` | thread token `TriggerManual→triggerRunToken→startRun→launchRun`; build caller-scoped client in `launchRun`; `EnableConcurrency()` on it; **manual runs fail-closed on crash recovery** | ✅ done |
| Engine registry | `internal/trigger/{registry,scanner}.go` | store owner per workflow (from the scan's `ListApps` + on registration) for local owner lookup | ✅ done |
| Engine concurrency | `internal/trigger/concurrency.go` | carry token in the in-memory `pendingRun` queue entry | ✅ done |
| Engine main | `cmd/engine/main.go` | `EnableConcurrency()` on the shared mgmt connection; **auto-refresh kept** (safe once the demuxer is on) | ✅ done |
| Go SDK | `src/sdk/go/subscribe.go` | public `EnableConcurrency()` (proactively start the response demuxer) | ✅ done |
| CLI | `src/cli/src/commands/workflow.rs` | `with_token()` helper; inject caller JWT into all 14 action payloads | ✅ done |
| Tests | `src/sdk/python/test/test_workflow_engine.py` | `TestWorkflowAuthz` class; token in `call()`; health-probe `setUp` | ✅ done |
| Run record | `internal/workdir` + `internal/trigger/checkpoint.go` | `actor` (triggering user) on `RunRecord` + `RunIndex`, threaded `TriggerManual→…→SaveRunning`; surfaced via `run_detail`/`runs` | ✅ done |
| Daemon (C++) | — | **none** | — |
| Operator config | env `APPMESH_WORKFLOW_ADMINS` | comma-separated workflow-admin usernames (default `admin`) | — |

## Consequences

- **+** Tenant isolation (own-vs-all) and the admin/user roles; privilege escalation
  removed (steps run as the caller).
- **+** No C++ daemon change, no new backend API; reuses `Authenticate` + per-App ACL.
- **+** Token never persisted; fail-closed on expiry/blacklist/disable.
- **+** Per-action overhead is one local `Authenticate` round-trip; owner lookup is an
  in-memory registry hit (no `GetApp`).
- **Crash recovery:** manual (caller-initiated) runs are **not** resumed after an engine
  restart — the in-memory caller token is gone, and resuming under the engine identity
  would be an escalation. They are marked `cancelled` ("re-run required"); automatic
  (event/cron) runs, which always ran as the engine, resume normally. True per-owner
  resume needs act-as (Phase 3).
- **−** Long-running workflows are bounded by token validity (expiry deferred).
- **−** Trigger clients must use a non-renewing token (operational discipline + docs).
- Automatic (cron/event) triggers have no caller token; running those under the
  workflow owner needs the daemon `act-as` / `execution_identity` capability — that is
  **Phase 3**, tracked by ADR 0004, still Proposed.

## References

- ADR 0002 — workflow stored as special App (ownership metadata; "stored but not
  enforced" note).
- ADR 0004 — unified run management / identity model (resource_owner / actor /
  execution_identity); longer-term target, still Proposed.
- ADR 0005 — `run_task` messaging and the L1 gate.
