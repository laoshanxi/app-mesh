# ADR 0011: Prove a managed system process with a pre-shared key

- Status: Accepted
- Date: 2026-09-21

## Context

The Workflow engine must prove it is the current Workflow process before the Engine issues it
an authorization capability. The old proof was weak: a loopback peer address (a network
position, not a cryptographic proof) plus a 10-character process key sent in every request.

The Agent already used a stronger method: a pre-shared key (PSK) in shared memory, and an
HMAC signature for each request.

## Decision

The Engine issues a pre-shared key to a managed system process — the Agent and the Workflow
engine — each time it starts that process.

- The Engine writes a fresh key to a shared memory segment per start, so the key binds one
  process instance. The segment belongs to the process user with mode 0600.
- The process gets the segment path in `PSK_SHM_NAME` and reads the key one time.
- The key never goes on the wire. The caller signs the request nonce and sends the signature
  in `X-Request-HMAC`. A request with a proof cannot be forwarded.

Only the two bootstrap routes of the Workflow engine use this proof; the work itself still
uses the capability. A bad proof gets HTTP 401: the engine exits and the Engine restarts it
with a new key. A 403 keeps its other meaning (valid capability, failed authorization).

Unchanged:

- The process key stays for the task RPC of user applications, where it also selects the
  process instance that receives the task.
- The loopback condition stays for capability use (it limits where a capability can be spent)
  and for first-administrator enrollment (a person has no pre-shared key).

## Consequences

- Every spawn gets a fresh key; an in-flight signed request during a restart can fail and be
  retried.
- A persistent handshake failure becomes a crash loop, bounded by the restart backoff.
- One mechanism (`HMACVerifier` per spawn, held by the Application) serves both the Agent
  and the Workflow engine instead of two parallel proofs.
