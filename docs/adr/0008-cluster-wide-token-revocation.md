# ADR 0008 — Cluster-Wide Token Revocation

## Status

Proposed. Nothing here is implemented. This ADR covers **local-JWT mode only**; in OAuth2
mode `JwtToken::verify` delegates to Keycloak and returns before the epoch check, so
revocation is Keycloak's problem, not ours.

## Context

Refresh-token rotation just landed. `apiUserTokenRenew` retires the presented refresh token
with an atomic `revokeOnce` (`src/daemon/rest/RestHandler.cpp`) and `verifyRefresh` rejects
anything already in the list (`src/daemon/security/JwtToken.cpp`). The OpenAPI documents the
resulting replay protection — and already documents its own caveat
(`src/daemon/rest/openapi.yaml:1731`): *"Revocation state is held per daemon and is not
replicated across a cluster."*

The revocation substrate is `TokenBlacklist`, an in-process `ACE_Singleton` snapshotted to a
local `.snapshot` file by `PersistManager` and reloaded at boot (`src/daemon/main.cpp`). It
has three limits.

### Limit 1 — Node-local

Nodes in a cluster share `JWTSalt`/`Issuer`, so every node accepts every other node's tokens,
but each keeps its own denylist. A refresh token rotated (and therefore revoked) on node A is
still valid on node B. An attacker holding a stolen refresh token simply presents it to a
different node, and the rotation chain forks: two live chains from one credential, which is
exactly what rotation exists to detect. Reaching another node is not exotic — a load balancer
in front of the cluster does it by accident, and `X-Target-Host` forwarding does it on
request (`src/daemon/rest/Worker.cpp` → `src/daemon/rest/ForwardingManager.cpp`).

The same gap applies to logoff and to legacy-flow renewal: all three write only to the local
list.

**Attacker gain:** full bypass of rotation replay detection and of logout, for the remaining
lifetime of the token. **Likelihood:** high in any multi-node deployment — no attacker
sophistication is required, and a plain round-robin LB triggers it without an attacker at all.

### Limit 2 — Bounded and lossy

The list is capped at 10240 entries (`src/daemon/security/TokenBlacklist.cpp:12`). On
overflow, `addToken` evicts the soonest-expiring half via `clearSoonestExpiring`, which
**silently un-revokes** them. Keying on `jti` rather than the whole JWT cut per-entry cost
from ~800B to ~16B, so the same cap now holds far more revocations, and the persisted
snapshot is no longer a file of live bearer credentials — but the cap is still finite and the
failure is still only one `LOG_WAR`.

Two secondary losses: the snapshot is written at most once every 60s (`PersistManager.cpp`),
so a crash drops up to a minute of revocations even on one node; and the default access-token
TTL is 7 days (`src/common/Utility.h`), so entries sit in the list a long time and the cap is
reached sooner than the token count suggests.

**Attacker gain:** resurrection of a specific revoked token, but only by winning a race the
attacker cannot steer — eviction takes the *soonest-expiring* half, and a token worth stealing
is usually long-lived. **Likelihood:** low, and requires enough revocation volume to overflow.
A correctness and observability problem more than an exploit.

### Limit 3 — No coarse revocation

`User::revokeIssuedTokens()` stamps `m_tokenEpoch`; `checkTokenEpoch` rejects any token whose
`iat` predates it. It is wired to exactly one caller — password change. There is no logout-all
and no administrative "revoke everything for this user" endpoint.

Note the epoch serialises through `to_time_t` (`src/daemon/security/User.cpp`), i.e. whole
seconds, so the comparison must be `<=` rather than `<` or every token issued during that same
second survives the revocation. (Fixed; called out here because any future precision change
must preserve the property.)

## What the Consul backend actually does

Read before proposing to build on it.

- The whole security document lives at one KV key, `/v1/kv/appmesh/security`
  (`src/daemon/security/ConsulConnection.cpp`), YAML-encoded.
- `SecurityConsul::save()` serialises **the entire security object** and blind-PUTs it. The PUT
  passes `flags` (a timestamp) and **no `cas` parameter**. `fetchSecurityJson` even validates
  that `ModifyIndex` is present and then throws it away.
  **Consequence: last-write-wins across the whole document.** Node A bumps a token epoch and
  PUTs; node B, holding a copy fetched before that, locks an unrelated user and PUTs — A's
  epoch bump is gone. Any design that stores revocation state in this blob inherits a
  lost-update bug on every concurrent security mutation.
- Propagation is a watch thread doing a blocking KV query with a 10s wait. The loop condition
  treats a timed-out blocking query (still HTTP 200) as success, so as written the thread
  re-fetches and **replaces the entire `Security` singleton** roughly every 10s regardless of
  whether anything changed. Propagation delay is bounded at ~10s, but the "watch" is
  effectively a poll, and **any state held only in memory on a `User` object is destroyed
  every 10s**. Persisted fields survive; anything else must not exist.
- **The failure mode today is a crash, not a fallback.** On a Consul outage `fetchSecurityJson`
  swallows the error and returns empty, `SecurityConsul::init()` then throws `invalid_argument`
  (`src/daemon/security/SecurityConsul.cpp:16-19`), and that throw is **not caught** anywhere in
  the watch thread — an uncaught exception on a detached thread terminates the daemon.
- Consul is **optional**; the default backend is `SecurityJson`, a local YAML file.

## Options considered

### (a) Replicate the jti denylist over Consul

Mirror each revocation into a Consul KV (e.g. `appmesh/revocations/<jti>`), watch for changes.

- **+** Preserves today's exact semantics cluster-wide; smallest conceptual change.
- **−** Puts a write on the auth hot path: every rotation, every logoff, every legacy renew
  becomes a quorum write. `revokeOnce` is a *linearizability* requirement — a check-then-insert
  against an eventually-consistent replica does not detect replay, it only detects it later.
  Doing it correctly means a synchronous CAS per rotation, on a store that is optional.
- **−** Unbounded key growth in Consul, needing TTL/session machinery the codebase does not
  have (`ConsulConnection` has no session or lock support at all).
- **−** Makes revocation *harder* to degrade: with no Consul we are back to node-local, so the
  guarantee silently changes with deployment shape.
- **Verdict:** rejected as the primary mechanism. The cost lands on the highest-frequency
  operation to fix the lowest-frequency risk.

### (b) Per-user/per-session epochs in the shared security store, shrink the denylist

Move revocation to coarse, low-cardinality state that the existing replication already carries.

- **+** Write volume is proportional to *revocation events*, not *token operations*.
- **+** Replication already exists and already works for the user record — `m_tokenEpoch` is
  serialised and `updateUser` copies it, so it survives the 10s object swap.
- **+** Degrades cleanly: with `SecurityJson` on one node, the same field in the local YAML is
  the same mechanism with a trivially-consistent store.
- **−** Per-*user* epochs are too coarse for rotation: bumping on every renew would log the
  user out of every other session. Rotation needs per-*chain* state.
- **−** Inherits the blind-PUT lost update above, so it needs CAS as a prerequisite.
- **−** ~10s propagation delay: revocation is eventually consistent, not immediate.

### (c) Short access TTLs plus accepted eventual consistency

- **+** Nearly free, no new state, no new dependency, helps every option.
- **+** Directly shrinks limit 2: shorter TTLs mean entries leave the list sooner.
- **−** Does nothing for refresh tokens, which are by construction long-lived and are the
  credential rotation is protecting.
- **−** More renews means more rotations, which makes option (a) worse and node-locality more
  visible.
- **Verdict:** necessary, not sufficient. Adopt as hygiene, not as the answer.

### (d) Split the problem: coarse revocation shared, fine-grained replay made node-affine

The observation that drives the recommendation: these are two requirements with two different
consistency needs, and merging them forces the strict requirement's cost onto the loose one.

- *Revocation* (logout-all, password change, compromise response) is rare, coarse, and
  tolerates ~10s of eventual consistency. It belongs in the shared security store — option (b).
- *Single-use replay detection* on a refresh chain is strict and per-operation, but it does
  **not** need to be global if the chain is pinned to one node. Give the refresh token a `sid`
  (chain id) and an issuing-node claim; a node receiving a refresh token for a chain it does
  not own either forwards it to the owner over machinery that already exists
  (`ForwardingManager::forward`) or rejects it with a re-authenticate hint. `revokeOnce` then
  stays exactly what it is today — local, atomic, correct — and becomes correct cluster-wide by
  construction.
- **−** A refresh chain dies with its owning node; the client must re-login. A real
  availability cost, but bounded, explainable, and it fails *closed*.
- **−** Forwarding on the auth path adds a hop and couples renew latency to a peer.
- **−** Requires new claims and a node identity, and clients must handle the re-authenticate
  response.

## Decision

Adopt **(d)**, with **(c)** as hygiene. Concretely:

1. **Coarse revocation lives in the security store**, extending the existing `m_tokenEpoch`
   pattern: keep the per-user epoch (password change, admin revoke-all, new logout-all
   endpoint) and add a per-session epoch map keyed by `sid`, persisted in the user record so it
   survives the 10s `Security` swap. Fail-**closed** on staleness: a node that cannot confirm
   the epoch rejects. Never fail open on revocation state.
2. **Fine-grained single-use stays node-local and exact**, via node-affine refresh chains and
   the existing `TokenBlacklist`. No new distributed state on the rotation path.
3. **Shorten the default access TTL** from 7 days. The refresh flow now exists precisely so
   short access tokens are practical.

Rationale: this is the only option where the guarantee does not change shape with the
deployment. On a single node with `SecurityJson`, epochs are a local YAML field and every chain
is locally owned — behaviour identical to today, no Consul anywhere. With Consul, the coarse
layer replicates over machinery that already exists and whose write volume stays proportional
to actual revocation events. Neither layer puts a quorum write on the rotation path, and
neither has a mode where a store outage silently degrades revocation to "off".

### Operational posture

| Concern | Position |
|---|---|
| Store unreachable | **Fail closed** for revocation checks. A node that cannot read current epoch state must reject, not accept. Today's behaviour is worse than fail-open: it crashes (see P0). |
| Partition | Coarse revocation is eventually consistent, bounded by the ~10s watch. A partitioned node serves stale epochs and under-revokes for that window; it must not over-revoke. Refresh chains are unaffected — affinity means the owner is authoritative or the chain is unusable. |
| Availability cost | Losing a node kills its refresh chains (re-login). Losing Consul must degrade to "last known security document, read-only" — not to a crash, and not to "revocation disabled". |
| Observability | Today the only signal is one `LOG_WAR` on eviction. Export gauges/counters via the existing prometheus-cpp integration: denylist size, evictions (un-revocations), epoch rejections, security-store fetch failures and staleness age. Eviction must be an alertable counter, not a log line. |

## Phased migration

No flag day. Each phase stands alone and single-node deployments are unaffected throughout.

- **P0 — fix what is broken, independent of this design.**
  (i) `saveSecurity` must use `cas=<ModifyIndex>` and retry on conflict; `fetchSecurityJson`
  already reads the index and only needs to keep it.
  (ii) Wrap the watch-thread body in try/catch so a Consul outage cannot terminate the daemon.
  (iii) Add the metrics above. (iv) Shorten the default access TTL.
- **P1 — coarse revocation.** Add `logout-all` and an admin revoke endpoint on top of the
  existing `revokeIssuedTokens()`. Purely additive: `FromJson` already tolerates a missing epoch
  field, so old records and older nodes keep working.
- **P2 — session epochs.** Add `sid` to issued tokens and a per-session epoch map to the user
  record. Tokens without `sid` fall back to P1 semantics until they expire — no coordinated
  restart.
- **P3 — node-affine chains.** Add the issuing-node claim and forward-or-reject on renew. Guard
  behind a config flag defaulting to off; single-node deployments never take the path.
- **P4 — shrink the denylist.** Once P2/P3 carry the load, the local list only needs to cover
  locally-owned chains and access-token logoff. Revisit the 10240 cap and consider moving the
  snapshot out of `.snapshot`, which the code already flags as a TODO.

## What was **not** verified

- **Nothing was built, run, or tested for this ADR.** It is a read of the source at one point
  in time.
- Consul behaviour is inferred from this code plus Consul's documented blocking-query
  semantics — no live cluster was observed. In particular the claim that the watch thread
  effectively re-inits every ~10s follows from `success` being true on a timed-out blocking
  query; it was not confirmed at runtime.
- The uncaught-exception-terminates-the-daemon path is read off the absence of a handler in the
  watch thread, not observed.
- `SecurityKeycloak` was not audited beyond establishing that the epoch check is unreachable in
  OAuth2 mode, nor was it checked what Keycloak-side revocation already provides.
- Only the REST path was traced. The TCP and WebSocket entry points, the HMAC PSK path, and the
  agent proxy were not checked for their own token-validation paths.
- No SDK or the Rust CLI was checked for its ability to handle a forward-or-reject response on
  renew, so P3's client impact is unquantified.
- No measurement of renew rate, revocation volume, or Consul write cost — the claim that option
  (a)'s write amplification is prohibitive is an argument, not a benchmark.

## References

- ADR 0006 — notes the related constraint that renew blacklists the prior token, and that
  workflow triggers must therefore use a non-renewing token.
- `src/daemon/rest/openapi.yaml:1731` — the currently documented "not replicated across a
  cluster" caveat, which P1–P3 progressively retire.
