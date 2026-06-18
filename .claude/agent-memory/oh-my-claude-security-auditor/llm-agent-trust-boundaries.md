---
name: llm-agent-trust-boundaries
description: Verified trust boundaries for src/sdk/llm-agent (JWT username derivation, run_task RBAC, tool invocation, budget TOCTOU)
metadata:
  type: project
---

Trust boundaries confirmed by reading the C++ daemon (so future reviews don't re-derive):

- **JWT username derivation.** llm-agent `jwt_username` (handler.py) decodes UNSIGNED claims with priority preferred_username > username > sub. Daemon: Keycloak backend uses the same priority (SecurityKeycloak.cpp:234-244); the default/local backend uses `sub` ONLY (RestBase.cpp getJwtUserName -> get_subject). Locally-issued tokens (JwtToken.cpp) set ONLY sub/aud/iss/jti/resource_access — no preferred_username/username. Because the JWT signature binds all claims and get_current_user() rejects forged/modified tokens, an attacker cannot inject a divergent preferred_username. So the claim-priority divergence is NOT exploitable in practice; it is a latent footgun if a future backend issues tokens with an unsigned/secondary username claim the daemon ignores.

- **run_task RBAC.** Daemon apiSendMessage (RestHandler.cpp:1274) enforces PERMISSION_KEY_run_task AND checkAppAccessPermission(app, write=true). So a tool invocation is bounded by the caller's own RBAC on that specific app. tools.py `invoke` does NOT restrict call.name to the advertised `specs()` catalog — the model can run_task ANY app the caller can run, not just metadata.tool apps. Catalog filtering affects discovery only, not invocation. Confused-deputy surface = prompt injection steering the model to a non-tool app within the caller's RBAC.

- **Path sanitizers.** session._safe and budget._path both regex to [A-Za-z0-9_-]; no traversal via tenant/session-id.

- **Budget TOCTOU.** Ledger.check() and Ledger.add() are separate flock cycles; concurrent worker processes can all pass check() before any add(), overrunning the per-tenant quota by up to (#concurrent turns - 1) turns. Defaults: MAX_TOKENS=0 and TENANT_QUOTA=0 (both unlimited); only MAX_ITERATIONS=8 caps a turn by default.

- **No service credentials confirmed.** Handler builds caller-scoped AppMeshClientTCP per request with set_token(caller token); task RPC auth is the daemon-injected APP_MESH_PROCESS_KEY (handled inside AppMeshServerTCP, not in this code). No elevated identity used.
