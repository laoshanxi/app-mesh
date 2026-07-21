// Live integration tests for AppMeshClientOAuth against a real Keycloak server.
// Gated by KEYCLOAK_URL: skipped cleanly when unset.
//
// Environment:
//   KEYCLOAK_URL                    - Keycloak base URL (e.g. http://localhost:8080), required
//   KEYCLOAK_REALM                  - realm name (default: appmesh-realm)
//   KEYCLOAK_CLIENT_ID              - client id (default: appmesh-client)
//   APPMESH_Keycloak_client_secret  - client secret (optional, confidential clients)
//   KEYCLOAK_USER / KEYCLOAK_PASS   - test user credentials (default: mesh / mesh123)
import { AppMeshClientOAuth } from "../src/appmesh_oauth.js";

const keycloakUrl = process.env.KEYCLOAK_URL;
if (!keycloakUrl) {
  console.log(
    "SKIP: KEYCLOAK_URL not set - skipping OAuth live integration tests",
  );
  process.exit(0);
}

const oauth2 = {
  authServerUrl: keycloakUrl,
  realm: process.env.KEYCLOAK_REALM || "appmesh-realm",
  clientId: process.env.KEYCLOAK_CLIENT_ID || "appmesh-client",
  clientSecret: process.env.APPMESH_Keycloak_client_secret || null,
};
const username = process.env.KEYCLOAK_USER || "mesh";
const password = process.env.KEYCLOAK_PASS || "mesh123";
const baseURL = process.env.APPMESH_URL || "https://127.0.0.1:6060";

let passed = 0;
let failed = 0;

async function assert(name, fn) {
  try {
    await fn();
    passed++;
    console.log(`  PASS: ${name}`);
  } catch (error) {
    failed++;
    console.error(`  FAIL: ${name} - ${error.message}`);
  }
}

async function test() {
  // Self-signed local daemon: explicitly disable server certificate verification
  const client = new AppMeshClientOAuth(oauth2, baseURL, {
    rejectUnauthorized: false,
  });

  console.log(
    "=== JavaScript SDK OAuth (Keycloak) Live Integration Tests ===\n",
  );

  // ---- Password login (Direct Access Grant) ----
  await assert("login (password grant)", async () => {
    await client.login(username, password);
    if (!client._oauthToken.access_token)
      throw new Error("expected access_token in token response");
    if (!client._oauthToken.refresh_token)
      throw new Error("expected refresh_token in token response");
    if (client._getAccessToken() !== client._oauthToken.access_token) {
      throw new Error("access_token was not propagated to the base client");
    }
  });

  // ---- Userinfo ----
  await assert("get_oauth_userinfo", async () => {
    const info = await client.get_oauth_userinfo();
    if (!info || info.preferred_username !== username) {
      throw new Error(
        `expected preferred_username "${username}", got "${info && info.preferred_username}"`,
      );
    }
  });

  // ---- Token renewal (refresh token rotation) ----
  await assert("renew_token (refresh token rotated)", async () => {
    const oldRefresh = client._oauthToken.refresh_token;
    await client.renew_token();
    if (!client._oauthToken.access_token)
      throw new Error("expected access_token after renewal");
    if (!client._oauthToken.refresh_token)
      throw new Error("expected refresh_token after renewal");
    if (client._oauthToken.refresh_token === oldRefresh) {
      throw new Error("expected refresh_token to be rotated by Keycloak");
    }
    if (client._getAccessToken() !== client._oauthToken.access_token) {
      throw new Error(
        "renewed access_token was not propagated to the base client",
      );
    }
  });

  // ---- Device flow (RFC 8628), non-interactive ----
  // Verifies the device authorization response and that one token poll returning
  // authorization_pending is handled (the loop continues); then aborts via a
  // sentinel from the _sleep seam instead of waiting for a human to approve.
  await assert(
    "login_device_flow (device auth + authorization_pending handled)",
    async () => {
      const deviceClient = new AppMeshClientOAuth(oauth2, baseURL, {
        rejectUnauthorized: false,
      });
      let device = null;
      let sleeps = 0;
      deviceClient._sleep = async () => {
        sleeps++;
        // sleep #1 precedes poll #1; sleep #2 only happens if poll #1 was
        // authorization_pending and the loop continued - abort there
        if (sleeps >= 2) throw new Error("ABORT_DEVICE_FLOW_TEST");
      };
      let aborted = false;
      try {
        await deviceClient.login_device_flow((resp) => {
          device = resp;
        });
      } catch (error) {
        if (error.message !== "ABORT_DEVICE_FLOW_TEST") throw error;
        aborted = true;
      }
      if (!device)
        throw new Error(
          "expected onPrompt to receive the device authorization response",
        );
      for (const field of [
        "device_code",
        "user_code",
        "verification_uri",
        "interval",
      ]) {
        if (
          device[field] === undefined ||
          device[field] === null ||
          device[field] === ""
        ) {
          throw new Error(
            `expected "${field}" in device authorization response`,
          );
        }
      }
      if (!aborted)
        throw new Error(
          "expected authorization_pending to keep the polling loop running",
        );
    },
  );

  // ---- Logout (Keycloak session revocation + daemon logoff) ----
  await assert("logout", async () => {
    const revoked = await client.logout();
    if (!revoked) throw new Error("expected Keycloak logout to succeed");
    if (client._oauthToken.access_token || client._oauthToken.refresh_token) {
      throw new Error("expected local token to be cleared after logout");
    }
  });

  // ---- Summary ----
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===`);
  if (failed > 0) process.exit(1);
}

test();
