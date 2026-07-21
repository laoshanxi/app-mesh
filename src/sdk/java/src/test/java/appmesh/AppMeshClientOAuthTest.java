package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.io.IOException;
import java.util.logging.Logger;

import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Live integration tests for {@link AppMeshClientOAuth} against a real Keycloak instance.
 *
 * <p>Gated on the {@code KEYCLOAK_URL} environment variable (e.g. {@code http://localhost:8080});
 * skipped cleanly when unset. Uses the documented test realm defaults (realm
 * {@code appmesh-realm}, client {@code appmesh-client}, user {@code mesh}); the confidential
 * client secret is read from the {@code APPMESH_Keycloak_client_secret} environment variable
 * and is never logged.
 */
public class AppMeshClientOAuthTest {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClientOAuthTest.class.getName());

    private static final String KEYCLOAK_URL = System.getenv("KEYCLOAK_URL");
    private static final String REALM = envOrDefault("KEYCLOAK_REALM", "appmesh-realm");
    private static final String CLIENT_ID = envOrDefault("KEYCLOAK_CLIENT_ID", "appmesh-client");
    private static final String CLIENT_SECRET = System.getenv("APPMESH_Keycloak_client_secret");
    private static final String USERNAME = envOrDefault("KEYCLOAK_USER", "mesh");
    private static final String PASSWORD = envOrDefault("KEYCLOAK_PASSWORD", "mesh123");

    private AppMeshClientOAuth client;

    private static String envOrDefault(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isEmpty()) ? fallback : value;
    }

    @BeforeEach
    public void setup() {
        assumeTrue(KEYCLOAK_URL != null && !KEYCLOAK_URL.isEmpty(),
                "KEYCLOAK_URL not set - skipping live Keycloak OAuth tests");
        client = new AppMeshClientOAuth.Builder()
                .oauth2(new AppMeshClientOAuth.Oauth2Config(KEYCLOAK_URL, REALM, CLIENT_ID, CLIENT_SECRET))
                .baseURL("https://127.0.0.1:6060")
                .disableSSLVerify()
                .autoRefreshToken(false)
                .build();
    }

    @AfterEach
    public void tearDown() {
        if (client != null) {
            client.close();
            client = null;
        }
    }

    @Test
    public void testPasswordLoginUserinfoRenewLogout() throws IOException {
        LOGGER.info("testPasswordLoginUserinfoRenewLogout");

        // Direct Access Grant login
        client.login(USERNAME, PASSWORD, null);
        JSONObject token = client.oauthTokenSnapshot();
        String accessToken = token.getString("access_token");
        String refreshToken = token.getString("refresh_token");
        assertNotNull(accessToken);
        assertNotNull(refreshToken);

        // Userinfo straight from Keycloak
        JSONObject userinfo = client.getOauthUserinfo();
        assertEquals(USERNAME, userinfo.getString("preferred_username"));

        // Renew: Keycloak rotates the refresh token, the full response must be replaced
        String newAccessToken = client.renewToken();
        JSONObject renewed = client.oauthTokenSnapshot();
        assertNotNull(newAccessToken);
        assertNotEquals(accessToken, newAccessToken, "access token should be re-issued on renew");
        assertNotEquals(refreshToken, renewed.getString("refresh_token"),
                "refresh token should be rotated on renew");

        // Logout: Keycloak session revocation runs first, then the daemon logoff. The daemon may
        // not be reachable in a Keycloak-only test environment; that failure is tolerated here.
        try {
            client.logout();
        } catch (IOException e) {
            LOGGER.info("daemon logoff unavailable in this environment: " + e.getMessage());
        }
        assertNull(client.oauthTokenSnapshot().optString("refresh_token", null),
                "local token state should be cleared after logout");
        assertThrows(AppMeshAuthException.class, () -> client.renewToken(),
                "renew after logout should fail without a refresh token");
    }

    @Test
    public void testDeviceFlowNonInteractive() throws IOException {
        LOGGER.info("testDeviceFlowNonInteractive");

        // RFC 8628 §3.1/3.2: device authorization request
        AppMeshClientOAuth.DeviceAuthResponse device =
                client.requestDeviceAuthorization("openid profile email");
        assertNotNull(device.getDeviceCode(), "device_code expected");
        assertNotNull(device.getUserCode(), "user_code expected");
        assertNotNull(device.getVerificationUri(), "verification_uri expected");
        assertTrue(device.getInterval() > 0, "interval expected");
        assertTrue(device.getExpiresIn() > 0, "expires_in expected");

        // RFC 8628 §3.4/3.5: a single unauthorized poll must report authorization_pending
        // (slow_down is also legal when polling immediately) and must not yield a token
        AppMeshClientOAuth.DeviceTokenResult result = client.pollDeviceToken(device.getDeviceCode());
        assertNull(result.token, "no token before the user approves");
        assertTrue("authorization_pending".equals(result.error) || "slow_down".equals(result.error),
                "expected authorization_pending/slow_down but got: " + result.error);
        assertFalse(client.oauthTokenSnapshot().has("access_token"),
                "client must remain unauthenticated after a pending poll");
    }
}
