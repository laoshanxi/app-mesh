package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpServer;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

/** Live HTTP integration coverage for the bearer-only 3.0 client. */
public class AppMeshClientTest {
    private AppMeshClient client;
    private HttpServer server;

    private AppMeshClient newLiveClient() {
        String bearer = System.getenv("APPMESH_BEARER_TOKEN");
        Assumptions.assumeTrue(bearer != null && !bearer.isEmpty(),
                "APPMESH_BEARER_TOKEN is required for live integration tests");
        return new AppMeshClient.Builder()
                .baseURL("https://127.0.0.1:6060")
                .disableSSLVerify()
                .jwtToken(bearer)
                .build();
    }

    @AfterEach
    public void tearDown() {
        if (client != null) client.close();
        if (server != null) server.stop(0);
    }

    @Test
    public void testBearerPrincipalAndApps() throws IOException {
        client = newLiveClient();
        assertNotNull(client.getToken());
        assertNotNull(client.getCurrentPrincipal());
        assertNotNull(client.getPrincipalPermissions());
        JSONArray apps = client.listApps();
        assertNotNull(apps);
    }

    @Test
    public void testAppLifecycle() throws IOException {
        client = newLiveClient();
        String name = "java-bearer-client-test";
        try { client.deleteApp(name); } catch (Exception ignored) { }
        JSONObject added = client.addApp(name, new JSONObject()
                .put("name", name)
                .put("command", "echo java-bearer-client"));
        assertEquals(name, added.getString("name"));
        assertEquals(name, client.getApp(name).getString("name"));
        assertTrue(client.disableApp(name));
        assertTrue(client.enableApp(name));
        assertTrue(client.deleteApp(name));
    }

    @Test
    public void testLabelsAndResources() throws IOException {
        client = newLiveClient();
        String label = "java_bearer_test";
        try { client.deleteLabel(label); } catch (Exception ignored) { }
        assertTrue(client.addLabel(label, "value"));
        Map<String, String> labels = client.listLabels();
        assertEquals("value", labels.get(label));
        assertTrue(client.deleteLabel(label));
        assertFalse(client.listLabels().containsKey(label));
        assertNotNull(client.getHostResources());
        assertNotNull(client.getConfig());
        assertNotNull(client.getMetrics());
    }

    // -------- TokenProvider contract & 401 refresh (local mock server) --------

    /** Refresh-capable fake provider that records how the client drove it. */
    private static class FakeRefreshProvider implements TokenProvider {
        final AtomicInteger refreshCalls = new AtomicInteger();
        final AtomicReference<String> rejectedSeen = new AtomicReference<>();
        volatile String current;

        FakeRefreshProvider(String initial) {
            this.current = initial;
        }

        @Override
        public String getAccessToken() {
            return current;
        }

        @Override
        public boolean canRefresh() {
            return true;
        }

        @Override
        public String refreshAccessToken(String rejectedToken) {
            refreshCalls.incrementAndGet();
            rejectedSeen.set(rejectedToken);
            current = "fresh-token";
            return current;
        }
    }

    private HttpServer startTokenServer(String validToken, AtomicInteger requestCount) throws IOException {
        return startTokenServer(validToken, requestCount, null);
    }

    private HttpServer startTokenServer(String validToken, AtomicInteger requestCount, List<String> authSeen)
            throws IOException {
        HttpServer http = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        http.createContext("/appmesh/", exchange -> {
            requestCount.incrementAndGet();
            String auth = exchange.getRequestHeaders().getFirst("Authorization");
            if (authSeen != null) authSeen.add(auth);
            boolean ok = ("Bearer " + validToken).equals(auth);
            byte[] body = (ok ? "{}" : "unauthorized").getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(ok ? 200 : 401, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
        });
        http.start();
        return http;
    }

    @Test
    public void testRefreshRejectedTokenMatchesSentToken() throws IOException {
        AtomicInteger requestCount = new AtomicInteger();
        List<String> authSeen = Collections.synchronizedList(new ArrayList<>());
        server = startTokenServer("fresh-token", requestCount, authSeen);
        // Each read returns a new token, emulating a provider whose stored token
        // rotates between the client's reads (e.g. a racing refresh).
        AtomicInteger reads = new AtomicInteger();
        AtomicReference<String> rejectedSeen = new AtomicReference<>();
        TokenProvider provider = new TokenProvider() {
            @Override
            public String getAccessToken() {
                return "rotating-token-" + reads.incrementAndGet();
            }

            @Override
            public boolean canRefresh() {
                return true;
            }

            @Override
            public String refreshAccessToken(String rejectedToken) {
                rejectedSeen.set(rejectedToken);
                return "fresh-token";
            }
        };
        client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .tokenProvider(provider)
                .build();

        assertNotNull(client.getConfig());
        assertEquals(2, requestCount.get());
        assertEquals("Bearer " + rejectedSeen.get(), authSeen.get(0),
                "refresh must be driven with the token actually sent on the wire");
        assertEquals("Bearer fresh-token", authSeen.get(1), "retry must carry the refreshed token");
    }

    @Test
    public void testTokenProviderRefreshesOnceOn401() throws IOException {
        AtomicInteger requestCount = new AtomicInteger();
        server = startTokenServer("fresh-token", requestCount);
        FakeRefreshProvider provider = new FakeRefreshProvider("stale-token");
        client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .tokenProvider(provider)
                .build();

        assertNotNull(client.getConfig());
        assertEquals(1, provider.refreshCalls.get(), "refresh must be called at most once");
        assertEquals("stale-token", provider.rejectedSeen.get(), "refresh must receive the rejected token");
        assertEquals(2, requestCount.get(), "exactly one retry after the 401");
        assertEquals("fresh-token", client.getToken());
    }

    @Test
    public void testSecond401AfterRefreshThrows() throws IOException {
        AtomicInteger requestCount = new AtomicInteger();
        server = startTokenServer("never-valid", requestCount);
        FakeRefreshProvider provider = new FakeRefreshProvider("stale-token");
        client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .tokenProvider(provider)
                .build();

        assertThrows(IOException.class, () -> client.getConfig());
        assertEquals(1, provider.refreshCalls.get());
        assertEquals(2, requestCount.get());
    }

    @Test
    public void testStaticTokenDoesNotRefreshOn401() throws IOException {
        AtomicInteger requestCount = new AtomicInteger();
        server = startTokenServer("some-other-token", requestCount);
        client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .jwtToken("stale-token")
                .build();

        assertThrows(IOException.class, () -> client.getConfig());
        assertEquals(1, requestCount.get(), "static tokens are never refreshed");
    }

    @Test
    public void testTokenProviderPrecedenceAndWrapping() {
        FakeRefreshProvider provider = new FakeRefreshProvider("provider-token");
        client = new AppMeshClient.Builder()
                .jwtToken("jwt-token")
                .tokenProvider(provider)
                .build();
        assertEquals("provider-token", client.getToken(), "explicit tokenProvider wins over jwtToken");

        client.setBearerToken("  bearer-token  ");
        assertEquals("bearer-token", client.getToken());
        assertFalse(client.getTokenProvider().canRefresh());

        client.clearBearerToken();
        assertNull(client.getToken());

        client = new AppMeshClient.Builder().jwtToken("  ").build();
        assertNull(client.getToken(), "a blank jwtToken attaches no token");
    }

    @Test
    public void testStaticAccessTokenProviderValidation() {
        assertThrows(IllegalArgumentException.class, () -> new StaticAccessTokenProvider(null));
        assertThrows(IllegalArgumentException.class, () -> new StaticAccessTokenProvider("   "));
        StaticAccessTokenProvider provider = new StaticAccessTokenProvider("  token  ");
        assertEquals("token", provider.getAccessToken());
        assertFalse(provider.canRefresh());
        provider.clear();
        assertNull(provider.getAccessToken());
    }

    // -------- RefreshTokenProvider (local mock token endpoint) --------

    /** Mock OAuth token endpoint that records grant requests and replays queued responses. */
    private static class MockTokenEndpoint {
        final HttpServer server;
        final AtomicInteger hits = new AtomicInteger();
        final List<String> bodies = Collections.synchronizedList(new ArrayList<>());
        final List<String> responses = Collections.synchronizedList(new ArrayList<>());
        volatile int status = 200;

        MockTokenEndpoint(String... jsonResponses) throws IOException {
            Collections.addAll(responses, jsonResponses);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/auth/token", exchange -> {
                hits.incrementAndGet();
                byte[] requestBody = Utils.readAllBytes(exchange.getRequestBody());
                bodies.add(new String(requestBody, StandardCharsets.UTF_8));
                String body = responses.isEmpty() ? "{}" : responses.remove(0);
                byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(bytes);
                }
            });
            server.start();
        }

        String url() {
            return "http://127.0.0.1:" + server.getAddress().getPort() + "/auth/token";
        }

        void stop() {
            server.stop(0);
        }
    }

    @Test
    public void testRefreshTokenProviderUrlPolicy() {
        assertThrows(IllegalArgumentException.class,
                () -> new RefreshTokenProvider("http://example.com/auth/token", "a", "r", 0));
        assertThrows(IllegalArgumentException.class,
                () -> new RefreshTokenProvider("http://192.168.1.10/auth/token", "a", "r", 0));
        assertThrows(IllegalArgumentException.class,
                () -> new RefreshTokenProvider("ftp://127.0.0.1/auth/token", "a", "r", 0));
        assertThrows(IllegalArgumentException.class,
                () -> new RefreshTokenProvider("  ", "a", "r", 0));

        // https and loopback http are accepted without dialing the endpoint
        RefreshTokenProvider https = new RefreshTokenProvider("https://127.0.0.1:1/auth/token", "a", "r", 0);
        assertTrue(https.canRefresh());
        assertEquals("a", https.getAccessToken(), "expiresIn=0 must not trigger a proactive refresh");
        new RefreshTokenProvider("http://127.0.0.1:6060/auth/token", "a", "r", 0);
        new RefreshTokenProvider("http://localhost:6060/auth/token", "a", "r", 0);
        new RefreshTokenProvider("http://[::1]:6060/auth/token", "a", "r", 0);
    }

    @Test
    public void testRefreshTokenProviderProactiveRefreshNearExpiry() throws IOException {
        MockTokenEndpoint endpoint = new MockTokenEndpoint(
                "{\"access_token\":\"fresh-token\",\"expires_in\":3600}");
        try {
            // 1s lifetime: margin (30s) exceeds it, so the first read is already due
            RefreshTokenProvider provider = new RefreshTokenProvider(endpoint.url(), "stale-token", "r1", 1);
            assertEquals("fresh-token", provider.getAccessToken(), "near-expiry token must refresh proactively");
            assertEquals(1, endpoint.hits.get());
            // New token carries a 3600s lifetime, well outside its refresh margin
            assertEquals("fresh-token", provider.getAccessToken());
            assertEquals(1, endpoint.hits.get(), "a fresh token must not be refreshed again");
        } finally {
            endpoint.stop();
        }
    }

    @Test
    public void testRefreshTokenProviderRaceCoalescing() throws IOException {
        MockTokenEndpoint endpoint = new MockTokenEndpoint(
                "{\"access_token\":\"new-token\",\"expires_in\":3600}");
        try {
            RefreshTokenProvider provider = new RefreshTokenProvider(endpoint.url(), "current-token", "r1", 0);
            // A stale rejected token means a racing caller already refreshed: no HTTP call
            assertEquals("current-token", provider.refreshAccessToken("older-token"));
            assertEquals(0, endpoint.hits.get(), "stale rejectedToken must not trigger a grant");
            // The actual current token is refreshed for real
            assertEquals("new-token", provider.refreshAccessToken("current-token"));
            assertEquals(1, endpoint.hits.get());
        } finally {
            endpoint.stop();
        }
    }

    @Test
    public void testRefreshTokenProviderGrantFormAndRotation() throws IOException {
        MockTokenEndpoint endpoint = new MockTokenEndpoint(
                "{\"access_token\":\"a2\",\"refresh_token\":\"r2\",\"expires_in\":3600}",
                "{\"access_token\":\"a3\",\"expires_in\":3600}");
        try {
            RefreshTokenProvider provider = new RefreshTokenProvider(endpoint.url(), "a1", "r1", 0);
            assertEquals("a2", provider.refreshAccessToken(null));
            String first = endpoint.bodies.get(0);
            assertTrue(first.contains("grant_type=refresh_token"), first);
            assertTrue(first.contains("client_id=" + RefreshTokenProvider.DEFAULT_CLIENT_ID), first);
            assertTrue(first.contains("refresh_token=r1"), first);

            // The rotated refresh token r2 must be used for the next grant
            assertEquals("a3", provider.refreshAccessToken(null));
            assertTrue(endpoint.bodies.get(1).contains("refresh_token=r2"), endpoint.bodies.get(1));
        } finally {
            endpoint.stop();
        }
    }

    @Test
    public void testRefreshTokenProviderKeepsRefreshTokenWhenAbsent() throws IOException {
        MockTokenEndpoint endpoint = new MockTokenEndpoint(
                "{\"access_token\":\"a2\",\"expires_in\":3600}",
                "{\"access_token\":\"a3\",\"expires_in\":3600}");
        try {
            RefreshTokenProvider provider = new RefreshTokenProvider(endpoint.url(), "custom-client", "a1", "r1", 0);
            assertEquals("a2", provider.refreshAccessToken(null));
            assertTrue(endpoint.bodies.get(0).contains("client_id=custom-client"), endpoint.bodies.get(0));
            // No rotation in the response: the original refresh token is reused
            assertEquals("a3", provider.refreshAccessToken(null));
            assertTrue(endpoint.bodies.get(1).contains("refresh_token=r1"), endpoint.bodies.get(1));
        } finally {
            endpoint.stop();
        }
    }

    @Test
    public void testRefreshTokenProviderInvalidGrantClearsState() throws IOException {
        MockTokenEndpoint endpoint = new MockTokenEndpoint(
                "{\"error\":\"invalid_grant\",\"error_description\":\"refresh token expired\"}",
                "{\"access_token\":\"a2\",\"expires_in\":3600}");
        try {
            endpoint.status = 400;
            RefreshTokenProvider provider = new RefreshTokenProvider(endpoint.url(), "a1", "r1", 0);
            assertThrows(IOException.class, () -> provider.refreshAccessToken(null));
            assertFalse(provider.canRefresh(), "invalid_grant must drop the refresh token");
            assertThrows(IllegalStateException.class, provider::getAccessToken);

            // Other errors keep the state so a later retry is still possible
            endpoint.status = 500;
            RefreshTokenProvider retryable = new RefreshTokenProvider(endpoint.url(), "a1", "r1", 0);
            assertThrows(IOException.class, () -> retryable.refreshAccessToken(null));
            assertTrue(retryable.canRefresh(), "transient errors must keep the refresh token");
            assertEquals("a1", retryable.getAccessToken());
        } finally {
            endpoint.stop();
        }
    }

    @Test
    public void testRefreshTokenProviderEndToEnd401Retry() throws IOException {
        MockTokenEndpoint endpoint = new MockTokenEndpoint(
                "{\"access_token\":\"fresh-token\",\"expires_in\":3600}");
        AtomicInteger requestCount = new AtomicInteger();
        try {
            server = startTokenServer("fresh-token", requestCount);
            String baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
            RefreshTokenProvider provider = new RefreshTokenProvider(endpoint.url(), "stale-token", "r1", 0);
            client = new AppMeshClient.Builder()
                    .baseURL(baseUrl)
                    .tokenProvider(provider)
                    .build();

            assertNotNull(client.getConfig(), "401 must be healed by the refresh grant and retried");
            assertEquals(1, endpoint.hits.get(), "exactly one refresh grant");
            assertEquals(2, requestCount.get(), "first request 401, retry 200");
            assertEquals("fresh-token", client.getToken());
        } finally {
            endpoint.stop();
        }
    }
}
