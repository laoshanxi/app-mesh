package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the sub/pub fixes ported from the Python SDK: the TCP
 * file-transfer guard, the 401 refresh-retry on TCP/WSS transports, and the
 * WSS forwarded-request bearer semantics.
 */
public class SubPubFixesTest {

    private static java.io.InputStream body(String text) {
        return new ByteArrayInputStream(text.getBytes(StandardCharsets.UTF_8));
    }

    private static HttpURLConnection fakeConnection(int status) throws IOException {
        return new HttpURLConnection(new URL("http://appmesh.test")) {
            @Override public void disconnect() {}
            @Override public boolean usingProxy() { return false; }
            @Override public void connect() {}
            @Override public int getResponseCode() { return status; }
            @Override public java.io.InputStream getInputStream() { return body(""); }
        };
    }

    // ------------------------------------------------------------------
    // File transfer must be rejected while the event demuxer owns the read side.
    // ------------------------------------------------------------------

    private static MessageDemuxer startBlockedDemuxer() {
        final LinkedBlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
        MessageDemuxer demuxer = new MessageDemuxer(() -> {
            try {
                byte[] data = queue.poll(60, TimeUnit.SECONDS);
                return data == null ? new byte[0] : data;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return new byte[0];
            }
        });
        demuxer.start();
        return demuxer;
    }

    @Test
    public void testFileTransferRejectedWhileDemuxerActive() throws IOException {
        MessageDemuxer demuxer = startBlockedDemuxer();
        try {
            assertTrue(demuxer.isRunning());
            IOException e = assertThrows(IOException.class,
                    () -> AppMeshClientTCP.ensureNoActiveDemuxer(demuxer));
            assertTrue(e.getMessage().contains("not supported"));
        } finally {
            demuxer.stop();
        }
        // No demuxer (or a stopped one) lets the transfer proceed.
        AppMeshClientTCP.ensureNoActiveDemuxer(null);
        AppMeshClientTCP.ensureNoActiveDemuxer(demuxer);
    }

    // ------------------------------------------------------------------
    // 401 refresh-retry on the TCP transport.
    // ------------------------------------------------------------------

    private static class ScriptedTCPClient extends AppMeshClientTCP {
        final List<String> tokens = new ArrayList<>();
        final List<Integer> statuses = new ArrayList<>();
        int calls;

        ScriptedTCPClient() {
            super("127.0.0.1", 6059);
        }

        @Override
        protected HttpURLConnection doRequest(String method, String path, Object bodyObj,
                Map<String, String> headers, Map<String, String> params, String tokenOverride) {
            calls++;
            tokens.add(tokenOverride);
            int status = statuses.size() >= calls ? statuses.get(calls - 1) : 200;
            try {
                return fakeConnection(status);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private static final class FakeRefreshProvider implements TokenProvider {
        String token;
        int refreshCount;

        FakeRefreshProvider(String token) {
            this.token = token;
        }

        @Override
        public String getAccessToken() {
            return token;
        }

        @Override
        public boolean canRefresh() {
            return true;
        }

        @Override
        public String refreshAccessToken(String rejectedToken) {
            refreshCount++;
            token = "fresh-token";
            return token;
        }
    }

    @Test
    public void testTCP401TriggersSingleRefreshAndReplay() throws IOException {
        ScriptedTCPClient client = new ScriptedTCPClient();
        FakeRefreshProvider provider = new FakeRefreshProvider("stale-token");
        client.setTokenProvider(provider);
        client.statuses.add(HttpURLConnection.HTTP_UNAUTHORIZED);
        client.statuses.add(HttpURLConnection.HTTP_OK);

        HttpURLConnection conn = client.request("GET", "/appmesh/app/test", null, null, null);
        assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
        assertEquals(2, client.calls, "the 401 must replay exactly once");
        assertEquals(1, provider.refreshCount);
        assertEquals("stale-token", client.tokens.get(0));
        assertEquals("fresh-token", client.tokens.get(1), "the replay must carry the refreshed bearer");
    }

    @Test
    public void testTCPSecond401Fails() {
        ScriptedTCPClient client = new ScriptedTCPClient();
        client.setTokenProvider(new FakeRefreshProvider("stale-token"));
        client.statuses.add(HttpURLConnection.HTTP_UNAUTHORIZED);
        client.statuses.add(HttpURLConnection.HTTP_UNAUTHORIZED);

        IOException e = assertThrows(IOException.class,
                () -> client.request("GET", "/appmesh/app/test", null, null, null));
        assertTrue(e.getMessage().contains("failed to replace a rejected access token"));
    }

    @Test
    public void testTCPCallerManagedAuthDisablesRetry() throws IOException {
        ScriptedTCPClient client = new ScriptedTCPClient();
        client.setTokenProvider(new FakeRefreshProvider("stale-token"));
        client.statuses.add(HttpURLConnection.HTTP_UNAUTHORIZED);

        Map<String, String> headers = new HashMap<>();
        headers.put("Authorization", "Bearer caller-token");
        HttpURLConnection conn = client.request("GET", "/appmesh/app/test", null, headers, null);
        assertEquals(HttpURLConnection.HTTP_UNAUTHORIZED, conn.getResponseCode());
        assertEquals(1, client.calls, "an explicit Authorization header must disable the retry");
    }

    // ------------------------------------------------------------------
    // 401 refresh-retry on the WSS transport.
    // ------------------------------------------------------------------

    private static class ScriptedWSSClient extends AppMeshClientWSS {
        final List<String> tokens = new ArrayList<>();
        int calls;

        ScriptedWSSClient() {
            super("127.0.0.1", 6058);
        }

        @Override
        protected HttpURLConnection doRequest(String method, String path, Object bodyObj,
                Map<String, String> headers, Map<String, String> params, String tokenOverride) {
            calls++;
            tokens.add(tokenOverride);
            int status = calls == 1 ? HttpURLConnection.HTTP_UNAUTHORIZED : HttpURLConnection.HTTP_OK;
            try {
                return fakeConnection(status);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Test
    public void testWSS401TriggersSingleRefreshAndReplay() throws IOException {
        ScriptedWSSClient client = new ScriptedWSSClient();
        FakeRefreshProvider provider = new FakeRefreshProvider("stale-token");
        client.setTokenProvider(provider);

        HttpURLConnection conn = client.request("GET", "/appmesh/app/test", null, null, null);
        assertEquals(HttpURLConnection.HTTP_OK, conn.getResponseCode());
        assertEquals(2, client.calls);
        assertEquals(1, provider.refreshCount);
        assertEquals("fresh-token", client.tokens.get(1));
    }

    // ------------------------------------------------------------------
    // WSS forwarded requests carry the bearer, per-request or client-wide.
    // ------------------------------------------------------------------

    @Test
    public void testWSSPerRequestForwardCarriesBearer() {
        Map<String, String> common = new HashMap<>();
        common.put("Authorization", "Bearer tok");
        Map<String, String> extra = new HashMap<>();
        extra.put("X-Target-Host", "10.0.0.2:6059");

        Map<String, String> merged = AppMeshClientWSS.assembleRequestHeaders(common, extra, "Bearer tok");
        assertEquals("Bearer tok", merged.get("Authorization"),
                "a per-request X-Target-Host must receive the bearer");
        assertEquals("10.0.0.2:6059", merged.get("X-Target-Host"));
    }

    @Test
    public void testWSSClientWideForwardCarriesBearer() {
        Map<String, String> common = new HashMap<>();
        common.put("Authorization", "Bearer tok");
        common.put("X-Target-Host", "10.0.0.2:6059");

        Map<String, String> merged = AppMeshClientWSS.assembleRequestHeaders(common, null, "Bearer tok");
        assertEquals("Bearer tok", merged.get("Authorization"));
    }

    @Test
    public void testWSSNonForwardedStripsBearer() {
        Map<String, String> common = new HashMap<>();
        common.put("Authorization", "Bearer tok");

        Map<String, String> merged = AppMeshClientWSS.assembleRequestHeaders(common, null, "Bearer tok");
        assertNull(merged.get("Authorization"), "the gateway session authenticates; no per-request bearer");
    }

    @Test
    public void testWSSExplicitCallerAuthWins() {
        Map<String, String> common = new HashMap<>();
        common.put("Authorization", "Bearer tok");
        Map<String, String> extra = new HashMap<>();
        extra.put("X-Target-Host", "10.0.0.2:6059");
        extra.put("Authorization", "Bearer caller");

        Map<String, String> merged = AppMeshClientWSS.assembleRequestHeaders(common, extra, "Bearer tok");
        assertEquals("Bearer caller", merged.get("Authorization"),
                "an explicit per-request Authorization must not be clobbered");
    }

    // ------------------------------------------------------------------
    // Live-daemon tests (gated on APPMESH_BEARER_TOKEN, like AppMeshClientTest)
    // ------------------------------------------------------------------

    private static String liveBearer() {
        String bearer = System.getenv("APPMESH_BEARER_TOKEN");
        org.junit.jupiter.api.Assumptions.assumeTrue(bearer != null && !bearer.isEmpty(),
                "APPMESH_BEARER_TOKEN is required for live integration tests");
        return bearer;
    }

    private static AppMeshClientTCP liveTCPClient() {
        return new AppMeshClientTCP.Builder().host("127.0.0.1").port(6059)
                .disableSSLVerify().jwtToken(liveBearer()).build();
    }

    @Test
    public void testLiveTCPWaitStreams() throws Exception {
        try (AppMeshClientTCP client = liveTCPClient()) {
            JSONObject app = new JSONObject()
                    .put("name", "live-java-wait-" + System.nanoTime() % 1000000)
                    .put("command", "echo live-java-line-1; echo live-java-line-2")
                    .put("shell", true);
            AppMeshClient.AppRun run = client.runAppAsync(app, 10, 0);
            StringBuilder out = new StringBuilder();
            Integer code = client.waitForAsyncRun(run, (data, position) -> out.append(data), 20);
            assertEquals(Integer.valueOf(0), code);
            assertTrue(out.toString().contains("live-java-line-1"), "stdout not streamed: " + out);
            assertTrue(out.toString().contains("live-java-line-2"), "stdout not streamed: " + out);
        }
    }

    @Test
    public void testLiveTCPFileTransferGuard() throws Exception {
        AppMeshClientTCP client = liveTCPClient();
        try {
            org.json.JSONObject sub = client.subscribe("*", "START");
            String subId = sub.getString("subscription_id");

            IOException e = assertThrows(IOException.class,
                    () -> client.downloadFile("/opt/appmesh/bin/appmesh", "/tmp/e2e-java-guarded", false));
            assertTrue(e.getMessage().contains("not supported"), "got: " + e.getMessage());

            // Unsubscribe removes the callback but the demuxer keeps the read side
            // (Python semantics); the guard still applies on this connection...
            client.unsubscribe(subId);
            IOException still = assertThrows(IOException.class,
                    () -> client.downloadFile("/opt/appmesh/bin/appmesh", "/tmp/e2e-java-still", false));
            assertTrue(still.getMessage().contains("not supported"), "got: " + still.getMessage());
        } finally {
            client.close();
        }

        // ...and a separate client instance (its own connection) transfers fine.
        try (AppMeshClientTCP plain = liveTCPClient()) {
            assertTrue(plain.downloadFile("/opt/appmesh/bin/appmesh", "/tmp/e2e-java-plain", false));
        }
    }

    @Test
    public void testLiveWSSWaitStreams() throws Exception {
        AppMeshClientWSS client = new AppMeshClientWSS.Builder().host("127.0.0.1").port(6058)
                .disableSSLVerify().jwtToken(liveBearer()).build();
        try {
            org.json.JSONObject app = new JSONObject()
                    .put("name", "live-java-wss-" + System.nanoTime() % 1000000)
                    .put("command", "echo wss-java-line")
                    .put("shell", true);
            AppMeshClient.AppRun run = client.runAppAsync(app, 10, 0);
            StringBuilder out = new StringBuilder();
            Integer code = client.waitForAsyncRun(run, (data, position) -> out.append(data), 20);
            assertEquals(Integer.valueOf(0), code);
            assertTrue(out.toString().contains("wss-java-line"), "stdout not streamed: " + out);
        } finally {
            client.close();
        }
    }

    private static final class LiveStaleFreshProvider implements TokenProvider {
        final String valid;
        int refreshCount;

        LiveStaleFreshProvider(String valid) {
            this.valid = valid;
        }

        @Override
        public String getAccessToken() {
            return refreshCount == 0 ? "definitely-stale-token" : valid;
        }

        @Override
        public boolean canRefresh() {
            return true;
        }

        @Override
        public String refreshAccessToken(String rejectedToken) {
            refreshCount++;
            return valid;
        }
    }

    @Test
    public void testLiveTCP401RefreshRetry() throws Exception {
        AppMeshClientTCP client = new AppMeshClientTCP.Builder().host("127.0.0.1").port(6059)
                .disableSSLVerify().build();
        LiveStaleFreshProvider provider = new LiveStaleFreshProvider(liveBearer());
        client.setTokenProvider(provider);
        try {
            org.json.JSONArray apps = client.listApps();
            assertTrue(apps.length() > 0, "the replay with the refreshed token must succeed");
            assertEquals(1, provider.refreshCount, "exactly one refresh must happen");
        } finally {
            client.close();
        }
    }
}
