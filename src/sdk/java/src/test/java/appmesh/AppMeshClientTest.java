package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.Map;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Live HTTP integration coverage for the bearer-only 3.0 client. */
public class AppMeshClientTest {
    private AppMeshClient client;

    @BeforeEach
    public void setup() {
        String bearer = System.getenv("APPMESH_BEARER_TOKEN");
        Assumptions.assumeTrue(bearer != null && !bearer.isEmpty(),
                "APPMESH_BEARER_TOKEN is required for live integration tests");
        client = new AppMeshClient.Builder()
                .baseURL("https://127.0.0.1:6060")
                .disableSSLVerify()
                .jwtToken(bearer)
                .build();
    }

    @AfterEach
    public void tearDown() {
        if (client != null) client.close();
    }

    @Test
    public void testBearerPrincipalAndApps() throws IOException {
        assertNotNull(client.getToken());
        assertNotNull(client.getCurrentPrincipal());
        assertNotNull(client.getPrincipalPermissions());
        JSONArray apps = client.listApps();
        assertNotNull(apps);
    }

    @Test
    public void testAppLifecycle() throws IOException {
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
}
