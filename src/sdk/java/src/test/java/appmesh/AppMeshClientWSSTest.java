package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
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

/** Live WSS integration coverage for the bearer-only 3.0 client. */
public class AppMeshClientWSSTest {
    private AppMeshClient client;

    @BeforeEach
    public void setup() {
        String bearer = System.getenv("APPMESH_BEARER_TOKEN");
        Assumptions.assumeTrue(bearer != null && !bearer.isEmpty(),
                "APPMESH_BEARER_TOKEN is required for live integration tests");
        client = new AppMeshClientWSS.Builder()
                .host("127.0.0.1")
                .port(6058)
                .disableSSLVerify()
                .jwtToken(bearer)
                .build();
    }

    @AfterEach
    public void tearDown() {
        if (client != null) client.close();
    }

    @Test
    public void testBearerAppsAndPrincipal() throws IOException {
        JSONArray apps = client.listApps();
        assertNotNull(apps);
        assertNotNull(client.getCurrentPrincipal());
    }

    @Test
    public void testAppAndLabels() throws IOException {
        String name = "java-wss-bearer-test";
        try { client.deleteApp(name); } catch (Exception ignored) { }
        JSONObject added = client.addApp(name, new JSONObject()
                .put("name", name)
                .put("command", "echo java-wss-bearer"));
        assertEquals(name, added.getString("name"));
        assertTrue(client.deleteApp(name));

        String label = "java_wss_bearer_test";
        try { client.deleteLabel(label); } catch (Exception ignored) { }
        assertTrue(client.addLabel(label, "value"));
        Map<String, String> labels = client.listLabels();
        assertEquals("value", labels.get(label));
        assertTrue(client.deleteLabel(label));
    }
}
