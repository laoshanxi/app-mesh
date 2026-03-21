import static org.junit.jupiter.api.Assertions.*;
import java.io.File;
import java.io.IOException;
import java.util.Map;
import java.util.logging.Logger;
import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Integration tests using WSS transport (port 6058). */
public class AppMeshClientWSSTest {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClientWSSTest.class.getName());
    private static final String USERNAME = "admin";
    private static final String PASSWORD = "admin123";

    private AppMeshClient client;

    @BeforeEach
    public void setup() {
        client = new AppMeshClientWSS.Builder()
                .host("127.0.0.1")
                .port(6058)
                .disableSSLVerify()
                .build();
        assertNotNull(client, "WSS client should be initialized");
    }

    @AfterEach
    public void tearDown() {
        if (client != null) {
            client.logout();
            client.close();
            client = null;
        }
    }

    @Test
    public void testWSSLoginAndApps() throws IOException {
        String token = client.login(USERNAME, PASSWORD, null, "P1W", "");
        assertNotNull(token);
        assertFalse(token.isEmpty());

        JSONArray apps = client.listApps();
        assertNotNull(apps);
        LOGGER.info("WSS listApps count: " + apps.length());

        boolean auth = client.authenticate(token, "app-view", "");
        assertTrue(auth);
    }

    @Test
    public void testWSSAppCRUD() throws Exception {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        try { client.deleteApp("wss_test_app"); } catch (Exception ignored) {}

        JSONObject app = client.addApp("wss_test_app", new JSONObject()
                .put("name", "wss_test_app")
                .put("command", "echo wss_hello"));
        assertEquals("wss_test_app", app.getString("name"));

        JSONObject fetched = client.getApp("wss_test_app");
        assertEquals("wss_test_app", fetched.getString("name"));

        assertTrue(client.disableApp("wss_test_app"));
        assertTrue(client.enableApp("wss_test_app"));
        assertTrue(client.deleteApp("wss_test_app"));
    }

    @Test
    public void testWSSSyncRun() throws Exception {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        Pair<Integer, String> result = client.runAppSync(
                new JSONObject().put("command", "echo wss_sync"), 10, 20);
        assertNotNull(result.getRight());
        LOGGER.info("WSS sync output: " + result.getRight().trim());
    }

    @Test
    public void testWSSAsyncRun() throws Exception {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        AppMeshClient.AppRun run = client.runAppAsync(
                new JSONObject().put("command", "echo wss_async"), 10, 10);
        assertNotNull(run);
        Integer exitCode = run.wait(true, 15);
        LOGGER.info("WSS async exit code: " + exitCode);
    }

    @Test
    public void testWSSLabels() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        try { client.deleteLabel("wss_tag"); } catch (Exception ignored) {}
        assertTrue(client.addLabel("wss_tag", "wss_val"));
        Map<String, String> labels = client.getLabels();
        assertEquals("wss_val", labels.get("wss_tag"));
        assertTrue(client.deleteLabel("wss_tag"));
    }

    @Test
    public void testWSSConfig() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        assertNotNull(client.getHostResources());
        assertNotNull(client.getConfig());
        assertEquals("DEBUG", client.setLogLevel("DEBUG"));
        assertNotNull(client.getMetrics());
    }

    @Test
    public void testWSSFileTransfer() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        File testFile = new File("/tmp/wss_test_upload.txt");
        java.nio.file.Files.writeString(testFile.toPath(), "wss file test " + System.currentTimeMillis());

        String remotePath = "/tmp/wss_test_remote_" + System.currentTimeMillis() + ".txt";
        client.uploadFile(testFile, remotePath, false);

        File downloaded = new File("/tmp/wss_test_downloaded.txt");
        if (downloaded.exists()) downloaded.delete();
        client.downloadFile(remotePath, downloaded.getAbsolutePath(), false);
        assertTrue(downloaded.exists());

        String content = java.nio.file.Files.readString(downloaded.toPath());
        assertTrue(content.startsWith("wss file test"));

        testFile.delete();
        downloaded.delete();
    }
}
