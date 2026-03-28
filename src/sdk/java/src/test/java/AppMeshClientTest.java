import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
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

public class AppMeshClientTest {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClientTest.class.getName());
    private static final String USERNAME = "admin";
    private static final String PASSWORD = "admin123";

    private AppMeshClient client;

    @BeforeEach
    public void setup() {
        LOGGER.info("setup");
        // Use HTTP transport with SSL verification disabled (connects to 6060)
        client = new AppMeshClient.Builder()
                .baseURL("https://127.0.0.1:6060")
                .disableSSLVerify()
                .build();
        assertNotNull(client, "AppMeshClient should be initialized");
    }

    @AfterEach
    public void tearDown() {
        LOGGER.info("tearDown");
        if (client != null) {
            client.logout();
            client.close();
            client = null;
        }
    }

    @Test
    public void testSetTokenAndCookieFile() throws IOException {
        LOGGER.info("testSetTokenAndCookieFile");

        // Login to get a valid token
        String token = client.login(USERNAME, PASSWORD, null, "P1W", "");
        assertNotNull(token);

        // 1. setToken without cookie file (in-memory)
        AppMeshClient client2 = new AppMeshClient.Builder()
                .baseURL("https://127.0.0.1:6060").disableSSLVerify().build();
        client2.setToken(token);
        JSONArray apps = client2.listApps();
        assertNotNull(apps);
        assertTrue(apps.length() > 0, "setToken in-memory: should list apps");
        LOGGER.info("setToken in-memory: " + apps.length() + " apps");

        // 2. jwtToken constructor without cookie file
        AppMeshClient client3 = new AppMeshClient.Builder()
                .baseURL("https://127.0.0.1:6060").disableSSLVerify().jwtToken(token).build();
        JSONArray apps3 = client3.listApps();
        assertEquals(apps.length(), apps3.length(), "jwtToken constructor: same app count");
        LOGGER.info("jwtToken constructor: " + apps3.length() + " apps");

        // 3. setToken with cookie file
        File tmpFile = File.createTempFile("appmesh_java_test_", ".cookie");
        tmpFile.delete(); // Remove to test lazy creation
        String cookiePath = tmpFile.getAbsolutePath();
        try {
            AppMeshClient client4 = new AppMeshClient.Builder()
                    .baseURL("https://127.0.0.1:6060").disableSSLVerify()
                    .cookieFile(cookiePath).build();
            assertFalse(tmpFile.exists(), "Cookie file should not exist before set_token");
            client4.setToken(token);
            assertTrue(tmpFile.exists(), "Cookie file should be created on set_token");
            JSONArray apps4 = client4.listApps();
            assertEquals(apps.length(), apps4.length());
            LOGGER.info("setToken + cookieFile: " + apps4.length() + " apps");

            // 4. Reload from cookie file
            AppMeshClient client5 = new AppMeshClient.Builder()
                    .baseURL("https://127.0.0.1:6060").disableSSLVerify()
                    .cookieFile(cookiePath).build();
            JSONArray apps5 = client5.listApps();
            assertEquals(apps.length(), apps5.length(), "Reload from cookie file: same app count");
            LOGGER.info("Reload from cookieFile: " + apps5.length() + " apps");

            // 5. jwtToken + cookieFile constructor
            tmpFile.delete();
            AppMeshClient client6 = new AppMeshClient.Builder()
                    .baseURL("https://127.0.0.1:6060").disableSSLVerify()
                    .jwtToken(token).cookieFile(cookiePath).build();
            assertTrue(tmpFile.exists(), "Cookie file created via jwtToken+cookieFile");
            JSONArray apps6 = client6.listApps();
            assertEquals(apps.length(), apps6.length());
            LOGGER.info("jwtToken + cookieFile: " + apps6.length() + " apps");

            client2.close();
            client3.close();
            client4.close();
            client5.close();
            client6.close();
        } finally {
            tmpFile.delete();
        }
    }

    @Test
    public void testLoginAndAuthentication() throws IOException {
        LOGGER.info("testLoginAndAuthentication");
        String token = client.login(USERNAME, PASSWORD, null, "P1W", "");
        assertNotNull(token, "Login should return a non-null token");
        assertFalse(token.isEmpty(), "Token should not be empty");

        token = client.renewToken("P1D");
        assertNotNull(token, "Renew should return a non-null token");

        JSONArray apps = client.listApps();
        assertNotNull(apps, "listApps should return a non-null JSONArray");
        LOGGER.info("All applications count: " + apps.length());

        Pair<Boolean, String> authResult = client.authenticate(token, "app-view", "");
        assertTrue(authResult.getLeft(), "User should be authenticated with the token");

        boolean loggedOut = client.logout();
        assertTrue(loggedOut, "User should be successfully logged out");
    }

    @Test
    public void testApp() throws Exception {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        // Create a test app so we don't depend on pre-existing apps
        JSONObject testApp = new JSONObject()
                .put("name", "test_ping")
                .put("command", "ping -c 1 127.0.0.1");
        client.addApp("test_ping", testApp);

        client.getAppOutput("test_ping", 0, 0, 0, "", 0);

        boolean appDisable = client.disableApp("test_ping");
        assertTrue(appDisable, "disableApp");

        boolean appEnable = client.enableApp("test_ping");
        assertTrue(appEnable, "enableApp");

        client.deleteApp("test_ping");

        // Test runAppSync with lifecycle parameter
        JSONObject appJson = new JSONObject();
        appJson.put("command", "echo hello_sync");
        Pair<Integer, String> pair = client.runAppSync(appJson, 10, 20);
        assertNotNull(pair.getRight(), "runAppSync should return output");
        LOGGER.info("runAppSync output: " + pair.getRight().trim());

        // Test runAppAsync
        JSONObject asyncApp = new JSONObject();
        asyncApp.put("command", "echo hello_async");
        AppMeshClient.AppRun run = client.runAppAsync(asyncApp, 10, 10);
        assertNotNull(run, "runAppAsync should return AppRun");
        Integer exitCode = run.wait(true, 15);
        LOGGER.info("Async run exit code: " + exitCode);
    }

    @Test
    public void testFile() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        // Create a small local file for upload test
        File testFile = new File("/tmp/test_java_sdk_upload.txt");
        java.nio.file.Files.writeString(testFile.toPath(), "hello from java sdk test " + System.currentTimeMillis());

        // Upload the small file (use unique name to avoid "file already exist" conflict)
        String remotePath = "/tmp/test_java_sdk_remote_" + System.currentTimeMillis() + ".txt";
        client.uploadFile(testFile, remotePath, false);

        // Download it back
        File downloaded = new File("/tmp/test_java_sdk_downloaded.txt");
        if (downloaded.exists()) downloaded.delete();
        client.downloadFile(remotePath, downloaded.getAbsolutePath(), false);
        assertTrue(downloaded.exists(), "Downloaded file should exist");

        String content = java.nio.file.Files.readString(downloaded.toPath());
        assertTrue(content.startsWith("hello from java sdk test"), "Downloaded content should match uploaded");

        // Cleanup
        testFile.delete();
        downloaded.delete();
    }

    @Test
    public void testInvalidLogin() {
        assertThrows(IOException.class, () -> {
            client.login("invalidUser", "invalidPassword", null, "P1W", "");
        }, "Login with invalid credentials should throw an IOException");
    }

    @Test
    public void testAppHealth() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        // Create a test app with a health check
        JSONObject testApp = new JSONObject()
                .put("name", "health_test")
                .put("command", "sleep 30")
                .put("health_check_cmd", "echo ok");
        client.addApp("health_test", testApp);

        try {
            // App may not be immediately healthy; just verify the API doesn't throw
            client.checkAppHealth("health_test");
        } finally {
            client.deleteApp("health_test");
        }

        // Non-existent app should return false, not throw
        assertFalse(client.checkAppHealth("nonexistent_app_xyz"));
    }

    @Test
    public void testUser() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");
        assertNotNull(client.getUserPermissions(), "permissions should not be null");
        assertNotNull(client.getCurrentUser(), "currentUser should not be null");
        assertNotNull(client.viewRoles(), "roles should not be null");
        LOGGER.info("User permissions: " + client.getUserPermissions());
    }

    @Test
    public void testAppAddAndView() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        // Clean up first
        try { client.deleteApp("testApp"); } catch (Exception ignored) {}

        JSONObject newAppConfig = new JSONObject()
                .put("name", "testApp")
                .put("command", "echo 'Hello, AppMesh!'")
                .put("description", "Test application");

        JSONObject addedApp = client.addApp("testApp", newAppConfig);
        assertNotNull(addedApp, "addApp should return a non-null JSONObject");
        assertEquals("testApp", addedApp.getString("name"), "Added app should have the correct name");

        JSONObject viewedApp = client.getApp("testApp");
        assertNotNull(viewedApp, "viewApp for 'testApp' should return a non-null JSONObject");
        assertEquals("testApp", viewedApp.getString("name"), "Viewed app should have the correct name");

        // Cleanup
        client.deleteApp("testApp");
    }

    @Test
    public void testHostResources() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");
        JSONObject resources = client.getHostResources();
        assertNotNull(resources, "getHostResources should return a non-null JSONObject");

        JSONObject config = client.getConfig();
        assertNotNull(config, "getConfig should return a non-null JSONObject");

        assertEquals("DEBUG", client.setLogLevel("DEBUG"));
    }

    @Test
    public void testLabel() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        // Cleanup first
        try { client.deleteLabel("ABC"); } catch (Exception ignored) {}

        Map<String, String> labels = client.getLabels();
        assertNotNull(labels, "getLabels should return non-null");

        assertTrue(client.addLabel("ABC", "DEF"), "addLabel should succeed");
        assertTrue(client.getLabels().containsKey("ABC"), "Label ABC should exist");

        assertTrue(client.deleteLabel("ABC"), "deleteLabel should succeed");
        assertFalse(client.getLabels().containsKey("ABC"), "Label ABC should be removed");

        String metrics = client.getMetrics();
        assertNotNull(metrics, "getMetrics should return non-null");
    }
}
