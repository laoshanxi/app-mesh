import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;
import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

public class AppMeshClientTest {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClientTest.class.getName());
    private static final String BASE_URL = "https://127.0.0.1:6060"; // Consider using a config file or env var
    private static final String CA_FILE = "/opt/appmesh/ssl/ca.pem";
    private static final String CLIENT_CERT_FILE = "/opt/appmesh/ssl/client.pem";
    private static final String CLIENT_CERT_KET_FILE = "/opt/appmesh/ssl/client-key.pem";
    private static final String USERNAME = "admin";
    private static final String PASSWORD = "admin123";

    private AppMeshClient client;

    @BeforeEach
    public void setup() {
        LOGGER.info("setup");
        client = new AppMeshClient.Builder().baseURL(BASE_URL).caCert(CA_FILE)
                .clientCert(CLIENT_CERT_FILE, CLIENT_CERT_KET_FILE).build();
        assertNotNull(client, "AppMeshClient should be initialized");
    }

    @AfterEach
    public void tearDown() {
        LOGGER.info("tearDown");
        if (client != null) {
            client.logout();
            client = null;
        }
    }

    @Test
    public void testLoginAndAuthentication() throws IOException {
        LOGGER.info("testLoginAndAuthentication");
        String token = client.login(USERNAME, PASSWORD, null, "P1W", "");
        assertNotNull(token, "Login should return a non-null token");

        token = client.renewToken("P1D");
        assertNotNull(token, "Renew should return a non-null token");

        JSONArray apps = client.listApps();
        assertNotNull(apps, "listApps should return a non-null JSONArray");
        System.out.println("All applications: " + apps.toString(2));

        JSONObject pingApp = client.getApp("ping");
        assertNotNull(pingApp, "viewApp for 'ping' should return a non-null JSONObject");
        System.out.println("Ping application: " + pingApp.toString(2));

        boolean authenticated = client.authenticate(token, "app-view", "");
        assertTrue(authenticated, "User should be authenticated with the token");

        boolean loggedOut = client.logout();
        assertTrue(loggedOut, "User should be successfully logged out");
    }

    @Test
    public void testApp() throws Exception {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        client.getAppOutput("ping", 0, 0, 0, "", 0); // System.out.println(out.httpBody);

        boolean appDisable = client.disableApp("ping");
        assertTrue(appDisable, "disableApp");

        boolean appEnable = client.enableApp("ping");
        assertTrue(appEnable, "enableApp");

        JSONObject appJson = new JSONObject();
        appJson.put("command", "ping www.github.com");
        Pair<Integer, String> pair = client.runAppSync(appJson, 3);
        System.out.println(pair.getRight());

        AppMeshClient.AppRun run = client.runAppAsync(appJson, 10, 10);
        run.wait(true, 0);

    }

    @Test
    public void testFile() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        File file = new File("appsvc");
        if (file.exists()) {
            file.delete();
        }
        file = new File("/tmp/app");
        if (file.exists()) {
            file.delete();
        }
        client.downloadFile("/opt/appmesh/bin/appsvc", "appsvc", true);
        client.uploadFile("appsvc", "/tmp/app", true);
        java.nio.file.Files.delete(java.nio.file.Paths.get("appsvc"));
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
        boolean isHealthy = client.checkAppHealth("ping");
        assertTrue(isHealthy, "The 'ping' application should be healthy");
    }

    @Test
    public void testUser() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");
        System.out.println(client.getUserPermissions().toString());
        System.out.println(client.getCurrentUser().toString());
        System.out.println(client.viewRoles().toString());
    }

    @Test
    public void testAppAddAndView() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");

        JSONObject newAppConfig = new JSONObject().put("name", "testApp").put("command", "echo 'Hello, AppMesh!'")
                .put("description", "Test application");

        JSONObject addedApp = client.addApp("testApp", newAppConfig);
        assertNotNull(addedApp, "addApp should return a non-null JSONObject");
        assertEquals("testApp", addedApp.getString("name"), "Added app should have the correct name");

        JSONObject viewedApp = client.getApp("testApp");
        assertNotNull(viewedApp, "viewApp for 'testApp' should return a non-null JSONObject");
        assertEquals("testApp", viewedApp.getString("name"), "Viewed app should have the correct name");
    }

    @Test
    public void testHostResources() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");
        System.out.println(client.getHostResources().toString());
        System.out.println(client.getConfig().toString());
        assertEquals("DEBUG", client.setLogLevel("DEBUG").toString());
    }

    @Test
    public void testTag() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W", "");
        System.out.println(client.getTags().toString());
        System.out.println(client.addTag("ABC", "DEF"));
        assertTrue(client.getTags().containsKey("ABC"));
        assertTrue(client.deleteTag("ABC"));
        assertTrue(!client.getTags().containsKey("ABC"));

        System.out.println(client.getMetrics());
    }
}
