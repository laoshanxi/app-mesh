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
        client = new AppMeshClient.Builder().baseURL(BASE_URL).caCert(CA_FILE).clientCert(CLIENT_CERT_FILE, CLIENT_CERT_KET_FILE).build();
        assertNotNull(client, "AppMeshClient should be initialized");
    }

    @AfterEach
    public void tearDown() {
        LOGGER.info("tearDown");
        if (client != null) {
            try {
                client.logout();
            } catch (IOException e) {
                // Log the exception or handle it as appropriate for your testing environment
                System.err.println("Error during logout in tearDown: " + e.getMessage());
            }
            client = null;
        }
    }

    @Test
    public void testLoginAndAuthentication() throws IOException {
        LOGGER.info("testLoginAndAuthentication");
        String token = client.login(USERNAME, PASSWORD, null, "P1W");
        assertNotNull(token, "Login should return a non-null token");

        token = client.renew("P1D");
        assertNotNull(token, "Renew should return a non-null token");

        JSONArray apps = client.appView();
        assertNotNull(apps, "appView should return a non-null JSONArray");
        System.out.println("All applications: " + apps.toString(2));

        JSONObject pingApp = client.appView("ping");
        assertNotNull(pingApp, "appView for 'ping' should return a non-null JSONObject");
        System.out.println("Ping application: " + pingApp.toString(2));

        boolean authenticated = client.authentication(token, "app-view");
        assertTrue(authenticated, "User should be authenticated with the token");

        boolean loggedOut = client.logout();
        assertTrue(loggedOut, "User should be successfully logged out");
    }

    @Test
    public void testApp() throws Exception {
        client.login(USERNAME, PASSWORD, null, "P1W");

        client.appOutput("ping", 0, 0, 0, "", 0); // System.out.println(out.httpBody);

        boolean appDisable = client.appDisable("ping");
        assertTrue(appDisable, "appDisable");

        boolean appEnable = client.appEnable("ping");
        assertTrue(appEnable, "appEnable");

        JSONObject appJson = new JSONObject();
        appJson.put("command", "ping www.github.com");
        Pair<Integer, String> pair = client.runSync(appJson, 3);
        System.out.println(pair.getRight());

        AppMeshClient.AppRun run = client.runAsync(appJson, 10, 10);
        run.wait(true, 0);

    }

    @Test
    public void testFile() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W");

        File file = new File("appsvc");
        if (file.exists()) {
            file.delete();
        }
        file = new File("/tmp/app");
        if (file.exists()) {
            file.delete();
        }
        client.fileDownload("/opt/appmesh/bin/appsvc", "appsvc");
        client.fileUpload("appsvc", "/tmp/app");
        java.nio.file.Files.delete(java.nio.file.Paths.get("appsvc"));
    }

    @Test
    public void testInvalidLogin() {
        assertThrows(IOException.class, () -> {
            client.login("invalidUser", "invalidPassword", null, "P1W");
        }, "Login with invalid credentials should throw an IOException");
    }

    @Test
    public void testAppHealth() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W");
        boolean isHealthy = client.appHealth("ping");
        assertTrue(isHealthy, "The 'ping' application should be healthy");
    }

    @Test
    public void testUser() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W");
        System.out.println(client.permissionsForUser().toString());
        System.out.println(client.userSelf().toString());
        System.out.println(client.rolesView().toString());
    }

    @Test
    public void testAppAddAndView() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W");

        JSONObject newAppConfig =
                new JSONObject().put("name", "testApp").put("command", "echo 'Hello, AppMesh!'").put("description", "Test application");

        JSONObject addedApp = client.appAdd("testApp", newAppConfig);
        assertNotNull(addedApp, "appAdd should return a non-null JSONObject");
        assertEquals("testApp", addedApp.getString("name"), "Added app should have the correct name");

        JSONObject viewedApp = client.appView("testApp");
        assertNotNull(viewedApp, "appView for 'testApp' should return a non-null JSONObject");
        assertEquals("testApp", viewedApp.getString("name"), "Viewed app should have the correct name");
    }

    @Test
    public void testHostResources() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W");
        System.out.println(client.hostResources().toString());
        System.out.println(client.configView().toString());
        assertEquals("DEBUG", client.logLevel("DEBUG").toString());
    }

    @Test
    public void testTag() throws IOException {
        client.login(USERNAME, PASSWORD, null, "P1W");
        System.out.println(client.tagView().toString());
        System.out.println(client.tagAdd("ABC", "DEF"));
        assertTrue(client.tagView().containsKey("ABC"));
        assertTrue(client.tagDelete("ABC"));
        assertTrue(!client.tagView().containsKey("ABC"));

        System.out.println(client.mertic());
    }
}
