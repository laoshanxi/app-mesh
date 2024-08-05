import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

public class AppMeshClientTest {

    private static final String BASE_URL = "https://127.0.0.1:6060"; // Consider using a config file or env var
    private static final String CA_FILE = "/opt/appmesh/ssl/ca.pem";
    private static final String USERNAME = "admin";
    private static final String PASSWORD = "admin123";

    @Test
    public void testLoginAndAuthentication() throws Exception {
        AppMeshClient client = new AppMeshClient(BASE_URL, CA_FILE);
        assertNotNull(client, "AppMeshClient should initialized");
        String token = client.login(USERNAME, PASSWORD, null, "P1W");
        assertNotNull(token, "Login should return a non-null token");

        token = client.renew("P1D");
        assertNotNull(token, "renew should return a non-null token");

        System.out.println(client.app_view());
        System.out.println(client.app_view("ping"));

        boolean authenticated = client.authentication(token, "app-view");
        assertTrue(authenticated, "User should be authenticated with the token");

        boolean loggedOut = client.logout();
        assertTrue(loggedOut, "User should be successfully logged out");
    }

    @Test
    public void testInvalidLogin() {
        assertThrows(Exception.class, () -> {
            AppMeshClient client = new AppMeshClient(BASE_URL);
            client.login("invalidUser", "invalidPassword", null, "P1W");
        }, "Login with invalid credentials should throw an exception");
    }
}