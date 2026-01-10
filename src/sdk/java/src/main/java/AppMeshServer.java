import java.io.IOException;
import java.net.HttpURLConnection;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * App Mesh server SDK for Java (HTTP transport).
 *
 * Provides methods `taskFetch` and `taskReturn` for application processes
 * to receive payloads from and return results to the App Mesh service.
 */
public class AppMeshServer {
    private static final Logger LOGGER = Logger.getLogger(AppMeshServer.class.getName());
    private static final long RETRY_DELAY_MS = 100;

    protected final AppMeshClient client;

    public AppMeshServer() {
        this.client = new AppMeshClient.Builder().build();
    }

    public AppMeshServer(AppMeshClient client) {
        this.client = client;
    }

    private String[] getRuntimeEnv() {
        String processKey = System.getenv("APP_MESH_PROCESS_KEY");
        String appName = System.getenv("APP_MESH_APPLICATION_NAME");
        if (processKey == null || processKey.isEmpty()) {
            throw new RuntimeException("Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.");
        }
        if (appName == null || appName.isEmpty()) {
            throw new RuntimeException("Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.");
        }
        return new String[] { processKey, appName };
    }

    public byte[] taskFetch() throws IOException {
        String[] env = getRuntimeEnv();
        String pkey = env[0];
        String appName = env[1];
        String path = "/appmesh/app/" + appName + "/task";

        Map<String, String> query = new HashMap<>();
        query.put("process_key", pkey);

        while (true) {
            HttpURLConnection conn = client.request("GET", path, null, null, query);
            try {
                int status = conn.getResponseCode();
                if (status == HttpURLConnection.HTTP_OK) {
                    return Utils.readResponseBytes(conn);
                }
                LOGGER.log(Level.WARNING, "taskFetch failed with status {0}: retrying...", status);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "taskFetch request failed, retrying", e);
            }

            try {
                Thread.sleep(RETRY_DELAY_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new IOException("Interrupted while waiting to retry taskFetch", e);
            }
        }
    }

    public void taskReturn(byte[] result) throws IOException {
        String[] env = getRuntimeEnv();
        String pkey = env[0];
        String appName = env[1];
        String path = "/appmesh/app/" + appName + "/task";

        Map<String, String> query = new HashMap<>();
        query.put("process_key", pkey);

        // Send result as UTF-8 string. For binary payloads, caller may encode as needed.
        String body = result == null ? "" : new String(result, StandardCharsets.UTF_8);
        HttpURLConnection conn = client.request("PUT", path, body, null, query);
        int status = conn.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            String err = Utils.readErrorResponse(conn);
            LOGGER.log(Level.SEVERE, "taskReturn failed with status {0}: {1}", new Object[] { status, err });
            throw new IOException("taskReturn failed with status " + status + ": " + err);
        }
    }
}
