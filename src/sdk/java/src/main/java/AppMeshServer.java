import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * App Mesh server SDK for Java (HTTP transport).
 *
 * <p>Provides methods {@link #taskFetch()} and {@link #taskReturn(byte[])} for application
 * processes to receive payloads from and return results to the App Mesh service.
 */
public class AppMeshServer {
    private static final Logger LOGGER = Logger.getLogger(AppMeshServer.class.getName());
    private static final long RETRY_DELAY_MS = 100;

    /** 0 = unlimited retries (original behavior). */
    private static final int DEFAULT_MAX_RETRIES = 0;

    protected final AppMeshClient client;
    private final int maxRetries;

    /** Create a server-side helper with the default HTTP client and unlimited fetch retries. */
    public AppMeshServer() {
        this(new AppMeshClient.Builder().build(), DEFAULT_MAX_RETRIES);
    }

    /** Create a server-side helper around an existing client with unlimited fetch retries. */
    public AppMeshServer(AppMeshClient client) {
        this(client, DEFAULT_MAX_RETRIES);
    }

    /**
     * Create a server with custom retry configuration.
     *
     * @param client     the underlying client
     * @param maxRetries maximum fetch retries (0 = unlimited)
     */
    public AppMeshServer(AppMeshClient client, int maxRetries) {
        this.client = client;
        this.maxRetries = maxRetries;
    }

    private String[] getRuntimeEnv() {
        String processKey = System.getenv("APP_MESH_PROCESS_KEY");
        String appName = System.getenv("APP_MESH_APPLICATION_NAME");
        if (processKey == null || processKey.isEmpty()) {
            throw new RuntimeException(
                    "Missing environment variable: APP_MESH_PROCESS_KEY. This must be set by App Mesh service.");
        }
        if (appName == null || appName.isEmpty()) {
            throw new RuntimeException(
                    "Missing environment variable: APP_MESH_APPLICATION_NAME. This must be set by App Mesh service.");
        }
        return new String[] { processKey, appName };
    }

    /**
     * Fetch a task payload from the App Mesh service.
     *
     * <p>Retries on non-OK responses with a fixed short delay up to {@code maxRetries}
     * times (0 = unlimited).
     *
     * @return the raw task payload bytes provided by the invoking client
     * @throws IOException if the maximum number of retries is exceeded or an unrecoverable error occurs
     */
    public byte[] taskFetch() throws IOException {
        String[] env = getRuntimeEnv();
        String pkey = env[0];
        String appName = env[1];
        String path = "/appmesh/app/" + URLEncoder.encode(appName, StandardCharsets.UTF_8.name()).replace("+", "%20") + "/task";

        Map<String, String> query = new HashMap<>();
        query.put("process_key", pkey);

        int attempts = 0;

        while (true) {
            long attemptStart = System.nanoTime();
            try {
                HttpURLConnection conn = client.request("GET", path, null, null, query);
                int status = conn.getResponseCode();
                if (status == HttpURLConnection.HTTP_OK) {
                    return Utils.readResponseBytes(conn);
                }
                LOGGER.log(Level.WARNING, "taskFetch failed with status {0}: retrying...", status);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "taskFetch request failed, retrying", e);
            }

            attempts++;
            if (maxRetries > 0 && attempts >= maxRetries) {
                throw new IOException("taskFetch failed after " + attempts + " retries");
            }

            long remainingMs = RETRY_DELAY_MS - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - attemptStart);
            if (remainingMs > 0) {
                try {
                    Thread.sleep(remainingMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new IOException("Interrupted while waiting to retry taskFetch", e);
                }
            }
        }
    }

    /**
     * Return a processing result back to the App Mesh service.
     *
     * @param result the result bytes to return to the invoking client as-is
     */
    public void taskReturn(byte[] result) throws IOException {
        String[] env = getRuntimeEnv();
        String pkey = env[0];
        String appName = env[1];
        String path = "/appmesh/app/" + URLEncoder.encode(appName, StandardCharsets.UTF_8.name()).replace("+", "%20") + "/task";

        Map<String, String> query = new HashMap<>();
        query.put("process_key", pkey);

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
