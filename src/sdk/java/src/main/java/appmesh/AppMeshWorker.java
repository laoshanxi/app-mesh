package appmesh;

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
 * App Mesh worker SDK for Java (HTTP transport).
 *
 * <p>Server-side task-loop helper: {@link #fetchTask()} and {@link #sendTaskResult(byte[])} let
 * application processes receive payloads from and return results to the App Mesh service.
 */
public class AppMeshWorker {
    private static final Logger LOGGER = Logger.getLogger(AppMeshWorker.class.getName());
    private static final long RETRY_DELAY_MS = 100;

    protected final AppMeshClient client;
    private volatile boolean stopped = false;

    /** Create a worker-side helper with the default HTTP client. */
    public AppMeshWorker() {
        // Server endpoints use APP_MESH_PROCESS_KEY; no JWT refresh needed.
        this(new AppMeshClient.Builder().autoRefreshToken(false).build());
    }

    /** Create a worker-side helper around an existing client. */
    public AppMeshWorker(AppMeshClient client) {
        this.client = client;
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
     * Request cancellation of the {@link #fetchTask()} retry loop.
     *
     * <p>Safe to call from any thread. A blocked {@code fetchTask()} returns
     * {@code null} at its next retry iteration (interrupting the fetching thread
     * makes it return immediately).
     */
    public void stop() {
        stopped = true;
    }

    /**
     * Fetch a task payload from the App Mesh service.
     *
     * <p>Retries until successful or cancelled via {@link #stop()} (or thread
     * interruption), in which case {@code null} is returned. If a request fails
     * within 100ms, sleeps briefly before retrying; otherwise retries immediately.
     *
     * @return the raw task payload bytes provided by the invoking client, or
     *         {@code null} when the fetch loop was cancelled
     * @throws ProcessSupersededException when the service reports (HTTP 412) that
     *         this process key is no longer valid and the task loop must stop
     */
    public byte[] fetchTask() {
        String[] env = getRuntimeEnv();
        String pkey = env[0];
        String appName = env[1];
        String path;
        try {
            path = "/appmesh/app/" + URLEncoder.encode(appName, StandardCharsets.UTF_8.name()).replace("+", "%20") + "/task";
        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }

        Map<String, String> query = new HashMap<>();
        query.put("process_key", pkey);

        while (!stopped) {
            long attemptStart = System.nanoTime();
            try {
                HttpURLConnection conn = client.request("GET", path, null, null, query);
                int status = conn.getResponseCode();
                if (status == HttpURLConnection.HTTP_OK) {
                    return Utils.readResponseBytes(conn);
                }
                if (status == HttpURLConnection.HTTP_PRECON_FAILED) {
                    LOGGER.log(Level.SEVERE, "Process key mismatch (412): this process has been superseded");
                    throw new ProcessSupersededException(
                            "Process key mismatch (412): this process has been superseded by a newer instance");
                }
                LOGGER.log(Level.WARNING, "fetchTask failed with status {0}: retrying...", status);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "fetchTask request failed, retrying", e);
            }

            long remainingMs = RETRY_DELAY_MS - TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - attemptStart);
            if (remainingMs > 0) {
                try {
                    Thread.sleep(remainingMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return null; // interruption doubles as cancellation
                }
            }
        }
        return null; // cancelled via stop()
    }

    /**
     * Return a processing result back to the App Mesh service.
     *
     * @param result the result bytes to return to the invoking client as-is
     */
    public void sendTaskResult(byte[] result) throws IOException {
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
            LOGGER.log(Level.SEVERE, "sendTaskResult failed with status {0}: {1}", new Object[] { status, err });
            throw new IOException("sendTaskResult failed with status " + status + ": " + err);
        }
    }
}
