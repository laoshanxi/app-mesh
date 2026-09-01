package appmesh;

import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;

import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * App Mesh client for interacting with App Mesh REST Service.
 *
 * <p>Supports HTTP, TCP and WSS transports through subclasses.
 * Use {@link Builder} for convenient construction with custom SSL and timeout settings.
 */
public class AppMeshClient implements Closeable {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClient.class.getName());

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String HTTP_USER_AGENT_HEADER_NAME = "User-Agent";
    private static final String HTTP_USER_AGENT = "appmesh/java";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_CONTENT_TYPE = "application/json; utf-8";

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 300_000;

    // Platform-aware default SSL directory (matches Python SDK)
    private static final String DEFAULT_SSL_DIR =
            System.getProperty("os.name", "").toLowerCase().contains("win")
                    ? "c:/local/appmesh/ssl" : "/opt/appmesh/ssl";
    private static final String DEFAULT_SSL_CA_CERT = DEFAULT_SSL_DIR + "/ca.pem";

    private final String baseURL;
    private final AtomicReference<String> jwtToken = new AtomicReference<>(null);
    private volatile String forwardTo;

    // Per-instance SSL (avoids modifying JVM global defaults)
    private final SSLSocketFactory sslSocketFactory;
    private final boolean disableHostnameVerification;

    // Timeout settings
    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    /**
     * Internal constructor used by Builder and subclasses.
     */
    protected AppMeshClient(Builder builder) {
        this.baseURL = Objects.requireNonNull(builder.baseURL, "Base URL cannot be null");
        this.connectTimeoutMs = builder.connectTimeoutMs;
        this.readTimeoutMs = builder.readTimeoutMs;
        this.disableHostnameVerification = builder.disableSSLVerification;

        if (builder.jwtToken != null) {
            this.jwtToken.set(builder.jwtToken);
        }

        // Explicit non-empty CA path must be readable; auto-detected defaults fall back to system trust
        if (builder.caCertExplicitlySet && !builder.disableSSLVerification && builder.caCertFilePath != null
                && !builder.caCertFilePath.isEmpty() && !new java.io.File(builder.caCertFilePath).canRead()) {
            throw new IllegalArgumentException("CA certificate file not found or unreadable: " + builder.caCertFilePath);
        }
        // Build per-instance SSLContext
        SSLSocketFactory factory = null;
        if (builder.caCertFilePath != null || builder.clientCertFilePath != null || builder.disableSSLVerification) {
            try {
                javax.net.ssl.SSLContext sc = Utils.createSSLContext(
                        builder.caCertFilePath, builder.clientCertFilePath,
                        builder.clientCertKeyFilePath, builder.keyPassword,
                        builder.disableSSLVerification);
                factory = sc.getSocketFactory();
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to create SSL context", e);
                throw new RuntimeException("Failed to initialize AppMeshClient SSL", e);
            }
        }
        this.sslSocketFactory = factory;
    }

    /** Builder for {@link AppMeshClient}. */
    public static class Builder {
        private String baseURL = "https://127.0.0.1:6060";
        private String caCertFilePath;
        private String clientCertFilePath;
        private String clientCertKeyFilePath;
        private char[] keyPassword;
        private String jwtToken;
        private boolean disableSSLVerification = false;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        private boolean sslPathsExplicitlySet = false;
        private boolean caCertExplicitlySet = false;

        public Builder() {
            // Auto-detect only the trust anchor. Client identities are always opt-in.
            if (new java.io.File(DEFAULT_SSL_DIR).isDirectory()) {
                this.caCertFilePath = DEFAULT_SSL_CA_CERT;
            }
        }

        /** AppMesh service base URL (default: {@code https://127.0.0.1:6060}). */
        public Builder baseURL(String baseURL) {
            this.baseURL = baseURL;
            return this;
        }

        /**
         * Path to a CA certificate bundle for server verification (overrides auto-detected default).
         * An explicit missing/unreadable path fails {@link #build()}; null/empty means system default trust.
         */
        public Builder caCert(String caCertFilePath) {
            this.caCertFilePath = caCertFilePath;
            this.sslPathsExplicitlySet = true;
            this.caCertExplicitlySet = true;
            return this;
        }

        /** Client certificate and key paths for mutual TLS (overrides auto-detected defaults). */
        public Builder clientCert(String clientCertFilePath, String clientCertKeyFilePath) {
            this.clientCertFilePath = clientCertFilePath;
            this.clientCertKeyFilePath = clientCertKeyFilePath;
            this.sslPathsExplicitlySet = true;
            return this;
        }

        /** Password for encrypted private key (default: none). */
        public Builder keyPassword(char[] password) {
            this.keyPassword = password;
            return this;
        }

        /** Disable SSL verification (insecure — development only). Clears any auto-detected certificate paths. */
        public Builder disableSSLVerify() {
            this.disableSSLVerification = true;
            if (!sslPathsExplicitlySet) {
                this.caCertFilePath = null;
                this.clientCertFilePath = null;
                this.clientCertKeyFilePath = null;
            }
            return this;
        }

        /** Initialize with an existing JWT token (no server verification). */
        public Builder jwtToken(String jwtToken) {
            this.jwtToken = jwtToken;
            return this;
        }

        /** Connection timeout in milliseconds (default: 30000). */
        public Builder connectTimeoutMs(int ms) {
            this.connectTimeoutMs = ms;
            return this;
        }

        /** Read timeout in milliseconds (default: 300000 = 5 min). */
        public Builder readTimeoutMs(int ms) {
            this.readTimeoutMs = ms;
            return this;
        }

        public AppMeshClient build() {
            return new AppMeshClient(this);
        }
    }

    @FunctionalInterface
    public interface OutputHandler {
        void handle(String data, long position);
    }

    public static final OutputHandler PRINT_OUTPUT_HANDLER = (data, position) -> System.out.print(data);

    /** Application output container for {@link #getAppOutput}. */
    public static class AppOutput {
        boolean httpSuccess;
        String httpBody;
        Long outputPosition;
        Integer exitCode;

        /** Whether the server answered the output query with HTTP 200. */
        public boolean isSuccess() {
            return httpSuccess;
        }

        /** The output chunk (or error body when {@link #isSuccess()} is false). */
        public String getOutput() {
            return httpBody;
        }

        /** Next output read cursor, or null when the server did not report one. */
        public Long getOutputPosition() {
            return outputPosition;
        }

        /** Process exit code, or null while the process is still running. */
        public Integer getExitCode() {
            return exitCode;
        }
    }

    /** Represents an asynchronous run on the server. */
    public static class AppRun {
        private final String appName;
        private final String procUid;
        private final AppMeshClient clientRef;
        private final String forwardingHost;

        public AppRun(AppMeshClient client, String appName, String processId) {
            this.appName = appName;
            this.procUid = processId;
            this.clientRef = client;
            this.forwardingHost = client.forwardTo;
        }

        public String getAppName() {
            return appName;
        }

        /** The process UUID assigned by the server for this run. */
        public String getProcessUuid() {
            return procUid;
        }

        public AppMeshClient getClient() {
            return clientRef;
        }

        public String getForwardingHost() {
            return forwardingHost;
        }

        /** Wait for this run to finish, streaming stdout to the handler. See {@link AppMeshClient#waitForAsyncRun}. */
        public Integer wait(OutputHandler stdoutHandler, int timeoutSeconds) throws Exception {
            return clientRef.waitForAsyncRun(this, stdoutHandler, timeoutSeconds);
        }
    }

    /**
     * Set the forwarding host (X-Target-Host) applied to all subsequent requests.
     *
     * <p>Thread-safety note: this mutates shared client state — every in-flight and future
     * request on this client instance is affected. {@link AppRun#wait} temporarily overrides
     * and restores it, so do not share one client between threads that rely on different
     * forwarding hosts concurrently.
     */
    public void setForwardTo(String host) {
        this.forwardTo = host;
    }

    @Override
    public void close() {
        this.jwtToken.set(null);
    }

    // -------- Bearer authentication --------

    /** Attach a caller-owned access token in memory. */
    public void setBearerToken(String token) {
        String value = token == null ? null : token.trim();
        this.jwtToken.set(value == null || value.isEmpty() ? null : value);
    }

    /** Source-compatible alias for {@link #setBearerToken(String)}. */
    public void setToken(String token) {
        setBearerToken(token);
    }

    /** Remove the locally attached bearer without contacting Engine or the authentication service. */
    public void clearBearerToken() {
        this.jwtToken.set(null);
    }

    /** Return the current in-memory access token, or null. */
    public String getToken() {
        return this.jwtToken.get();
    }

    /** Return Engine's public OAuth/OIDC configuration. */
    public JSONObject getAuthConfig() throws IOException {
        return new JSONObject(Utils.readResponse(request("GET", "/appmesh/auth/config", null, null, null)));
    }

    /** Return the verified principal represented by the current bearer. */
    public JSONObject getCurrentPrincipal() throws IOException {
        return new JSONObject(Utils.readResponse(request("GET", "/appmesh/principal/self", null, null, null)));
    }

    // -------- Labels / Tags --------

    /** List all server labels. */
    public Map<String, String> listLabels() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/labels", null, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        Map<String, String> labels = new HashMap<>();
        for (String key : jsonResponse.keySet()) {
            labels.put(key, jsonResponse.getString(key));
        }
        return labels;
    }

    /** Add or update a label. Throws IOException on failure. */
    public boolean addLabel(String key, String value) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("value", value);
        HttpURLConnection conn = request("PUT", "/appmesh/label/" + encodeURIComponent(key), null, null, params);
        return ensureOk("addLabel", conn);
    }


    /** Delete a label. Returns false when the label does not exist; throws IOException on other failures. */
    public boolean deleteLabel(String key) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/label/" + encodeURIComponent(key), null, null, null);
        return ensureOkOrNotFound("deleteLabel", conn);
    }


    // -------- Application Management --------

    /** List all applications. */
    public JSONArray listApps() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/applications", null, null, null);
        return new JSONArray(Utils.readResponse(conn));
    }

    /** Get one application by name. */
    public JSONObject getApp(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName), null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Check application health (returns {@code true} if healthy). */
    public boolean checkAppHealth(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName) + "/health", null, null,
                null);
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            return false;
        }
        return "0".equals(Utils.readResponse(conn).trim());
    }

    /** Enable an application. Throws IOException on failure. */
    public boolean enableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/enable", null, null,
                null);
        return ensureOk("enableApp", conn);
    }

    /** Disable an application. Throws IOException on failure. */
    public boolean disableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/disable", null, null,
                null);
        return ensureOk("disableApp", conn);
    }

    /** Delete an application. Returns false when the app does not exist; throws IOException on other failures. */
    public boolean deleteApp(String appName) throws IOException {
        return deleteApp(appName, null);
    }

    /** Internal variant with per-request header overrides (e.g. {@code X-Target-Host} forwarding). */
    boolean deleteApp(String appName, Map<String, String> extraHeaders) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + encodeURIComponent(appName), null, extraHeaders,
                null);
        return ensureOkOrNotFound("deleteApp", conn);
    }

    /** Register or update an application. */
    public JSONObject addApp(String appName, JSONObject appJson) throws IOException {
        return addApp(appName, appJson, (String[]) null);
    }

    /**
     * Register or update an application, optionally subscribing to events atomically.
     *
     * <p>When {@code subscribeEvents} is non-null, a subscription is created before the app starts,
     * ensuring no events are missed. The response includes {@code subscription_id} when active.
     * Requires TCP or WebSocket transport; ignored over HTTP.
     *
     * @param subscribeEvents event types: "START", "EXIT", "STDOUT", "ALL", etc.
     */
    public JSONObject addApp(String appName, JSONObject appJson, String... subscribeEvents) throws IOException {
        Map<String, String> query = null;
        if (subscribeEvents != null && subscribeEvents.length > 0) {
            // START may be pushed before the add-app response. The persistent
            // transport's demuxer must own the read side before this request.
            ensureDemuxer();
            query = new HashMap<>();
            query.put("subscribe_events", String.join(",", subscribeEvents));
        }
        HttpURLConnection conn = request("PUT", "/appmesh/app/" + encodeURIComponent(appName), appJson, null, query);
        return new JSONObject(Utils.readResponse(conn));
    }

    /**
     * Subscribe to real-time events for a specific app (or all apps if appName is "*" or null).
     * Requires TCP or WebSocket transport.
     *
     * @param appName application name, or null/"*" for all apps
     * @param events  event types to subscribe, e.g. "START", "EXIT", "STDOUT"
     * @return JSON with subscription_id, app_name, events
     */
    public JSONObject subscribe(String appName, String... events) throws IOException {
        return subscribe(appName, events, null);
    }

    /**
     * Subscribe to real-time events with a callback for event delivery.
     *
     * @param appName  application name, or null/"*" for all apps
     * @param events   event types to subscribe, e.g. "START", "EXIT", "STDOUT"
     * @param callback event callback, or null
     * @return JSON with subscription_id, app_name, events
     */
    public JSONObject subscribe(String appName, String[] events, MessageDemuxer.EventCallback callback)
            throws IOException {
        return subscribe(appName, events, callback, null);
    }

    /** Internal variant with per-request header overrides (e.g. {@code X-Target-Host} forwarding). */
    JSONObject subscribe(String appName, String[] events, MessageDemuxer.EventCallback callback,
            Map<String, String> extraHeaders) throws IOException {
        // A matching event may race the subscribe response once the server installs
        // the subscription, even when the caller did not supply a callback.
        ensureDemuxer();

        String path = "/appmesh/subscribe";
        if (appName != null && !appName.isEmpty() && !"*".equals(appName)) {
            path = "/appmesh/app/" + encodeURIComponent(appName) + "/subscribe";
        }
        Map<String, String> query = null;
        if (events != null && events.length > 0) {
            query = new HashMap<>();
            query.put("events", String.join(",", events));
        }
        HttpURLConnection conn = request("POST", path, null, extraHeaders, query);
        JSONObject result = new JSONObject(Utils.readResponse(conn));

        // Events received before this point are held by the demuxer's bounded buffer.
        if (callback != null && result.has("subscription_id")) {
            String subscriptionId = result.getString("subscription_id");
            MessageDemuxer demuxer = demuxerOrNull();
            if (demuxer != null) {
                demuxer.registerEventCallback(subscriptionId, callback);
            }
        }

        return result;
    }

    /**
     * Unsubscribe from events by subscription ID.
     *
     * @param subscriptionId the subscription ID returned by {@link #subscribe}
     * @return true if unsubscribed successfully
     * @throws IOException on network failure or a non-2xx server response
     */
    public boolean unsubscribe(String subscriptionId) throws IOException {
        return unsubscribe(subscriptionId, null);
    }

    /** Internal variant with per-request header overrides (e.g. {@code X-Target-Host} forwarding). */
    boolean unsubscribe(String subscriptionId, Map<String, String> extraHeaders) throws IOException {
        // Unregister from demuxer first
        MessageDemuxer demuxer = demuxerOrNull();
        if (demuxer != null) {
            demuxer.unregisterEventCallback(subscriptionId);
        }

        Map<String, String> query = new HashMap<>();
        query.put("subscription_id", subscriptionId);
        HttpURLConnection conn = request("DELETE", "/appmesh/subscribe", null, extraHeaders, query);
        return ensureOk("unsubscribe", conn);
    }

    // -------- Application Output & Execution --------

    /**
     * Get incremental stdout/stderr output for a running or completed process.
     *
     * <p>{@code outputPosition} is the next cursor to read from, {@code exitCode} is populated once
     * the process has finished, and {@code timeout} lets the server long-poll for new output.
     */
    public AppOutput getAppOutput(String appName, long stdoutPosition, int stdoutIndex, int stdoutMaxsize,
            String processUuid, int timeout) throws IOException {
        return getAppOutput(appName, stdoutPosition, stdoutIndex, stdoutMaxsize, processUuid, timeout, null);
    }

    /** Internal variant with per-request header overrides (e.g. {@code X-Target-Host} forwarding). */
    AppOutput getAppOutput(String appName, long stdoutPosition, int stdoutIndex, int stdoutMaxsize,
            String processUuid, int timeout, Map<String, String> extraHeaders) throws IOException {
        Map<String, String> query = new HashMap<>();
        query.put("stdout_position", String.valueOf(stdoutPosition));
        query.put("stdout_index", String.valueOf(stdoutIndex));
        query.put("stdout_maxsize", String.valueOf(stdoutMaxsize));
        query.put("process_uuid", processUuid);
        query.put("timeout", String.valueOf(timeout));
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName) + "/output", null,
                extraHeaders, query);
        AppOutput response = new AppOutput();
        response.httpSuccess = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
        response.httpBody = Utils.readResponseSafe(conn);

        String exitCodeStr = conn.getHeaderField("X-Exit-Code");
        if (exitCodeStr != null && !exitCodeStr.isEmpty()) {
            try {
                response.exitCode = Integer.parseInt(exitCodeStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code: " + exitCodeStr, e);
            }
        }

        String outputPositionStr = conn.getHeaderField("X-Output-Position");
        if (outputPositionStr != null && !outputPositionStr.isEmpty()) {
            try {
                response.outputPosition = Long.parseLong(outputPositionStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse output position: " + outputPositionStr, e);
            }
        }
        return response;
    }

    /**
     * Run an application synchronously (blocking).
     *
     * @param appJson   application JSON definition
     * @param maxTime   maximum execution time in seconds
     * @param lifecycle application lifecycle time (0 = server default)
     * @return (exitCode, stdout) pair
     */
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTime, int lifecycle)
            throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(maxTime));
        if (lifecycle > 0) {
            query.put("lifecycle", String.valueOf(lifecycle));
        }
        HttpURLConnection conn = request("POST", "/appmesh/app/syncrun", appJson, null, query);
        String exitCodeHeader = conn.getHeaderField("X-Exit-Code");
        Integer exitCode = null;
        if (exitCodeHeader != null && !exitCodeHeader.isEmpty()) {
            try {
                exitCode = Integer.parseInt(exitCodeHeader);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code header", e);
            }
        }
        return Pair.of(exitCode, Utils.readResponseSafe(conn));
    }

    /**
     * Run an application synchronously (overload without lifecycle).
     */
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTime) throws Exception {
        return runAppSync(appJson, maxTime, 0);
    }

    /**
     * Run an application asynchronously (non-blocking).
     *
     * @param appJson          application JSON definition
     * @param maxTimeSeconds   maximum execution time in seconds
     * @param lifecycleSeconds application lifecycle time in seconds
     * @return an {@link AppRun} handle to track the execution
     */
    public AppRun runAppAsync(JSONObject appJson, long maxTimeSeconds, long lifecycleSeconds) throws Exception {
        return runAppAsyncImpl(appJson, maxTimeSeconds, lifecycleSeconds);
    }

    /**
     * Run an application asynchronously (non-blocking).
     *
     * @param appJson   application JSON definition
     * @param maxTime   maximum execution time as an ISO 8601 duration, e.g. {@code "PT1H"}
     * @param lifecycle application lifecycle time as an ISO 8601 duration
     * @return an {@link AppRun} handle to track the execution
     */
    public AppRun runAppAsync(JSONObject appJson, String maxTime, String lifecycle) throws Exception {
        return runAppAsyncImpl(appJson, Utils.toSeconds(maxTime), Utils.toSeconds(lifecycle));
    }

    private AppRun runAppAsyncImpl(JSONObject appJson, long maxTimeSeconds, long lifecycleSeconds) throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(maxTimeSeconds));
        query.put("lifecycle", String.valueOf(lifecycleSeconds));
        HttpURLConnection conn = request("POST", "/appmesh/app/run", appJson, null, query);
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            String responseBody = Utils.readErrorResponse(conn);
            throw new IOException("Async run failed: HTTP " + conn.getResponseCode() + " - " + responseBody);
        }
        JSONObject jsonResponse = new JSONObject(Utils.readResponse(conn));
        return new AppRun(this, jsonResponse.getString("name"), jsonResponse.getString("process_uuid"));
    }

    /**
     * Wait for an async run to complete, optionally streaming stdout locally.
     *
     * <p>When the process exits, this method makes a best-effort attempt to delete the temporary
     * run app before returning the exit code.
     *
     * <p>The forwarding host captured on the {@link AppRun} is applied per-request without mutating
     * the shared {@link #setForwardTo} state.
     */
    public Integer waitForAsyncRun(AppRun run, OutputHandler stdoutHandler, int timeoutSeconds) throws Exception {
        if (run == null)
            return null;
        Map<String, String> forwardHeaders = forwardHeaders(run.getForwardingHost());
        long lastOutputPosition = 0;
        LocalDateTime start = LocalDateTime.now();
        int interval = 1;
        while (!run.getProcessUuid().isEmpty()) {
            AppOutput appOut = this.getAppOutput(run.getAppName(), lastOutputPosition, 0, 10240,
                    run.getProcessUuid(), interval, forwardHeaders);
            if (appOut.getOutput() != null && stdoutHandler != null) {
                stdoutHandler.handle(appOut.getOutput(), lastOutputPosition);
            }
            if (appOut.getOutputPosition() != null) {
                lastOutputPosition = appOut.getOutputPosition();
            }
            if (appOut.getExitCode() != null) {
                this.deleteApp(run.getAppName(), forwardHeaders);
                return appOut.getExitCode();
            }
            if (!appOut.isSuccess()) {
                break;
            }
            if (timeoutSeconds > 0
                    && java.time.Duration.between(start, LocalDateTime.now()).getSeconds() > timeoutSeconds) {
                break;
            }
        }
        return null;
    }

    // -------- Task Management --------

    /** Send a task payload to a running application and wait for its response body. */
    public String runTask(String appName, String data, int timeout) throws IOException {
        if (timeout <= 0) {
            timeout = 300;
        }
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(timeout));

        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/task", data, null,
                query);

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Task failed: " + Utils.readResponseSafe(conn));
        }
        return Utils.readResponse(conn);
    }

    /** Cancel a running task. Throws IOException on failure. */
    public boolean cancelTask(String appName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + encodeURIComponent(appName) + "/task", null, null,
                null);
        return ensureOk("cancelTask", conn);
    }

    // -------- File Transfer --------

    /**
     * Download a remote file to local disk.
     *
     * <p>When {@code applyFileAttributes} is true, POSIX metadata from response headers is applied
     * locally on a best-effort basis.
     */
    public boolean downloadFile(String filePath, String localFile, boolean applyFileAttributes) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put("X-File-Path", encodeURIComponent(filePath));

        HttpURLConnection conn = request("GET", "/appmesh/file/download", null, headers, null);
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException(Utils.readResponseSafe(conn));
        }
        try (InputStream inputStream = conn.getInputStream();
                OutputStream outputStream = new FileOutputStream(localFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        if (applyFileAttributes) {
            Utils.applyFileAttributes(localFile, conn);
        }
        return true;
    }

    /**
     * Download a remote file to local disk. Uses the remote file's name as the local file name.
     */
    public boolean downloadFile(String remoteFile, boolean applyFileAttributes) throws IOException {
        return downloadFile(remoteFile, new File(remoteFile).getName(), applyFileAttributes);
    }

    /**
     * Upload a local file to the remote server.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent in headers so the
     * server can recreate permissions and ownership when supported.
     */
    public boolean uploadFile(String localFilePath, String remoteFile, boolean preservePermissions)
            throws IOException {
        return uploadFile(new File(localFilePath), remoteFile, preservePermissions);
    }

    /**
     * Upload a local file to the remote server. Uses the local file's name as the remote file name.
     */
    public boolean uploadFile(String localFilePath, boolean preservePermissions) throws IOException {
        return uploadFile(localFilePath, new File(localFilePath).getName(), preservePermissions);
    }

    /**
     * Upload a local file to the remote server.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent in headers so the
     * server can recreate permissions and ownership when supported.
     */
    public boolean uploadFile(File localFile, String remoteFile, boolean preservePermissions) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put("X-File-Path", encodeURIComponent(remoteFile));

        File file = localFile;
        if (!file.exists()) {
            throw new IOException("File not found: " + file.getAbsolutePath());
        }

        if (preservePermissions) {
            headers.putAll(Utils.getFileAttributes(file));
        }

        String boundary = Utils.generateBoundary();
        headers.put(CONTENT_TYPE_HEADER, "multipart/form-data; boundary=" + boundary);

        URL url = Utils.toUrl(this.baseURL + "/appmesh/file/upload");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        applySSL(connection);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        // Stream the request body instead of buffering the whole file in memory
        connection.setChunkedStreamingMode(4096);
        connection.setConnectTimeout(connectTimeoutMs);
        connection.setReadTimeout(readTimeoutMs);
        commonHeaders().forEach(connection::setRequestProperty);
        headers.forEach(connection::setRequestProperty);

        try (OutputStream output = connection.getOutputStream()) {
            Utils.writeMultipartFormData(output, boundary, file);
        }

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            String responseBody = Utils.readErrorResponse(connection);
            LOGGER.severe("HTTP error code: " + responseCode);
            throw new IOException("HTTP error code: " + responseCode + ", Response: " + responseBody);
        }
        return true;
    }

    /**
     * Upload a local file to the remote server. Uses the local file's name as the remote file name.
     */
    public boolean uploadFile(File localFile, boolean preservePermissions) throws IOException {
        return uploadFile(localFile, localFile.getName(), preservePermissions);
    }

    // -------- System & Configuration --------

    /** Get host resource report (CPU, memory, disk). */
    public JSONObject getHostResources() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/resources", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Get App Mesh configuration. */
    public JSONObject getConfig() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/config", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Update configuration (supports partial update). */
    public JSONObject setConfig(JSONObject config) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/config", config, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Update log level (DEBUG/INFO/NOTICE/WARN/ERROR). */
    public String setLogLevel(String level) throws IOException {
        JSONObject config = new JSONObject().put("BaseConfig", new JSONObject().put("LogLevel", level));
        HttpURLConnection conn = request("POST", "/appmesh/config", config, null, null);
        JSONObject cfg = new JSONObject(Utils.readResponse(conn));
        return cfg.getJSONObject("BaseConfig").getString("LogLevel");
    }

    /** Get Prometheus metrics text. */
    public String getMetrics() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/metrics", null, null, null);
        return Utils.readResponse(conn);
    }

    // -------- Principal authorization --------

    /** List Engine authorization overlays keyed by immutable principal ID. */
    public JSONObject listPrincipals() throws IOException {
        return new JSONObject(Utils.readResponse(request("GET", "/appmesh/principals", null, null, null)));
    }

    /** Update an Engine authorization overlay; this never changes IdP account data. */
    public boolean updatePrincipal(String principalId, JSONObject policy) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/principal/" + encodeURIComponent(principalId), policy, null, null);
        return ensureOk("updatePrincipal", conn);
    }

    /** Delete only the Engine authorization overlay for a principal. */
    public boolean deletePrincipal(String principalId) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/principal/" + encodeURIComponent(principalId), null, null, null);
        int status = conn.getResponseCode();
        if (status == HttpURLConnection.HTTP_NO_CONTENT || status == HttpURLConnection.HTTP_OK) return true;
        if (status == HttpURLConnection.HTTP_NOT_FOUND) return false;
        throw new IOException("deletePrincipal failed with status " + status + ": " + Utils.readErrorResponse(conn));
    }

    /** Safe source-compatibility alias; returns a Principal, not an IdP user record. */
    public JSONObject getCurrentUser() throws IOException {
        return getCurrentPrincipal();
    }

    // -------- Permissions & Roles --------

    /** List all available permissions. */
    public Set<String> listPermissions() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/permissions", null, null, null);
        JSONArray jsonArray = new JSONArray(Utils.readResponse(conn));
        Set<String> permissions = new HashSet<>();
        for (int i = 0; i < jsonArray.length(); i++) {
            permissions.add(jsonArray.getString(i));
        }
        return permissions;
    }

    /** List effective permissions for the current verified principal. */
    public Set<String> getPrincipalPermissions() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/principal/self/permissions", null, null, null);
        JSONArray jsonArray = new JSONArray(Utils.readResponse(conn));
        Set<String> permissions = new HashSet<>();
        for (int i = 0; i < jsonArray.length(); i++) {
            permissions.add(jsonArray.getString(i));
        }
        return permissions;
    }

    /** Safe source-compatibility alias for {@link #getPrincipalPermissions()}. */
    public Set<String> getUserPermissions() throws IOException {
        return getPrincipalPermissions();
    }

    /** List all roles and their permissions. */
    public JSONObject listRoles() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/roles", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Update permissions for a role. Throws IOException on failure. */
    public boolean updateRole(String roleName, JSONObject rolePermissionJson) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/role/" + encodeURIComponent(roleName), rolePermissionJson,
                null, null);
        return ensureOk("updateRole", conn);
    }

    /** Delete a role. Returns false when the role does not exist; throws IOException on other failures. */
    public boolean deleteRole(String roleName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/role/" + encodeURIComponent(roleName), null, null, null);
        return ensureOkOrNotFound("deleteRole", conn);
    }

    // -------- Internal Helpers --------

    /**
     * Transport hook: return the message demuxer when the transport supports one, otherwise null.
     * Overridden by demux-capable transports (TCP/WSS).
     */
    protected MessageDemuxer demuxerOrNull() {
        return null;
    }

    /**
     * Transport hook: ensure the message demuxer is running.
     * No-op for transports without demuxing (plain HTTP).
     */
    protected void ensureDemuxer() throws IOException {
    }

    /** Ensure the response is HTTP 200, otherwise throw an IOException carrying status and error body. */
    private boolean ensureOk(String action, HttpURLConnection conn) throws IOException {
        int status = conn.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            throw new IOException(action + " failed with status " + status + ": " + Utils.readErrorResponse(conn));
        }
        return true;
    }

    /** Like {@link #ensureOk} but maps HTTP 404 to false (not-found existence semantics for delete APIs). */
    private boolean ensureOkOrNotFound(String action, HttpURLConnection conn) throws IOException {
        int status = conn.getResponseCode();
        if (status == HttpURLConnection.HTTP_OK) {
            return true;
        }
        if (status == HttpURLConnection.HTTP_NOT_FOUND) {
            return false;
        }
        throw new IOException(action + " failed with status " + status + ": " + Utils.readErrorResponse(conn));
    }

    private Map<String, String> commonHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT);
        String token = this.jwtToken.get();
        if (token != null && !token.isEmpty()) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        }
        if (this.forwardTo != null && !this.forwardTo.isEmpty()) {
            headers.put("X-Target-Host", normalizeForwardHost(this.forwardTo));
        }
        return headers;
    }

    /** Append the base URL port when the forward host carries none. */
    private String normalizeForwardHost(String host) {
        if (host.contains(":")) {
            return host;
        }
        try {
            URL url = Utils.toUrl(this.baseURL);
            int port = url.getPort();
            if (port == -1) {
                port = "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
            }
            return host + ":" + port;
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Failed to parse baseURL", e);
            throw new RuntimeException("Failed to set forward host", e);
        }
    }

    /**
     * Build a per-request {@code X-Target-Host} header map for the given forwarding host,
     * or null when no forwarding is requested. Explicit request headers override
     * {@link #commonHeaders()}, so this wins over the client-wide forward setting.
     */
    Map<String, String> forwardHeaders(String forwardingHost) {
        if (forwardingHost == null || forwardingHost.isEmpty()) {
            return null;
        }
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Target-Host", normalizeForwardHost(forwardingHost));
        return headers;
    }

    /** Accessor for subclasses to reuse common headers. */
    protected Map<String, String> getCommonHeaders() {
        return commonHeaders();
    }

    /** Accessor for subclasses to get the base URL. */
    protected String getBaseURL() {
        return this.baseURL;
    }

    /**
     * Accessor for subclasses to reuse the client-level SSL socket factory
     * (null when no SSL configuration was supplied or auto-detected).
     */
    protected SSLSocketFactory getSSLSocketFactory() {
        return this.sslSocketFactory;
    }

    /** Apply per-instance SSL configuration to a connection (if configured). */
    protected void applySSL(HttpURLConnection connection) {
        if (connection instanceof HttpsURLConnection && sslSocketFactory != null) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) connection;
            httpsConn.setSSLSocketFactory(sslSocketFactory);
            if (disableHostnameVerification) {
                httpsConn.setHostnameVerifier((hostname, session) -> true);
            }
        }
    }

    private String encodeURIComponent(String value) {
        if (value == null)
            return null;
        try {
            String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
            return encoded.replace("+", "%20")
                    .replace("%21", "!")
                    .replace("%27", "'")
                    .replace("%28", "(")
                    .replace("%29", ")")
                    .replace("%7E", "~")
                    .replace("%2A", "*");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }

    /**
     * Core HTTP request helper. Builds URL, attaches headers and body, applies SSL
     * and timeout settings, and returns the {@link HttpURLConnection}.
     */
    public HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params) throws IOException {
        StringBuilder urlBuilder = new StringBuilder(baseURL).append(path);

        if (params != null && !params.isEmpty()) {
            urlBuilder.append('?');
            for (Map.Entry<String, ?> e : params.entrySet()) {
                try {
                    urlBuilder.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8.name()))
                            .append('=')
                            .append(URLEncoder.encode(String.valueOf(e.getValue()), StandardCharsets.UTF_8.name()))
                            .append('&');
                } catch (UnsupportedEncodingException ex) {
                    throw new RuntimeException("Error encoding URL parameters", ex);
                }
            }
            urlBuilder.setLength(urlBuilder.length() - 1);
        }

        URL url = Utils.toUrl(urlBuilder.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method.toUpperCase());
        connection.setConnectTimeout(connectTimeoutMs);
        connection.setReadTimeout(readTimeoutMs);

        // Apply per-instance SSL
        applySSL(connection);

        Map<String, String> allHeaders = new HashMap<>(commonHeaders());
        if (headers != null) {
            allHeaders.putAll(headers);
        }
        allHeaders.forEach(connection::setRequestProperty);

        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            if (body != null) {
                String bodyString;
                if (body instanceof JSONObject) {
                    bodyString = body.toString();
                    connection.setRequestProperty(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
                    connection.setRequestProperty(ACCEPT_HEADER, JSON_CONTENT_TYPE);
                } else if (body instanceof String) {
                    bodyString = (String) body;
                    if (!allHeaders.containsKey(CONTENT_TYPE_HEADER)) {
                        connection.setRequestProperty(CONTENT_TYPE_HEADER, "text/plain; charset=utf-8");
                    }
                } else {
                    bodyString = body.toString();
                }

                connection.setDoOutput(true);
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(bodyString.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }
            }
        }

        return connection;
    }
}
