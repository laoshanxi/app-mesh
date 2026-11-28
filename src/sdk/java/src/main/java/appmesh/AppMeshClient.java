package appmesh;

import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.Charset;
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

    // Wire-header names shared with the transport subclasses (same package).
    static final String AUTHORIZATION_HEADER = "Authorization";
    static final String BEARER_PREFIX = "Bearer ";
    static final String X_TARGET_HOST_HEADER = "X-Target-Host";
    static final String X_FILE_PATH_HEADER = "X-File-Path";
    static final String X_FILE_OVERWRITE_HEADER = "X-File-Overwrite";
    static final String X_EXIT_CODE_HEADER = "X-Exit-Code";
    static final String X_OUTPUT_POSITION_HEADER = "X-Output-Position";
    static final String X_OUTPUT_TRUNCATED_HEADER = "X-Output-Truncated";
    static final String X_APP_NAME_HEADER = "X-App-Name";
    static final String X_INPUT_CLOSE_HEADER = "X-Input-Close";
    static final String X_SEND_FILE_SOCKET_HEADER = "X-Send-File-Socket";
    static final String X_RECV_FILE_SOCKET_HEADER = "X-Recv-File-Socket";
    static final String X_APPMESH_PROCESS_KEY_HEADER = "X-AppMesh-Process-Key";
    private static final String HTTP_USER_AGENT_HEADER_NAME = "User-Agent";
    private static final String HTTP_USER_AGENT = "appmesh/java";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_CONTENT_TYPE = "application/json";

    // The daemon answers a sync run with one output page and keeps the run only for a
    // short retention once that page is full.
    /** Maximum size of one sync-run output page, in bytes (visible for tests). */
    static final int SYNC_RUN_OUTPUT_PAGE_BYTES = 5 * 1024 * 1024;
    /** Seconds a truncated sync-run instance stays readable before the daemon removes it. */
    static final int SYNC_RUN_TRUNCATED_RETENTION_SECONDS = 600;

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 300_000;

    // Platform-aware default SSL directory (matches Python SDK)
    private static final String DEFAULT_SSL_DIR =
            System.getProperty("os.name", "").toLowerCase().contains("win")
                    ? "c:/local/appmesh/ssl" : "/opt/appmesh/ssl";
    private static final String DEFAULT_SSL_CA_CERT = DEFAULT_SSL_DIR + "/ca.pem";

    private final String baseURL;
    private final AtomicReference<TokenProvider> tokenProvider = new AtomicReference<>(null);
    private volatile String forwardTo;
    // Opt-in HMAC request signer (REST.RequestSignature hardening); null when disabled.
    private volatile RequestSigner requestSigner;

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

        if (builder.tokenProvider != null) {
            this.tokenProvider.set(builder.tokenProvider);
        } else if (builder.jwtToken != null && !builder.jwtToken.trim().isEmpty()) {
            this.tokenProvider.set(new StaticAccessTokenProvider(builder.jwtToken));
        }
        if (builder.requestSignature != null) {
            this.requestSigner = builder.requestSignature;
        }

        // Explicit non-empty CA path must be readable; auto-detected defaults fall back to system trust
        if (builder.caCertExplicitlySet && !builder.disableSSLVerification && builder.caCertFilePath != null
                && !builder.caCertFilePath.isEmpty() && !new File(builder.caCertFilePath).canRead()) {
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

    /** Applies the shared SSL options (CA, client certificate pair, verify switch) to a builder. */
    protected static Builder configureSSL(Builder base, boolean disableSSLVerification,
            String caCertPath, String clientCertPath, String clientKeyPath) {
        if (caCertPath != null) {
            base.caCert(caCertPath);
        }
        if (clientCertPath != null || clientKeyPath != null) {
            base.clientCert(clientCertPath, clientKeyPath);
        }
        if (disableSSLVerification) {
            base.disableSSLVerify();
        }
        return base;
    }

    /** Builder for {@link AppMeshClient}. */
    public static class Builder {
        private String baseURL = "https://127.0.0.1:6060";
        private String caCertFilePath;
        private String clientCertFilePath;
        private String clientCertKeyFilePath;
        private char[] keyPassword;
        private String jwtToken;
        private TokenProvider tokenProvider;
        private RequestSigner requestSignature;
        private boolean disableSSLVerification = false;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        private boolean sslPathsExplicitlySet = false;
        private boolean caCertExplicitlySet = false;

        public Builder() {
            // Auto-detect only the trust anchor. Client identities are always opt-in.
            if (new File(DEFAULT_SSL_DIR).isDirectory()) {
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

        /**
         * Attach a provider that supplies and refreshes access tokens. Takes precedence
         * over {@link #jwtToken(String)}. Refresh credentials remain provider-private.
         */
        public Builder tokenProvider(TokenProvider tokenProvider) {
            this.tokenProvider = tokenProvider;
            return this;
        }

        /**
         * Enable HMAC request signing (opt-in) with a per-principal API key
         * ({@code POST /appmesh/security/apikeys}). Each request then carries the
         * {@code X-Request-Key}, {@code X-Timestamp}, {@code X-Nonce} and
         * {@code X-Signature} headers. The secret is never logged.
         */
        public Builder requestSignature(String keyId, String secret) {
            this.requestSignature = new RequestSigner(keyId, secret);
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
        this.tokenProvider.set(null);
    }

    // -------- Bearer authentication --------

    /** Attach a refresh-capable provider to this bearer-only Engine client. */
    public void setTokenProvider(TokenProvider provider) {
        this.tokenProvider.set(Objects.requireNonNull(provider, "tokenProvider cannot be null"));
    }

    /** Return the provider currently attached to this Engine client, or null. */
    public TokenProvider getTokenProvider() {
        return this.tokenProvider.get();
    }

    /** Attach a caller-owned, non-refreshing access token. */
    public void setBearerToken(String token) {
        String value = token == null ? null : token.trim();
        if (value == null || value.isEmpty()) {
            this.tokenProvider.set(null);
        } else {
            this.tokenProvider.set(new StaticAccessTokenProvider(value));
        }
    }

    /** Source-compatible alias for {@link #setBearerToken(String)}. */
    public void setToken(String token) {
        setBearerToken(token);
    }

    /** Remove the locally attached bearer without contacting Engine or the authentication service. */
    public void clearBearerToken() {
        this.tokenProvider.set(null);
    }

    /** Return the current in-memory access token, or null. */
    public String getToken() {
        TokenProvider provider = this.tokenProvider.get();
        return provider == null ? null : provider.getAccessToken();
    }

    // -------- Request signature (opt-in hardening) --------

    /**
     * Enable HMAC request signing on every subsequent request (opt-in) with a
     * per-principal API key ({@code POST /appmesh/security/apikeys}). Adds the
     * {@code X-Request-Key}, {@code X-Timestamp}, {@code X-Nonce} and
     * {@code X-Signature} headers on HTTP, TCP and WSS transports. The signature is an
     * integrity layer on top of the bearer, not a replacement for it. The secret is
     * kept in memory only and never logged.
     */
    public void setRequestSignature(String keyId, String secret) {
        this.requestSigner = new RequestSigner(keyId, secret);
    }

    /** Disable request signing; subsequent requests carry no signature headers. */
    public void clearRequestSignature() {
        this.requestSigner = null;
    }

    /** Whether {@link #setRequestSignature} is currently active on this client. */
    public boolean isRequestSignatureEnabled() {
        return this.requestSigner != null;
    }

    /** The attached signer, or null when signing is disabled. */
    protected RequestSigner getRequestSigner() {
        return this.requestSigner;
    }

    /**
     * Attach the four signature headers to a framed (TCP/WSS) request: the query map
     * carries decoded values and the body is the exact frame body (empty for the
     * streamed file endpoints, which sign the empty-string hash).
     */
    protected void applyRequestSignature(Map<String, String> headers, String method, String path,
            Map<String, String> query, byte[] body) {
        RequestSigner signer = this.requestSigner;
        if (signer == null) {
            return;
        }
        signer.attach(headers, method, path, RequestSigner.canonicalQuery(query), body);
    }

    /**
     * Attach the four signature headers to a raw connection with no query and no bound
     * body — used by the streamed file endpoints, which sign the empty-string hash
     * (documented exemption: the file content is not bound into the signature).
     */
    protected void applyRequestSignature(HttpURLConnection connection, String method, String path) {
        RequestSigner signer = this.requestSigner;
        if (signer == null) {
            return;
        }
        Map<String, String> headers = new HashMap<>();
        signer.attach(headers, method, path, "", null);
        headers.forEach(connection::setRequestProperty);
    }

    // -------- SSE side channel --------

    /**
     * Base URL for direct HTTPS requests (the SSE side channel): the plain HTTP transport
     * serves them on the service URL; the framed TCP transport overrides to the REST listener.
     */
    protected String directRequestBaseURL() {
        return this.baseURL;
    }

    /**
     * Transport hook: open an SSE stream and return the connected HttpURLConnection
     * (HTTP 200, InputStream still streaming). Plain HTTP by design: SSE frames cannot
     * ride a framed (TCP/WSS) transport, so every transport dials the daemon's REST
     * listener directly (the WSS file data side-channel shape).
     */
    protected HttpURLConnection sseRequest(String method, String path, Object body, Map<String, String> params)
            throws IOException {
        // One 401 refresh-and-retry, same contract as request().
        TokenProvider provider = this.tokenProvider.get();
        String sentToken = provider == null ? null : provider.getAccessToken();
        HttpURLConnection connection = openSseConnection(method, path, body, params, sentToken);
        if (provider != null && provider.canRefresh() && isReplayable(body)
                && connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            String newToken = provider.refreshAccessToken(sentToken);
            connection.disconnect();
            if (newToken == null || newToken.trim().isEmpty()) {
                throw new IOException("TokenProvider returned an invalid access token");
            }
            connection = openSseConnection(method, path, body, params, newToken);
        }
        int status = connection.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            String error = Utils.readErrorResponse(connection);
            connection.disconnect();
            throw new IOException("stream request failed with status " + status + ": " + error);
        }
        return connection;
    }

    /** Open one direct HTTPS SSE connection attempt with the given bearer token (null for none). */
    private HttpURLConnection openSseConnection(String method, String path, Object body, Map<String, String> params,
            String token) throws IOException {
        StringBuilder urlBuilder = new StringBuilder(directRequestBaseURL()).append(path);
        String encodedQuery = encodeQuery(params);
        if (encodedQuery != null) {
            urlBuilder.append('?').append(encodedQuery);
        }

        HttpURLConnection connection = (HttpURLConnection) Utils.toUrl(urlBuilder.toString()).openConnection();
        connection.setRequestMethod(method.toUpperCase());
        connection.setConnectTimeout(connectTimeoutMs);
        connection.setReadTimeout(readTimeoutMs);
        applySSL(connection);

        // Streams bypass node forwarding (X-Target-Host) and the agent proxy: bearer only, no commonHeaders().
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT);
        if (token != null && !token.isEmpty()) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        }

        byte[] bodyBytes = null;
        if (body instanceof byte[]) {
            bodyBytes = (byte[]) body;
            connection.setRequestProperty(CONTENT_TYPE_HEADER, "application/octet-stream");
        } else if (body != null) {
            bodyBytes = (body instanceof JSONObject ? body.toString() : String.valueOf(body))
                    .getBytes(StandardCharsets.UTF_8);
            connection.setRequestProperty(CONTENT_TYPE_HEADER, "text/plain; charset=utf-8");
        }

        // Streamed endpoints sign the empty-string body hash (exemption, like the file side channels).
        applyRequestSignature(headers, method.toUpperCase(), path, params, null);
        headers.forEach(connection::setRequestProperty);

        if (bodyBytes != null) {
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }
        }
        return connection;
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

    /**
     * Check application health.
     *
     * @return {@code true} when healthy, {@code false} only for the daemon's unhealthy verdict
     * @throws IOException on auth/missing-app/server errors (non-200) or network failure
     */
    public boolean checkAppHealth(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName) + "/health", null, null,
                null);
        ensureOk("checkAppHealth", conn);
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
    /**
     * Add or update an application.
     * <p>Docker applications: set {@code docker_image} (container Cmd comes from {@code command});
     * common wiring is first-class — {@code docker_ports} (docker run -p spelling
     * {@code "[hostIp:]hostPort:containerPort[/protocol]"}), {@code docker_volumes} (docker run -v
     * spelling) and {@code docker_network} (host/bridge/none/name); {@code metadata}
     * carries a full Docker create request body.
     * Registry credentials for image pulls go in {@code secret_env} as
     * {@code APP_DOCKER_REGISTRY_SERVER/USER/PASSWORD}.
     * <p>{@code stdin}: {@code "none"} (default) uses /dev/null or the {@code metadata} launch
     * file; {@code "pipe"} keeps the daemon-side write end open so {@link #sendInput} can drive
     * the process turn by turn. Not combinable with {@code metadata}; unsupported for containers.
     *
     * @param appName application name; for a Docker app it must start with a letter or digit
     * @param appJson application definition
     * @return the registered application view
     */
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
     * Unsubscribe from events by subscription ID. Idempotent: the daemon drops a
     * subscription itself when its app is removed.
     *
     * @param subscriptionId the subscription ID returned by {@link #subscribe}
     * @return true if the server removed it, false if it was already gone (HTTP 404)
     * @throws IOException on network failure or any other non-2xx server response
     */
    public boolean unsubscribe(String subscriptionId) throws IOException {
        return unsubscribe(subscriptionId, null);
    }

    /** Internal variant with per-request header overrides (e.g. {@code X-Target-Host} forwarding). */
    boolean unsubscribe(String subscriptionId, Map<String, String> extraHeaders) throws IOException {
        Map<String, String> query = new HashMap<>();
        query.put("subscription_id", subscriptionId);
        HttpURLConnection conn = request("DELETE", "/appmesh/subscribe", null, extraHeaders, query);
        // 404: the daemon already dropped the subscription with its app. Any other
        // failure keeps the callback able to receive events (Python SDK order).
        boolean existed = ensureOkOrNotFound("unsubscribe", conn);
        MessageDemuxer demuxer = demuxerOrNull();
        if (demuxer != null) {
            demuxer.unregisterEventCallback(subscriptionId);
        }
        return existed;
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

        String exitCodeStr = conn.getHeaderField(X_EXIT_CODE_HEADER);
        if (exitCodeStr != null && !exitCodeStr.isEmpty()) {
            try {
                response.exitCode = Integer.parseInt(exitCodeStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code: " + exitCodeStr, e);
            }
        }

        String outputPositionStr = conn.getHeaderField(X_OUTPUT_POSITION_HEADER);
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
        return runAppSync(appJson, maxTime, lifecycle, 0);
    }

    /**
     * Run an application synchronously (overload without lifecycle).
     */
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTime) throws Exception {
        return runAppSync(appJson, maxTime, 0, 0);
    }

    /**
     * Run an application synchronously (blocking), with a ceiling on the returned output.
     *
     * <p>The daemon answers with a single output page (5 MiB). When the output fills that page,
     * the remaining pages are read from the run's output endpoint and concatenated, so the
     * returned stdout is complete regardless of size. The temporary run instance is removed
     * once everything has been read.
     *
     * @param appJson        application JSON definition
     * @param maxTime        maximum execution time in seconds
     * @param lifecycle      application lifecycle time (0 = server default)
     * @param maxOutputBytes maximum size of the returned stdout in bytes, 0 or negative for no
     *                        limit. When the output exceeds it, an {@link IOException} is thrown
     *                        instead of returning a truncated result; the run instance is then
     *                        left on the server for a 600 second retention so the rest of the
     *                        output can still be read.
     * @return (exitCode, stdout) pair
     */
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTime, int lifecycle, long maxOutputBytes)
            throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(maxTime));
        if (lifecycle > 0) {
            query.put("lifecycle", String.valueOf(lifecycle));
        }
        HttpURLConnection conn = request("POST", "/appmesh/app/syncrun", appJson, null, query);
        String exitCodeHeader = conn.getHeaderField(X_EXIT_CODE_HEADER);
        Integer exitCode = null;
        if (exitCodeHeader != null && !exitCodeHeader.isEmpty()) {
            try {
                exitCode = Integer.parseInt(exitCodeHeader);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code header", e);
            }
        }
        String runName = conn.getHeaderField(X_APP_NAME_HEADER);
        int status = conn.getResponseCode();
        if (runName != null && !runName.isEmpty() && status >= 200 && status < 300
                && "1".equals(conn.getHeaderField(X_OUTPUT_TRUNCATED_HEADER))) {
            return Pair.of(exitCode, readTruncatedRunOutput(conn, runName, maxOutputBytes));
        }
        return Pair.of(exitCode, Utils.readResponseSafe(conn));
    }

    /**
     * Read the output pages that follow a full sync-run reply page, then drop the run instance.
     *
     * <p>Exactly {@code maxOutputBytes} bytes is accepted.
     *
     * @throws IOException when the output exceeds {@code maxOutputBytes} (the run instance is kept)
     *                     or a page cannot be read
     */
    private String readTruncatedRunOutput(HttpURLConnection first, String runName, long maxOutputBytes)
            throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] firstPage = Utils.readResponseBytes(first);
        output.write(firstPage, 0, firstPage.length);

        String positionHeader = first.getHeaderField(X_OUTPUT_POSITION_HEADER);
        long position;
        try {
            position = Long.parseLong(positionHeader);
        } catch (NumberFormatException e) {
            throw new IOException("Sync run '" + runName + "' returned an invalid X-Output-Position: "
                    + positionHeader, e);
        }

        boolean complete = false;
        try {
            // Checked after every page, the short final one included.
            checkSyncRunOutputCeiling(output.size(), maxOutputBytes, runName);
            while (true) {
                Map<String, String> query = new HashMap<>();
                query.put("stdout_position", String.valueOf(position));
                HttpURLConnection pageConn = request("GET", "/appmesh/app/" + encodeURIComponent(runName) + "/output",
                        null, null, query);
                if (pageConn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                    throw new IOException("Reading sync run '" + runName + "' output failed with status "
                            + pageConn.getResponseCode() + ": " + Utils.readErrorResponse(pageConn));
                }
                byte[] page = Utils.readResponseBytes(pageConn);
                output.write(page, 0, page.length);
                // Positions are byte offsets; a page shorter than a full page (or empty) ends the output.
                position += page.length;
                checkSyncRunOutputCeiling(output.size(), maxOutputBytes, runName);
                if (page.length < SYNC_RUN_OUTPUT_PAGE_BYTES) {
                    complete = true;
                    break;
                }
            }
        } finally {
            // Best effort: the daemon removes the run when the retention ends. A failed or
            // abandoned read keeps the instance so the output can still be recovered.
            if (complete) {
                try {
                    deleteApp(runName);
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to remove sync run application '" + runName + "'", e);
                }
            }
        }
        return new String(output.toByteArray(), responseCharset(first));
    }

    /**
     * Throw when the sync-run output collected so far is over the ceiling ({@code maxOutputBytes}
     * of 0 or less means no limit; exactly the ceiling is accepted).
     */
    private static void checkSyncRunOutputCeiling(int collectedBytes, long maxOutputBytes, String runName)
            throws IOException {
        if (maxOutputBytes > 0 && collectedBytes > maxOutputBytes) {
            throw new IOException("Sync run output exceeds maxOutputBytes=" + maxOutputBytes
                    + "; the remaining output stays readable on application '" + runName + "' for "
                    + SYNC_RUN_TRUNCATED_RETENTION_SECONDS + " seconds");
        }
    }

    /** Charset declared by the response {@code Content-Type}, UTF-8 when absent or unknown. */
    private static Charset responseCharset(HttpURLConnection conn) {
        String contentType = conn.getContentType();
        if (contentType != null) {
            for (String part : contentType.split(";")) {
                String parameter = part.trim();
                if (parameter.regionMatches(true, 0, "charset=", 0, "charset=".length())) {
                    try {
                        return Charset.forName(parameter.substring("charset=".length()).replace("\"", ""));
                    } catch (IllegalArgumentException ignored) {
                        // fall through to UTF-8
                    }
                }
            }
        }
        return StandardCharsets.UTF_8;
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
        if (run == null) {
            return null;
        }
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

    // -------- Streaming (server-sent events) --------

    /**
     * Stream an application's stdout incrementally over server-sent events.
     *
     * <p>Replays from {@code stdoutPosition}, then (with {@code follow=true}) streams new
     * output until exit, removal or the overall {@code timeoutSeconds}. The server
     * de-duplicates the replay/live boundary.
     *
     * @param appName        name of the target application
     * @param stdoutPosition byte cursor to start from (0 replays from the beginning)
     * @param processUuid    pin the stream to one run; empty follows the current run
     * @param follow         {@code false} replays to the current end of output and stops
     * @param timeoutSeconds overall stream lifetime cap in seconds (server-side)
     * @return the stream; iterate {@link SseStream#nextChunk()} and read {@link SseStream#getEnd()}
     * @throws IOException the stream request failed; terminal error/timeout ends throw
     *                     from {@link SseStream#nextChunk()} instead
     */
    public SseStream followOutput(String appName, long stdoutPosition, String processUuid, boolean follow,
            int timeoutSeconds) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("stdout_position", String.valueOf(stdoutPosition));
        params.put("follow", follow ? "true" : "false");
        params.put("timeout", String.valueOf(timeoutSeconds));
        if (processUuid != null && !processUuid.isEmpty()) {
            params.put("process_uuid", processUuid);
        }
        HttpURLConnection conn = sseRequest("GET",
                "/appmesh/app/" + encodeURIComponent(appName) + "/output/stream", null, params);
        return new SseStream(conn, "stdout", "output", null, null);
    }

    /** Follow the current run's output from the beginning (see {@link #followOutput(String, long, String, boolean, int)}). */
    public SseStream followOutput(String appName) throws IOException {
        return followOutput(appName, 0, "", true, 3600);
    }

    /**
     * Streaming task RPC: send an invocation and receive incremental results as they arrive.
     *
     * <p>The {@link #runTask} counterpart for continuous-output services (LLM agents): the
     * worker pushes partial results ({@code sendTaskPartial}) before its final reply, which
     * lands in {@link SseEnd#getResult()}.
     *
     * @param appName        name of the target application
     * @param data           payload to deliver to the application (same contract as runTask)
     * @param timeoutSeconds maximum seconds for the whole call (server-side)
     * @return the stream; the final reply is {@link SseEnd#getResult()} after iteration
     * @throws IOException the stream request failed; terminal error/timeout ends throw
     *                     from {@link SseStream#nextChunk()} instead
     */
    public SseStream runTaskStream(String appName, String data, int timeoutSeconds) throws IOException {
        Map<String, String> params = null;
        if (timeoutSeconds > 0) {
            params = new HashMap<>();
            params.put("timeout", String.valueOf(timeoutSeconds));
        }
        HttpURLConnection conn = sseRequest("POST",
                "/appmesh/app/" + encodeURIComponent(appName) + "/task/stream", data, params);
        return new SseStream(conn, "partial", "data", "final", "result");
    }

    /** Streaming task RPC with the default 300 second timeout (see {@link #runTaskStream(String, String, int)}). */
    public SseStream runTaskStream(String appName, String data) throws IOException {
        return runTaskStream(appName, data, 300);
    }

    /**
     * Run a one-shot application remotely and stream its stdout incrementally.
     *
     * <p>Equivalent to {@link #runAppAsync(JSONObject, long, long)} + {@link #followOutput}
     * + {@link #deleteApp}: stdout chunks are delivered as produced. The temporary application
     * is always deleted when the stream ends or is closed.
     *
     * @param appJson            application JSON definition (same contract as runAppAsync)
     * @param maxTimeSeconds     maximum runtime for the remote process
     * @param lifecycleSeconds   retention window for the temporary run app
     * @return the stream; the run's exit code is {@link SseEnd#getExitCode()} after iteration
     * @throws Exception the async run failed; terminal error/timeout ends throw
     *                     from {@link SseStream#nextChunk()} instead
     */
    public SseStream streamRun(JSONObject appJson, long maxTimeSeconds, long lifecycleSeconds) throws Exception {
        AppRun run = runAppAsync(appJson, maxTimeSeconds, lifecycleSeconds);
        SseStream stream = followOutput(run.getAppName(), 0, run.getProcessUuid(), true,
                (int) Math.min(Math.max(maxTimeSeconds, lifecycleSeconds), Integer.MAX_VALUE));
        stream.onCompletion(() -> {
            try {
                deleteApp(run.getAppName(), forwardHeaders(run.getForwardingHost()));
            } catch (Exception ignored) {
                // Best-effort cleanup, mirrors the Python SDK's suppressed delete.
            }
        });
        return stream;
    }

    /** Run a one-shot application with ISO 8601 durations (see {@link #streamRun(JSONObject, long, long)}). */
    public SseStream streamRun(JSONObject appJson, String maxTime, String lifecycle) throws Exception {
        return streamRun(appJson, Utils.toSeconds(maxTime), Utils.toSeconds(lifecycle));
    }

    /**
     * Inject bytes into the stdin of a running application.
     *
     * <p>The application must be registered with {@code "stdin": "pipe"}; the daemon holds the
     * write end open, making the process conversational while
     * {@link #followOutput(String, long, String, boolean, int)} reads its output. A full pipe
     * answers 412 with the bytes already written — retry with the remainder.
     *
     * @param appName     name of the target application
     * @param data        raw bytes to write to the process stdin
     * @param close       also close the pipe write end so the process reads EOF
     * @param processUuid restrict the write to this run; empty targets the current run
     * @return number of bytes written
     * @throws IOException the write failed (412: pipe full, 409: no running process)
     */
    public long sendInput(String appName, byte[] data, boolean close, String processUuid) throws IOException {
        Map<String, String> headers = null;
        if (close) {
            headers = new HashMap<>();
            headers.put(X_INPUT_CLOSE_HEADER, "true");
        }
        Map<String, String> params = null;
        if (processUuid != null && !processUuid.isEmpty()) {
            params = new HashMap<>();
            params.put("process_uuid", processUuid);
        }
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/input", data,
                headers, params);
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("sendInput failed with status " + conn.getResponseCode() + ": "
                    + Utils.readResponseSafe(conn));
        }
        return new JSONObject(Utils.readResponse(conn)).optLong("bytes_written", 0);
    }

    /** Write UTF-8 text to the current run's stdin (see {@link #sendInput(String, byte[], boolean, String)}). */
    public long sendInput(String appName, String data) throws IOException {
        return sendInput(appName, data.getBytes(StandardCharsets.UTF_8), false, "");
    }

    // -------- File Transfer --------

    /**
     * Download a remote file to local disk.
     *
     * <p>Plain-HTTP transport: GET answers the file bytes; the agent proxy serves the same
     * route from local disk. {@code applyFileAttributes} applies returned POSIX metadata
     * best-effort.
     */
    public boolean downloadFile(String filePath, String localFile, boolean applyFileAttributes) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put(X_FILE_PATH_HEADER, encodeURIComponent(filePath));

        HttpURLConnection conn = request("GET", "/appmesh/file/download", null, headers, null);
        // A JSON reply without Content-Disposition is a legacy placeholder, not content.
        String contentType = conn.getContentType() == null ? "" : conn.getContentType().toLowerCase();
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK && contentType.contains("json")
                && conn.getHeaderField("Content-Disposition") == null) {
            conn.disconnect();
            throw new IOException("File download is not supported by this server surface (legacy reply without content)");
        }
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
     * Upload a local file to the remote server.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent in headers so the
     * server can recreate permissions and ownership when supported. When {@code overwrite} is
     * true, an existing remote file is replaced; the default keeps the server's 409 refusal.
     */
    public boolean uploadFile(String localFilePath, String remoteFile, boolean preservePermissions,
            boolean overwrite) throws IOException {
        return uploadFile(new File(localFilePath), remoteFile, preservePermissions, overwrite);
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
     * <p>Plain-HTTP transport: POST streams the raw file bytes as the body; the agent
     * proxy accepts the same route.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent in headers so the
     * server can recreate permissions and ownership when supported.
     */
    public boolean uploadFile(File localFile, String remoteFile, boolean preservePermissions) throws IOException {
        return uploadFile(localFile, remoteFile, preservePermissions, false);
    }

    /**
     * Upload a local file to the remote server.
     *
     * <p>Plain-HTTP transport: POST streams the raw file bytes as the body; the agent
     * proxy accepts the same route.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent in headers so the
     * server can recreate permissions and ownership when supported. When {@code overwrite} is
     * true, an existing remote file is replaced; the default keeps the server's 409 refusal.
     */
    public boolean uploadFile(File localFile, String remoteFile, boolean preservePermissions,
            boolean overwrite) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put(X_FILE_PATH_HEADER, encodeURIComponent(remoteFile));
        if (overwrite) {
            headers.put(X_FILE_OVERWRITE_HEADER, "true");
        }

        File file = localFile;
        if (!file.exists()) {
            throw new IOException("File not found: " + file.getAbsolutePath());
        }

        if (preservePermissions) {
            headers.putAll(Utils.getFileAttributes(file));
        }
        headers.put(CONTENT_TYPE_HEADER, "application/octet-stream");

        URL url = Utils.toUrl(this.baseURL + "/appmesh/file/upload");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        applySSL(connection);
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        // Stream the request body instead of buffering the whole file in memory
        connection.setFixedLengthStreamingMode(file.length());
        connection.setConnectTimeout(connectTimeoutMs);
        connection.setReadTimeout(readTimeoutMs);
        commonHeaders().forEach(connection::setRequestProperty);
        headers.forEach(connection::setRequestProperty);
        // Streamed file upload: sign the empty-string body hash (documented exemption —
        // the signature binds method/path/timestamp/nonce, not the file content).
        applyRequestSignature(connection, "POST", "/appmesh/file/upload");

        try (InputStream fis = new FileInputStream(file);
                OutputStream os = connection.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            os.flush();
        }

        int responseCode = connection.getResponseCode();
        // A 200 JSON status reply means a legacy daemon stored nothing.
        String replyType = connection.getContentType() == null ? "" : connection.getContentType().toLowerCase();
        if (responseCode >= HttpURLConnection.HTTP_OK && responseCode < HttpURLConnection.HTTP_MULT_CHOICE) {
            if (responseCode == HttpURLConnection.HTTP_OK && replyType.contains("json")
                    && Utils.readResponseSafe(connection).contains("\"message\"")) {
                connection.disconnect();
                throw new IOException("File upload is not supported by this server surface (legacy reply without storage)");
            }
            connection.disconnect();
            return true;
        }
        String responseBody = Utils.readErrorResponse(connection);
        connection.disconnect();
        LOGGER.severe("HTTP error code: " + responseCode);
        throw new IOException("HTTP error code: " + responseCode + ", Response: " + responseBody);
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
        HttpURLConnection conn =
                request("POST", "/appmesh/principal/" + encodeURIComponent(principalId), policy, null, null);
        return ensureOk("updatePrincipal", conn);
    }

    /** Delete only the Engine authorization overlay for a principal. */
    public boolean deletePrincipal(String principalId) throws IOException {
        HttpURLConnection conn =
                request("DELETE", "/appmesh/principal/" + encodeURIComponent(principalId), null, null, null);
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
        TokenProvider provider = this.tokenProvider.get();
        return commonHeaders(provider == null ? null : provider.getAccessToken());
    }

    private Map<String, String> commonHeaders(String token) {
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT);
        if (token != null && !token.isEmpty()) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        }
        if (this.forwardTo != null && !this.forwardTo.isEmpty()) {
            headers.put(X_TARGET_HOST_HEADER, this.forwardTo);
        }
        return headers;
    }

    /**
     * Build a per-request {@code X-Target-Host} header map for the given forwarding host,
     * or null when no forwarding is requested. Explicit request headers override
     * {@link #commonHeaders()}, so this wins over the client-wide forward setting.
     * The host is sent as given: a bare host is resolved to the server's own service
     * port, since the client-side port may be a host-side mapping absent on the target.
     */
    Map<String, String> forwardHeaders(String forwardingHost) {
        if (forwardingHost == null || forwardingHost.isEmpty()) {
            return null;
        }
        Map<String, String> headers = new HashMap<>();
        headers.put(X_TARGET_HOST_HEADER, forwardingHost);
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

    protected String encodeURIComponent(String value) {
        if (value == null) {
            return null;
        }
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
     *
     * <p>When the attached {@link TokenProvider} can refresh and the request body is
     * replayable (null, {@link String}, {@code byte[]}, or {@link JSONObject}), a single
     * HTTP 401 triggers one {@link TokenProvider#refreshAccessToken(String)} and one retry
     * with the new token. A second 401 throws an {@link IOException}.
     */
    public HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params) throws IOException {
        TokenProvider provider = callerManagesAuth(headers) ? null : this.tokenProvider.get();
        String sentToken = provider == null ? null : provider.getAccessToken();

        HttpURLConnection connection = openRequest(method, path, body, headers, params, sentToken);
        if (provider == null || !provider.canRefresh() || !isReplayable(body)
                || connection.getResponseCode() != HttpURLConnection.HTTP_UNAUTHORIZED) {
            return connection;
        }

        String newToken = provider.refreshAccessToken(sentToken);
        if (newToken != null && newToken.trim().isEmpty()) {
            connection.disconnect();
            throw new IOException("TokenProvider returned an invalid access token");
        }
        connection.disconnect();
        connection = openRequest(method, path, body, headers, params, newToken);
        if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            throw new IOException("TokenProvider failed to replace a rejected access token: HTTP 401 - "
                    + Utils.readErrorResponse(connection));
        }
        return connection;
    }

    /** Whether the caller supplied its own Authorization header, disabling provider-managed auth. */
    protected static boolean callerManagesAuth(Map<String, String> headers) {
        if (headers == null) {
            return false;
        }
        for (String key : headers.keySet()) {
            if (key != null && AUTHORIZATION_HEADER.equalsIgnoreCase(key)) {
                return true;
            }
        }
        return false;
    }

    /** Streaming bodies cannot be assumed replayable after a 401 response. */
    private static boolean isReplayable(Object body) {
        return body == null || body instanceof String || body instanceof byte[] || body instanceof JSONObject;
    }

    /** Open and send one HTTP request attempt with the given bearer token (null for none). */
    private HttpURLConnection openRequest(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params, String token) throws IOException {
        StringBuilder urlBuilder = new StringBuilder(directRequestBaseURL()).append(path);

        // The encoded query is kept as a string: the signature canonicalizes from the
        // exact wire form (the daemon percent-decodes it back with %-only decoding).
        String encodedQuery = encodeQuery(params);
        if (encodedQuery != null) {
            urlBuilder.append('?').append(encodedQuery);
        }

        URL url = Utils.toUrl(urlBuilder.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method.toUpperCase());
        connection.setConnectTimeout(connectTimeoutMs);
        connection.setReadTimeout(readTimeoutMs);

        // Apply per-instance SSL
        applySSL(connection);

        Map<String, String> allHeaders = new HashMap<>(commonHeaders(token));
        if (headers != null) {
            allHeaders.putAll(headers);
        }

        // The body bytes are computed once: the signature must hash exactly the bytes written.
        byte[] bodyBytes = null;
        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            if (body instanceof byte[]) {
                // Raw bytes are sent verbatim (stdin injection payload).
                bodyBytes = (byte[]) body;
                if (!allHeaders.containsKey(CONTENT_TYPE_HEADER)) {
                    connection.setRequestProperty(CONTENT_TYPE_HEADER, "application/octet-stream");
                }
            } else if (body != null) {
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
                bodyBytes = bodyString.getBytes(StandardCharsets.UTF_8);
            }
        }

        // Sign the path exactly as sent: a baseURL path prefix is part of the
        // wire path, so the signed path comes from the final URL (sign == send).
        RequestSigner signer = this.requestSigner;
        if (signer != null) {
            signer.attach(allHeaders, method.toUpperCase(), url.getPath(),
                    encodedQuery == null ? "" : RequestSigner.canonicalQueryFromEncoded(encodedQuery), bodyBytes);
        }

        allHeaders.forEach(connection::setRequestProperty);

        if (bodyBytes != null) {
            connection.setDoOutput(true);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(bodyBytes);
                os.flush();
            }
        }

        return connection;
    }

    /** URL-encode a query map into wire form ({@code k=v&k2=v2}), or null when empty. */
    private static String encodeQuery(Map<String, ?> params) {
        if (params == null || params.isEmpty()) {
            return null;
        }
        StringBuilder queryBuilder = new StringBuilder();
        for (Map.Entry<String, ?> e : params.entrySet()) {
            try {
                queryBuilder.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8.name()))
                        .append('=')
                        .append(URLEncoder.encode(String.valueOf(e.getValue()), StandardCharsets.UTF_8.name()))
                        .append('&');
            } catch (UnsupportedEncodingException ex) {
                throw new RuntimeException("Error encoding URL parameters", ex);
            }
        }
        queryBuilder.setLength(queryBuilder.length() - 1);
        return queryBuilder.toString();
    }
}
