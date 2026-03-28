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
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
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
    private static final String BASIC_PREFIX = "Basic ";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_CONTENT_TYPE = "application/json; utf-8";
    private static final int HTTP_PRECONDITION_REQUIRED = 428;

    private static final int DEFAULT_CONNECT_TIMEOUT_MS = 30_000;
    private static final int DEFAULT_READ_TIMEOUT_MS = 300_000;

    // Platform-aware default SSL directory (matches Python SDK)
    private static final String DEFAULT_SSL_DIR =
            System.getProperty("os.name", "").toLowerCase().contains("win")
                    ? "c:/local/appmesh/ssl" : "/opt/appmesh/ssl";
    private static final String DEFAULT_SSL_CA_CERT = DEFAULT_SSL_DIR + "/ca.pem";
    private static final String DEFAULT_SSL_CLIENT_CERT = DEFAULT_SSL_DIR + "/client.pem";
    private static final String DEFAULT_SSL_CLIENT_KEY = DEFAULT_SSL_DIR + "/client-key.pem";

    private static final long TOKEN_REFRESH_INTERVAL_SECONDS = 300; // 5 minutes
    private static final long TOKEN_REFRESH_OFFSET_SECONDS = 30;   // 30 seconds before expiry

    private final String baseURL;
    private final AtomicReference<String> jwtToken = new AtomicReference<>(null);
    private volatile String forwardTo;

    // Per-instance SSL (avoids modifying JVM global defaults)
    private final SSLSocketFactory sslSocketFactory;
    private final boolean disableHostnameVerification;

    // Timeout settings
    private final int connectTimeoutMs;
    private final int readTimeoutMs;

    // Cookie file persistence
    private final String cookieFile;

    // Token auto-refresh
    private final boolean autoRefreshToken;
    private volatile ScheduledExecutorService refreshExecutor;
    private volatile ScheduledFuture<?> refreshFuture;

    /**
     * Internal constructor used by Builder and subclasses.
     */
    protected AppMeshClient(Builder builder) {
        this.baseURL = Objects.requireNonNull(builder.baseURL, "Base URL cannot be null");
        this.connectTimeoutMs = builder.connectTimeoutMs;
        this.readTimeoutMs = builder.readTimeoutMs;
        this.disableHostnameVerification = builder.disableSSLVerification;

        this.cookieFile = builder.cookieFile;
        this.autoRefreshToken = builder.autoRefreshToken;

        // Load token from cookie file if exists
        if (this.cookieFile != null && !this.cookieFile.isEmpty()) {
            String savedToken = loadTokenFromFile();
            if (savedToken != null) {
                this.jwtToken.set(savedToken);
            }
        }

        if (builder.jwtToken != null) {
            this.jwtToken.set(builder.jwtToken);
            onTokenChanged(builder.jwtToken);
        }

        if (this.autoRefreshToken && this.jwtToken.get() != null && !this.jwtToken.get().isEmpty()) {
            startTokenRefresh();
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
        private String cookieFile;
        private boolean autoRefreshToken = false;
        private boolean disableSSLVerification = false;
        private int connectTimeoutMs = DEFAULT_CONNECT_TIMEOUT_MS;
        private int readTimeoutMs = DEFAULT_READ_TIMEOUT_MS;
        private boolean sslPathsExplicitlySet = false;

        public Builder() {
            // Auto-detect default SSL certificates if the directory exists
            if (new java.io.File(DEFAULT_SSL_DIR).isDirectory()) {
                this.caCertFilePath = DEFAULT_SSL_CA_CERT;
                this.clientCertFilePath = DEFAULT_SSL_CLIENT_CERT;
                this.clientCertKeyFilePath = DEFAULT_SSL_CLIENT_KEY;
            }
        }

        /** AppMesh service base URL (default: {@code https://127.0.0.1:6060}). */
        public Builder baseURL(String baseURL) {
            this.baseURL = baseURL;
            return this;
        }

        /** Path to a CA certificate bundle for server verification (overrides auto-detected default). */
        public Builder caCert(String caCertFilePath) {
            this.caCertFilePath = caCertFilePath;
            this.sslPathsExplicitlySet = true;
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

        /** Cookie file path for persistent token storage. */
        public Builder cookieFile(String cookieFile) {
            this.cookieFile = cookieFile;
            return this;
        }

        /** Enable automatic token refresh before expiration. */
        public Builder autoRefreshToken(boolean enable) {
            this.autoRefreshToken = enable;
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

    /** Application output container for {@link #getAppOutput}. */
    public static class AppOutput {
        public boolean httpSuccess;
        public String httpBody;
        public Long outputPosition;
        public Integer exitCode;
    }

    /** Represents an asynchronous run on the server. */
    public class AppRun {
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

        public String getProcUid() {
            return procUid;
        }

        public AppMeshClient getClient() {
            return clientRef;
        }

        public String getForwardingHost() {
            return forwardingHost;
        }

        /**
         * Helper that temporarily sets forwarding host while calling waitForAsyncRun.
         * Use with try-with-resources.
         */
        public class ForwardingHostManager implements Closeable {
            private final String originalForwardingHost;

            public ForwardingHostManager() {
                this.originalForwardingHost = clientRef.forwardTo;
                clientRef.setForwardTo(forwardingHost);
            }

            @Override
            public void close() {
                clientRef.setForwardTo(originalForwardingHost);
            }
        }

        public Integer wait(boolean stdoutPrint, int timeoutSeconds) throws Exception {
            try (ForwardingHostManager manager = new ForwardingHostManager()) {
                return clientRef.waitForAsyncRun(this, stdoutPrint, timeoutSeconds);
            }
        }
    }

    public void setForwardTo(String host) {
        this.forwardTo = host;
    }

    @Override
    public void close() {
        stopTokenRefresh();
        this.jwtToken.set(null);
    }

    // -------- Token Persistence --------

    private void onTokenChanged(String token) {
        if (cookieFile != null && !cookieFile.isEmpty()) {
            saveTokenToFile(token);
        }
    }

    private void saveTokenToFile(String token) {
        try {
            File file = new File(cookieFile);
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                parent.mkdirs();
            }
            try (java.io.PrintWriter pw = new java.io.PrintWriter(file)) {
                pw.println("# Netscape HTTP Cookie File");
                if (token != null && !token.isEmpty()) {
                    pw.println("localhost\tTRUE\t/\tTRUE\t0\tappmesh_auth_token\t" + token);
                }
            }
            // Set file permissions to 600 on Unix
            if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
                file.setReadable(false, false);
                file.setWritable(false, false);
                file.setReadable(true, true);
                file.setWritable(true, true);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to save token to cookie file", e);
        }
    }

    private String loadTokenFromFile() {
        try {
            File file = new File(cookieFile);
            if (!file.exists()) {
                return null;
            }
            try (java.io.BufferedReader br = new java.io.BufferedReader(new java.io.FileReader(file))) {
                String line;
                while ((line = br.readLine()) != null) {
                    line = line.trim();
                    if (line.isEmpty() || line.startsWith("#")) continue;
                    String[] parts = line.split("\t");
                    if (parts.length == 7 && "appmesh_auth_token".equals(parts[5])) {
                        return parts[6];
                    }
                }
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to load token from cookie file", e);
        }
        return null;
    }

    // -------- Token Auto-Refresh --------

    /** Start background token auto-refresh. */
    public void startTokenRefresh() {
        if (!autoRefreshToken) return;
        stopTokenRefresh();
        refreshExecutor = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "appmesh-token-refresh");
            t.setDaemon(true);
            return t;
        });
        scheduleNextRefresh();
    }

    /** Stop background token auto-refresh. */
    public void stopTokenRefresh() {
        if (refreshFuture != null) {
            refreshFuture.cancel(false);
            refreshFuture = null;
        }
        if (refreshExecutor != null) {
            refreshExecutor.shutdownNow();
            refreshExecutor = null;
        }
    }

    private void scheduleNextRefresh() {
        if (refreshExecutor == null || refreshExecutor.isShutdown()) return;
        long delaySec = computeRefreshDelay();
        refreshFuture = refreshExecutor.schedule(() -> {
            try {
                renewToken(null);
                LOGGER.fine("Auto-refresh: token renewed successfully");
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Auto-refresh: token renewal failed", e);
            }
            scheduleNextRefresh();
        }, delaySec, TimeUnit.SECONDS);
    }

    private long computeRefreshDelay() {
        String token = this.jwtToken.get();
        if (token != null) {
            try {
                long exp = decodeJwtExp(token);
                long remaining = exp - System.currentTimeMillis() / 1000;
                if (remaining <= TOKEN_REFRESH_OFFSET_SECONDS) {
                    return 1;
                }
                return Math.min(remaining - TOKEN_REFRESH_OFFSET_SECONDS, TOKEN_REFRESH_INTERVAL_SECONDS);
            } catch (Exception ignored) {
            }
        }
        return TOKEN_REFRESH_INTERVAL_SECONDS;
    }

    private static long decodeJwtExp(String token) {
        String[] parts = token.split("\\.");
        if (parts.length < 2) throw new IllegalArgumentException("Invalid JWT");
        String payload = parts[1];
        // Add base64 padding
        switch (payload.length() % 4) {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }
        byte[] decoded = Base64.getUrlDecoder().decode(payload);
        JSONObject claims = new JSONObject(new String(decoded, StandardCharsets.UTF_8));
        return claims.getLong("exp");
    }

    // -------- Authentication --------

    /**
     * Login with username/password and attach the issued token to this client.
     *
     * <p>Returns the JWT token on immediate success, or the TOTP challenge string when the
     * server replies with HTTP 428 and no valid TOTP code was supplied. On success, the token
     * is persisted to the configured cookie file and background refresh starts when enabled.
     *
     * @param username login name
     * @param password login password
     * @param totpCode TOTP code (null if not using MFA)
     * @param expireSeconds token expiry as integer seconds or ISO 8601 duration (null = server default)
     * @param audience JWT audience (null = default)
     * @return JWT token on immediate success, or the TOTP challenge string when MFA is required
     * @throws IOException on network or authentication failure
     */
    public String login(String username, String password, String totpCode, Object expireSeconds, String audience)
            throws IOException {
        Map<String, String> headers = new HashMap<>();
        String basic = BASIC_PREFIX
                + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        headers.put(AUTHORIZATION_HEADER, basic);
        headers.put("X-Set-Cookie", "true");
        if (expireSeconds != null) {
            headers.put("X-Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }
        if (totpCode != null && !totpCode.isEmpty()) {
            headers.put("X-Totp-Code", totpCode);
        }
        if (audience != null && !audience.isEmpty()) {
            headers.put("X-Audience", audience);
        }

        HttpURLConnection conn = request("POST", "/appmesh/login", null, headers, null);
        int statusCode = conn.getResponseCode();

        if (statusCode == HttpURLConnection.HTTP_OK) {
            String responseContent = Utils.readResponse(conn);
            JSONObject jsonResponse = new JSONObject(responseContent);
            String token = jsonResponse.getString("access_token");
            this.jwtToken.set(token);
            onTokenChanged(token);
            startTokenRefresh();
            return token;
        } else if (statusCode == HTTP_PRECONDITION_REQUIRED) {
            String responseContent = Utils.readResponseSafe(conn);
            JSONObject jsonResponse = new JSONObject(responseContent);
            if (jsonResponse.has("totp_challenge")) {
                if (totpCode != null && !totpCode.isEmpty()) {
                    String challenge = jsonResponse.getString("totp_challenge");
                    return validateTotp(username, challenge, totpCode, expireSeconds);
                }
                return jsonResponse.getString("totp_challenge");
            }
            throw new IOException("Login failed: HTTP " + statusCode + " - " + responseContent);
        }

        String errorBody = Utils.readErrorResponse(conn);
        throw new IOException("Login failed: HTTP " + statusCode + " - " + errorBody);
    }

    /**
     * Validate a TOTP challenge and store the returned JWT in this client session.
     *
     * @return the JWT token on success
     */
    public String validateTotp(String username, String challenge, String code, Object expireSeconds)
            throws IOException {
        JSONObject body = new JSONObject();
        body.put("user_name", username);
        body.put("totp_code", code);
        body.put("totp_challenge", challenge);
        if (expireSeconds != null) {
            body.put("expire_seconds", Utils.toSeconds(expireSeconds));
        }
        HttpURLConnection conn = request("POST", "/appmesh/totp/validate", body, null, null);
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            String responseContent = Utils.readResponse(conn);
            JSONObject jsonResponse = new JSONObject(responseContent);
            String token = jsonResponse.getString("access_token");
            this.jwtToken.set(token);
            onTokenChanged(token);
            startTokenRefresh();
            return token;
        }
        String errorBody = Utils.readResponseSafe(conn);
        throw new IOException("TOTP validation failed: HTTP " + conn.getResponseCode() + " - " + errorBody);
    }

    /** Logout from the current session and clear any locally stored token state. */
    public boolean logout() {
        stopTokenRefresh();
        try {
            HttpURLConnection conn = request("POST", "/appmesh/self/logoff", null, null, null);
            boolean ok = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
            this.jwtToken.set(null);
            onTokenChanged(null);
            return ok;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to logoff", e);
            this.jwtToken.set(null);
            onTokenChanged(null);
            return false;
        }
    }

    /**
     * Set a JWT token directly without server-side verification.
     * Use when the token is already known to be valid.
     * For server-side verification, use {@link #authenticate(String, String, String)} instead.
     */
    public void setToken(String token) {
        this.jwtToken.set(token);
        onTokenChanged(token);
        startTokenRefresh();
    }

    /**
     * Verify only the provided JWT token with the server and optionally check permission.
     *
     * @param token      JWT token to verify
     * @param permission optional permission to check (null to skip)
     * @param audience   optional JWT audience (null to skip)
     * @return a pair of (success, responseText)
     */
    public Pair<Boolean, String> authenticate(String token, String permission, String audience) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        if (audience != null && !audience.isEmpty()) {
            headers.put("X-Audience", audience);
        }
        if (permission != null && !permission.isEmpty()) {
            headers.put("X-Permission", permission);
        }
        HttpURLConnection conn = request("POST", "/appmesh/auth", null, headers, null);
        boolean ok = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
        String responseText = Utils.readResponseSafe(conn);
        return Pair.of(ok, responseText);
    }

    /**
     * Renew the current JWT token.
     *
     * @param expireSeconds token expiry duration (integer seconds or ISO 8601 string, null = server default)
     * @return the new JWT token
     */
    public String renewToken(Object expireSeconds) throws IOException {
        Map<String, String> headers = new HashMap<>();
        if (expireSeconds != null) {
            headers.put("X-Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }
        HttpURLConnection conn = request("POST", "/appmesh/token/renew", null, headers, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        String token = jsonResponse.getString("access_token");
        this.jwtToken.set(token);
        onTokenChanged(token);
        return token;
    }

    /**
     * Return the decoded OTP provisioning URI for the current user.
     *
     * <p>Unlike some other SDKs that extract only the raw secret, the Java SDK returns the full
     * URI decoded from the server's base64 {@code mfa_uri} payload.
     */
    public String getTotpSecret() throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/secret", null, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        String mfaUri = jsonResponse.getString("mfa_uri");
        return new String(Base64.getDecoder().decode(mfaUri), StandardCharsets.UTF_8);
    }

    /** Enable TOTP for the current user with a 6-digit verification code and return the new JWT token. */
    public String enableTotp(String totpCode) throws IOException {
        if (totpCode == null || !totpCode.matches("\\d{6}")) {
            throw new IllegalArgumentException("TOTP code must be a 6-digit number");
        }
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Totp-Code", totpCode);
        HttpURLConnection conn = request("POST", "/appmesh/totp/setup", null, headers, null);
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            String responseContent = Utils.readResponse(conn);
            JSONObject jsonResponse = new JSONObject(responseContent);
            String token = jsonResponse.getString("access_token");
            this.jwtToken.set(token);
            onTokenChanged(token);
            return token;
        }
        String errorBody = Utils.readResponseSafe(conn);
        throw new IOException("TOTP setup failed: HTTP " + conn.getResponseCode() + " - " + errorBody);
    }

    /** Disable TOTP for the current user. */
    public boolean disableTotp() throws IOException {
        return disableTotp("self");
    }

    /** Disable TOTP for a specific user. */
    public boolean disableTotp(String user) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/" + encodeURIComponent(user) + "/disable", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // -------- Labels / Tags --------

    /** Get all server labels. */
    public Map<String, String> getLabels() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/labels", null, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        Map<String, String> labels = new HashMap<>();
        for (String key : jsonResponse.keySet()) {
            labels.put(key, jsonResponse.getString(key));
        }
        return labels;
    }


    /** Add or update a label. */
    public boolean addLabel(String key, String value) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("value", value);
        HttpURLConnection conn = request("PUT", "/appmesh/label/" + encodeURIComponent(key), null, null, params);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }


    /** Delete a label. */
    public boolean deleteLabel(String key) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/label/" + encodeURIComponent(key), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
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

    /** Enable an application. */
    public boolean enableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/enable", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Disable an application. */
    public boolean disableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/disable", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Delete an application. */
    public boolean deleteApp(String appName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + encodeURIComponent(appName), null, null, null);
        int status = conn.getResponseCode();
        if (status == HttpURLConnection.HTTP_OK)
            return true;
        if (status == HttpURLConnection.HTTP_NOT_FOUND)
            return false;
        // Other errors (permission denied, server error, etc.)
        throw new IOException("deleteApp failed with status " + status + ": " + Utils.readErrorResponse(conn));
    }

    /** Register or update an application. */
    public JSONObject addApp(String appName, JSONObject appJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/app/" + encodeURIComponent(appName), appJson, null, null);
        return new JSONObject(Utils.readResponse(conn));
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
        Map<String, String> query = new HashMap<>();
        query.put("stdout_position", String.valueOf(stdoutPosition));
        query.put("stdout_index", String.valueOf(stdoutIndex));
        query.put("stdout_maxsize", String.valueOf(stdoutMaxsize));
        query.put("process_uuid", processUuid);
        query.put("timeout", String.valueOf(timeout));
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName) + "/output", null, null,
                query);
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
     * @param appJson           application JSON definition
     * @param maxTimeoutSeconds maximum execution time in seconds
     * @param lifeCycleSeconds  application lifecycle time (0 = server default)
     * @return (exitCode, stdout) pair
     */
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTimeoutSeconds, int lifeCycleSeconds)
            throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(maxTimeoutSeconds));
        if (lifeCycleSeconds > 0) {
            query.put("lifecycle", String.valueOf(lifeCycleSeconds));
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
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTimeoutSeconds) throws Exception {
        return runAppSync(appJson, maxTimeoutSeconds, 0);
    }

    /**
     * Run an application asynchronously (non-blocking).
     *
     * @return an {@link AppRun} handle to track the execution
     */
    public AppRun runAppAsync(JSONObject appJson, Object maxTimeSeconds, Object lifeCycleSeconds) throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(Utils.toSeconds(maxTimeSeconds)));
        query.put("lifecycle", String.valueOf(Utils.toSeconds(lifeCycleSeconds)));
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
     */
    public Integer waitForAsyncRun(AppRun run, boolean stdoutPrint, int timeoutSeconds) throws Exception {
        if (run == null)
            return null;
        long lastOutputPosition = 0;
        LocalDateTime start = LocalDateTime.now();
        int interval = 1;
        while (!run.getProcUid().isEmpty()) {
            AppOutput appOut = this.getAppOutput(run.getAppName(), lastOutputPosition, 0, 10240, run.getProcUid(),
                    interval);
            if (appOut.httpBody != null && stdoutPrint) {
                System.out.print(appOut.httpBody);
            }
            if (appOut.outputPosition != null) {
                lastOutputPosition = appOut.outputPosition;
            }
            if (appOut.exitCode != null) {
                this.deleteApp(run.getAppName());
                return appOut.exitCode;
            }
            if (!appOut.httpSuccess) {
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
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(timeout));

        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/task", data, null,
                query);

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Task failed: " + Utils.readResponseSafe(conn));
        }
        return Utils.readResponse(conn);
    }

    /** Cancel a running task. */
    public boolean cancelTask(String appName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + encodeURIComponent(appName) + "/task", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
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
     * Upload a local file to the remote server.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent in headers so the
     * server can recreate permissions and ownership when supported.
     */
    public boolean uploadFile(Object localFile, String remoteFile, boolean preservePermissions) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put("X-File-Path", encodeURIComponent(remoteFile));

        File file;
        if (localFile instanceof String) {
            file = new File((String) localFile);
        } else if (localFile instanceof File) {
            file = (File) localFile;
        } else {
            throw new IllegalArgumentException("localFile must be a String path or a File object");
        }

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
    public JSONObject setConfig(JSONObject configJson) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/config", configJson, null, null);
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

    // -------- User Management --------

    /** Change password for a specific user. */
    public boolean updatePassword(String oldPassword, String newPassword, String userName) throws IOException {
        JSONObject body = new JSONObject();
        body.put("old_password", Base64.getEncoder().encodeToString(oldPassword.getBytes(StandardCharsets.UTF_8)));
        body.put("new_password", Base64.getEncoder().encodeToString(newPassword.getBytes(StandardCharsets.UTF_8)));
        HttpURLConnection conn = request("POST", "/appmesh/user/" + encodeURIComponent(userName) + "/passwd", body,
                null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Change password for the current user. */
    public boolean updatePassword(String oldPassword, String newPassword) throws IOException {
        return updatePassword(oldPassword, newPassword, "self");
    }

    /** Add or update a user. */
    public boolean addUser(String userName, JSONObject userJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/user/" + encodeURIComponent(userName), userJson, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Delete a user. */
    public boolean deleteUser(String userName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/user/" + encodeURIComponent(userName), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Lock a user account. */
    public boolean lockUser(String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + encodeURIComponent(userName) + "/lock", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Unlock a user account. */
    public boolean unlockUser(String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + encodeURIComponent(userName) + "/unlock", null,
                null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** List all users. */
    public JSONObject listUsers() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/users", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Get current authenticated user info. */
    public JSONObject getCurrentUser() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/user/self", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** List user groups. */
    public JSONObject listGroups() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/user/groups", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
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

    /** List permissions for the current user. */
    public Set<String> getUserPermissions() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/user/permissions", null, null, null);
        JSONArray jsonArray = new JSONArray(Utils.readResponse(conn));
        Set<String> permissions = new HashSet<>();
        for (int i = 0; i < jsonArray.length(); i++) {
            permissions.add(jsonArray.getString(i));
        }
        return permissions;
    }

    /** View all roles and their permissions. */
    public JSONObject viewRoles() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/roles", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Update permissions for a role. */
    public boolean updateRole(String roleName, JSONObject rolePermissionJson) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/role/" + encodeURIComponent(roleName), rolePermissionJson,
                null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    /** Delete a role. */
    public boolean deleteRole(String roleName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/role/" + encodeURIComponent(roleName), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // -------- Internal Helpers --------

    private Map<String, String> commonHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT);
        String token = this.jwtToken.get();
        if (token != null && !token.isEmpty()) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        }
        if (this.forwardTo != null && !this.forwardTo.isEmpty()) {
            String host = this.forwardTo;
            if (!host.contains(":")) {
                try {
                    URL url = Utils.toUrl(this.baseURL);
                    int port = url.getPort();
                    if (port == -1) {
                        port = "https".equalsIgnoreCase(url.getProtocol()) ? 443 : 80;
                    }
                    host = this.forwardTo + ":" + port;
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to parse baseURL", e);
                    throw new RuntimeException("Failed to set forward host", e);
                }
            }
            headers.put("X-Target-Host", host);
        }
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
