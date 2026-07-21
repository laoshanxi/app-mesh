package appmesh;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

/**
 * App Mesh client with Keycloak as the OAuth2 identity provider.
 *
 * <p>Authentication (password grant, device flow, token refresh, logout, userinfo) is performed
 * directly against Keycloak; the issued access token is then used as the Bearer token for all
 * App Mesh daemon API calls inherited from {@link AppMeshClient}. Mirrors the Python SDK's
 * {@code AppMeshClientOAuth}.
 */
public class AppMeshClientOAuth extends AppMeshClient {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClientOAuth.class.getName());

    private static final String DEFAULT_SCOPE = "openid profile email";
    private static final String DEVICE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code";
    private static final String FORM_CONTENT_TYPE = "application/x-www-form-urlencoded";

    private final Oauth2Config oauth2;
    /** Keycloak OIDC endpoint base: {authServerUrl}/realms/{realm}/protocol/openid-connect. */
    private final String oidcBaseUrl;
    private final int oauthConnectTimeoutMs;
    private final int oauthReadTimeoutMs;

    /** The complete last token response from Keycloak (access_token, refresh_token, ...). */
    private volatile JSONObject oauthToken = new JSONObject();

    /** Keycloak OAuth2 configuration: server URL, realm, client ID and optional client secret. */
    public static class Oauth2Config {
        private final String authServerUrl;
        private final String realm;
        private final String clientId;
        private final String clientSecret;

        /**
         * @param authServerUrl Keycloak server URL (e.g. {@code "https://keycloak.example.com/"})
         * @param realm        Keycloak realm name
         * @param clientId     Keycloak client ID
         * @param clientSecret Keycloak client secret (null for public clients)
         */
        public Oauth2Config(String authServerUrl, String realm, String clientId, String clientSecret) {
            this.authServerUrl = Objects.requireNonNull(authServerUrl, "authServerUrl cannot be null");
            this.realm = Objects.requireNonNull(realm, "realm cannot be null");
            this.clientId = Objects.requireNonNull(clientId, "clientId cannot be null");
            this.clientSecret = clientSecret;
        }

        /** Convenience constructor for public clients (no client secret). */
        public Oauth2Config(String authServerUrl, String realm, String clientId) {
            this(authServerUrl, realm, clientId, null);
        }
    }

    /** Device authorization response per RFC 8628 §3.2. */
    public static class DeviceAuthResponse {
        private final String deviceCode;
        private final String userCode;
        private final String verificationUri;
        private final String verificationUriComplete;
        private final long expiresIn;
        private final long interval;

        DeviceAuthResponse(JSONObject json) {
            this.deviceCode = json.getString("device_code");
            this.userCode = json.optString("user_code", null);
            this.verificationUri = json.optString("verification_uri", null);
            this.verificationUriComplete = json.optString("verification_uri_complete", null);
            this.expiresIn = json.optLong("expires_in", 600);
            this.interval = json.optLong("interval", 5);
        }

        /** The device verification code polled against the token endpoint. */
        public String getDeviceCode() {
            return deviceCode;
        }

        /** The code the end user enters on the verification page. */
        public String getUserCode() {
            return userCode;
        }

        /** The end-user verification URI. */
        public String getVerificationUri() {
            return verificationUri;
        }

        /** Verification URI with the user code embedded, or null when not provided. */
        public String getVerificationUriComplete() {
            return verificationUriComplete;
        }

        /** Lifetime of the device code in seconds. */
        public long getExpiresIn() {
            return expiresIn;
        }

        /** Minimum polling interval in seconds. */
        public long getInterval() {
            return interval;
        }
    }

    /**
     * Create an OAuth-enabled App Mesh client.
     *
     * <p>Subclass-visible so tests and transports can extend; use {@link Builder} normally.
     */
    protected AppMeshClientOAuth(Builder builder) {
        super(builder.base);
        this.oauth2 = Objects.requireNonNull(builder.oauth2, "oauth2 configuration is required");
        String serverUrl = oauth2.authServerUrl;
        while (serverUrl.endsWith("/")) {
            serverUrl = serverUrl.substring(0, serverUrl.length() - 1);
        }
        this.oidcBaseUrl = serverUrl + "/realms/" + oauth2.realm + "/protocol/openid-connect";
        this.oauthConnectTimeoutMs = builder.connectTimeoutMs;
        this.oauthReadTimeoutMs = builder.readTimeoutMs;
    }

    /** Builder for {@link AppMeshClientOAuth}. Token auto-refresh defaults to enabled. */
    public static class Builder {
        private final AppMeshClient.Builder base = new AppMeshClient.Builder().autoRefreshToken(true);
        private Oauth2Config oauth2;
        private int connectTimeoutMs = 30_000;
        private int readTimeoutMs = 300_000;

        /** Keycloak OAuth2 configuration (required). */
        public Builder oauth2(Oauth2Config config) {
            this.oauth2 = config;
            return this;
        }

        /** AppMesh service base URL (default: {@code https://127.0.0.1:6060}). */
        public Builder baseURL(String baseURL) {
            base.baseURL(baseURL);
            return this;
        }

        /** Path to a CA certificate bundle for server verification. */
        public Builder caCert(String caCertFilePath) {
            base.caCert(caCertFilePath);
            return this;
        }

        /** Client certificate and key paths for mutual TLS. */
        public Builder clientCert(String clientCertFilePath, String clientCertKeyFilePath) {
            base.clientCert(clientCertFilePath, clientCertKeyFilePath);
            return this;
        }

        /** Disable SSL verification (insecure — development only). */
        public Builder disableSSLVerify() {
            base.disableSSLVerify();
            return this;
        }

        /** Cookie file path for persistent token storage. */
        public Builder cookieFile(String cookieFile) {
            base.cookieFile(cookieFile);
            return this;
        }

        /** Enable or disable automatic token refresh before expiration (default: enabled). */
        public Builder autoRefreshToken(boolean enable) {
            base.autoRefreshToken(enable);
            return this;
        }

        /** Connection timeout in milliseconds for both daemon and Keycloak requests. */
        public Builder connectTimeoutMs(int ms) {
            this.connectTimeoutMs = ms;
            base.connectTimeoutMs(ms);
            return this;
        }

        /** Read timeout in milliseconds for both daemon and Keycloak requests. */
        public Builder readTimeoutMs(int ms) {
            this.readTimeoutMs = ms;
            base.readTimeoutMs(ms);
            return this;
        }

        public AppMeshClientOAuth build() {
            return new AppMeshClientOAuth(this);
        }
    }

    // -------- Keycloak Authentication --------

    /**
     * Login with username and password using the Keycloak Direct Access Grant.
     *
     * <p>On success the full token response is stored and the access token becomes the Bearer
     * token for daemon API calls made through this client.
     *
     * @param username the name of the user
     * @param password the password of the user
     * @param totpCode the TOTP code if enabled for the user (sent verbatim as a string —
     *                 leading zeros are significant), or null
     * @throws AppMeshAuthException when Keycloak rejects the credentials
     * @throws IOException          on network failure
     */
    public void login(String username, String password, String totpCode) throws IOException {
        Map<String, String> form = clientCredentialsForm();
        form.put("grant_type", "password");
        form.put("username", username);
        form.put("password", password);
        // Request identity claims so userinfo returns preferred_username/email
        form.put("scope", DEFAULT_SCOPE);
        if (totpCode != null && !totpCode.isEmpty()) {
            // Pass TOTP as-is: parsing to a number would strip leading zeros (e.g. "012345" -> 12345)
            form.put("totp", totpCode);
        }
        applyOauthToken(postTokenForm(form, "Login"));
    }

    /**
     * Login via the OAuth 2.0 Device Authorization Grant (RFC 8628) with the default scope.
     *
     * @see #loginDeviceFlow(String, Consumer)
     */
    public void loginDeviceFlow(Consumer<DeviceAuthResponse> onPrompt) throws IOException {
        loginDeviceFlow(DEFAULT_SCOPE, onPrompt);
    }

    /**
     * Login via the OAuth 2.0 Device Authorization Grant (RFC 8628).
     *
     * <p>For browserless/input-constrained environments: the user opens
     * {@code verification_uri_complete} (or {@code verification_uri} plus the user code) on
     * another device, and this call polls the token endpoint until approval, denial, or expiry.
     * Requires "OAuth 2.0 Device Authorization Grant" enabled on the Keycloak client.
     *
     * @param scope    OAuth2 scopes to request
     * @param onPrompt callback receiving the device authorization response to present the
     *                 instructions to the user; null prints them to stdout
     * @throws AppMeshAuthException when the user denies the request, the device code expires,
     *                              or the token request fails for any other reason
     * @throws IOException          on network failure
     */
    public void loginDeviceFlow(String scope, Consumer<DeviceAuthResponse> onPrompt) throws IOException {
        DeviceAuthResponse device = requestDeviceAuthorization(scope);

        if (onPrompt != null) {
            onPrompt.accept(device);
        } else {
            String uri = device.getVerificationUriComplete() != null
                    ? device.getVerificationUriComplete() : device.getVerificationUri();
            System.out.println("To sign in, open " + uri + " and enter code: " + device.getUserCode());
        }

        // RFC 8628 §3.5: poll no faster than "interval", stop once the device code expires
        long intervalMs = device.getInterval() * 1000L;
        long deadline = System.nanoTime() / 1_000_000L + device.getExpiresIn() * 1000L;

        while (true) {
            long remaining = deadline - System.nanoTime() / 1_000_000L;
            if (remaining <= 0) {
                throw new AppMeshAuthException("Device authorization expired before the user approved the request");
            }
            sleepMs(Math.min(intervalMs, remaining));
            DeviceTokenResult result = pollDeviceToken(device.getDeviceCode());
            if (result.token != null) {
                applyOauthToken(result.token);
                return;
            }
            if ("authorization_pending".equals(result.error)) {
                continue;
            }
            if ("slow_down".equals(result.error)) {
                intervalMs += 5000L; // RFC 8628 §3.5: back off by 5 seconds
                continue;
            }
            throw new AppMeshAuthException("Device authorization failed: "
                    + (result.error.isEmpty() ? result.rawBody : result.error));
        }
    }

    /**
     * Renew the current Keycloak token via the refresh_token grant.
     *
     * <p>Keycloak rotates the refresh token: the complete new token response replaces the
     * stored one. Also invoked by the inherited background auto-refresh scheduler.
     *
     * @return the new access token
     * @throws AppMeshAuthException when no refresh token is available or the renewal is rejected
     */
    @Override
    public String renewToken() throws IOException {
        Map<String, String> form = clientCredentialsForm();
        form.put("grant_type", "refresh_token");
        form.put("refresh_token", requireRefreshToken("renew"));
        JSONObject token = postTokenForm(form, "Keycloak token renewal");
        applyOauthToken(token);
        return token.getString("access_token");
    }

    /** Renew the Keycloak token; the expiry argument is ignored (Keycloak controls token lifetime). */
    @Override
    public String renewToken(long tokenExpireSeconds) throws IOException {
        return renewToken();
    }

    /** Renew the Keycloak token; the expiry argument is ignored (Keycloak controls token lifetime). */
    @Override
    public String renewToken(String tokenExpire) throws IOException {
        return renewToken();
    }

    /**
     * Log out of the current session from Keycloak, then from the App Mesh daemon.
     *
     * <p>The daemon logoff runs before the local token state is cleared so it can still present
     * the access token; the local OAuth token state is cleared even when either call fails.
     *
     * @return true when both Keycloak and the daemon acknowledged the logoff
     */
    @Override
    public boolean logout() throws IOException {
        boolean keycloakResult = keycloakLogout();
        try {
            return keycloakResult && super.logout();
        } finally {
            this.oauthToken = new JSONObject();
        }
    }

    /**
     * Get Keycloak OIDC userinfo for the current access token, directly from Keycloak.
     *
     * <p>Unlike {@link #getCurrentUser()}, which asks the App Mesh daemon, this queries the
     * Keycloak userinfo endpoint without involving the daemon.
     *
     * @return OIDC claims such as {@code sub}, {@code preferred_username}, {@code email}
     */
    public JSONObject getOauthUserinfo() throws IOException {
        String accessToken = this.oauthToken.optString("access_token", null);
        if (accessToken == null || accessToken.isEmpty()) {
            throw new AppMeshAuthException("No Keycloak access token available");
        }
        HttpURLConnection conn = openOauthConnection("GET", oidcBaseUrl + "/userinfo");
        conn.setRequestProperty("Authorization", "Bearer " + accessToken);
        int status = conn.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            throw new AppMeshAuthException("Userinfo request failed: HTTP " + status
                    + " - " + Utils.readErrorResponse(conn));
        }
        return new JSONObject(Utils.readResponse(conn));
    }

    /** Close the session and release resources, including a best-effort Keycloak logout. */
    @Override
    public void close() {
        try {
            keycloakLogout();
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to logout from Keycloak during close", e);
        }
        this.oauthToken = new JSONObject();
        super.close();
    }

    // -------- Internal Helpers --------

    /** Outcome of a single device-flow token poll: a token, or an OAuth2 error code. */
    static final class DeviceTokenResult {
        final JSONObject token;
        final String error;
        final String rawBody;

        DeviceTokenResult(JSONObject token, String error, String rawBody) {
            this.token = token;
            this.error = error;
            this.rawBody = rawBody;
        }
    }

    /** Request a device authorization (RFC 8628 §3.1) from Keycloak. */
    DeviceAuthResponse requestDeviceAuthorization(String scope) throws IOException {
        Map<String, String> form = clientCredentialsForm();
        if (scope != null && !scope.isEmpty()) {
            form.put("scope", scope);
        }
        HttpURLConnection conn = postForm(oidcBaseUrl + "/auth/device", form);
        int status = conn.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            throw new AppMeshAuthException("Device authorization request failed: HTTP " + status
                    + " - " + Utils.readErrorResponse(conn));
        }
        return new DeviceAuthResponse(new JSONObject(Utils.readResponse(conn)));
    }

    /** Poll the token endpoint once for a pending device authorization (RFC 8628 §3.4). */
    DeviceTokenResult pollDeviceToken(String deviceCode) throws IOException {
        Map<String, String> form = clientCredentialsForm();
        form.put("grant_type", DEVICE_GRANT_TYPE);
        form.put("device_code", deviceCode);
        HttpURLConnection conn = postForm(oidcBaseUrl + "/token", form);
        int status = conn.getResponseCode();
        if (status >= 200 && status < 300) {
            return new DeviceTokenResult(new JSONObject(Utils.readResponse(conn)), null, null);
        }
        String body = Utils.readErrorResponse(conn);
        return new DeviceTokenResult(null, oauthErrorCode(body), body);
    }

    /** Current raw Keycloak token response (package-private, for tests). */
    JSONObject oauthTokenSnapshot() {
        return this.oauthToken;
    }

    /** Store the complete Keycloak token response and apply the access token to this client. */
    private void applyOauthToken(JSONObject token) throws AppMeshAuthException {
        String accessToken = token.optString("access_token", null);
        if (accessToken == null || accessToken.isEmpty()) {
            throw new AppMeshAuthException("Keycloak token response contains no access_token");
        }
        this.oauthToken = token;
        // Applies Bearer token, cookie-file persistence and auto-refresh scheduling
        setToken(accessToken);
    }

    /** Best-effort Keycloak logout with the stored refresh token; false when it fails or none is stored. */
    private boolean keycloakLogout() throws IOException {
        String refreshToken = this.oauthToken.optString("refresh_token", null);
        if (refreshToken == null || refreshToken.isEmpty()) {
            return false;
        }
        Map<String, String> form = clientCredentialsForm();
        form.put("refresh_token", refreshToken);
        try {
            HttpURLConnection conn = postForm(oidcBaseUrl + "/logout", form);
            int status = conn.getResponseCode();
            if (status >= 200 && status < 300) {
                return true;
            }
            LOGGER.warning("Failed to logout from Keycloak: HTTP " + status
                    + " - " + Utils.readErrorResponse(conn));
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to logout from Keycloak", e);
        }
        return false;
    }

    private String requireRefreshToken(String action) throws AppMeshAuthException {
        String refreshToken = this.oauthToken.optString("refresh_token", null);
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new AppMeshAuthException("No Keycloak refresh token available to " + action);
        }
        return refreshToken;
    }

    /** Base form parameters carrying the OAuth2 client credentials. */
    private Map<String, String> clientCredentialsForm() {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("client_id", oauth2.clientId);
        if (oauth2.clientSecret != null && !oauth2.clientSecret.isEmpty()) {
            form.put("client_secret", oauth2.clientSecret);
        }
        return form;
    }

    /** POST the form to the token endpoint and return the parsed token JSON, or throw on failure. */
    private JSONObject postTokenForm(Map<String, String> form, String action) throws IOException {
        HttpURLConnection conn = postForm(oidcBaseUrl + "/token", form);
        int status = conn.getResponseCode();
        if (status < 200 || status >= 300) {
            String body = Utils.readErrorResponse(conn);
            String error = oauthErrorCode(body);
            throw new AppMeshAuthException(action + " failed: HTTP " + status + " - "
                    + (error.isEmpty() ? body : error));
        }
        return new JSONObject(Utils.readResponse(conn));
    }

    /** POST a form-encoded request to a Keycloak endpoint. */
    private HttpURLConnection postForm(String url, Map<String, String> form) throws IOException {
        HttpURLConnection conn = openOauthConnection("POST", url);
        conn.setRequestProperty("Content-Type", FORM_CONTENT_TYPE);
        conn.setDoOutput(true);
        byte[] body = encodeForm(form).getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = conn.getOutputStream()) {
            os.write(body);
            os.flush();
        }
        return conn;
    }

    private HttpURLConnection openOauthConnection(String method, String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) Utils.toUrl(url).openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(oauthConnectTimeoutMs);
        conn.setReadTimeout(oauthReadTimeoutMs);
        conn.setRequestProperty("Accept", "application/json");
        applySSL(conn);
        return conn;
    }

    private static String encodeForm(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> entry : form.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            try {
                sb.append(URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8.name()))
                        .append('=')
                        .append(URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8.name()));
            } catch (UnsupportedEncodingException e) {
                throw new RuntimeException("UTF-8 encoding not supported", e);
            }
        }
        return sb.toString();
    }

    /** Extract the OAuth2 "error" code from an error response body ("" when not parseable). */
    private static String oauthErrorCode(String body) {
        try {
            return new JSONObject(body).optString("error", "");
        } catch (Exception e) {
            return "";
        }
    }

    private static void sleepMs(long millis) throws IOException {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted while waiting for device authorization", e);
        }
    }
}
