package appmesh;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * {@link TokenProvider} for a caller-supplied access token / refresh token pair.
 *
 * <p>The provider refreshes the access token with the OAuth 2.0
 * {@code refresh_token} grant against the given token endpoint: proactively when
 * the current token is near expiry (only when a lifetime is known), and reactively
 * when the Engine rejects a token with HTTP 401. A rotated refresh token returned
 * by the endpoint replaces the stored one; a response without a refresh token
 * keeps the previous one. An {@code invalid_grant} error clears both tokens.
 *
 * <p>The token endpoint must use HTTPS, or plain HTTP only for loopback hosts
 * (127.0.0.1, localhost, ::1). Tokens are never logged.
 */
public class RefreshTokenProvider implements TokenProvider {
    public static final String DEFAULT_CLIENT_ID = "appmesh-cli";

    private static final long MIN_REFRESH_MARGIN_MS = 30_000;
    private static final int CONNECT_TIMEOUT_MS = 30_000;
    private static final int READ_TIMEOUT_MS = 30_000;

    private final String tokenUrl;
    private final String clientId;
    private String accessToken;
    private String refreshToken;
    // Absolute expiry in epoch milliseconds; 0 means unknown (refresh only on 401).
    private long expiresAtMs = 0;
    private long refreshMarginMs = MIN_REFRESH_MARGIN_MS;

    /** Create a provider with the {@link #DEFAULT_CLIENT_ID} client id. */
    public RefreshTokenProvider(String tokenUrl, String accessToken, String refreshToken, long expiresInSeconds) {
        this(tokenUrl, DEFAULT_CLIENT_ID, accessToken, refreshToken, expiresInSeconds);
    }

    /**
     * Create a provider for an access token / refresh token pair.
     *
     * @param tokenUrl         absolute token endpoint URL (https, or http on loopback)
     * @param clientId         OAuth client id sent with the refresh grant
     * @param accessToken      current access token
     * @param refreshToken     refresh token used to replace the access token
     * @param expiresInSeconds access-token lifetime in seconds; 0 or negative means
     *                         unknown, in which case refresh happens only after a 401
     */
    public RefreshTokenProvider(String tokenUrl, String clientId, String accessToken, String refreshToken,
            long expiresInSeconds) {
        this.tokenUrl = validateTokenUrl(tokenUrl);
        if (clientId == null || clientId.trim().isEmpty()) {
            throw new IllegalArgumentException("clientId must be a non-empty string");
        }
        this.clientId = clientId.trim();
        if (accessToken == null || accessToken.trim().isEmpty()) {
            throw new IllegalArgumentException("accessToken must be a non-empty string");
        }
        this.accessToken = accessToken.trim();
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new IllegalArgumentException("refreshToken must be a non-empty string");
        }
        this.refreshToken = refreshToken.trim();
        installExpiry(expiresInSeconds);
    }

    private static String validateTokenUrl(String tokenUrl) {
        if (tokenUrl == null || tokenUrl.trim().isEmpty()) {
            throw new IllegalArgumentException("tokenUrl is required");
        }
        String value = tokenUrl.trim();
        URI uri;
        try {
            uri = new URI(value);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("tokenUrl is not a valid URL", e);
        }
        String scheme = uri.getScheme();
        String host = uri.getHost();
        if ("https".equalsIgnoreCase(scheme) && host != null) {
            return value;
        }
        if ("http".equalsIgnoreCase(scheme) && host != null && isLoopbackHost(host)) {
            return value;
        }
        throw new IllegalArgumentException(
                "tokenUrl must use https, or http only for loopback hosts (127.0.0.1, localhost, ::1)");
    }

    private static boolean isLoopbackHost(String host) {
        return "localhost".equalsIgnoreCase(host) || "127.0.0.1".equals(host)
                || "::1".equals(host) || "[::1]".equals(host);
    }

    // Must be called with the lock held or during construction.
    private void installExpiry(long expiresInSeconds) {
        if (expiresInSeconds > 0) {
            this.expiresAtMs = System.currentTimeMillis() + expiresInSeconds * 1000;
            this.refreshMarginMs = Math.max(MIN_REFRESH_MARGIN_MS, expiresInSeconds * 100);
        } else {
            this.expiresAtMs = 0;
            this.refreshMarginMs = MIN_REFRESH_MARGIN_MS;
        }
    }

    @Override
    public synchronized String getAccessToken() {
        if (this.accessToken == null) {
            throw new IllegalStateException("No access token is available");
        }
        if (this.expiresAtMs > 0 && System.currentTimeMillis() >= this.expiresAtMs - this.refreshMarginMs) {
            try {
                return refreshGrantLocked();
            } catch (IOException e) {
                // A failed proactive refresh must not break the caller; the current
                // token may still be accepted until expiry, and a 401 triggers a retry.
                if (this.accessToken == null) {
                    throw new IllegalStateException("No access token is available", e);
                }
            }
        }
        return this.accessToken;
    }

    @Override
    public synchronized boolean canRefresh() {
        return this.refreshToken != null;
    }

    @Override
    public synchronized String refreshAccessToken(String rejectedToken) throws IOException {
        if (rejectedToken != null && this.accessToken != null && !this.accessToken.equals(rejectedToken)) {
            // A racing caller already replaced the rejected token.
            return this.accessToken;
        }
        return refreshGrantLocked();
    }

    @Override
    public synchronized void clear() {
        this.accessToken = null;
        this.refreshToken = null;
        this.expiresAtMs = 0;
    }

    // Must be called with the lock held.
    private String refreshGrantLocked() throws IOException {
        if (this.refreshToken == null) {
            throw new IOException("No refresh token is available");
        }
        String form = "grant_type=refresh_token"
                + "&refresh_token=" + URLEncoder.encode(this.refreshToken, StandardCharsets.UTF_8.name())
                + "&client_id=" + URLEncoder.encode(this.clientId, StandardCharsets.UTF_8.name());

        HttpURLConnection connection = (HttpURLConnection) Utils.toUrl(this.tokenUrl).openConnection();
        int status;
        String responseBody;
        try {
            connection.setRequestMethod("POST");
            connection.setConnectTimeout(CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(READ_TIMEOUT_MS);
            connection.setDoOutput(true);
            connection.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            connection.setRequestProperty("Accept", "application/json");
            byte[] body = form.getBytes(StandardCharsets.UTF_8);
            connection.setFixedLengthStreamingMode(body.length);
            try (OutputStream os = connection.getOutputStream()) {
                os.write(body);
            }

            status = connection.getResponseCode();
            responseBody = Utils.readResponseSafe(connection);
        } finally {
            connection.disconnect();
        }

        if (status < 200 || status >= 300) {
            String error = null;
            try {
                error = new JSONObject(responseBody).optString("error", null);
            } catch (JSONException ignored) {
                // Non-JSON error body; report the status only.
            }
            if ("invalid_grant".equals(error)) {
                // The refresh token is dead; drop both tokens so canRefresh() goes false.
                this.accessToken = null;
                this.refreshToken = null;
                this.expiresAtMs = 0;
            }
            throw new IOException("Token refresh failed with HTTP " + status
                    + (error == null ? "" : ": " + error));
        }

        JSONObject tokens;
        try {
            tokens = new JSONObject(responseBody);
        } catch (JSONException e) {
            throw new IOException("Token endpoint returned a non-JSON response", e);
        }
        String newAccessToken = tokens.optString("access_token", null);
        if (newAccessToken == null || newAccessToken.isEmpty()) {
            throw new IOException("Token response did not include an access token");
        }
        this.accessToken = newAccessToken;
        String newRefreshToken = tokens.optString("refresh_token", null);
        if (newRefreshToken != null && !newRefreshToken.isEmpty()) {
            this.refreshToken = newRefreshToken;
        }
        installExpiry(tokens.optLong("expires_in", 0));
        return this.accessToken;
    }
}
