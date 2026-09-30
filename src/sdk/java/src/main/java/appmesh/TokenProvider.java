package appmesh;

import java.io.IOException;

/**
 * Provide a usable access token to an App Mesh Engine client.
 *
 * <p>Providers own token acquisition and refresh. Engine clients consume only the
 * resulting access token and never receive passwords, refresh tokens, or OAuth
 * authorization responses.
 *
 * <p>{@link #getAccessToken()} may refresh proactively when the current token is near
 * expiry. {@link #refreshAccessToken(String)} is called at most once after the Engine
 * rejects a provider-managed token with HTTP 401. Implementations should use
 * {@code rejectedToken} to avoid duplicate refreshes when requests race.
 *
 * <p>Providers keep refresh credentials private; only an access token crosses
 * this boundary into the Engine client.
 */
public interface TokenProvider {

    /** Return a current access token, refreshing before expiry when possible. */
    String getAccessToken();

    /** Whether this provider can replace a rejected or expiring token. */
    default boolean canRefresh() {
        return false;
    }

    /** Replace a rejected token and return the new access token. */
    default String refreshAccessToken(String rejectedToken) throws IOException {
        return getAccessToken();
    }

    /** Forget provider-owned in-memory token state, if any. */
    default void clear() {
    }
}
