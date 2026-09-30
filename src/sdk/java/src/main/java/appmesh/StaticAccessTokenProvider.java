package appmesh;

/** In-memory provider for a caller-supplied access token. */
public class StaticAccessTokenProvider implements TokenProvider {
    private String token;

    public StaticAccessTokenProvider(String token) {
        if (token == null || token.trim().isEmpty()) {
            throw new IllegalArgumentException("bearer token must be a non-empty string");
        }
        this.token = token.trim();
    }

    @Override
    public synchronized String getAccessToken() {
        return this.token;
    }

    @Override
    public synchronized void clear() {
        this.token = null;
    }
}
