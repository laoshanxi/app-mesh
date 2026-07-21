package appmesh;

import java.io.IOException;

/**
 * Thrown by {@link AppMeshClientOAuth} when an OAuth2 authentication step fails —
 * e.g. the user denies a device authorization request, the device code expires,
 * or a token grant/renewal is rejected by the identity provider.
 */
public class AppMeshAuthException extends IOException {
    private static final long serialVersionUID = 1L;

    public AppMeshAuthException(String message) {
        super(message);
    }

    public AppMeshAuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
