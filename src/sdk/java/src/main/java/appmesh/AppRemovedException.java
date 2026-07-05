package appmesh;

import java.io.IOException;

/**
 * Thrown by {@code waitForAsyncRun} (TCP/WSS) when the watched app was removed before
 * its exit code was observed — a typed failure instead of a sentinel exit code.
 */
public class AppRemovedException extends IOException {
    private static final long serialVersionUID = 1L;

    public AppRemovedException(String message) {
        super(message);
    }
}
