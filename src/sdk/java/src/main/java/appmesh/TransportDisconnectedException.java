package appmesh;

import java.io.IOException;

/**
 * Thrown by demux-routed requests and {@code waitForAsyncRun} (TCP/WSS) when the underlying
 * connection dropped — a typed failure instead of a sentinel exit code.
 */
public class TransportDisconnectedException extends IOException {
    private static final long serialVersionUID = 1L;

    public TransportDisconnectedException(String message) {
        super(message);
    }
}
