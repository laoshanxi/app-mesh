import org.java_websocket.client.WebSocketClient;
import org.java_websocket.drafts.Draft_6455;
import org.java_websocket.handshake.ServerHandshake;
import org.java_websocket.protocols.IProtocol;
import org.java_websocket.protocols.Protocol;
import org.java_websocket.enums.ReadyState;
import org.java_websocket.extensions.IExtension;

import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/**
 * WebSocket Secure (WSS) Transport layer with TLS support.
 * This implementation uses blocking-style operations with configurable
 * timeouts.
 */
public class WSSTransport implements AutoCloseable {

    /** Maximum message size: 100 MB */
    public static final int WSS_MAX_BLOCK_SIZE = 100 * 1024 * 1024;
    /** Default connect timeout in seconds */
    public static final int WSS_CONNECT_TIMEOUT = 30;

    private final String host;
    private final int port;
    private final SSLSocketFactory sslSocketFactory;
    private final Draft_6455 draft;

    private volatile WebSocketClient client;
    private final ArrayBlockingQueue<byte[]> recvQueue = new ArrayBlockingQueue<>(1024);
    private final AtomicReference<Exception> lastError = new AtomicReference<>();

    private int connectTimeout = WSS_CONNECT_TIMEOUT;

    public WSSTransport(String host, int port) {
        this(host, port, null);
    }

    public WSSTransport(String host, int port, SSLSocketFactory sslSocketFactory) {
        this.host = host;
        this.port = port;
        this.sslSocketFactory = sslSocketFactory;
        this.draft = new Draft_6455(
                Collections.<IExtension>emptyList(),
                Collections.<IProtocol>singletonList(new Protocol("appmesh-ws")));
    }

    public WSSTransport setConnectTimeout(int seconds) {
        this.connectTimeout = seconds;
        return this;
    }

    public synchronized void connect() throws Exception {
        if (connected()) {
            return;
        }

        // Clear any previous state
        recvQueue.clear();
        lastError.set(null);

        URI uri = new URI(toString() + "/");
        client = new WebSocketClient(uri, draft) {
            @Override
            public void onOpen(ServerHandshake handshake) {
                // Connection established successfully
            }

            @Override
            public void onMessage(String message) {
                // Text frame - convert to UTF-8 bytes
                if (message != null) {
                    recvQueue.offer(message.getBytes(java.nio.charset.StandardCharsets.UTF_8));
                }
            }

            @Override
            public void onMessage(ByteBuffer bytes) {
                // Binary frame
                if (bytes != null && bytes.hasRemaining()) {
                    byte[] data = new byte[bytes.remaining()];
                    bytes.get(data);
                    recvQueue.offer(data);
                } else {
                    // Empty message - EOF signal
                    recvQueue.offer(new byte[0]);
                }
            }

            @Override
            public void onClose(int code, String reason, boolean remote) {
                // Signal EOF to any waiting receivers
                recvQueue.offer(new byte[0]);
            }

            @Override
            public void onError(Exception ex) {
                lastError.set(ex);
                // Signal error to any waiting receivers
                recvQueue.offer(new byte[0]);
            }
        };

        // Configure SSL
        if (sslSocketFactory != null) {
            client.setSocketFactory(sslSocketFactory);
        }

        // Set connection timeout
        client.setConnectionLostTimeout(connectTimeout);

        // Blocking connect with timeout
        boolean success = client.connectBlocking(connectTimeout, TimeUnit.SECONDS);
        if (!success) {
            client = null;
            throw new IOException("Failed to connect to " + host + ":" + port + " within " + connectTimeout + "s");
        }

    }

    @Override
    public synchronized void close() {
        if (client != null) {
            try {
                client.closeBlocking();
            } catch (Exception ignored) {
                // Suppress all exceptions during close
            } finally {
                client = null;
            }
        }
        recvQueue.clear();
    }

    public boolean connected() {
        WebSocketClient c = client;
        return c != null && c.getReadyState() == ReadyState.OPEN;
    }

    public void sendMessage(byte[] data) throws IOException {
        if (!connected())
            throw new IllegalStateException("Not connected");

        byte[] messageData = (data != null) ? data : new byte[0];
        client.send(messageData);
    }

    public byte[] receiveMessage() throws InterruptedException {
        return recvQueue.take();
    }

    /**
     * Return WSS URI representation.
     */
    @Override
    public String toString() {
        return "wss://" + host + ":" + port;
    }

    /**
     * Get the host.
     */
    public String getHost() {
        return host;
    }

    /**
     * Get the port.
     */
    public int getPort() {
        return port;
    }
}
