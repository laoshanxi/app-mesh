import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class TCPTransport implements AutoCloseable {
    private final String host;
    private final int port;
    private final SSLSocketFactory socketFactory;

    private SSLSocket socket;
    private DataInputStream inputStream;
    private DataOutputStream outputStream;

    // Must match C++ service and Python implementation
    public static final int TCP_MESSAGE_HEADER_LENGTH = 8;
    public static final int TCP_MESSAGE_MAGIC = 0x07C707F8;
    public static final int TCP_MAX_BLOCK_SIZE = 100 * 1024 * 1024; // 100MB

    public TCPTransport(String host, int port, SSLSocketFactory socketFactory) {
        this.host = host;
        this.port = port;
        this.socketFactory = socketFactory != null ? socketFactory : (SSLSocketFactory) SSLSocketFactory.getDefault();
    }

    public synchronized void connect() throws IOException {
        if (connected())
            return;

        Socket rawSocket = null;
        try {
            // Create a TCP socket
            rawSocket = new Socket();
            rawSocket.connect(new InetSocketAddress(host, port), 30000); // 30 sec connection timeout

            // Wrap the socket with SSL/TLS
            this.socket = (SSLSocket) socketFactory.createSocket(
                    rawSocket,
                    host,
                    port,
                    true // autoClose: close underlying socket when SSLSocket is closed
            );

            // Start TLS handshake
            this.socket.startHandshake();

            // Disable Nagle's algorithm (matches Python: socket.TCP_NODELAY)
            this.socket.setTcpNoDelay(true);

            // Set read timeout for recv/send
            this.socket.setSoTimeout(30000);

            // Use buffered streams for performance
            this.inputStream = new DataInputStream(new BufferedInputStream(this.socket.getInputStream()));
            this.outputStream = new DataOutputStream(new BufferedOutputStream(this.socket.getOutputStream()));

        } catch (IOException e) {
            // Clean up on failure (matches Python's exception handling)
            if (rawSocket != null && !rawSocket.isClosed()) {
                try {
                    rawSocket.close();
                } catch (Exception ignored) {
                }
            }
            close();
            throw new IOException("Failed to connect to " + host + ":" + port + ": " + e.getMessage(), e);
        }
    }

    @Override
    public synchronized void close() {
        // Close streams first, then socket
        if (this.inputStream != null) {
            try {
                this.inputStream.close();
            } catch (Exception ignored) {
            }
            this.inputStream = null;
        }

        if (this.outputStream != null) {
            try {
                this.outputStream.close();
            } catch (Exception ignored) {
            }
            this.outputStream = null;
        }

        if (this.socket != null) {
            try {
                this.socket.close();
            } catch (Exception e) {
                System.err.println("Error closing socket: " + e.getMessage());
            }
            this.socket = null;
        }
    }

    public synchronized boolean connected() {
        return this.socket != null && !this.socket.isClosed() && this.socket.isConnected();
    }

    /**
     * Sends a framed message.
     * 
     * @param data Byte array to send. Pass byte[0] or null for EOF/Empty message.
     */
    public synchronized void sendMessage(byte[] data) throws IOException {
        if (!connected())
            throw new IOException("Not connected");

        try {
            int length = (data != null) ? data.length : 0;

            // Pack the header into 8 bytes using big-endian format
            outputStream.writeInt(TCP_MESSAGE_MAGIC);
            outputStream.writeInt(length);

            // Write body if present
            if (length > 0) {
                outputStream.write(data);
            }
            outputStream.flush();

        } catch (IOException e) {
            close();
            throw new IOException("Error sending message: " + e.getMessage(), e);
        }
    }

    /**
     * Receives a framed message.
     * 
     * @return byte array of body, or null if EOF/Empty frame (length 0).
     */
    public synchronized byte[] receiveMessage() throws IOException {
        if (!connected())
            throw new IOException("Not connected");

        try {
            int magic = inputStream.readInt();
            int length = inputStream.readInt();

            if (magic != TCP_MESSAGE_MAGIC) {
                throw new IOException(String.format("Invalid magic number: 0x%X", magic));
            }

            if (length < 0 || length > TCP_MAX_BLOCK_SIZE) {
                throw new IOException("Invalid message length: " + length);
            }

            if (length == 0) {
                return null;
            }

            byte[] buf = new byte[length];
            inputStream.readFully(buf);
            return buf;

        } catch (java.io.EOFException e) {
            close();
            throw new IOException("Connection closed by peer", e);
        } catch (IOException e) {
            close();
            throw e;
        }
    }

    @Override
    public String toString() {
        return "tcps://" + host + ":" + port;
    }
}
