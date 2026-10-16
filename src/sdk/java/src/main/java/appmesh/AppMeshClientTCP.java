package appmesh;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.Objects;


/** App Mesh client over TCP (TLS). Control requests go over TCP; file transfers use a TCP side channel. */
public class AppMeshClientTCP extends AppMeshClient {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClientTCP.class.getName());
    private static final int TCP_BLOCK_SIZE = 16 * 1024 - 128; // TLS-optimized chunk size
    private final TCPTransport tcpTransport;
    private volatile MessageDemuxer demuxer;

    /** Create a TCP transport client with default TLS verification behavior. */
    public AppMeshClientTCP(String host, int port) {
        this(host, port, false, null, null, null);
    }

    /**
     * Create a TCP transport client that reuses the standard App Mesh client API.
     *
     * <p>Control requests use the normal SDK surface, while file transfers switch to the TCP
     * file-socket side channel for larger payloads. The SSL settings configure both the base
     * client (HTTPS paths) and the TCP transport, so one configuration is authoritative.
     */
    public AppMeshClientTCP(String host, int port, boolean disableSSLVerification, String caCertPath,
            String clientCertPath, String clientKeyPath) {
        this(configureSSL(new AppMeshClient.Builder().baseURL("https://" + host + ":" + port),
                disableSSLVerification, caCertPath, clientCertPath, clientKeyPath), host, port);
    }

    /**
     * Create a TCP transport client from a fully configured base builder. The builder's SSL
     * settings are reused for the TCP transport (system default trust when none configured).
     */
    protected AppMeshClientTCP(AppMeshClient.Builder builder, String host, int port) {
        super(builder);
        Objects.requireNonNull(host, "host");
        this.tcpTransport = new TCPTransport(host, port, getSSLSocketFactory());
    }

    /** Builder for {@link AppMeshClientTCP} to allow fluent configuration. */
    public static class Builder {
        private final AppMeshClient.Builder base = new AppMeshClient.Builder();
        private String host = "127.0.0.1";
        private int port = 6059;

        public Builder() {
        }

        public Builder host(String host) {
            this.host = host;
            return this;
        }

        public Builder port(int port) {
            this.port = port;
            return this;
        }

        /** Disable SSL verification (insecure — development only). */
        public Builder disableSSLVerify() {
            base.disableSSLVerify();
            return this;
        }

        public Builder caCert(String caCertPath) {
            base.caCert(caCertPath);
            return this;
        }

        public Builder clientCert(String clientCertPath, String clientKeyPath) {
            base.clientCert(clientCertPath, clientKeyPath);
            return this;
        }

        /** Password for encrypted private key. */
        public Builder keyPassword(char[] password) {
            base.keyPassword(password);
            return this;
        }

        /** Initialize with an existing JWT token (no server verification). */
        public Builder jwtToken(String jwtToken) {
            base.jwtToken(jwtToken);
            return this;
        }

        /** Attach a provider that supplies and refreshes access tokens (takes precedence over jwtToken). */
        public Builder tokenProvider(TokenProvider tokenProvider) {
            base.tokenProvider(tokenProvider);
            return this;
        }

        /** Connection timeout in milliseconds for HTTPS side-channel requests. */
        public Builder connectTimeoutMs(int ms) {
            base.connectTimeoutMs(ms);
            return this;
        }

        /** Read timeout in milliseconds for HTTPS side-channel requests. */
        public Builder readTimeoutMs(int ms) {
            base.readTimeoutMs(ms);
            return this;
        }

        public AppMeshClientTCP build() {
            Objects.requireNonNull(host, "host");
            base.baseURL("https://" + host + ":" + port);
            return new AppMeshClientTCP(base, host, port);
        }
    }

    /** Send a request over TCP transport and expose it as an {@link HttpURLConnection}-like object. */
    @Override
    public HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params) throws IOException {
        // Same 401 refresh-retry contract as the HTTP transport: when a refresh-capable
        // provider is attached and the caller did not set an explicit Authorization
        // header, one provider refresh and one replay (mirroring the Python SDK).
        TokenProvider provider = callerManagesAuth(headers) ? null : getTokenProvider();
        String sentToken = provider == null ? null : provider.getAccessToken();
        HttpURLConnection connection = doRequest(method, path, body, headers, params, sentToken);
        if (provider == null || !provider.canRefresh()
                || connection.getResponseCode() != HttpURLConnection.HTTP_UNAUTHORIZED) {
            return connection;
        }
        String newToken = provider.refreshAccessToken(sentToken);
        if (newToken == null || newToken.trim().isEmpty()) {
            throw new IOException("TokenProvider returned an invalid access token");
        }
        connection = doRequest(method, path, body, headers, params, newToken);
        if (connection.getResponseCode() == HttpURLConnection.HTTP_UNAUTHORIZED) {
            throw new IOException("TokenProvider failed to replace a rejected access token: HTTP 401");
        }
        return connection;
    }

    protected HttpURLConnection doRequest(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params, String tokenOverride) throws IOException {
        try {
            if (!tcpTransport.connected()) {
                tcpTransport.connect();
            }
            if (demuxer != null && demuxer.isRunning()) {
                // connect() re-armed the connect-time SO_TIMEOUT; the demuxer reader must
                // block indefinitely or an idle subscription gets a spurious DISCONNECTED
                // after 30 quiet seconds (same rationale as in ensureDemuxer()).
                tcpTransport.setReadTimeout(0);
            }

            RequestMessage req = new RequestMessage();
            req.uuid = java.util.UUID.randomUUID().toString();
            req.httpMethod = method;
            req.requestUri = path;
            try {
                req.clientAddr = java.net.InetAddress.getLocalHost().getHostName();
            } catch (Exception e) {
                // No DNS / container environments may fail or block here; fall back to loopback
                req.clientAddr = java.net.InetAddress.getLoopbackAddress().getHostAddress();
            }
            // Merge common headers from parent
            req.headers = new java.util.HashMap<>();
            req.headers.putAll(super.getCommonHeaders());
            if (tokenOverride != null) {
                req.headers.put("Authorization", "Bearer " + tokenOverride);
            }
            if (headers != null) {
                req.headers.putAll(headers);
            }
            if (params != null) {
                req.query = params;
            }
            if (body != null) {
                if (body instanceof byte[])
                    req.body = (byte[]) body;
                else
                    req.body = body.toString().getBytes(StandardCharsets.UTF_8);
            }

            byte[] data = req.serialize();

            ResponseMessage resp;
            if (demuxer != null && demuxer.isRunning()) {
                // Demuxer is active: register before send to avoid race
                demuxer.registerPending(req.uuid);
                try {
                    // Re-check after register: racing stop()'s pending.clear() would leave the latch never counted down
                    if (!demuxer.isRunning()) {
                        throw new TransportDisconnectedException("connection lost before request was sent");
                    }
                    tcpTransport.sendMessage(data);
                    // No wait cap: null means the demuxer stopped (disconnect), not a slow request
                    resp = demuxer.waitForResponse(req.uuid);
                    if (resp == null) {
                        throw new TransportDisconnectedException("connection lost while waiting for response");
                    }
                } finally {
                    demuxer.unregisterPending(req.uuid);
                }
            } else {
                // Legacy synchronous mode: hold one lock across send+receive so
                // concurrent callers cannot interleave and read each other's response.
                synchronized (tcpTransport) {
                    tcpTransport.sendMessage(data);
                    while (true) {
                        byte[] respBuf = tcpTransport.receiveMessage();
                        if (respBuf == null || respBuf.length == 0) {
                            // EOF frame: the transport is dead; close it so the next
                            // request reconnects instead of reusing the half-open socket.
                            tcpTransport.close();
                            throw new IOException("EOF from transport");
                        }
                        resp = ResponseMessage.deserialize(respBuf);
                        // Skip server-push event frames (no demuxer to route them)
                        if (MessageDemuxer.EVENT_URI.equals(resp.requestUri)) {
                            continue;
                        }
                        break;
                    }
                }
                if (!req.uuid.equals(resp.uuid)) {
                    throw new IOException("Response UUID mismatch: expected " + req.uuid + ", got " + resp.uuid);
                }
            }

            // Build a lightweight HttpURLConnection wrapper
            URL fake = new java.net.URI("http", null, "appmesh.local", -1, path, null, null).toURL();
            return new TransportHttpURLConnection(fake, resp);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("TCP transport error", e);
        }
    }

    /**
     * Reject TCP file transfers while the event demuxer owns the read side: the demuxer
     * read loop would steal the raw (non-msgpack) chunk frames and corrupt the transfer
     * (mirrors the Python SDK).
     */
    private void ensureNoActiveDemuxer() throws IOException {
        ensureNoActiveDemuxer(demuxer);
    }

    // Visible for tests in the same package.
    static void ensureNoActiveDemuxer(MessageDemuxer demuxer) throws IOException {
        if (demuxer != null && demuxer.isRunning()) {
            throw new IOException(
                    "file transfer is not supported while an event subscription is active over the same TCP connection; "
                            + "use a separate client instance");
        }
    }

    /**
     * Download a file through the TCP file-socket side channel.
     *
     * <p>When {@code applyFileAttributes} is true, returned POSIX metadata is applied locally on a
     * best-effort basis.
     */
    @Override
    public boolean downloadFile(String filePath, String localFile, boolean applyFileAttributes) throws IOException {
        ensureNoActiveDemuxer();
        Map<String, String> headers = new HashMap<>();
        headers.put("X-File-Path", encodeURIComponent(filePath));
        headers.put("X-Recv-File-Socket", "true");

        // Initiate the request
        HttpURLConnection conn = request("GET", "/appmesh/file/download", null, headers, null);
        if (conn.getHeaderField("X-Recv-File-Socket") == null) {
            throw new IOException("Server did not respond with socket transfer option");
        }

        // Check for success status before proceeding
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Download failed: " + conn.getResponseCode());
        }

        // In TCP mode, subsequent messages on the socket are the file chunks
        try (OutputStream outputStream = new FileOutputStream(localFile)) {
            while (true) {
                byte[] chunk = tcpTransport.receiveMessage();
                if (chunk == null || chunk.length == 0) {
                    break;
                }
                outputStream.write(chunk);
            }
        } catch (Exception e) {
            throw new IOException("Failed to receive file chunks over TCP", e);
        }

        if (applyFileAttributes) {
            Utils.applyFileAttributes(localFile, conn);
        }
        return true;
    }

    /**
     * Download a file through the TCP file-socket side channel. Uses the remote file's name as the
     * local file name.
     */
    @Override
    public boolean downloadFile(String filePath, boolean applyFileAttributes) throws IOException {
        return downloadFile(filePath, new File(filePath).getName(), applyFileAttributes);
    }

    /**
     * Upload a file through the TCP file-socket side channel.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent so the server can
     * recreate permissions and ownership when supported.
     */
    @Override
    public boolean uploadFile(File localFile, String remoteFile, boolean preservePermissions) throws IOException {
        ensureNoActiveDemuxer();
        File file = localFile;
        Path localPath = file.toPath();
        if (!Files.exists(localPath)) {
            throw new IOException("Local file not found: " + file.getAbsolutePath());
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("X-File-Path", encodeURIComponent(remoteFile));
        headers.put("Content-Type", "application/octet-stream");
        headers.put("X-Send-File-Socket", "true");

        if (preservePermissions) {
            headers.putAll(Utils.getFileAttributes(file));
        }

        // Initiate upload request
        HttpURLConnection conn = request("POST", "/appmesh/file/upload", null, headers, null);

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Upload init failed: " + conn.getResponseCode());
        }
        if (conn.getHeaderField("X-Send-File-Socket") == null) {
            throw new IOException("Server did not respond with socket transfer option");
        }

        // Send file chunks
        try (FileInputStream inputStream = new FileInputStream(file)) {
            byte[] buffer = new byte[TCP_BLOCK_SIZE];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                // If we read less than the buffer, copy it to a correctly sized array
                byte[] chunk = (bytesRead == buffer.length) ? buffer : Arrays.copyOf(buffer, bytesRead);
                tcpTransport.sendMessage(chunk);
            }
            // Send EOF signal (empty byte array)
            tcpTransport.sendMessage(null);
        } catch (Exception e) {
            throw new IOException("Failed to send file chunks over TCP", e);
        }

        return true;
    }

    /**
     * Upload a file through the TCP file-socket side channel. Uses the local file's name as the
     * remote file name.
     */
    @Override
    public boolean uploadFile(File localFile, boolean preservePermissions) throws IOException {
        return uploadFile(localFile, localFile.getName(), preservePermissions);
    }

    /**
     * Enable the message demuxer for concurrent request-response and event routing.
     * Creates and starts the demuxer if not already running.
     */
    public synchronized void enableDemuxer() {
        try {
            ensureDemuxer();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to enable TCP demuxer", e);
        }
    }

    @Override
    protected synchronized void ensureDemuxer() throws IOException {
        if (demuxer != null && demuxer.isRunning()) {
            return;
        }
        if (!tcpTransport.connected()) {
            tcpTransport.connect();
        }
        // Demuxer owns the read side and must block indefinitely between frames:
        // the connect-time SO_TIMEOUT would tear down idle subscriptions with a spurious
        // DISCONNECTED. Request timeouts live in MessageDemuxer.waitForResponse.
        try {
            tcpTransport.setReadTimeout(0);
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Failed to clear TCP read timeout for demuxer", e);
        }
        demuxer = new MessageDemuxer(() -> tcpTransport.receiveMessage());
        demuxer.start();
    }

    /**
     * Return the message demuxer instance, or null if not enabled.
     */
    public MessageDemuxer getDemuxer() {
        return demuxer;
    }

    @Override
    protected MessageDemuxer demuxerOrNull() {
        return getDemuxer();
    }

    /**
     * Subscribe-based override for TCP transport.
     *
     * <p>Instead of polling, subscribes to STDOUT/EXIT/REMOVED events, backfills
     * output emitted before subscribe took effect, deduplicates by byte offset,
     * and waits for the process to finish or the connection to drop.
     *
     * <p>Returns the real process exit code, or {@code null} on caller-side timeout;
     * throws {@link AppRemovedException} (app removed before EXIT) or
     * {@link TransportDisconnectedException} (demuxer disconnected) instead of sentinel codes.
     */
    @Override
    public Integer waitForAsyncRun(AppRun run, OutputHandler stdoutHandler, int timeoutSeconds) throws Exception {
        return AsyncRunWaiter.waitViaEvents(this, run, stdoutHandler, timeoutSeconds);
    }

    @Override
    public void close() {
        if (demuxer != null) {
            demuxer.stop();
            demuxer = null;
        }
        try {
            tcpTransport.close();
        } catch (Exception ignored) {
        }
        super.close();
    }

}
