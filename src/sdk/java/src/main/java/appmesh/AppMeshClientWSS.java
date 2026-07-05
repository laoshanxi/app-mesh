package appmesh;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;



/**
 * Client SDK for interacting with the App Mesh service over WebSocket Secure
 */
public class AppMeshClientWSS extends AppMeshClient {
    private static final int WSS_BLOCK_SIZE = 64 * 1024;
    private static final String HTTP_USER_AGENT_WSS = "appmesh/java/wss";
    private static final String HEADER_X_FILE_PATH = "X-File-Path";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final int FILE_TRANSFER_TIMEOUT = 120000; // 120 seconds

    private final WSSTransport wssTransport;
    private volatile MessageDemuxer demuxer;

    /** Create a WSS transport client with default TLS verification behavior. */
    public AppMeshClientWSS(String host, int port) {
        this(host, port, false, null, null, null);
    }

    /**
     * Create a WSS transport client that reuses the standard App Mesh client API.
     *
     * <p>Control requests go over WebSocket, while file transfers use an HTTPS side channel
     * authorized by the WSS control response. The SSL settings configure both the base
     * client (HTTPS side channel) and the WSS transport, so one configuration is authoritative.
     */
    public AppMeshClientWSS(String host, int port, boolean disableSSLVerification,
            String caCertPath, String clientCertPath, String clientKeyPath) {
        this(configureSSL(new AppMeshClient.Builder().baseURL("https://" + host + ":" + port),
                disableSSLVerification, caCertPath, clientCertPath, clientKeyPath), host, port);
    }

    /**
     * Create a WSS transport client from a fully configured base builder. The builder's SSL
     * settings are reused for the WSS transport (library default trust when none configured).
     */
    protected AppMeshClientWSS(AppMeshClient.Builder builder, String host, int port) {
        super(builder);
        Objects.requireNonNull(host, "host cannot be null");
        this.wssTransport = new WSSTransport(host, port, getSSLSocketFactory());
    }

    private static AppMeshClient.Builder configureSSL(AppMeshClient.Builder base, boolean disableSSLVerification,
            String caCertPath, String clientCertPath, String clientKeyPath) {
        if (caCertPath != null) {
            base.caCert(caCertPath);
        }
        if (clientCertPath != null || clientKeyPath != null) {
            base.clientCert(clientCertPath, clientKeyPath);
        }
        if (disableSSLVerification) {
            base.disableSSLVerify();
        }
        return base;
    }

    /**
     * Builder for fluent configuration of {@link AppMeshClientWSS}.
     */
    public static class Builder {
        private final AppMeshClient.Builder base = new AppMeshClient.Builder();
        private String host = "127.0.0.1";
        private int port = 6058;
        private int connectTimeout = WSSTransport.WSS_CONNECT_TIMEOUT;
        private Integer connectionLostTimeout;

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

        /** Cookie file path for persistent token storage. */
        public Builder cookieFile(String cookieFile) {
            base.cookieFile(cookieFile);
            return this;
        }

        /** Enable automatic token refresh before expiration. */
        public Builder autoRefreshToken(boolean enable) {
            base.autoRefreshToken(enable);
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

        /** WebSocket blocking-connect timeout in seconds. */
        public Builder connectTimeout(int seconds) {
            this.connectTimeout = seconds;
            return this;
        }

        /** WebSocket connection-lost (ping/pong keepalive) interval in seconds. */
        public Builder connectionLostTimeout(int seconds) {
            this.connectionLostTimeout = seconds;
            return this;
        }

        public AppMeshClientWSS build() {
            Objects.requireNonNull(host, "host cannot be null");
            base.baseURL("https://" + host + ":" + port);
            AppMeshClientWSS client = new AppMeshClientWSS(base, host, port);
            client.wssTransport.setConnectTimeout(connectTimeout);
            if (connectionLostTimeout != null) {
                client.wssTransport.setConnectionLostTimeout(connectionLostTimeout);
            }
            return client;
        }
    }

    /** Send a request over WSS transport and expose it as an {@link HttpURLConnection}-like object. */
    @Override
    public HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params) throws IOException {
        try {
            if (!wssTransport.connected()) {
                wssTransport.connect();
            }

            RequestMessage req = new RequestMessage();
            req.uuid = UUID.randomUUID().toString();
            req.http_method = method;
            req.request_uri = path;
            req.client_addr = "wss-client";
            req.headers = new HashMap<>();

            // Add user agent
            req.headers.put("User-Agent", HTTP_USER_AGENT_WSS);

            // Add common headers from parent
            req.headers.putAll(super.getCommonHeaders());

            // Add custom headers
            if (headers != null) {
                req.headers.putAll(headers);
            }

            // Add query parameters
            if (params != null) {
                req.query = new HashMap<>(params);
            }

            // Prepare body
            if (body != null) {
                req.body = convertToBytes(body);
            }

            // Send request
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
                    wssTransport.sendMessage(data);
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
                synchronized (wssTransport) {
                    wssTransport.sendMessage(data);
                    while (true) {
                        byte[] respBuf = wssTransport.receiveMessage();
                        if (respBuf == null || respBuf.length == 0) {
                            wssTransport.close();
                            throw new IOException("WebSocket connection broken");
                        }
                        resp = ResponseMessage.deserialize(respBuf);
                        // Skip server-push event frames (no demuxer to route them)
                        if (MessageDemuxer.EVENT_URI.equals(resp.request_uri)) {
                            continue;
                        }
                        break;
                    }
                }
                if (!req.uuid.equals(resp.uuid)) {
                    throw new IOException("Response UUID mismatch: expected " + req.uuid + ", got " + resp.uuid);
                }
            }

            // Create simulated HTTP connection
            URL fakeUrl = new java.net.URI("https", null, wssTransport.getHost(),
                    wssTransport.getPort(), path, null, null).toURL();
            return new TransportHttpURLConnection(fakeUrl, resp);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("WSS transport error: " + e.getMessage(), e);
        }
    }

    /**
     * Download a file through WSS control messages plus an HTTPS data side channel.
     *
     * <p>When {@code applyFileAttributes} is true, returned POSIX metadata is applied locally on a
     * best-effort basis.
     */
    @Override
    public boolean downloadFile(String remoteFile, String localFile, boolean applyFileAttributes) throws IOException {
        // Step 1: Request download via WSS to get Auth token
        Map<String, String> header = new HashMap<>();
        header.put(HEADER_X_FILE_PATH, remoteFile);
        HttpURLConnection resp = request("GET", "/appmesh/file/download", null, header, null);

        String authToken = resp.getHeaderField(HEADER_AUTHORIZATION);
        if (authToken == null || authToken.isEmpty()) {
            throw new IOException("Server did not respond with file transfer authentication: " + HEADER_AUTHORIZATION);
        }

        // Step 2: Perform HTTPS GET for the file stream
        URL url = new URL(getBaseURL() + "/appmesh/file/download/ws");
        HttpURLConnection conn = createSecureConnection(url);
        conn.setRequestMethod("GET");
        conn.setRequestProperty(HEADER_X_FILE_PATH, remoteFile);
        conn.setRequestProperty(HEADER_AUTHORIZATION, authToken);
        conn.setConnectTimeout(FILE_TRANSFER_TIMEOUT);
        conn.setReadTimeout(FILE_TRANSFER_TIMEOUT);

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            String errorMsg = readErrorStream(conn);
            throw new IOException("HTTPS download failed: " + responseCode + " " + errorMsg);
        }

        // Write file in chunks
        File localPath = new File(localFile);
        try (InputStream in = conn.getInputStream();
                OutputStream out = new FileOutputStream(localPath)) {
            byte[] buffer = new byte[WSS_BLOCK_SIZE];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
        }

        // Apply file attributes if requested
        if (applyFileAttributes) {
            Utils.applyFileAttributes(localFile, conn);
        }

        return true;
    }

    @Override
    public boolean uploadFile(File localFile, String remoteFile, boolean applyFileAttributes) throws IOException {
        File file = localFile;

        if (!file.exists()) {
            throw new IOException("Local file not found: " + file.getAbsolutePath());
        }

        // Step 1: Request upload via WSS to get Auth token
        Map<String, String> wssHeader = new HashMap<>();
        wssHeader.put(HEADER_X_FILE_PATH, remoteFile);
        HttpURLConnection resp = request("POST", "/appmesh/file/upload", null, wssHeader, null);

        String authToken = resp.getHeaderField(HEADER_AUTHORIZATION);
        if (authToken == null || authToken.isEmpty()) {
            throw new IOException("Server did not respond with file transfer authentication: " + HEADER_AUTHORIZATION);
        }

        // Step 2: Perform HTTPS POST for the file stream
        URL url = new URL(getBaseURL() + "/appmesh/file/upload/ws");
        HttpURLConnection conn = createSecureConnection(url);
        conn.setDoOutput(true);
        conn.setRequestMethod("POST");
        conn.setRequestProperty(HEADER_AUTHORIZATION, authToken);
        conn.setRequestProperty(HEADER_X_FILE_PATH, remoteFile);
        conn.setRequestProperty("Content-Type", "application/octet-stream");
        conn.setRequestProperty("Content-Length", String.valueOf(file.length()));
        conn.setConnectTimeout(FILE_TRANSFER_TIMEOUT);
        conn.setReadTimeout(FILE_TRANSFER_TIMEOUT);

        // Disable chunked transfer for better compatibility
        conn.setFixedLengthStreamingMode(file.length());

        // Add file attributes if requested
        if (applyFileAttributes) {
            Map<String, String> headers = Utils.getFileAttributes(file);
            for (Map.Entry<String, String> entry : headers.entrySet()) {
                conn.setRequestProperty(entry.getKey(), entry.getValue());
            }
        }

        // Stream file content
        try (InputStream fis = new FileInputStream(file);
                OutputStream os = conn.getOutputStream()) {
            byte[] buffer = new byte[WSS_BLOCK_SIZE];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                os.write(buffer, 0, bytesRead);
            }
            os.flush();
        }

        int responseCode = conn.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            String errorMsg = readErrorStream(conn);
            throw new IOException("HTTPS upload failed: " + responseCode + " " + errorMsg);
        }

        return true;
    }

    /**
     * Enable the message demuxer for concurrent request-response and event routing.
     * Creates and starts the demuxer if not already running.
     */
    public synchronized void enableDemuxer() {
        if (demuxer != null && demuxer.isRunning()) {
            return;
        }
        demuxer = new MessageDemuxer(() -> wssTransport.receiveMessage());
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

    @Override
    protected void ensureDemuxer() {
        enableDemuxer();
    }

    /**
     * Subscribe-based override for WSS transport.
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
            wssTransport.close();
        } catch (Exception ignored) {
            // Suppress exceptions during close
        }
        super.close();
    }

    /**
     * Create an HTTPS connection reusing the base client's SSL configuration.
     */
    private HttpURLConnection createSecureConnection(URL url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        applySSL(conn);
        return conn;
    }

    /**
     * Convert body to bytes.
     */
    private byte[] convertToBytes(Object body) {
        if (body == null) {
            return new byte[0];
        }
        if (body instanceof byte[]) {
            return (byte[]) body;
        }
        if (body instanceof String) {
            return ((String) body).getBytes(StandardCharsets.UTF_8);
        }
        // For maps, lists, etc., convert to JSON string
        return body.toString().getBytes(StandardCharsets.UTF_8);
    }

    /**
     * Read error stream content for better error messages.
     */
    private String readErrorStream(HttpURLConnection conn) {
        try (InputStream errorStream = conn.getErrorStream()) {
            if (errorStream == null) {
                return "";
            }
            byte[] bytes = errorStream.readAllBytes();
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return "";
        }
    }

}
