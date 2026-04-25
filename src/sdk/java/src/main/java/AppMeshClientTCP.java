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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

/**
 * Simple TCP (TLS) client wrapper that reuses `AppMeshClient`.
 *
 * It constructs an HTTPS base URL using the provided TCP address and
 * reuses `AppMeshClient` for underlying HTTP requests. This mirrors the
 * Python approach of injecting a TCP client while reusing the same public API.
 */
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
     * file-socket side channel for larger payloads.
     */
    public AppMeshClientTCP(String host, int port, boolean disableSSLVerification, String caCertPath,
            String clientCertPath, String clientKeyPath) {
        super(new AppMeshClient.Builder().baseURL("https://" + host + ":" + port));
        Objects.requireNonNull(host, "host");
        try {
            javax.net.ssl.SSLContext sc = Utils.createSSLContext(caCertPath, clientCertPath, clientKeyPath,
                    disableSSLVerification);
            this.tcpTransport = new TCPTransport(host, port, sc.getSocketFactory());
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize TCP transport SSL context", e);
        }
    }

    /** Builder for {@link AppMeshClientTCP} to allow fluent configuration. */
    public static class Builder {
        private String host = "127.0.0.1";
        private int port = 6059;
        private boolean disableSSLVerification = false;
        private String caCertPath;
        private String clientCertPath;
        private String clientKeyPath;

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

        public Builder disableSSLVerify() {
            this.disableSSLVerification = true;
            return this;
        }

        public Builder caCert(String caCertPath) {
            this.caCertPath = caCertPath;
            return this;
        }

        public Builder clientCert(String clientCertPath, String clientKeyPath) {
            this.clientCertPath = clientCertPath;
            this.clientKeyPath = clientKeyPath;
            return this;
        }

        public AppMeshClientTCP build() {
            Objects.requireNonNull(host, "host");
            return new AppMeshClientTCP(host, port, disableSSLVerification, caCertPath, clientCertPath,
                    clientKeyPath);
        }
    }

    /** Send a request over TCP transport and expose it as an {@link HttpURLConnection}-like object. */
    @Override
    public HttpURLConnection request(String method, String path, Object body, java.util.Map<String, String> headers,
            java.util.Map<String, String> params) throws IOException {
        try {
            if (!tcpTransport.connected()) {
                tcpTransport.connect();
            }

            RequestMessage req = new RequestMessage();
            req.uuid = java.util.UUID.randomUUID().toString();
            req.http_method = method;
            req.request_uri = path;
            req.client_addr = java.net.InetAddress.getLocalHost().getHostName();
            // Merge common headers from parent
            req.headers = new java.util.HashMap<>();
            req.headers.putAll(super.getCommonHeaders());
            if (headers != null)
                req.headers.putAll(headers);
            if (params != null)
                req.query = params;
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
                    tcpTransport.sendMessage(data);
                    resp = demuxer.waitForResponse(req.uuid, 60);
                    if (resp == null) {
                        throw new IOException("Demuxer response timeout");
                    }
                } finally {
                    demuxer.unregisterPending(req.uuid);
                }
            } else {
                // Legacy synchronous mode: send then read directly
                tcpTransport.sendMessage(data);
                byte[] respBuf = tcpTransport.receiveMessage();
                if (respBuf == null) {
                    throw new IOException("EOF from transport");
                }
                resp = ResponseMessage.deserialize(respBuf);
            }

            // Build a lightweight HttpURLConnection wrapper
            URL fake = new java.net.URI("http", null, "appmesh.local", -1, path, null, null).toURL();
            return new TcpHttpURLConnection(fake, resp);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("TCP transport error", e);
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
        Map<String, String> headers = new HashMap<>();
        headers.put("X-File-Path", filePath);
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
     * Upload a file through the TCP file-socket side channel.
     *
     * <p>When {@code preservePermissions} is true, local file metadata is sent so the server can
     * recreate permissions and ownership when supported.
     */
    @Override
    public boolean uploadFile(Object localFile, String remoteFile, boolean preservePermissions) throws IOException {
        File file;
        if (localFile instanceof String) {
            file = new File((String) localFile);
        } else if (localFile instanceof File) {
            file = (File) localFile;
        } else {
            throw new IllegalArgumentException("localFile must be a String path or a File object");
        }

        Path localPath = file.toPath();
        if (!Files.exists(localPath)) {
            throw new IOException("Local file not found: " + file.getAbsolutePath());
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("X-File-Path", remoteFile);
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
     * Enable the message demuxer for concurrent request-response and event routing.
     * Creates and starts the demuxer if not already running.
     */
    public synchronized void enableDemuxer() {
        if (demuxer != null && demuxer.isRunning()) {
            return;
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

    /**
     * Subscribe-based override for TCP transport.
     *
     * <p>Instead of polling, subscribes to STDOUT/EXIT/REMOVED events, backfills
     * output emitted before subscribe took effect, deduplicates by byte offset,
     * and waits for the process to finish or the connection to drop.
     *
     * <p>Sentinel exit codes: {@code null} = caller-side timeout,
     * {@code -1} = REMOVED before EXIT, {@code -2} = demuxer disconnected.
     */
    @Override
    public Integer waitForAsyncRun(AppRun run, boolean printStdout, int timeoutSeconds) throws Exception {
        if (run == null) {
            return null;
        }

        // EXIT_CODE_NONE signals "not yet set"; real exit codes are >= 0,
        // sentinels are -1 (REMOVED) and -2 (disconnected).
        final int EXIT_CODE_NONE = Integer.MIN_VALUE;
        final AtomicInteger exitCode = new AtomicInteger(EXIT_CODE_NONE);
        final AtomicLong deliveredUntil = new AtomicLong(0);
        final CountDownLatch done = new CountDownLatch(1);
        final Object deliverLock = new Object();

        // Event callback: routes STDOUT / EXIT / REMOVED / __disconnected__
        MessageDemuxer.EventCallback callback = (event) -> {
            switch (event.eventType) {
                case "STDOUT":
                    if (event.data != null) {
                        long pos = event.data.optLong("position", 0);
                        String output = event.data.optString("output", "");
                        deliverOutput(output, pos, deliveredUntil, deliverLock, printStdout);
                    }
                    break;
                case "EXIT":
                    int code = (event.data != null) ? event.data.optInt("exit_code", -1) : -1;
                    exitCode.compareAndSet(EXIT_CODE_NONE, code);
                    done.countDown();
                    break;
                case "REMOVED":
                    exitCode.compareAndSet(EXIT_CODE_NONE, -1);
                    done.countDown();
                    break;
                case MessageDemuxer.EVENT_TYPE_DISCONNECTED:
                    exitCode.compareAndSet(EXIT_CODE_NONE, -2);
                    done.countDown();
                    break;
                default:
                    break;
            }
        };

        JSONObject sub = this.subscribe(run.getAppName(),
                new String[] { "STDOUT", "EXIT", "REMOVED" }, callback);
        String subscriptionId = sub.optString("subscription_id", "");

        try {
            // Backfill bytes emitted before subscribe took effect
            try {
                AppOutput backfill = this.getAppOutput(run.getAppName(), 0, 0, 0,
                        run.getProcUid(), 0);
                if (backfill.httpBody != null && !backfill.httpBody.isEmpty()) {
                    deliverOutput(backfill.httpBody, 0, deliveredUntil, deliverLock, printStdout);
                }
                if (backfill.exitCode != null) {
                    exitCode.compareAndSet(EXIT_CODE_NONE, backfill.exitCode);
                    done.countDown();
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Backfill failed for " + run.getAppName(), e);
            }

            // Wait for done signal
            if (timeoutSeconds > 0) {
                done.await(timeoutSeconds, TimeUnit.SECONDS);
            } else {
                done.await();
            }
        } finally {
            // Unsubscribe
            try {
                if (!subscriptionId.isEmpty()) {
                    this.unsubscribe(subscriptionId);
                }
            } catch (Exception ignored) {
            }
            // Best-effort delete on a real exit (>= 0).
            // Sentinels (-1 REMOVED, -2 disconnected) mean the app is already gone.
            int finalCode = exitCode.get();
            if (finalCode != EXIT_CODE_NONE && finalCode >= 0) {
                try {
                    this.deleteApp(run.getAppName());
                } catch (Exception ignored) {
                }
            }
        }

        int result = exitCode.get();
        return (result == EXIT_CODE_NONE) ? null : result;
    }

    /**
     * Deliver stdout output with deduplication by byte offset.
     */
    private static void deliverOutput(String chunk, long pos, AtomicLong deliveredUntil,
            Object lock, boolean printStdout) {
        if (chunk == null || chunk.isEmpty()) {
            return;
        }
        byte[] chunkBytes = chunk.getBytes(StandardCharsets.UTF_8);
        synchronized (lock) {
            long current = deliveredUntil.get();
            long end = pos + chunkBytes.length;
            if (end <= current) {
                return; // already delivered
            }
            String toPrint;
            if (pos < current) {
                // Partial overlap: trim the already-delivered prefix
                int skip = (int) (current - pos);
                toPrint = new String(chunkBytes, skip, chunkBytes.length - skip, StandardCharsets.UTF_8);
            } else {
                toPrint = chunk;
            }
            deliveredUntil.set(end);
            if (printStdout && !toPrint.isEmpty()) {
                System.out.print(toPrint);
                System.out.flush();
            }
        }
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

    // Minimal HttpURLConnection wrapper around ResponseMessage
    private static class TcpHttpURLConnection extends HttpURLConnection {
        private final ResponseMessage resp;
        // Use case-insensitive map for HTTP header lookups (RFC 7230)
        private final java.util.TreeMap<String, String> headerMap =
                new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        private final byte[] content;

        protected TcpHttpURLConnection(URL u, ResponseMessage resp) {
            super(u);
            this.resp = resp;
            if (resp.headers != null)
                headerMap.putAll(resp.headers);
            this.content = resp.body != null ? resp.body : new byte[0];
            this.connected = true;
        }

        @Override
        public void disconnect() {
            this.connected = false;
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public void connect() throws IOException {
            this.connected = true;
        }

        @Override
        public int getResponseCode() throws IOException {
            return resp.http_status;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            if (getResponseCode() >= 400)
                throw new IOException("HTTP error " + getResponseCode());
            return new ByteArrayInputStream(content);
        }

        @Override
        public InputStream getErrorStream() {
            try {
                if (getResponseCode() >= 400)
                    return new ByteArrayInputStream(content);
            } catch (IOException e) {
                return new ByteArrayInputStream(content);
            }
            return null;
        }

        @Override
        public String getHeaderField(String name) {
            return headerMap.get(name);
        }
    }
}
