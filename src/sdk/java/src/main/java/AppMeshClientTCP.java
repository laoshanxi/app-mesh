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
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Simple TCP (TLS) client wrapper that reuses `AppMeshClient`.
 *
 * It constructs an HTTPS base URL using the provided TCP address and
 * reuses `AppMeshClient` for underlying HTTP requests. This mirrors the
 * Python approach of injecting a TCP client while reusing the same public API.
 */
public class AppMeshClientTCP extends AppMeshClient {
    private final TCPTransport tcpTransport;
    private static final int TCP_BLOCK_SIZE = 16 * 1024 - 128; // TLS-optimized chunk size

    public AppMeshClientTCP(String host, int port) {
        this(host, port, false, null, null, null);
    }

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

    /**
     * Builder for {@link AppMeshClientTCP} to allow fluent configuration.
     */
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
            tcpTransport.sendMessage(data);

            byte[] respBuf = tcpTransport.receiveMessage();
            if (respBuf == null) {
                throw new IOException("EOF from transport");
            }
            ResponseMessage resp = ResponseMessage.deserialize(respBuf);

            // Build a lightweight HttpURLConnection wrapper
            URL fake = new java.net.URI("http", null, "appmesh.local", -1, path, null, null).toURL();
            return new TcpHttpURLConnection(fake, resp);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("TCP transport error", e);
        }
    }

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
            applyFileAttributes(localFile, conn);
        }
        return true;
    }

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
            headers.putAll(getFileAttributes(file));
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

    @Override
    public void close() {
        try {
            tcpTransport.close();
        } catch (Exception ignored) {
        }
        super.close();
    }

    // Helper to reuse base class attribute logic if possible, or reimplement
    private void applyAttributes(HttpURLConnection conn, String localFile) {
        String fileMode = conn.getHeaderField("X-File-Mode");
        if (fileMode != null) {
            try {
                Files.setPosixFilePermissions(Paths.get(localFile),
                        java.nio.file.attribute.PosixFilePermissions
                                .fromString(Utils.toPermissionString(Integer.parseInt(fileMode, 10))));
            } catch (Exception ignored) {
            }
        }
        // Owner/Group logic is platform specific and often requires more setup,
        // skipping for brevity or
        // it can be copied from AppMeshClient.java if that method is accessible.
    }

    // Minimal HttpURLConnection wrapper around ResponseMessage
    private static class TcpHttpURLConnection extends HttpURLConnection {
        private final ResponseMessage resp;
        private final Map<String, String> headerMap = new HashMap<>();
        private byte[] content;

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
