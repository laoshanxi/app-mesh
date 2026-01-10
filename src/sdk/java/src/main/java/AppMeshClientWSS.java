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

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

/**
 * Client SDK for interacting with the App Mesh service over WebSocket Secure
 */
public class AppMeshClientWSS extends AppMeshClient {

    private static final int WSS_BLOCK_SIZE = 64 * 1024;
    private static final String HTTP_USER_AGENT_WSS = "appmesh/java/wss";
    private static final String HEADER_X_FILE_PATH = "X-File-Path";
    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String HEADER_X_FILE_MODE = "X-File-Mode";
    private static final int FILE_TRANSFER_TIMEOUT = 120000; // 120 seconds

    private final WSSTransport wssTransport;
    private final SSLSocketFactory sslSocketFactory;

    /**
     * Create a new WSS client with default settings.
     */
    public AppMeshClientWSS(String host, int port) {
        this(host, port, false, null, null, null);
    }

    /**
     * Create a new WSS client with full SSL configuration.
     */
    public AppMeshClientWSS(String host, int port, boolean disableSSLVerification,
            String caCertPath, String clientCertPath, String clientKeyPath) {
        super(new AppMeshClient.Builder().baseURL("https://" + host + ":" + port));
        Objects.requireNonNull(host, "host cannot be null");

        SSLContext sslContext;
        try {
            sslContext = Utils.createSSLContext(caCertPath, clientCertPath, clientKeyPath, disableSSLVerification);
            this.sslSocketFactory = sslContext.getSocketFactory();
            this.wssTransport = new WSSTransport(host, port, this.sslSocketFactory);
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize WSS transport SSL context", e);
        }
    }

    /**
     * Builder for fluent configuration of {@link AppMeshClientWSS}.
     */
    public static class Builder {
        private String host = "127.0.0.1";
        private int port = 6058;
        private boolean disableSSLVerification = false;
        private String caCertPath;
        private String clientCertPath;
        private String clientKeyPath;
        private int connectTimeout = WSSTransport.WSS_CONNECT_TIMEOUT;

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

        public Builder connectTimeout(int seconds) {
            this.connectTimeout = seconds;
            return this;
        }

        public AppMeshClientWSS build() {
            Objects.requireNonNull(host, "host cannot be null");
            AppMeshClientWSS client = new AppMeshClientWSS(
                    host, port, disableSSLVerification, caCertPath, clientCertPath, clientKeyPath);
            client.wssTransport.setConnectTimeout(connectTimeout);
            return client;
        }
    }

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
            wssTransport.sendMessage(data);

            // Receive response
            byte[] respBuf = wssTransport.receiveMessage();
            if (respBuf == null) {
                wssTransport.close();
                throw new IOException("WebSocket connection broken");
            }

            // Parse response
            ResponseMessage resp = ResponseMessage.deserialize(respBuf);

            // Create simulated HTTP connection
            URL fakeUrl = new java.net.URI("https", null, wssTransport.getHost(),
                    wssTransport.getPort(), path, null, null).toURL();
            return new WSSHttpURLConnection(fakeUrl, resp);

        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("WSS transport error: " + e.getMessage(), e);
        }
    }

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
            applyFileAttributes(localFile, conn);
        }

        return true;
    }

    @Override
    public boolean uploadFile(Object localFile, String remoteFile, boolean applyFileAttributes) throws IOException {
        File file = resolveFile(localFile);

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
            conn.setRequestProperty(HEADER_X_FILE_MODE, String.valueOf(Utils.getFilePermissions(file)));
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

    @Override
    public void close() {
        try {
            wssTransport.close();
        } catch (Exception ignored) {
            // Suppress exceptions during close
        }
        super.close();
    }

    /**
     * Create an HTTPS connection with proper SSL configuration.
     */
    private HttpURLConnection createSecureConnection(URL url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        if (conn instanceof HttpsURLConnection && sslSocketFactory != null) {
            HttpsURLConnection httpsConn = (HttpsURLConnection) conn;
            httpsConn.setSSLSocketFactory(sslSocketFactory);
        }
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
     * Resolve file object from various input types.
     */
    private File resolveFile(Object localFile) {
        if (localFile instanceof String) {
            return new File((String) localFile);
        } else if (localFile instanceof File) {
            return (File) localFile;
        } else {
            throw new IllegalArgumentException("localFile must be a String path or a File object");
        }
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

    /**
     * Internal HTTP connection wrapper for WSS responses.
     */
    private static class WSSHttpURLConnection extends HttpURLConnection {
        private final ResponseMessage response;
        private final Map<String, List<String>> headerFields;
        private final byte[] content;

        protected WSSHttpURLConnection(URL url, ResponseMessage response) {
            super(url);
            this.response = response;
            this.content = response.body != null ? response.body : new byte[0];
            this.connected = true;

            // Build header fields map
            this.headerFields = new HashMap<>();
            if (response.headers != null) {
                for (Map.Entry<String, String> entry : response.headers.entrySet()) {
                    List<String> values = new ArrayList<>();
                    values.add(entry.getValue());
                    headerFields.put(entry.getKey(), values);
                }
            }
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
            return response.http_status;
        }

        @Override
        public InputStream getInputStream() throws IOException {
            if (getResponseCode() >= 400) {
                throw new IOException("HTTP error " + getResponseCode());
            }
            return new ByteArrayInputStream(content);
        }

        @Override
        public InputStream getErrorStream() {
            try {
                if (getResponseCode() >= 400) {
                    return new ByteArrayInputStream(content);
                }
            } catch (IOException e) {
                return new ByteArrayInputStream(content);
            }
            return null;
        }

        @Override
        public String getHeaderField(String name) {
            if (response.headers == null) {
                return null;
            }
            // Case-insensitive header lookup
            for (Map.Entry<String, String> entry : response.headers.entrySet()) {
                if (entry.getKey().equalsIgnoreCase(name)) {
                    return entry.getValue();
                }
            }
            return null;
        }
    }
}
