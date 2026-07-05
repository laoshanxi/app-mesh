package appmesh;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.TreeMap;

/**
 * Shared read-only {@link HttpURLConnection} adapter around a {@link ResponseMessage}
 * received over a non-HTTP transport (TCP or WSS). The response is already fully
 * buffered, so this class only exposes status, headers and body.
 */
class TransportHttpURLConnection extends HttpURLConnection {
    private final ResponseMessage resp;
    // Case-insensitive map for HTTP header lookups (RFC 7230)
    private final TreeMap<String, String> headerMap = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    private final byte[] content;

    protected TransportHttpURLConnection(URL u, ResponseMessage resp) {
        super(u);
        this.resp = resp;
        if (resp.headers != null) {
            headerMap.putAll(resp.headers);
        }
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
        return headerMap.get(name);
    }
}
