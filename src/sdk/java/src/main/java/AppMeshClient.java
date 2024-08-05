import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;

import org.json.JSONObject;
import org.threeten.extra.PeriodDuration;

public class AppMeshClient {
    private String baseURL;
    private String jwtToken;
    private String delegateHost;

    public AppMeshClient(String baseURL, String certFilePath) throws Exception {
        if (baseURL == null || baseURL.isEmpty()) {
            throw new IllegalArgumentException("Base URL cannot be null or empty");
        }
        if (certFilePath == null || certFilePath.isEmpty()) {
            throw new IllegalArgumentException("SSL Cert file cannot be null or empty");
        }
        this.baseURL = baseURL;
        useCustomCertificate(certFilePath);
    }

    public AppMeshClient(String baseURL) throws Exception {
        if (baseURL == null || baseURL.isEmpty()) {
            throw new IllegalArgumentException("Base URL cannot be null or empty");
        }
        this.baseURL = baseURL;
        disableSSLVerification();
    }

    public void delegateHost(String host) throws Exception {
        if (host.contains(":")) {
            // If host already contains a port, use it as is
            this.delegateHost = host;
        } else {
            // If no port in host, extract port from baseURL and append it
            URL url = new URL(this.baseURL);
            int port = url.getPort();
            this.delegateHost = host + ":" + String.valueOf(port);
        }
    }

    public String login(String username, String password, String totpCode, Object expireSeconds) throws Exception {
        Map<String, String> header = new HashMap<String, String>();
        header.put("Authorization",
                "Basic " + new String(java.util.Base64.getEncoder().encode((username + ":" + password).getBytes())));
        header.put("Expire-Seconds", Long.toString(this.toSeconds(expireSeconds)));
        HttpURLConnection conn = this.request("POST", "/appmesh/login", null, header, null);
        int responseCode = conn.getResponseCode();
        if (responseCode == 200) {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(conn.getInputStream()))) {
                String inputLine;
                StringBuilder content = new StringBuilder();
                while ((inputLine = in.readLine()) != null) {
                    content.append(inputLine);
                }

                // Parse the JSON response and extract the token
                JSONObject jsonResponse = new JSONObject(content.toString());
                this.jwtToken = jsonResponse.getString("Access-Token");
                return this.jwtToken;
            }
        } else {
            throw new RuntimeException("Failed to login, HTTP response code: " + responseCode);
        }
    }

    public boolean authentication(String token, String permission) throws Exception {
        this.jwtToken = token;

        Map<String, String> header = new HashMap<String, String>();
        header.put("Authorization", "Bearer " + token);
        if (permission != null) {
            header.put("Auth-Permission", permission);
        }
        HttpURLConnection conn = this.request("POST", "/appmesh/auth", null, header, null);
        int responseCode = conn.getResponseCode();
        return responseCode == HttpURLConnection.HTTP_OK;
    }

    public boolean logout() throws Exception {
        HttpURLConnection conn = this.request("POST", "/appmesh/self/logoff", null, null, null);
        int responseCode = conn.getResponseCode();
        return responseCode == HttpURLConnection.HTTP_OK;
    }

    private void disableSSLVerification() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        } };

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HostnameVerifier allHostsValid = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    private void useCustomCertificate(String certFilePath) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert;
        try (InputStream caInput = new FileInputStream(certFilePath)) {
            caCert = (X509Certificate) cf.generateCertificate(caInput);
        }

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("caCert", caCert);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, tmf.getTrustManagers(), new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    public long toSeconds(Object input) {
        if (input instanceof Number) {
            return ((Number) input).intValue();
        }

        if (input instanceof String) {
            try {
                return PeriodDuration.parse((String) input).getDuration().getSeconds();
            } catch (Exception e) {
                throw new IllegalArgumentException("Invalid ISO 8601 duration string", e);
            }
        }

        throw new IllegalArgumentException("Invalid input type. Expected number or ISO 8601 duration string.");
    }

    private Map<String, String> commonHeaders() throws Exception {
        Map<String, String> headers = new HashMap<>();
        headers.put("User-Agent", "AppMesh-Java-SDK");
        if (this.jwtToken != null) {
            headers.put("Authorization", "Bearer " + this.jwtToken);
        }
        if (this.delegateHost != null) {
            headers.put("X-Target-Host", this.delegateHost);
        }

        if (delegateHost != null) {
            if (delegateHost.contains(":")) {
                headers.put("X-Target-Host", delegateHost);
            } else {
                URL parsedUrl = new URL(baseURL);
                headers.put("X-Target-Host", delegateHost + ":" + parsedUrl.getPort());
            }
        }
        return headers;
    }

    private HttpURLConnection request(String method, String path, String body, Map<String, String> headers,
            Map<String, String> params) throws Exception {

        // Build the query string from params
        StringJoiner query = new StringJoiner("&");
        if (params != null) {
            for (Map.Entry<String, String> entry : params.entrySet()) {
                query.add(URLEncoder.encode(entry.getKey(), "UTF-8") + "="
                        + URLEncoder.encode(entry.getValue(), "UTF-8"));
            }
        }

        // Construct the full URL with path and query parameters
        String fullUrl = baseURL + path + (query.length() > 0 ? "?" + query.toString() : "");
        URL url = new URL(fullUrl);
        // System.out.println(url.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method.toUpperCase());

        // Add common headers
        Map<String, String> headerMap = commonHeaders();
        if (headers != null) {
            headerMap.putAll(headers);
        }
        for (Map.Entry<String, String> entry : headerMap.entrySet()) {
            // System.out.println(entry.toString());
            connection.setRequestProperty(entry.getKey(), entry.getValue());
        }

        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            connection.setDoOutput(true);
            if (body != null) {
                byte[] outputInBytes = body.getBytes("UTF-8");
                connection.getOutputStream().write(outputInBytes);
            }
        }

        int status = connection.getResponseCode();
        if (status != 200) {
            throw new RuntimeException("HTTP error: " + status);
        }

        return connection;
    }

}
