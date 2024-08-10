import javax.net.ssl.*;
import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.stream.Collectors;

import org.threeten.extra.PeriodDuration;
import org.json.JSONArray;
import org.json.JSONObject;

public class AppMeshClient {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClient.class.getName());
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String USER_AGENT_HEADER = "User-Agent";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_CONTENT_TYPE = "application/json; utf-8";

    private final String baseURL;
    private String jwtToken;
    private String delegateHost;

    private AppMeshClient(Builder builder) {
        this.baseURL = Objects.requireNonNull(builder.baseURL, "Base URL cannot be null");
        if (builder.certFilePath != null) {
            try {
                useCustomCertificate(builder.certFilePath);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to use custom certificate", e);
                throw new RuntimeException("Failed to initialize AppMeshClient", e);
            }
        } else {
            try {
                disableSSLVerification();
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to disable SSL verification", e);
                throw new RuntimeException("Failed to initialize AppMeshClient", e);
            }
        }
    }

    public static class Builder {
        private String baseURL;
        private String certFilePath;

        public Builder baseURL(String baseURL) {
            this.baseURL = baseURL;
            return this;
        }

        public Builder certFilePath(String certFilePath) {
            this.certFilePath = certFilePath;
            return this;
        }

        public AppMeshClient build() {
            return new AppMeshClient(this);
        }
    }

    public static class AppOutputResponse {
        public boolean httpSuccess;
        public String httpBody;
        public Long outputPosition;
        public Integer exitCode;
        public String error;
    }

    public void delegateHost(String host) {
        if (host.contains(":")) {
            this.delegateHost = host;
        } else {
            try {
                URL url = new URL(this.baseURL);
                int port = url.getPort();
                this.delegateHost = host + ":" + port;
            } catch (IOException e) {
                LOGGER.log(Level.SEVERE, "Failed to parse baseURL", e);
                throw new RuntimeException("Failed to set delegate host", e);
            }
        }
    }

    public String login(String username, String password, String totpCode, Object expireSeconds) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION_HEADER, BASIC_PREFIX + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));
        if (expireSeconds != null) {
            headers.put("Expire-Seconds", Long.toString(toSeconds(expireSeconds)));
        }
        if (totpCode != null) {
            headers.put("Totp", totpCode);
        }

        HttpURLConnection conn = request("POST", "/appmesh/login", null, headers, null);
        String responseContent = readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        this.jwtToken = jsonResponse.getString("Access-Token");
        return this.jwtToken;
    }

    public boolean authentication(String token, String permission) throws IOException {
        this.jwtToken = token;
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        if (permission != null) {
            headers.put("Auth-Permission", permission);
        }

        HttpURLConnection conn = request("POST", "/appmesh/auth", null, headers, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public String totpSecret() throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/secret", null, null, null);
        String responseContent = readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        String mfaUri = jsonResponse.getString("Mfa-Uri");
        return new String(Base64.getDecoder().decode(mfaUri));
    }

    public boolean totpSetup(String totpCode) throws IOException, IllegalArgumentException {
        if (totpCode == null || !totpCode.matches("\\d{6}")) {
            throw new IllegalArgumentException("TOTP code must be a 6-digit number");
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Totp", totpCode);

        HttpURLConnection conn = request("POST", "/appmesh/totp/setup", null, headers, null);
        return conn.getResponseCode() == 200;
    }

    public boolean totpDisable() throws IOException {
        return totpDisable("self");
    }

    public boolean totpDisable(String user) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/" + user + "/disable", null, null, null);
        return conn.getResponseCode() == 200;
    }

    public boolean logout() throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/self/logoff", null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public String renew(Object expireSeconds) throws IOException {
        Map<String, String> headers = new HashMap<>();
        if (expireSeconds != null) {
            headers.put("Expire-Seconds", Long.toString(toSeconds(expireSeconds)));
        }

        HttpURLConnection conn = request("POST", "/appmesh/token/renew", null, headers, null);
        String responseContent = readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        this.jwtToken = jsonResponse.getString("Access-Token");
        return this.jwtToken;
    }

    public Map<String, String> getTags() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/labels", null, null, null);
        String responseContent = readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);

        Map<String, String> labels = new HashMap<>();
        for (String key : jsonResponse.keySet()) {
            labels.put(key, jsonResponse.getString(key));
        }
        return labels;

    }

    public JSONArray appView() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/applications", null, null, null);
        String responseContent = readResponse(conn);
        return new JSONArray(responseContent);
    }

    public JSONObject appView(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + appName, null, null, null);
        String responseContent = readResponse(conn);
        return new JSONObject(responseContent);
    }

    public boolean appHealth(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + appName + "/health", null, null, null);
        String responseContent = readResponse(conn);
        return "0".equals(responseContent);
    }

    public JSONObject appAdd(String appName, JSONObject appJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/app/" + appName, appJson, null, null);
        String responseContent = readResponse(conn);
        return new JSONObject(responseContent);
    }

    public AppOutputResponse getAppOutput(String appName, long stdoutPosition, int stdoutIndex, int stdoutMaxsize, String processUuid)
            throws IOException {

        Map<String, String> querys = new HashMap<>();
        querys.put("stdout_position", String.valueOf(stdoutPosition));
        querys.put("stdout_index", String.valueOf(stdoutIndex));
        querys.put("stdout_maxsize", String.valueOf(stdoutMaxsize));
        querys.put("process_uuid", processUuid);

        HttpURLConnection conn = request("GET", "/appmesh/app/" + appName + "/output", null, null, querys);

        AppOutputResponse response = new AppOutputResponse();
        response.httpSuccess = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
        response.httpBody = readResponse(conn);

        // Extract and parse headers
        String exitCodeStr = conn.getHeaderField("Exit-Code");
        if (exitCodeStr != null && !exitCodeStr.isEmpty()) {
            try {
                response.exitCode = Integer.parseInt(exitCodeStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code", e);
            }
        }

        String outputPositionStr = conn.getHeaderField("Output-Position");
        if (outputPositionStr != null && !outputPositionStr.isEmpty()) {
            try {
                response.outputPosition = Long.parseLong(outputPositionStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse output position", e);
            }
        }

        return response;
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

    private long toSeconds(Object input) {
        if (input instanceof Number) {
            return ((Number) input).longValue();
        }
        if (input instanceof String) {
            try {
                return PeriodDuration.parse((String) input).getDuration().getSeconds();
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "toSeconds", e);
                throw new IllegalArgumentException("Invalid ISO 8601 duration string", e);
            }
        }
        throw new IllegalArgumentException("Invalid input type. Expected number or ISO 8601 duration string.");
    }

    private String readResponse(HttpURLConnection conn) throws IOException {
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream(), StandardCharsets.UTF_8))) {
            return reader.lines().collect(Collectors.joining("\n"));
        }
    }

    private Map<String, String> commonHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(USER_AGENT_HEADER, "AppMesh-Java-SDK");
        if (this.jwtToken != null) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + this.jwtToken);
        }
        if (this.delegateHost != null) {
            headers.put("X-Target-Host", this.delegateHost);
        }
        return headers;
    }

    private HttpURLConnection request(String method, String path, JSONObject body, Map<String, String> headers, Map<String, String> params)
            throws IOException {
        StringBuilder urlBuilder = new StringBuilder(baseURL).append(path);

        if (params != null && !params.isEmpty()) {
            urlBuilder.append('?');
            params.forEach((key, value) -> {
                try {
                    urlBuilder.append(URLEncoder.encode(key, "UTF-8")).append('=').append(URLEncoder.encode(value, "UTF-8")).append('&');
                } catch (UnsupportedEncodingException e) {
                    throw new RuntimeException("Error encoding URL parameters", e);
                }
            });
            urlBuilder.setLength(urlBuilder.length() - 1); // Remove the trailing '&'
        }

        URL url = new URL(urlBuilder.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method.toUpperCase());

        Map<String, String> allHeaders = new HashMap<>(commonHeaders());
        if (headers != null) {
            allHeaders.putAll(headers);
        }
        allHeaders.forEach(connection::setRequestProperty);

        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            if (body != null) {
                connection.setRequestProperty(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
                connection.setRequestProperty(ACCEPT_HEADER, JSON_CONTENT_TYPE);
                connection.setDoOutput(true);
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
        }

        int status = connection.getResponseCode();
        if (status != HttpURLConnection.HTTP_OK) {
            throw new IOException("HTTP error: " + status);
        }

        return connection;
    }
}