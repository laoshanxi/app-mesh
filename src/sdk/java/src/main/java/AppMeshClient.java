import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * App Mesh client object used to access App Mesh REST Service.
 */
public class AppMeshClient implements Closeable {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClient.class.getName());

    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String HTTP_USER_AGENT_HEADER_NAME = "User-Agent";
    private static final String HTTP_USER_AGENT = "appmesh/java";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_CONTENT_TYPE = "application/json; utf-8";
    private static final int HTTP_PRECONDITION_REQUIRED = 428;

    private final String baseURL;
    private final AtomicReference<String> jwtToken = new AtomicReference<>(null);
    private volatile String forwardTo;

    private AppMeshClient(Builder builder) {
        this.baseURL = Objects.requireNonNull(builder.baseURL, "Base URL cannot be null");
        if (builder.jwtToken != null) {
            this.jwtToken.set(builder.jwtToken);
        }
        if (builder.caCertFilePath != null || builder.clientCertFilePath != null) {
            try {
                Utils.configureSSLCertificates(builder.caCertFilePath, builder.clientCertFilePath,
                        builder.clientCertKeyFilePath);
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to use custom certificate", e);
                throw new RuntimeException("Failed to initialize AppMeshClient", e);
            }
        } else if (builder.disableSSLVerification) {
            try {
                Utils.disableSSLVerification();
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Failed to disable SSL verification", e);
                throw new RuntimeException("Failed to initialize AppMeshClient", e);
            }
        }
    }

    /** Builder for AppMeshClient. */
    public static class Builder {
        private String baseURL = "https://127.0.0.1:6060";
        private String caCertFilePath;
        private String clientCertFilePath;
        private String clientCertKeyFilePath;
        private String jwtToken;
        private boolean disableSSLVerification = false;

        public Builder() {
        }

        // AppMesh service URI string.
        public Builder baseURL(String baseURL) {
            this.baseURL = baseURL;
            return this;
        }

        // SSL CA certification, a path to a CA bundle
        public Builder caCert(String caCertFilePath) {
            this.caCertFilePath = caCertFilePath;
            return this;
        }

        // SSL client certificate and key pair.
        public Builder clientCert(String clientCertFilePath, String clientCertKeyFilePath) {
            this.clientCertFilePath = clientCertFilePath;
            this.clientCertKeyFilePath = clientCertKeyFilePath;
            return this;
        }

        // Disable SSL verification for none-production use
        public Builder disableSSLVerify() {
            this.disableSSLVerification = true;
            return this;
        }

        // Initial with a correct token, same with login() & authenticate()
        public Builder jwtToken(String jwtToken) {
            this.jwtToken = jwtToken;
            return this;
        }

        public AppMeshClient build() {
            return new AppMeshClient(this);
        }
    }

    // Application output object for appOutput() method.
    public static class AppOutput {
        public boolean httpSuccess;
        public String httpBody;
        public Long outputPosition;
        public Integer exitCode;
    }

    //  AppRun represents an asynchronous run on the server.
    public class AppRun {
        private final String appName;
        private final String procUid;
        private final AppMeshClient clientRef;
        private final String forwardingHost;

        public AppRun(AppMeshClient client, String appName, String processId) {
            this.appName = appName;
            this.procUid = processId;
            this.clientRef = client;
            this.forwardingHost = client.forwardTo;
        }

        // Getters and setters for appName, procUid, client, and forwardingHost
        public String getAppName() {
            return appName;
        }

        public String getProcUid() {
            return procUid;
        }

        public AppMeshClient getClient() {
            return clientRef;
        }

        public String getForwardingHost() {
            return forwardingHost;
        }

        /**
         * A small helper that temporarily sets forwarding host while calling
         * waitForAsyncRun.
         * Use as try-with-resources:
         * try (ForwardingHostManager m = new ForwardingHostManager()) { run.wait(...);
         * }
         */
        public class ForwardingHostManager implements Closeable {
            private final String originalForwardingHost;

            public ForwardingHostManager() {
                this.originalForwardingHost = clientRef.forwardTo;
                clientRef.setForwardTo(forwardingHost); // may be null
            }

            @Override
            public void close() {
                clientRef.setForwardTo(originalForwardingHost);
            }
        }

        public Integer wait(boolean stdoutPrint, int timeoutSeconds) throws Exception {
            try (ForwardingHostManager manager = new ForwardingHostManager()) {
                return clientRef.waitForAsyncRun(this, stdoutPrint, timeoutSeconds);
            }
        }
    }

    public void setForwardTo(String host) {
        this.forwardTo = host;
    }

    @Override
    public void close() {
        // nothing to close here directly; Utils may own global resources
        this.jwtToken.set(null);
    }

    // Login with user name and password.
    public String login(String username, String password, String totpCode, Object expireSeconds, String audience)
            throws IOException {
        Map<String, String> headers = new HashMap<>();
        String basic = BASIC_PREFIX
                + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        headers.put(AUTHORIZATION_HEADER, basic);
        if (expireSeconds != null) {
            headers.put("X-Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }
        if (totpCode != null && !totpCode.isEmpty()) {
            headers.put("X-Totp-Code", totpCode);
        }
        if (audience != null && !audience.isEmpty()) {
            headers.put("X-Audience", audience);
        }

        HttpURLConnection conn = request("POST", "/appmesh/login", null, headers, null);
        int statusCode = conn.getResponseCode();
        String responseContent = Utils.readResponse(conn);

        if (statusCode == HttpURLConnection.HTTP_OK) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            String token = jsonResponse.getString("access_token");
            this.jwtToken.set(token);
            return token;
        } else if (statusCode == HTTP_PRECONDITION_REQUIRED && totpCode != null && !totpCode.isEmpty()) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            if (jsonResponse.has("totp_challenge")) {
                String challenge = jsonResponse.getString("totp_challenge");
                return validateTotp(username, challenge, totpCode, expireSeconds);
            }
        }

        throw new IOException("Login failed: HTTP " + statusCode + " - " + responseContent);
    }

    // Validates TOTP challenge.
    public String validateTotp(String username, String challenge, String code, Object expireSeconds)
            throws IOException {
        JSONObject body = new JSONObject();
        body.put("user_name", username);
        body.put("totp_code", code);
        body.put("totp_challenge", challenge);
        if (expireSeconds != null) {
            body.put("expire_seconds", Utils.toSeconds(expireSeconds));
        }
        HttpURLConnection conn = request("POST", "/appmesh/totp/validate", body, null, null);
        String responseContent = Utils.readResponse(conn);
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            String token = jsonResponse.getString("access_token");
            this.jwtToken.set(token);
            return token;
        }
        throw new IOException("TOTP validation failed: HTTP " + conn.getResponseCode() + " - " + responseContent);
    }

    // Logoff current session from server
    public boolean logoff() {
        try {
            HttpURLConnection conn = request("POST", "/appmesh/self/logoff", null, null, null);
            boolean ok = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
            this.jwtToken.set(null);
            return ok;
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to logoff", e);
            this.jwtToken.set(null);
            return false;
        }
    }

    // Login with token and verify permission when specified, verified token will be
    // stored in client object when success
    public boolean authenticate(String token, String permission, String audience) throws IOException {
        this.jwtToken.set(token);
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        if (audience != null && !audience.isEmpty()) {
            headers.put("X-Audience", audience);
        }
        if (permission != null && !permission.isEmpty()) {
            headers.put("X-Permission", permission);
        }
        HttpURLConnection conn = request("POST", "/appmesh/auth", null, headers, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Renew current token
    // expireSeconds (int | str, optional): token expire timeout of seconds. support
    // ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W'),
    // default is 7 days.
    public String renewToken(Object expireSeconds) throws IOException {
        Map<String, String> headers = new HashMap<>();
        if (expireSeconds != null) {
            headers.put("X-Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }
        HttpURLConnection conn = request("POST", "/appmesh/token/renew", null, headers, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        String token = jsonResponse.getString("access_token");
        this.jwtToken.set(token);
        return token;
    }

    // Generate TOTP secret for current login user and return MFA URI with JSON body
    public String getTotpSecret() throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/secret", null, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        String mfaUri = jsonResponse.getString("mfa_uri");
        return new String(Base64.getDecoder().decode(mfaUri), StandardCharsets.UTF_8);
    }

    // Setup 2FA for current login user
    public String setupTotp(String totpCode) throws IOException {
        if (totpCode == null || !totpCode.matches("\\d{6}")) {
            throw new IllegalArgumentException("TOTP code must be a 6-digit number");
        }
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Totp-Code", totpCode);
        HttpURLConnection conn = request("POST", "/appmesh/totp/setup", null, headers, null);
        String responseContent = Utils.readResponse(conn);
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            String token = jsonResponse.getString("access_token");
            this.jwtToken.set(token);
            return token;
        }
        throw new IOException("TOTP setup failed: HTTP " + conn.getResponseCode() + " - " + responseContent);
    }

    public boolean disableTotp() throws IOException {
        return disableTotp("self");
    }

    // Disable 2FA for specific user
    public boolean disableTotp(String user) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/" + encodeURIComponent(user) + "/disable", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Get the server labels
    public Map<String, String> viewTags() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/labels", null, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        Map<String, String> labels = new HashMap<>();
        for (String key : jsonResponse.keySet()) {
            labels.put(key, jsonResponse.getString(key));
        }
        return labels;
    }

    // Add a new label
    public boolean addTag(String key, String value) throws IOException {
        Map<String, String> params = new HashMap<>();
        params.put("value", value);
        HttpURLConnection conn = request("PUT", "/appmesh/label/" + encodeURIComponent(key), null, null, params);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Delete a label
    public boolean deleteTag(String key) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/label/" + encodeURIComponent(key), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Get all applications
    public JSONArray viewAllApps() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/applications", null, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONArray(responseContent);
    }

    // Get one application information
    public JSONObject viewApp(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName), null, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Get application health status
    public boolean checkAppHealth(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName) + "/health", null, null,
                null);
        String responseContent = Utils.readResponse(conn);
        return "0".equals(responseContent.trim());
    }

    // Enable an application
    public boolean enableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/enable", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Stop and disable an application
    public boolean disableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + encodeURIComponent(appName) + "/disable", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Remove an application.
    public boolean deleteApp(String appName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + encodeURIComponent(appName), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Register an application
    public JSONObject addApp(String appName, JSONObject appJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/app/" + encodeURIComponent(appName), appJson, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Get application stdout/stderr
    public AppOutput getAppOutput(String appName, long stdoutPosition, int stdoutIndex, int stdoutMaxsize,
            String processUuid, int timeout) throws IOException {
        Map<String, String> query = new HashMap<>();
        query.put("stdout_position", String.valueOf(stdoutPosition));
        query.put("stdout_index", String.valueOf(stdoutIndex));
        query.put("stdout_maxsize", String.valueOf(stdoutMaxsize));
        query.put("process_uuid", processUuid);
        query.put("timeout", String.valueOf(timeout));
        HttpURLConnection conn = request("GET", "/appmesh/app/" + encodeURIComponent(appName) + "/output", null, null,
                query);
        AppOutput response = new AppOutput();
        response.httpSuccess = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
        response.httpBody = Utils.readResponse(conn);

        String exitCodeStr = conn.getHeaderField("X-Exit-Code");
        if (exitCodeStr != null && !exitCodeStr.isEmpty()) {
            try {
                response.exitCode = Integer.parseInt(exitCodeStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code: " + exitCodeStr, e);
            }
        }

        String outputPositionStr = conn.getHeaderField("X-Output-Position");
        if (outputPositionStr != null && !outputPositionStr.isEmpty()) {
            try {
                response.outputPosition = Long.parseLong(outputPositionStr);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse output position: " + outputPositionStr, e);
            }
        }
        return response;
    }

    // Block run a command remotely, 'name' attribute in appJson dict used to run an
    // existing application
    // The synchronized run will block the process until the remote run is finished
    // then return the result from HTTP response
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTimeoutSeconds) throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(maxTimeoutSeconds));
        HttpURLConnection conn = request("POST", "/appmesh/app/syncrun", appJson, null, query);
        String exitCodeHeader = conn.getHeaderField("X-Exit-Code");
        Integer exitCode = null;
        if (exitCodeHeader != null && !exitCodeHeader.isEmpty()) {
            try {
                exitCode = Integer.parseInt(exitCodeHeader);
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Failed to parse exit code header", e);
            }
        }
        return Pair.of(exitCode, Utils.readResponse(conn));
    }

    // Asyncrized run a command remotely, 'name' attribute in appJson dict used to
    // run an existing application
    // Asyncrized run will not block process
    public AppRun runAppAsync(JSONObject appJson, Object maxTimeSeconds, Object lifeCycleSeconds) throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(Utils.toSeconds(maxTimeSeconds)));
        query.put("lifecycle", String.valueOf(Utils.toSeconds(lifeCycleSeconds)));
        HttpURLConnection conn = request("POST", "/appmesh/app/run", appJson, null, query);
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            String responseBody = Utils.readErrorResponse(conn);
            throw new IOException("Async run failed: HTTP " + conn.getResponseCode() + " - " + responseBody);
        }
        JSONObject jsonResponse = new JSONObject(Utils.readResponse(conn));
        return new AppRun(this, jsonResponse.getString("name"), jsonResponse.getString("process_uuid"));
    }

    // Wait for an async run to be finished
    public Integer waitForAsyncRun(AppRun run, boolean stdoutPrint, int timeoutSeconds) throws Exception {
        if (run == null)
            return null;
        long lastOutputPosition = 0;
        LocalDateTime start = LocalDateTime.now();
        int interval = 1;
        while (!run.getProcUid().isEmpty()) {
            AppOutput appOut = this.getAppOutput(run.getAppName(), lastOutputPosition, 0, 10240, run.getProcUid(),
                    interval);
            if (appOut.httpBody != null && stdoutPrint) {
                System.out.print(appOut.httpBody);
            }
            if (appOut.outputPosition != null) {
                lastOutputPosition = appOut.outputPosition;
            }
            if (appOut.exitCode != null) {
                this.deleteApp(run.getAppName());
                return appOut.exitCode;
            }
            if (!appOut.httpSuccess) {
                break;
            }
            if (timeoutSeconds > 0
                    && java.time.Duration.between(start, LocalDateTime.now()).getSeconds() > timeoutSeconds) {
                break;
            }
        }
        return null;
    }

    // Run a task remotely - send data to a running application and wait for result
    public String runTask(String appName, String data, int timeout) throws IOException {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(timeout));

        HttpURLConnection conn = request("POST", "/appmesh/app/" + appName + "/task", data, null, query);

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException("Task failed: " + Utils.readResponse(conn));
        }

        return Utils.readResponse(conn);
    }

    // Cancel a running task
    public boolean cancelTask(String appName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + appName + "/task", null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Copy a remote file to local, the local file will have the same permission as
    // the remote file
    public boolean downloadFile(String filePath, String localFile, boolean applyFileAttributes) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put("X-File-Path", encodeURIComponent(filePath));
        HttpURLConnection conn = request("GET", "/appmesh/file/download", null, headers, null);
        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException(Utils.readResponse(conn));
        }
        try (InputStream inputStream = conn.getInputStream();
                OutputStream outputStream = new FileOutputStream(localFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
        if (applyFileAttributes) {
            String fileMode = conn.getHeaderField("X-File-Mode");
            if (fileMode != null) {
                try {
                    Files.setPosixFilePermissions(Paths.get(localFile),
                            PosixFilePermissions.fromString(Utils.toPermissionString(Integer.parseInt(fileMode))));
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to apply file mode: " + fileMode, e);
                }
            }
            String fileUser = conn.getHeaderField("X-File-User");
            String fileGroup = conn.getHeaderField("X-File-Group");
            if (fileUser != null && fileGroup != null) {
                try {
                    Files.setOwner(Paths.get(localFile),
                            FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(fileUser));
                    Files.getFileAttributeView(Paths.get(localFile), PosixFileAttributeView.class)
                            .setGroup(FileSystems.getDefault().getUserPrincipalLookupService()
                                    .lookupPrincipalByGroupName(fileGroup));
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to set file owner or group", e);
                }
            }
        }
        return true;
    }

    // Upload a local file to the remote server, the remote file will have the same
    // permission as the local file
    public boolean uploadFile(Object localFile, String filePath, boolean applyFileAttributes) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put("X-File-Path", encodeURIComponent(filePath));

        File file;
        if (localFile instanceof String) {
            file = new File((String) localFile);
        } else if (localFile instanceof File) {
            file = (File) localFile;
        } else {
            throw new IllegalArgumentException("localFile must be a String path or a File object");
        }

        if (!file.exists()) {
            throw new IOException("File not found: " + file.getAbsolutePath());
        }

        if (applyFileAttributes) {
            int fileMode = Utils.getFilePermissions(file);
            headers.put("X-File-Mode", String.valueOf(fileMode));
            Map<String, String> fileAttributes = Utils.getFileAttributes(file);
            headers.putAll(fileAttributes);
        }

        String boundary = Utils.generateBoundary();
        headers.put(CONTENT_TYPE_HEADER, "multipart/form-data; boundary=" + boundary);

        URL url = Utils.toUrl(this.baseURL + "/appmesh/file/upload");
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setDoOutput(true);
        connection.setRequestMethod("POST");
        commonHeaders().forEach(connection::setRequestProperty);
        if (headers != null) {
            headers.forEach(connection::setRequestProperty);
        }

        try (OutputStream output = connection.getOutputStream()) {
            Utils.writeMultipartFormData(output, boundary, file);
        }

        int responseCode = connection.getResponseCode();
        if (responseCode != HttpURLConnection.HTTP_OK) {
            String responseBody = Utils.readErrorResponse(connection);
            LOGGER.severe("HTTP error code: " + responseCode);
            LOGGER.severe("Response body: " + responseBody);
            throw new IOException("HTTP error code: " + responseCode + ", Response: " + responseBody);
        }
        return true;
    }

    // Get App Mesh host resource report include CPU, memory and disk
    public JSONObject viewHostResources() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/resources", null, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Get App Mesh configuration JSON
    public JSONObject viewConfig() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/config", null, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Update configuration, the format follow 'config.yaml', support partial update
    public JSONObject setConfig(JSONObject configJson) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/config", configJson, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Update App Mesh log level(DEBUG/INFO/NOTICE/WARN/ERROR)
    public String setLogLevel(String level) throws IOException {
        JSONObject config = new JSONObject().put("BaseConfig", new JSONObject().put("LogLevel", level));
        HttpURLConnection conn = request("POST", "/appmesh/config", config, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject cfg = new JSONObject(responseContent);
        return cfg.getJSONObject("BaseConfig").getString("LogLevel");
    }

    public boolean updateUserPassword(String oldPassword, String newPassword, String userName) throws IOException {
        JSONObject newPwd = new JSONObject();
        newPwd.put("old_password", Base64.getEncoder().encodeToString(oldPassword.getBytes(StandardCharsets.UTF_8)));
        newPwd.put("new_password", Base64.getEncoder().encodeToString(newPassword.getBytes(StandardCharsets.UTF_8)));
        HttpURLConnection conn = request("POST", "/appmesh/user/" + encodeURIComponent(userName) + "/passwd", newPwd,
                null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean updateUserPassword(String oldPassword, String newPassword) throws IOException {
        return updateUserPassword(oldPassword, newPassword, "self");
    }

    public boolean addUser(String userName, JSONObject userJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/user/" + encodeURIComponent(userName), userJson, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean deleteUser(String userName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/user/" + encodeURIComponent(userName), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean lockUser(String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + encodeURIComponent(userName) + "/lock", null, null,
                null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean unlockUser(String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + encodeURIComponent(userName) + "/unlock", null,
                null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public JSONObject viewUsers() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/users", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    public JSONObject viewSelf() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/user/self", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    public JSONObject viewGroups() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/user/groups", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    public Set<String> viewPermissions() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/permissions", null, null, null);
        Set<String> permissions = new HashSet<>();
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            JSONArray jsonArray = new JSONArray(Utils.readResponse(conn));
            for (int i = 0; i < jsonArray.length(); i++) {
                permissions.add(jsonArray.getString(i));
            }
        }
        return permissions;
    }

    public Set<String> viewUserPermissions() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/user/permissions", null, null, null);
        Set<String> permissions = new HashSet<>();
        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            JSONArray jsonArray = new JSONArray(Utils.readResponse(conn));
            for (int i = 0; i < jsonArray.length(); i++) {
                permissions.add(jsonArray.getString(i));
            }
        }
        return permissions;
    }

    public JSONObject viewRoles() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/roles", null, null, null);
        return new JSONObject(Utils.readResponse(conn));
    }

    public boolean updateRole(String roleName, JSONObject rolePermissionJson) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/role/" + encodeURIComponent(roleName), rolePermissionJson,
                null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean deleteRole(String roleName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/role/" + encodeURIComponent(roleName), null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public String getMetrics() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/metrics", null, null, null);
        return Utils.readResponse(conn);
    }

    // -------- Internal helpers --------

    private Map<String, String> commonHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT);
        String token = this.jwtToken.get();
        if (token != null && !token.isEmpty()) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        }
        if (this.forwardTo != null && !this.forwardTo.isEmpty()) {
            String host = this.forwardTo;
            if (!host.contains(":")) {
                try {
                    URL url = Utils.toUrl(this.baseURL);
                    int port = url.getPort();
                    host = this.forwardTo + ":" + port;
                } catch (Exception e) {
                    LOGGER.log(Level.SEVERE, "Failed to parse baseURL", e);
                    throw new RuntimeException("Failed to set forward host", e);
                }
            }
            headers.put("X-Target-Host", host);
        }
        return headers;
    }

    private String encodeURIComponent(String value) {
        if (value == null)
            return null;
        try {
            String encoded = URLEncoder.encode(value, StandardCharsets.UTF_8.name());
            // make it closer to JS encodeURIComponent
            return encoded.replace("+", "%20")
                    .replace("%21", "!")
                    .replace("%27", "'")
                    .replace("%28", "(")
                    .replace("%29", ")")
                    .replace("%7E", "~")
                    .replace("%2A", "*");
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }

    /**
     * Core HTTP request helper. Builds URL, attaches headers and body (for JSON
     * POST/PUT),
     * and returns the HttpURLConnection for caller to inspect response / read
     * streams.
     */
    private HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
            Map<String, String> params)
            throws IOException {
        StringBuilder urlBuilder = new StringBuilder(baseURL).append(path);

        if (params != null && !params.isEmpty()) {
            urlBuilder.append('?');
            for (Map.Entry<String, ?> e : params.entrySet()) {
                try {
                    urlBuilder.append(URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8.name()))
                            .append('=')
                            .append(URLEncoder.encode(String.valueOf(e.getValue()), StandardCharsets.UTF_8.name()))
                            .append('&');
                } catch (UnsupportedEncodingException ex) {
                    throw new RuntimeException("Error encoding URL parameters", ex);
                }
            }
            urlBuilder.setLength(urlBuilder.length() - 1); // remove trailing &
        }

        URL url = Utils.toUrl(urlBuilder.toString());
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod(method.toUpperCase());

        Map<String, String> allHeaders = new HashMap<>(commonHeaders());
        if (headers != null) {
            allHeaders.putAll(headers);
        }
        allHeaders.forEach(connection::setRequestProperty);

        if ("POST".equalsIgnoreCase(method) || "PUT".equalsIgnoreCase(method) || "PATCH".equalsIgnoreCase(method)) {
            if (body != null) {
                String bodyString;
                if (body instanceof JSONObject) {
                    bodyString = body.toString();
                    connection.setRequestProperty(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
                    connection.setRequestProperty(ACCEPT_HEADER, JSON_CONTENT_TYPE);
                } else if (body instanceof String) {
                    bodyString = (String) body;
                    if (!allHeaders.containsKey(CONTENT_TYPE_HEADER)) {
                        connection.setRequestProperty(CONTENT_TYPE_HEADER, "text/plain; charset=utf-8");
                    }
                } else {
                    bodyString = body.toString();
                }

                connection.setDoOutput(true);
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(bodyString.getBytes(StandardCharsets.UTF_8));
                    os.flush();
                }
            }
        }

        return connection;
    }
}
