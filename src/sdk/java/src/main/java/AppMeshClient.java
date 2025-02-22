import java.io.BufferedReader;
import java.io.Closeable;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
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
import java.util.stream.Collectors;
import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONArray;
import org.json.JSONObject;


/**
 * App Mesh client object used to access App Mesh REST Service.
 */
public class AppMeshClient {
    private static final Logger LOGGER = Logger.getLogger(AppMeshClient.class.getName());
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String HTTP_USER_AGENT_HEADER_NAME = "User-Agent";
    private static final String HTTP_USER_AGENT = "appmesh/java";
    private static final String BEARER_PREFIX = "Bearer ";
    private static final String BASIC_PREFIX = "Basic ";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String ACCEPT_HEADER = "Accept";
    private static final String JSON_CONTENT_TYPE = "application/json; utf-8";
    private static final String DEFAULT_JWT_AUDIENCE = "appmesh-service";
    private static final int HTTP_PRECONDITION_REQUIRED = 428;

    private final String baseURL;
    private AtomicReference<String> jwtToken = new AtomicReference<String>(null);
    private String forwardTo;

    // Construct an App Mesh client object.
    private AppMeshClient(Builder builder) {
        this.baseURL = Objects.requireNonNull(builder.baseURL, "Base URL cannot be null");
        this.jwtToken.set(builder.jwtToken);
        if (builder.caCertFilePath != null || builder.clientCertFilePath != null) {
            try {
                Utils.configureSSLCertificates(builder.caCertFilePath, builder.clientCertFilePath, builder.clientCertKeyFilePath);
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

    /**
     * Used to build AppMeshClient constructor parameters.
     */
    public static class Builder {
        private String baseURL = "https://localhost:6060";
        private String caCertFilePath;
        private String clientCertFilePath;
        private String clientCertKeyFilePath;
        private String jwtToken;
        private boolean disableSSLVerification = false;

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


    /**
     * Application output object for appOutput() method.
     */
    public static class AppOutput {
        public boolean httpSuccess;
        public String httpBody;
        public Long outputPosition;
        public Integer exitCode;
    }

    /**
     * Application run object indicate to a remote run from runAsync().
     */
    public class AppRun {
        private String appName;
        private String procUid;
        private AppMeshClient client;
        private String forwardingHost;

        public AppRun(AppMeshClient client, String appName, String processId) {
            this.appName = appName;
            this.procUid = processId;
            this.client = client;
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
            return client;
        }

        public String getForwardingHost() {
            return forwardingHost;
        }

        // Context manager equivalent in Java
        public class ForwardingHostManager implements Closeable {
            private String originalForwardingHost;

            public ForwardingHostManager() {
                this.originalForwardingHost = client.forwardTo;
                client.forwardTo(forwardingHost);
            }

            @Override
            public void close() throws IOException {
                client.forwardTo(originalForwardingHost);
            }
        }

        // Equivalent to the wait method in Python
        public Integer wait(boolean stdoutPrint, int timeout) throws Exception {
            try (ForwardingHostManager manager = new ForwardingHostManager()) {
                return client.waitForAsyncRun(this, stdoutPrint, timeout);
            }
        }
    }

    public void forwardTo(String host) {
        this.forwardTo = host;
    }

    // Login with user name and password.
    public String login(String username, String password, String totpCode, Object expireSeconds, String audience) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION_HEADER, BASIC_PREFIX + Base64.getEncoder().encodeToString((username + ":" + password).getBytes()));
        if (expireSeconds != null) {
            headers.put("Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }
        if (totpCode != null) {
            headers.put("Totp", totpCode);
        }
        if (audience != null && !audience.isEmpty()) {
            headers.put("Audience", audience);
        }

        HttpURLConnection conn = request("POST", "/appmesh/login", null, headers, null);
        int statusCode = conn.getResponseCode();
        String responseContent = Utils.readResponse(conn);

        if (statusCode == HttpURLConnection.HTTP_OK) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            this.jwtToken.set(jsonResponse.getString("Access-Token"));
            return this.jwtToken.get();
        } else if (statusCode == HTTP_PRECONDITION_REQUIRED && totpCode != null && !totpCode.isEmpty()) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            if (jsonResponse.has("Totp-Challenge")) {
                String challenge = jsonResponse.getString("Totp-Challenge");
                return validateTotp(username, challenge, totpCode, expireSeconds);
            }
        }
        throw new IOException("Login failed: " + responseContent);
    }

    /**
     * Validates TOTP challenge.
     * 
     * @param username Username to validate
     * @param challenge Challenge from server
     * @param code TOTP code
     * @param expireSeconds Token expiry duration in seconds or ISO duration string
     * @return New JWT token
     * @throws IOException if validation fails
     */
    public String validateTotp(String username, String challenge, String code, Object expireSeconds) throws IOException {
        Map<String, String> headers = new HashMap<>();
        headers.put("Username", Base64.getEncoder().encodeToString(username.getBytes()));
        headers.put("Totp", code);
        headers.put("Totp-Challenge", Base64.getEncoder().encodeToString(challenge.getBytes()));
        if (expireSeconds != null) {
            headers.put("Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }

        HttpURLConnection conn = request("POST", "/appmesh/totp/validate", null, headers, null);
        String responseContent = Utils.readResponse(conn);

        if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
            JSONObject jsonResponse = new JSONObject(responseContent);
            this.jwtToken.set(jsonResponse.getString("Access-Token"));
            return this.jwtToken.get();
        }
        throw new IOException("TOTP validation failed: " + responseContent);
    }

    // Logoff current session from server
    public boolean logoff() throws IOException {
        if (this.jwtToken != null) {
            HttpURLConnection conn = request("POST", "/appmesh/self/logoff", null, null, null);
            this.jwtToken.set(null);
            return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
        }
        return true;
    }

    // Login with token and verify permission when specified, verified token will be stored in client object when success
    public boolean authenticate(String token, String permission, String audience) throws IOException {
        this.jwtToken.set(token);
        Map<String, String> headers = new HashMap<>();
        headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + token);
        if (audience != null && !audience.isEmpty()) {
            headers.put("Audience", audience);
        }
        if (permission != null) {
            headers.put("Auth-Permission", permission);
        }

        HttpURLConnection conn = request("POST", "/appmesh/auth", null, headers, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Renew current token
    // expireSeconds (int | str, optional): token expire timeout of seconds. support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P1W'),
    // default is 7 days.
    public String renewToken(Object expireSeconds) throws IOException {
        Map<String, String> headers = new HashMap<>();
        if (expireSeconds != null) {
            headers.put("Expire-Seconds", Long.toString(Utils.toSeconds(expireSeconds)));
        }

        HttpURLConnection conn = request("POST", "/appmesh/token/renew", null, headers, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        this.jwtToken.set(jsonResponse.getString("Access-Token"));
        return this.jwtToken.get();
    }

    // Generate TOTP secret for current login user and return MFA URI with JSON body
    public String getTotpSecret() throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/secret", null, null, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        String mfaUri = jsonResponse.getString("Mfa-Uri");
        return new String(Base64.getDecoder().decode(mfaUri));
    }

    // Setup 2FA for current login user
    public String setupTotp(String totpCode) throws IOException, IllegalArgumentException {
        if (totpCode == null || !totpCode.matches("\\d{6}")) {
            throw new IllegalArgumentException("TOTP code must be a 6-digit number");
        }

        Map<String, String> headers = new HashMap<>();
        headers.put("Totp", totpCode);

        HttpURLConnection conn = request("POST", "/appmesh/totp/setup", null, headers, null);
        String responseContent = Utils.readResponse(conn);
        JSONObject jsonResponse = new JSONObject(responseContent);
        this.jwtToken.set(jsonResponse.getString("Access-Token"));
        return this.jwtToken.get();
    }

    // Disable 2FA for current user
    public boolean disableTotp() throws IOException {
        return disableTotp("self");
    }

    // Disable 2FA for specific user
    public boolean disableTotp(String user) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/totp/" + user + "/disable", null, null, null);
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
        HttpURLConnection conn = request("PUT", "/appmesh/label/" + key, null, null, params);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Delete a label
    public boolean deleteTag(String key) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/label/" + key, null, null, null);
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
        HttpURLConnection conn = request("GET", "/appmesh/app/" + appName, null, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Get application health status
    public boolean checkAppHealth(String appName) throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/app/" + appName + "/health", null, null, null);
        String responseContent = Utils.readResponse(conn);
        return "0".equals(responseContent);
    }

    // Enable an application
    public boolean enableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + appName + "/enable", null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Stop and disable an application
    public boolean disableApp(String appName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/app/" + appName + "/disable", null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Remove an application.
    public boolean deleteApp(String appName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/app/" + appName, null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    // Register an application
    public JSONObject addApp(String appName, JSONObject appJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/app/" + appName, appJson, null, null);
        String responseContent = Utils.readResponse(conn);
        return new JSONObject(responseContent);
    }

    // Get application stdout/stderr
    public AppOutput getAppOutput(String appName, long stdoutPosition, int stdoutIndex, int stdoutMaxsize, String processUuid, int timeout)
            throws IOException {

        Map<String, String> querys = new HashMap<>();
        querys.put("stdout_position", String.valueOf(stdoutPosition));
        querys.put("stdout_index", String.valueOf(stdoutIndex));
        querys.put("stdout_maxsize", String.valueOf(stdoutMaxsize));
        querys.put("process_uuid", processUuid);
        querys.put("timeout", String.valueOf(timeout));

        HttpURLConnection conn = request("GET", "/appmesh/app/" + appName + "/output", null, null, querys);

        AppOutput response = new AppOutput();
        response.httpSuccess = conn.getResponseCode() == HttpURLConnection.HTTP_OK;
        response.httpBody = Utils.readResponse(conn);

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

    // Block run a command remotely, 'name' attribute in appJson dict used to run an existing application
    // The synchronized run will block the process until the remote run is finished then return the result from HTTP response
    public Pair<Integer, String> runAppSync(JSONObject appJson, int maxTimeoutSeconds) throws Exception {
        Integer exitCode = null;
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(maxTimeoutSeconds));

        HttpURLConnection conn = request("POST", "/appmesh/app/syncrun", appJson, null, query);

        String exitCodeHeader = conn.getHeaderField("Exit-Code");
        if (exitCodeHeader != null && !exitCodeHeader.isEmpty()) {
            exitCode = Integer.parseInt(exitCodeHeader);
        }

        return Pair.of(exitCode, Utils.readResponse(conn));
    }

    // Asyncrized run a command remotely, 'name' attribute in appJson dict used to run an existing application
    // Asyncrized run will not block process
    public AppRun runAppAsync(JSONObject appJson, Object maxTimeSeconds, Object lifeCycleSeconds) throws Exception {
        Map<String, String> query = new HashMap<>();
        query.put("timeout", String.valueOf(Utils.toSeconds(maxTimeSeconds)));
        query.put("lifecycle", String.valueOf(Utils.toSeconds(lifeCycleSeconds)));

        HttpURLConnection conn = request("POST", "/appmesh/app/run", appJson, null, query);

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getErrorStream(), StandardCharsets.UTF_8))) {
                throw new Exception(reader.lines().collect(Collectors.joining("\n")));
            }
        }
        JSONObject jsonResponse = new JSONObject(Utils.readResponse(conn));
        return new AppRun(this, jsonResponse.getString("name"), jsonResponse.getString("process_uuid"));
    }

    // Wait for an async run to be finished
    public Integer waitForAsyncRun(AppRun run, boolean stdoutPrint, int timeout) throws Exception {
        if (run != null) {
            long lastOutputPosition = 0;
            LocalDateTime start = LocalDateTime.now();
            int interval = 1;

            while (!run.getProcUid().isEmpty()) {
                AppOutput appOut = this.getAppOutput(run.getAppName(), lastOutputPosition, 0, 10240, run.getProcUid(), interval);

                if (appOut.httpBody != null && stdoutPrint) {
                    System.out.print(appOut.httpBody);
                }

                if (appOut.outputPosition != null) {
                    lastOutputPosition = appOut.outputPosition;
                }

                if (appOut.exitCode != null) {
                    this.deleteApp(run.getAppName());
                    return appOut.exitCode.intValue();
                }

                if (!appOut.httpSuccess) {
                    break;
                }

                if (timeout > 0 && java.time.Duration.between(start, LocalDateTime.now()).getSeconds() > timeout) {
                    break;
                }
            }
        }
        return null;
    }

    // Copy a remote file to local, the local file will have the same permission as the remote file
    public boolean downloadFile(String filePath, String localFile, boolean applyFileAttributes) throws IOException {
        Map<String, String> headers = new HashMap<>(commonHeaders());
        headers.put("File-Path", encodeURIComponent(filePath));

        HttpURLConnection conn = request("GET", "/appmesh/file/download", null, headers, null);

        if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
            throw new IOException(Utils.readResponse(conn));
        }

        try (InputStream inputStream = conn.getInputStream(); OutputStream outputStream = new FileOutputStream(localFile)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }

        if (applyFileAttributes) {
            String fileMode = conn.getHeaderField("File-Mode");
            if (fileMode != null) {
                Files.setPosixFilePermissions(Paths.get(localFile),
                        PosixFilePermissions.fromString(Utils.toPermissionString(Integer.parseInt(fileMode))));
            }

            String fileUser = conn.getHeaderField("File-User");
            String fileGroup = conn.getHeaderField("File-Group");
            if (fileUser != null && fileGroup != null) {
                try {
                    Files.setOwner(Paths.get(localFile),
                            FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByName(fileUser));
                    Files.getFileAttributeView(Paths.get(localFile), PosixFileAttributeView.class)
                            .setGroup(FileSystems.getDefault().getUserPrincipalLookupService().lookupPrincipalByGroupName(fileGroup));
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Failed to set file owner or group: {0}", e.toString());
                }
            }
        }

        return true;
    }

    // Upload a local file to the remote server, the remote file will have the same permission as the local file
    public boolean uploadFile(Object localFile, String filePath, boolean applyFileAttributes) {
        try {
            Map<String, String> headers = commonHeaders();
            headers.put("File-Path", encodeURIComponent(filePath));

            File file;
            if (localFile instanceof String) {
                file = new File((String) localFile);
            } else if (localFile instanceof File) {
                file = (File) localFile;
            } else {
                throw new IllegalArgumentException("localFile must be a String path or a File object");
            }

            // Get file permissions and attributes
            if (applyFileAttributes) {
                int fileMode = Utils.getFilePermissions(file);
                headers.put("File-Mode", String.valueOf(fileMode));

                Map<String, String> fileAttributes = Utils.getFileAttributes(file);
                headers.putAll(fileAttributes);
            }

            String boundary = Utils.generateBoundary();
            headers.put("Content-Type", "multipart/form-data; boundary=" + boundary);

            StringBuilder urlBuilder = new StringBuilder(baseURL).append("/appmesh/file/upload");
            URL url = Utils.toUrl(urlBuilder.toString());
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setDoOutput(true);
            connection.setRequestMethod("POST");

            for (Map.Entry<String, String> entry : headers.entrySet()) {
                connection.setRequestProperty(entry.getKey(), entry.getValue());
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
        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Upload failed", e);
            return false;
        }
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

        config = new JSONObject(responseContent);
        return config.getJSONObject("BaseConfig").getString("LogLevel");
    }

    public boolean updateUserPassword(String newPassword, String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + userName + "/passwd", null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean updateUserPassword(String newPassword) throws IOException {
        return updateUserPassword(newPassword, "self");
    }

    public boolean addUser(String userName, JSONObject userJson) throws IOException {
        HttpURLConnection conn = request("PUT", "/appmesh/user/" + userName, userJson, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean deleteUser(String userName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/user/" + userName, null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean lockUser(String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + userName + "/lock", null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean unlockUser(String userName) throws IOException {
        HttpURLConnection conn = request("POST", "/appmesh/user/" + userName + "/unlock", null, null, null);
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
        HttpURLConnection conn = request("POST", "/appmesh/role/" + roleName, rolePermissionJson, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public boolean deleteRole(String roleName) throws IOException {
        HttpURLConnection conn = request("DELETE", "/appmesh/role/" + roleName, null, null, null);
        return conn.getResponseCode() == HttpURLConnection.HTTP_OK;
    }

    public String metrics() throws IOException {
        HttpURLConnection conn = request("GET", "/appmesh/metrics", null, null, null);
        return Utils.readResponse(conn);
    }

    private Map<String, String> commonHeaders() {
        Map<String, String> headers = new HashMap<>();
        headers.put(HTTP_USER_AGENT_HEADER_NAME, HTTP_USER_AGENT);
        if (this.jwtToken != null) {
            headers.put(AUTHORIZATION_HEADER, BEARER_PREFIX + this.jwtToken);
        }
        if (this.forwardTo != null) {
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
            // Convert the string to UTF-8 bytes and encode special characters
            String encoded = java.net.URLEncoder.encode(value, "UTF-8");

            // JavaScript's encodeURIComponent() doesn't encode these characters
            return encoded.replace("+", "%20") // Space is encoded as + in Java, but %20 in JavaScript
                    .replace("%21", "!") // !
                    .replace("%27", "'") // '
                    .replace("%28", "(") // (
                    .replace("%29", ")") // )
                    .replace("%7E", "~") // ~
                    .replace("%2A", "*"); // *

        } catch (java.io.UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
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
                connection.setRequestProperty(CONTENT_TYPE_HEADER, JSON_CONTENT_TYPE);
                connection.setRequestProperty(ACCEPT_HEADER, JSON_CONTENT_TYPE);
                connection.setDoOutput(true);
                try (OutputStream os = connection.getOutputStream()) {
                    os.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
        }

        return connection;
    }
}
