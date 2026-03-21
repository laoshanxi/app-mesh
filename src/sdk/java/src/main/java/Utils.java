import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.GroupPrincipal;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.nio.file.attribute.UserPrincipalLookupService;
import java.nio.file.attribute.UserPrincipalNotFoundException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.threeten.extra.PeriodDuration;

public class Utils {
    private static final Logger LOGGER = Logger.getLogger(Utils.class.getName());

    /**
     * Disable SSL verification globally. Insecure — development only.
     *
     * @deprecated Use {@link #createSSLContext(String, String, String, boolean)} with
     *             per-connection SSL instead of modifying global defaults.
     */
    @Deprecated
    public static void disableSSLVerification() throws Exception {
        LOGGER.log(Level.WARNING,
                "SSL verification is disabled globally. This is insecure and should only be used in development environments.");
        SSLContext sc = createSSLContext(null, null, null, true);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
        HostnameVerifier allHostsValid = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    /**
     * Enable custom SSL certificates globally.
     *
     * @deprecated Use {@link #createSSLContext(String, String, String, boolean)} with
     *             per-connection SSL instead of modifying global defaults.
     */
    @Deprecated
    public static void enableSSLCertificates(String caCertFilePath, String clientCertFilePath,
            String clientCertKeyFilePath) throws Exception {
        SSLContext sc = createSSLContext(caCertFilePath, clientCertFilePath, clientCertKeyFilePath, false);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    /**
     * Create a per-instance SSLContext. This does NOT modify JVM global defaults.
     *
     * @param caCertFilePath        path to CA certificate (null = system default)
     * @param clientCertFilePath    path to client certificate (null = no mTLS)
     * @param clientCertKeyFilePath path to client private key (null = no mTLS)
     * @param disableVerification   if true, accept all certificates (insecure)
     * @return configured SSLContext
     */
    public static SSLContext createSSLContext(String caCertFilePath, String clientCertFilePath,
            String clientCertKeyFilePath, boolean disableVerification) throws Exception {
        return createSSLContext(caCertFilePath, clientCertFilePath, clientCertKeyFilePath, null, disableVerification);
    }

    /**
     * Create a per-instance SSLContext with optional private key password.
     *
     * @param caCertFilePath        path to CA certificate (null = system default)
     * @param clientCertFilePath    path to client certificate (null = no mTLS)
     * @param clientCertKeyFilePath path to client private key (null = no mTLS)
     * @param keyPassword           password for encrypted private key (null = no password)
     * @param disableVerification   if true, accept all certificates (insecure)
     * @return configured SSLContext
     */
    public static SSLContext createSSLContext(String caCertFilePath, String clientCertFilePath,
            String clientCertKeyFilePath, char[] keyPassword, boolean disableVerification) throws Exception {
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
            LOGGER.log(Level.INFO, "BouncyCastle provider added.");
        }

        if (disableVerification) {
            TrustManager[] trustAllCerts = new TrustManager[] { new X509TrustManager() {
                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }

                @Override
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            } };
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            return sc;
        }

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);

        TrustManager[] trustManagers = createTrustManagers(keyStore, caCertFilePath);
        KeyManager[] keyManagers = createKeyManagers(keyStore, clientCertFilePath, clientCertKeyFilePath, keyPassword);

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(keyManagers, trustManagers, null);
        return sc;
    }

    private static TrustManager[] createTrustManagers(KeyStore keyStore, String caCertFilePath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        boolean customCAProvided = isFileExists(caCertFilePath);
        if (customCAProvided) {
            X509Certificate caCert = loadCertificate(caCertFilePath);
            keyStore.setCertificateEntry("caCert", caCert);
        } else if (caCertFilePath != null) {
            LOGGER.log(Level.INFO, "CA certificate not provided. Using system default CA trust store.");
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        if (customCAProvided) {
            tmf.init(keyStore);
        } else {
            tmf.init((KeyStore) null);
        }
        return tmf.getTrustManagers();
    }

    private static KeyManager[] createKeyManagers(KeyStore keyStore, String clientCertFilePath,
            String clientCertKeyFilePath, char[] keyPassword) throws Exception {
        if (!isFileExists(clientCertFilePath) || !isFileExists(clientCertKeyFilePath)) {
            if (clientCertFilePath != null) {
                LOGGER.log(Level.INFO,
                        "Client certificate or key file does not exist. Proceeding without client certificate.");
            }
            return null;
        }

        Certificate clientCert = loadCertificate(clientCertFilePath);
        PrivateKey clientCertKey = loadPrivateKey(clientCertKeyFilePath, keyPassword);

        char[] ksPassword = (keyPassword != null) ? keyPassword : new char[0];
        keyStore.setKeyEntry("clientCert", clientCertKey, ksPassword, new Certificate[] { clientCert });

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, ksPassword);
        return kmf.getKeyManagers();
    }

    private static X509Certificate loadCertificate(String certPath) throws IOException, CertificateException {
        LOGGER.log(Level.CONFIG, "Loading certificate from: {0}", certPath);
        try (FileInputStream fis = new FileInputStream(certPath)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        }
    }

    /**
     * Load a PEM-encoded private key, optionally decrypting with the given password.
     *
     * @param keyFilePath path to PEM private key file
     * @param password    password for encrypted keys (null for unencrypted)
     * @return the private key
     */
    private static PrivateKey loadPrivateKey(String keyFilePath, char[] password) throws Exception {
        LOGGER.log(Level.CONFIG, "Loading private key from: {0}", keyFilePath);
        try (PEMParser pemParser = new PEMParser(new FileReader(keyFilePath))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PEMEncryptedKeyPair) {
                if (password == null || password.length == 0) {
                    throw new IllegalArgumentException(
                            "Private key is encrypted but no password was provided. "
                                    + "Use Builder.keyPassword() to supply the decryption password.");
                }
                PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password);
                PEMKeyPair decryptedKeyPair = ((PEMEncryptedKeyPair) object).decryptKeyPair(decryptorProvider);
                return converter.getPrivateKey(decryptedKeyPair.getPrivateKeyInfo());
            } else if (object instanceof PEMKeyPair) {
                return converter.getPrivateKey(((PEMKeyPair) object).getPrivateKeyInfo());
            } else if (object instanceof PrivateKeyInfo) {
                return converter.getPrivateKey((PrivateKeyInfo) object);
            } else {
                throw new IllegalArgumentException("Unsupported private key format in file: " + keyFilePath);
            }
        }
    }

    private static boolean isFileExists(String filePath) {
        if (filePath != null && !filePath.isEmpty()) {
            File file = new File(filePath);
            return file.exists() && file.isFile();
        }
        return false;
    }

    /**
     * Parse a duration value: accepts integer seconds or ISO 8601 duration string
     * (e.g., {@code "P1W"}, {@code "P2DT12H"}).
     */
    public static long toSeconds(Object input) {
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

    /** Safely convert a URL string to a {@link URL} via URI. */
    public static URL toUrl(String url) throws IOException {
        try {
            URI uri = new URI(url);
            return uri.toURL();
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URL syntax", e);
        }
    }

    // ---- File Attribute Utilities ----

    private static String toPermissionString(int mode) {
        StringBuilder result = new StringBuilder(9);
        result.append((mode & 0400) == 0 ? '-' : 'r');
        result.append((mode & 0200) == 0 ? '-' : 'w');
        result.append((mode & 0100) == 0 ? '-' : 'x');
        result.append((mode & 040) == 0 ? '-' : 'r');
        result.append((mode & 020) == 0 ? '-' : 'w');
        result.append((mode & 010) == 0 ? '-' : 'x');
        result.append((mode & 04) == 0 ? '-' : 'r');
        result.append((mode & 02) == 0 ? '-' : 'w');
        result.append((mode & 01) == 0 ? '-' : 'x');
        return result.toString();
    }

    private static int posixPermissionsToMode(Set<PosixFilePermission> perms) {
        int mode = 0;
        if (perms.contains(PosixFilePermission.OWNER_READ)) mode |= 0400;
        if (perms.contains(PosixFilePermission.OWNER_WRITE)) mode |= 0200;
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE)) mode |= 0100;
        if (perms.contains(PosixFilePermission.GROUP_READ)) mode |= 0040;
        if (perms.contains(PosixFilePermission.GROUP_WRITE)) mode |= 0020;
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE)) mode |= 0010;
        if (perms.contains(PosixFilePermission.OTHERS_READ)) mode |= 0004;
        if (perms.contains(PosixFilePermission.OTHERS_WRITE)) mode |= 0002;
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE)) mode |= 0001;
        return mode;
    }

    /** Extract POSIX file attributes as HTTP header key-value pairs. */
    public static Map<String, String> getFileAttributes(File file) {
        Map<String, String> attributes = new HashMap<>();
        Path path = file.toPath();

        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            LOGGER.log(Level.FINE, "POSIX file attributes not supported on this system");
            return attributes;
        }

        try {
            PosixFileAttributeView posixView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
            if (posixView != null) {
                PosixFileAttributes attrs = posixView.readAttributes();
                int mode = posixPermissionsToMode(attrs.permissions());
                attributes.put("X-File-Mode", String.valueOf(mode));

                UserPrincipal owner = attrs.owner();
                GroupPrincipal group = attrs.group();
                if (owner != null) attributes.put("X-File-User", owner.getName());
                if (group != null) attributes.put("X-File-Group", group.getName());
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error reading file attributes for: " + file.getPath(), e);
        }
        return attributes;
    }

    /** Apply POSIX file attributes (owner, group, mode) from HTTP response headers. */
    public static void applyFileAttributes(String localFile, HttpURLConnection conn) {
        Path path = Paths.get(localFile);
        if (!Files.exists(path)) {
            LOGGER.log(Level.WARNING, "File does not exist: " + localFile);
            return;
        }
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            LOGGER.log(Level.FINE, "POSIX file attributes not supported on this system");
            return;
        }

        // Owner / Group — apply first (chown clears setuid/setgid)
        String userStr = conn.getHeaderField("X-File-User");
        String groupStr = conn.getHeaderField("X-File-Group");
        if (userStr != null && !userStr.isEmpty() && groupStr != null && !groupStr.isEmpty()) {
            try {
                UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();
                PosixFileAttributeView posixView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
                if (posixView != null) {
                    try {
                        posixView.setOwner(lookupService.lookupPrincipalByName(userStr.trim()));
                    } catch (UserPrincipalNotFoundException e) {
                        LOGGER.log(Level.FINE, "User not found, ownership not changed: " + userStr);
                    }
                    try {
                        posixView.setGroup(lookupService.lookupPrincipalByGroupName(groupStr.trim()));
                    } catch (UserPrincipalNotFoundException e) {
                        LOGGER.log(Level.FINE, "Group not found, group not changed: " + groupStr);
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to apply file ownership: " + userStr + "/" + groupStr, e);
            }
        }

        // File mode — apply after chown to preserve all permission bits
        String fileModeStr = conn.getHeaderField("X-File-Mode");
        if (fileModeStr != null && !fileModeStr.isEmpty()) {
            try {
                int mode = Integer.parseInt(fileModeStr.trim());
                if (mode < 0 || mode > 511) {
                    LOGGER.log(Level.WARNING, "File mode out of valid range (0-511): " + mode);
                } else {
                    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString(toPermissionString(mode)));
                }
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Invalid file mode format: " + fileModeStr, e);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to apply file mode: " + fileModeStr, e);
            }
        }
    }

    // ---- HTTP Utilities ----

    /** Generate a multipart form boundary string. */
    public static String generateBoundary() {
        return "----WebKitFormBoundary" + Long.toHexString(System.currentTimeMillis());
    }

    /** Write a file as multipart/form-data to the output stream. */
    public static void writeMultipartFormData(OutputStream output, String boundary, File file) throws IOException {
        String LINE_FEED = "\r\n";
        String fileName = file.getName();

        output.write(("--" + boundary + LINE_FEED).getBytes());
        output.write(("Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"" + LINE_FEED)
                .getBytes());
        output.write(("Content-Type: application/octet-stream" + LINE_FEED + LINE_FEED).getBytes());

        try (FileInputStream inputStream = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }

        output.write(LINE_FEED.getBytes());
        output.write(("--" + boundary + "--" + LINE_FEED).getBytes());
    }

    /**
     * Read the error stream from an HTTP connection.
     * Returns empty string if the error stream is null.
     */
    public static String readErrorResponse(HttpURLConnection conn) {
        try {
            InputStream errorStream = conn.getErrorStream();
            if (errorStream == null) {
                return "";
            }
            try (InputStream is = errorStream;
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    outputStream.write(buffer, 0, bytesRead);
                }
                return outputStream.toString(StandardCharsets.UTF_8.name());
            }
        } catch (IOException e) {
            return "";
        }
    }

    private static byte[] readAllBytes(InputStream input) throws IOException {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int bytesRead;
        while ((bytesRead = input.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        return outputStream.toByteArray();
    }

    /** Read the response body as a UTF-8 string. */
    public static String readResponse(HttpURLConnection conn) throws IOException {
        try (InputStream inputStream = conn.getInputStream()) {
            return new String(readAllBytes(inputStream), StandardCharsets.UTF_8);
        }
    }

    /** Read the response body as raw bytes. */
    public static byte[] readResponseBytes(HttpURLConnection conn) throws IOException {
        try (InputStream inputStream = conn.getInputStream()) {
            return readAllBytes(inputStream);
        }
    }

    /**
     * Read response body regardless of status code: uses getInputStream() for 2xx,
     * getErrorStream() otherwise.
     */
    public static String readResponseSafe(HttpURLConnection conn) throws IOException {
        int code = conn.getResponseCode();
        if (code >= 200 && code < 300) {
            return readResponse(conn);
        }
        return readErrorResponse(conn);
    }
}
