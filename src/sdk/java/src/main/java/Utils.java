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

    public static void disableSSLVerification() throws Exception {
        LOGGER.log(Level.WARNING, "SSL verification is disabled. This is insecure and should only be used in development environments.");
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            @Override
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            @Override
            public void checkClientTrusted(X509Certificate[] certs, String authType) {}

            @Override
            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }};

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HostnameVerifier allHostsValid = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    public static void enableSSLCertificates(String caCertFilePath, String clientCertFilePath, String clientCertKeyFilePath)
            throws Exception {
        // Reuse createSSLContext to avoid duplicating certificate/provider initialization logic
        SSLContext sc = createSSLContext(caCertFilePath, clientCertFilePath, clientCertKeyFilePath, false);
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    public static SSLContext createSSLContext(String caCertFilePath, String clientCertFilePath,
            String clientCertKeyFilePath, boolean disableVerification)
            throws Exception {
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
        KeyManager[] keyManagers = createKeyManagers(keyStore, clientCertFilePath, clientCertKeyFilePath);

        // Initialize SSLContext with the KeyManagers (if any) and TrustManagers
        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(keyManagers, trustManagers, null);
        return sc;
    }

    private static TrustManager[] createTrustManagers(KeyStore keyStore, String caCertFilePath)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        // Load the CA certificate (trusted root certificate), if provided
        boolean customCAProvided = isFileExists(caCertFilePath);
        if (customCAProvided) {
            X509Certificate caCert = loadCertificate(caCertFilePath);
            keyStore.setCertificateEntry("caCert", caCert);
        } else if (caCertFilePath != null) {
            LOGGER.log(Level.INFO, "CA certificate not provided. Using system default CA trust store.");
        }

        // Create a TrustManagerFactory to use system's default CA if no custom CA provided
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        TrustManager[] trustManagers;
        if (customCAProvided) {
            tmf.init(keyStore);
            trustManagers = tmf.getTrustManagers();
        } else {
            // Initialize with system's default trusted CA certificates
            tmf.init((KeyStore) null);
            trustManagers = tmf.getTrustManagers();
        }
        return trustManagers;
    }

    private static KeyManager[] createKeyManagers(KeyStore keyStore, String clientCertFilePath, String clientCertKeyFilePath)
            throws Exception {
        Certificate clientCert = null;
        PrivateKey clientCertKey = null;

        // Attempt to load client certificate and key if the paths are provided and exist
        if (isFileExists(clientCertFilePath) && isFileExists(clientCertKeyFilePath)) {
            // Load client certificate
            clientCert = loadCertificate(clientCertFilePath);

            // Load client private key
            clientCertKey = loadPrivateKey(clientCertKeyFilePath);

            // Add client certificate and private key to KeyStore
            keyStore.setKeyEntry("clientCert", clientCertKey, new char[0], new Certificate[] {clientCert});
        } else if (clientCertFilePath != null) {
            LOGGER.log(Level.INFO, "Client certificate or key file does not exist. Proceeding without client certificate.");
        }

        // Optionally create a KeyManager if client cert and key were loaded
        KeyManager[] keyManagers = null;
        if (clientCert != null && clientCertKey != null) {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
            kmf.init(keyStore, new char[0]);
            keyManagers = kmf.getKeyManagers();
        }

        return keyManagers;
    }

    private static X509Certificate loadCertificate(String certPath) throws IOException, CertificateException {
        LOGGER.log(Level.CONFIG, "Loading certificate from: {}", certPath);
        try (FileInputStream fis = new FileInputStream(certPath)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(fis);
        }
    }

    private static PrivateKey loadPrivateKey(String keyFilePath) throws Exception {
        LOGGER.log(Level.CONFIG, "Loading private key  from: {}", keyFilePath);
        try (PEMParser pemParser = new PEMParser(new FileReader(keyFilePath))) {
            Object object = pemParser.readObject();
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

            if (object instanceof PEMEncryptedKeyPair) {
                // Handle encrypted key (you need the password to decrypt)
                PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build("your_password".toCharArray());
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

    public static URL toUrl(String url) throws IOException {
        try {
            URI uri = new URI(url);
            return uri.toURL();
        } catch (URISyntaxException e) {
            throw new IOException("Invalid URL syntax", e);
        }
    }

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

    // Helper to convert PosixFilePermissions to numeric mode
    private static int posixPermissionsToMode(Set<PosixFilePermission> perms) {
        int mode = 0;
        if (perms.contains(PosixFilePermission.OWNER_READ))
            mode |= 0400;
        if (perms.contains(PosixFilePermission.OWNER_WRITE))
            mode |= 0200;
        if (perms.contains(PosixFilePermission.OWNER_EXECUTE))
            mode |= 0100;
        if (perms.contains(PosixFilePermission.GROUP_READ))
            mode |= 0040;
        if (perms.contains(PosixFilePermission.GROUP_WRITE))
            mode |= 0020;
        if (perms.contains(PosixFilePermission.GROUP_EXECUTE))
            mode |= 0010;
        if (perms.contains(PosixFilePermission.OTHERS_READ))
            mode |= 0004;
        if (perms.contains(PosixFilePermission.OTHERS_WRITE))
            mode |= 0002;
        if (perms.contains(PosixFilePermission.OTHERS_EXECUTE))
            mode |= 0001;
        return mode;
    }

    public static Map<String, String> getFileAttributes(File file) {
        Map<String, String> attributes = new HashMap<>();

        Path path = file.toPath();

        // Check if we're on a POSIX system
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            LOGGER.log(Level.FINE, "POSIX file attributes not supported on this system");
            return attributes;
        }

        try {
            PosixFileAttributeView posixView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
            if (posixView != null) {
                PosixFileAttributes attrs = posixView.readAttributes();

                // File mode
                Set<PosixFilePermission> perms = attrs.permissions();
                int mode = posixPermissionsToMode(perms);
                attributes.put("X-File-Mode", String.valueOf(mode));

                // Owner and group by NAME (more portable across systems)
                UserPrincipal owner = attrs.owner();
                GroupPrincipal group = attrs.group();

                if (owner != null) {
                    attributes.put("X-File-User", owner.getName());
                }
                if (group != null) {
                    attributes.put("X-File-Group", group.getName());
                }
            }
        } catch (IOException e) {
            LOGGER.log(Level.WARNING, "Error reading file attributes for: " + file.getPath(), e);
        }
        return attributes;
    }

    public static void applyFileAttributes(String localFile, java.net.HttpURLConnection conn) {
        Path path = Paths.get(localFile);

        if (!Files.exists(path)) {
            LOGGER.log(Level.WARNING, "File does not exist: " + localFile);
            return;
        }

        // Check if we're on a POSIX system
        if (!FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
            LOGGER.log(Level.FINE, "POSIX file attributes not supported on this system");
            return;
        }

        // ----- Owner / Group by NAME - Apply FIRST (chown clears setuid/setgid) -----
        String userStr = conn.getHeaderField("X-File-User");
        String groupStr = conn.getHeaderField("X-File-Group");

        if (userStr != null && !userStr.isEmpty() && groupStr != null && !groupStr.isEmpty()) {
            try {
                UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();

                UserPrincipal owner = null;
                GroupPrincipal group = null;

                try {
                    owner = lookupService.lookupPrincipalByName(userStr.trim());
                } catch (UserPrincipalNotFoundException e) {
                    LOGGER.log(Level.FINE, "User not found by name, ownership not changed: " + userStr);
                }

                try {
                    group = lookupService.lookupPrincipalByGroupName(groupStr.trim());
                } catch (UserPrincipalNotFoundException e) {
                    LOGGER.log(Level.FINE, "Group not found by name, group not changed: " + groupStr);
                }

                PosixFileAttributeView posixView = Files.getFileAttributeView(path, PosixFileAttributeView.class);
                if (posixView != null) {
                    if (owner != null) {
                        posixView.setOwner(owner);
                    }
                    if (group != null) {
                        posixView.setGroup(group);
                    }
                }
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to apply file ownership: " + userStr + "/" + groupStr, e);
            }
        }

        // ----- File mode - Apply AFTER chown to preserve all permission bits -----
        String fileModeStr = conn.getHeaderField("X-File-Mode");
        if (fileModeStr != null && !fileModeStr.isEmpty()) {
            try {
                int mode = Integer.parseInt(fileModeStr.trim());
                // Validate mode range (0-511 in decimal, which is 0-0777 in octal)
                if (mode < 0 || mode > 511) {
                    LOGGER.log(Level.WARNING, "File mode out of valid range (0-511): " + mode);
                } else {
                    Set<PosixFilePermission> perms = PosixFilePermissions.fromString(toPermissionString(mode));
                    Files.setPosixFilePermissions(path, perms);
                }
            } catch (NumberFormatException e) {
                LOGGER.log(Level.WARNING, "Invalid file mode format: " + fileModeStr, e);
            } catch (IOException e) {
                LOGGER.log(Level.WARNING, "Failed to apply file mode: " + fileModeStr, e);
            }
        }
    }

    public static String generateBoundary() {
        return "----WebKitFormBoundary" + Long.toHexString(System.currentTimeMillis());
    }

    public static void writeMultipartFormData(OutputStream output, String boundary, File file) throws IOException {
        String LINE_FEED = "\r\n";
        String fileName = file.getName();

        // Write the first boundary
        output.write(("--" + boundary + LINE_FEED).getBytes());
        output.write(("Content-Disposition: form-data; name=\"file\"; filename=\"" + fileName + "\"" + LINE_FEED).getBytes());
        output.write(("Content-Type: application/octet-stream" + LINE_FEED + LINE_FEED).getBytes());

        // Write the file content
        try (FileInputStream inputStream = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }

        output.write((LINE_FEED).getBytes());

        // Write the final boundary
        output.write(("--" + boundary + "--" + LINE_FEED).getBytes());
    }

    public static String readErrorResponse(HttpURLConnection conn) throws IOException {
        InputStream errorStream = conn.getErrorStream();
        if (errorStream == null) {
            return "";
        }

        try (InputStream inputStream = conn.getErrorStream(); ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            return outputStream.toString(StandardCharsets.UTF_8.name());
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

    public static String readResponse(HttpURLConnection conn) throws IOException {
        try (InputStream inputStream = conn.getInputStream()) {
            byte[] bytes = readAllBytes(inputStream);
            return new String(bytes, StandardCharsets.UTF_8);
        }
    }

    public static byte[] readResponseBytes(HttpURLConnection conn) throws IOException {
        try (InputStream inputStream = conn.getInputStream()) {
            return readAllBytes(inputStream);
        }
    }
}
