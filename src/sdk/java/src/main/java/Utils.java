import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.threeten.extra.PeriodDuration;

public class Utils {
    private static final Logger LOGGER = Logger.getLogger(Utils.class.getName());

    public static void disableSSLVerification() throws Exception {
        TrustManager[] trustAllCerts = new TrustManager[] {new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {}

            public void checkServerTrusted(X509Certificate[] certs, String authType) {}
        }};

        SSLContext sc = SSLContext.getInstance("TLS");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

        HostnameVerifier allHostsValid = (hostname, session) -> true;
        HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
    }

    public static void useCustomCertificate(String certFilePath) throws Exception {
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

    public static int getFilePermissions(File file) throws IOException {
        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(file.toPath());
        int mode = 0;
        for (PosixFilePermission permission : permissions) {
            switch (permission) {
                case OWNER_READ:
                    mode |= 0400;
                    break;
                case OWNER_WRITE:
                    mode |= 0200;
                    break;
                case OWNER_EXECUTE:
                    mode |= 0100;
                    break;
                case GROUP_READ:
                    mode |= 040;
                    break;
                case GROUP_WRITE:
                    mode |= 020;
                    break;
                case GROUP_EXECUTE:
                    mode |= 010;
                    break;
                case OTHERS_READ:
                    mode |= 04;
                    break;
                case OTHERS_WRITE:
                    mode |= 02;
                    break;
                case OTHERS_EXECUTE:
                    mode |= 01;
                    break;
            }
        }
        return mode;
    }

    public static String toPermissionString(int mode) {
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

    public static Map<String, String> getFileAttributes(File file) {
        Map<String, String> attributes = new HashMap<>();
        try {
            PosixFileAttributeView posixView = Files.getFileAttributeView(file.toPath(), PosixFileAttributeView.class);
            PosixFileAttributes attrs = posixView.readAttributes();
            attributes.put("File-User", attrs.owner().getName());
            attributes.put("File-Group", attrs.group().getName());
        } catch (UnsupportedOperationException e) {
            LOGGER.log(Level.WARNING, "POSIX file attributes not supported", e);
        } catch (IOException e) {
            LOGGER.log(Level.SEVERE, "Error reading file attributes", e);
        }
        return attributes;
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

    public static String readResponse(HttpURLConnection conn) throws IOException {
        try (InputStream inputStream = conn.getInputStream(); ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            return outputStream.toString(StandardCharsets.UTF_8.name());
        }
    }
}
