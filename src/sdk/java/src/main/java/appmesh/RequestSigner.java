package appmesh;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.time.Instant;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Opt-in HMAC-SHA256 request signer (anti-tamper layer on top of the bearer).
 *
 * <p>Mirrors the daemon verifier in {@code src/daemon/security/RequestSignature.{h,cpp}}
 * byte-for-byte. The canonical string is:
 *
 * <pre>METHOD + "\n" + path + "\n" + sortedQuery + "\n" + sha256hex(body) + "\n" + timestamp + "\n" + nonce</pre>
 *
 * <ul>
 *   <li>path: the request path without the query, exactly as sent (not percent-decoded).
 *       The WSS data-channel file routes sign the route WITHOUT the trailing
 *       {@code /ws} — the suffix selects the transfer channel, not the signed resource
 *       (daemon {@code canonicalFileRoute});</li>
 *   <li>sortedQuery: decoded {@code key=value} pairs joined with {@code &}, sorted by key then
 *       value, empty string when there is no query ({@code %XX}-decoding only — {@code +} stays
 *       literal, matching the daemon);</li>
 *   <li>body hash: lowercase hex SHA-256 of the raw body bytes; no body hashes the empty string;</li>
 *   <li>streamed file endpoints ({@code /appmesh/file/download|upload|delete}) sign the
 *       empty-string body hash (documented exemption: the file content is not bound).</li>
 * </ul>
 *
 * <p>The secret is never logged and never exposed through a getter or {@link #toString()}.
 */
public final class RequestSigner {
    /** API key id header ({@code X-Request-Key}). */
    public static final String KEY_ID_HEADER = "X-Request-Key";
    /** Unix-seconds timestamp header ({@code X-Timestamp}). */
    public static final String TIMESTAMP_HEADER = "X-Timestamp";
    /** Per-request unique nonce header ({@code X-Nonce}). */
    public static final String NONCE_HEADER = "X-Nonce";
    /** Lowercase hex HMAC-SHA256 header ({@code X-Signature}). */
    public static final String SIGNATURE_HEADER = "X-Signature";

    /** Streamed file routes: the signature binds method/path/query/timestamp/nonce, not the bytes.
     * The exact daemon set — subpaths are not exempt. */
    private static final Set<String> EMPTY_BODY_EXEMPT_PATHS = Set.of(
        "/appmesh/file/download", "/appmesh/file/upload", "/appmesh/file/delete"
    );

    private static final byte[] EMPTY_BODY = new byte[0];

    private final String keyId;
    private final byte[] secret;

    /**
     * Create a signer for one API key.
     *
     * @param keyId  the API key id sent as {@code X-Request-Key}
     * @param secret the API key secret (kept private, never logged)
     */
    public RequestSigner(String keyId, String secret) {
        if (keyId == null || keyId.trim().isEmpty()) {
            throw new IllegalArgumentException("keyId must not be empty");
        }
        if (secret == null || secret.isEmpty()) {
            throw new IllegalArgumentException("secret must not be empty");
        }
        this.keyId = keyId;
        this.secret = secret.getBytes(StandardCharsets.UTF_8);
    }

    /** The API key id this signer advertises. */
    public String getKeyId() {
        return keyId;
    }

    /**
     * Attach the four signature headers ({@code X-Request-Key}, {@code X-Timestamp},
     * {@code X-Nonce}, {@code X-Signature}) to a request header map, generating a fresh
     * unix-seconds timestamp and random nonce.
     *
     * @param headers        request header map (mutated)
     * @param method         HTTP method exactly as sent on the wire
     * @param path           request path without query, exactly as sent; the WSS
     *                       data-channel file routes ({@code /appmesh/file/{upload,download}/ws})
     *                       are signed under the route without the trailing {@code /ws}
     *                       ({@link #canonicalSigningPath(String)})
     * @param canonicalQuery already-canonicalized query (empty string when none)
     * @param body           raw body bytes; null means no body; ignored for streamed
     *                       file endpoints which always sign the empty-string hash
     */
    public void attach(Map<String, String> headers, String method, String path, String canonicalQuery,
            byte[] body) {
        attach(headers, method, path, canonicalQuery, body,
                String.valueOf(Instant.now().getEpochSecond()), UUID.randomUUID().toString());
    }

    /**
     * Deterministic variant of {@link #attach(Map, String, String, String, byte[])} with the
     * timestamp and nonce supplied by the caller (unit tests and known-answer vectors).
     */
    public void attach(Map<String, String> headers, String method, String path, String canonicalQuery,
            byte[] body, String timestamp, String nonce) {
        String signPath = canonicalSigningPath(path);
        byte[] bytesToHash = isEmptyBodyExemptPath(signPath) ? EMPTY_BODY : (body == null ? EMPTY_BODY : body);
        String canonical = canonicalString(method, signPath, canonicalQuery, sha256Hex(bytesToHash), timestamp, nonce);
        headers.put(KEY_ID_HEADER, keyId);
        headers.put(TIMESTAMP_HEADER, timestamp);
        headers.put(NONCE_HEADER, nonce);
        headers.put(SIGNATURE_HEADER, sign(canonical));
    }

    /** True for the streamed file endpoints that sign the empty-string body hash. */
    public static boolean isEmptyBodyExemptPath(String path) {
        if (path == null) {
            return false;
        }
        return EMPTY_BODY_EXEMPT_PATHS.contains(canonicalSigningPath(path));
    }

    /**
     * The canonical path the daemon signs: the trailing {@code /ws} of the WSS HTTPS
     * data-channel file routes selects the transfer channel, not the signed resource,
     * so it is dropped (daemon {@code RequestHardening::canonicalFileRoute};
     * docs/source/Security.md, "Request replay protection and signatures"). Every
     * other path passes through unchanged.
     */
    public static String canonicalSigningPath(String path) {
        if ("/appmesh/file/download/ws".equals(path)) {
            return "/appmesh/file/download";
        }
        if ("/appmesh/file/upload/ws".equals(path)) {
            return "/appmesh/file/upload";
        }
        return path;
    }

    /**
     * Sorted {@code k=v&k2=v2} form used in the canonical string. Inputs are the decoded
     * parameter pairs (TCP/WSS query map). Pairs are sorted by key, then by value.
     */
    public static String canonicalQuery(Map<String, String> query) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        List<Map.Entry<String, String>> pairs = new ArrayList<>(query.entrySet());
        // Order by UTF-8 bytes, matching the daemon (not UTF-16 code units).
        pairs.sort((a, b) -> {
            int byKey = Arrays.compare(a.getKey().getBytes(StandardCharsets.UTF_8),
                    b.getKey().getBytes(StandardCharsets.UTF_8));
            return byKey != 0 ? byKey
                    : Arrays.compare(a.getValue().getBytes(StandardCharsets.UTF_8),
                            b.getValue().getBytes(StandardCharsets.UTF_8));
        });
        StringBuilder canonical = new StringBuilder();
        for (Map.Entry<String, String> entry : pairs) {
            if (canonical.length() > 0) {
                canonical.append('&');
            }
            canonical.append(entry.getKey()).append('=').append(entry.getValue());
        }
        return canonical.toString();
    }

    /**
     * Canonical query built from the encoded query string exactly as it goes on the wire
     * (HTTP transport). Mirrors the daemon parser loop: split on {@code &}, split each pair
     * at the first {@code =}, decode each component with {@code %XX}-only decoding
     * ({@code +} stays literal, a malformed escape keeps the whole raw component), dedup
     * decoded-key-first-wins (daemon {@code std::map::emplace}), then sort. An empty
     * segment ({@code a=1&&b=2}) inserts {@code ("", "")} and the canonical output keeps
     * its {@code =}; a trailing {@code &} adds no segment (the daemon loop ends at its
     * bounds).
     */
    public static String canonicalQueryFromEncoded(String encodedQuery) {
        if (encodedQuery == null || encodedQuery.isEmpty()) {
            return "";
        }
        Map<String, String> decoded = new HashMap<>();
        int pos = 0;
        while (pos < encodedQuery.length()) {
            int amp = encodedQuery.indexOf('&', pos);
            String pair = amp < 0 ? encodedQuery.substring(pos) : encodedQuery.substring(pos, amp);
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            String value = eq < 0 ? "" : pair.substring(eq + 1);
            decoded.putIfAbsent(percentDecode(key), percentDecode(value));
            if (amp < 0) {
                break;
            }
            pos = amp + 1;
        }
        return canonicalQuery(decoded);
    }

    /** {@code %XX}-only decode; a malformed escape keeps the whole raw value (daemon behavior). */
    private static String percentDecode(String value) {
        if (value.indexOf('%') < 0) {
            return value;
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c == '%') {
                if (i + 2 >= value.length() || !isHexDigit(value.charAt(i + 1)) || !isHexDigit(value.charAt(i + 2))) {
                    // Malformed escape: the daemon keeps the raw value verbatim.
                    return value;
                }
                bytes.write((Character.digit(value.charAt(i + 1), 16) << 4) | Character.digit(value.charAt(i + 2), 16));
                i += 2;
            } else {
                byte[] charBytes = String.valueOf(c).getBytes(StandardCharsets.UTF_8);
                bytes.write(charBytes, 0, charBytes.length);
            }
        }
        return new String(bytes.toByteArray(), StandardCharsets.UTF_8);
    }

    private static boolean isHexDigit(char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    /**
     * The exact canonical string both sides must build byte-for-byte:
     * {@code METHOD \n path \n sortedQuery \n sha256hex(body) \n timestamp \n nonce}.
     */
    public static String canonicalString(String method, String path, String query, String bodySha256Hex,
            String timestamp, String nonce) {
        Objects.requireNonNull(method, "method");
        Objects.requireNonNull(path, "path");
        return new StringBuilder(method.length() + path.length() + (query == null ? 0 : query.length())
                + bodySha256Hex.length() + timestamp.length() + nonce.length() + 5)
                .append(method).append('\n')
                .append(path).append('\n')
                .append(query == null ? "" : query).append('\n')
                .append(bodySha256Hex).append('\n')
                .append(timestamp).append('\n')
                .append(nonce)
                .toString();
    }

    /** Lowercase hex HMAC-SHA256 of the canonical string under this signer's secret. */
    public String sign(String canonical) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            return toHexLower(mac.doFinal(canonical.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) {
            throw new IllegalStateException("could not sign request", e);
        }
    }

    /** Lowercase hex SHA-256 of the raw body bytes (empty body hashes the empty string). */
    public static String sha256Hex(byte[] body) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return toHexLower(digest.digest(body == null ? EMPTY_BODY : body));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String toHexLower(byte[] bytes) {
        StringBuilder hex = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            hex.append(Character.forDigit((b >> 4) & 0xF, 16)).append(Character.forDigit(b & 0xF, 16));
        }
        return hex.toString().toLowerCase(Locale.ROOT);
    }

    /** Redacted: never exposes the secret. */
    @Override
    public String toString() {
        return "RequestSigner[keyId=" + keyId + "]";
    }
}
