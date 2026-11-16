package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Known-answer and attachment coverage for the opt-in HMAC request signature.
 *
 * The canonical string must mirror src/daemon/security/RequestSignature.{h,cpp}
 * byte-for-byte: the fixed vectors below were produced independently with
 * `openssl dgst -sha256 -hmac`, so a drift in the canonical form (separator,
 * order, body hash, hex case) fails the test instead of failing on the daemon.
 */
public class RequestSignatureTest {
    private static final String EMPTY_SHA256 =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    private static final String KEY_ID = "ak-3f9c2a81b0d4";
    private static final String SECRET = "s3cret-key";

    // openssl dgst -sha256 -hmac "s3cret-key" over
    // "GET\n/appmesh/app/demo\nb=2&a=1\n<empty-sha>\n1700000000\nn-12345"
    private static final String VECTOR_GET_QUERY =
            "53f587f8c38267cbd15f7b5c846f21a1e00e8baedb8b901b3d1f0b802cc06cfe";
    // Same over "POST\n/appmesh/file/upload\n\n<empty-sha>\n1700000001\nabc"
    private static final String VECTOR_POST_FILE =
            "fa047e47d2b039c652e7029a41530cc8e3a0e81fe2fc71a7fcd145ea96f6ef80";

    private HttpServer server;

    @AfterEach
    public void tearDown() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    public void sha256HexKnownAnswers() {
        assertEquals(EMPTY_SHA256, RequestSigner.sha256Hex(null), "no body hashes the empty string");
        assertEquals(EMPTY_SHA256, RequestSigner.sha256Hex(new byte[0]));
        // sha256("abc"), FIPS 180-2 vector
        assertEquals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                RequestSigner.sha256Hex("abc".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    public void canonicalStringMatchesDaemonForm() {
        String canonical = RequestSigner.canonicalString("GET", "/appmesh/app/demo", "b=2&a=1",
                EMPTY_SHA256, "1700000000", "n-12345");
        assertEquals("GET\n/appmesh/app/demo\nb=2&a=1\n" + EMPTY_SHA256 + "\n1700000000\nn-12345", canonical);
        // The bytes must equal the openssl vector input exactly.
        assertEquals(VECTOR_GET_QUERY, new RequestSigner(KEY_ID, SECRET).sign(canonical));
    }

    @Test
    public void signKnownAnswerVectors() {
        RequestSigner signer = new RequestSigner(KEY_ID, SECRET);
        assertEquals(VECTOR_GET_QUERY,
                signer.sign(RequestSigner.canonicalString("GET", "/appmesh/app/demo", "b=2&a=1",
                        EMPTY_SHA256, "1700000000", "n-12345")));
        assertEquals(VECTOR_POST_FILE,
                signer.sign(RequestSigner.canonicalString("POST", "/appmesh/file/upload", "",
                        EMPTY_SHA256, "1700000001", "abc")));
    }

    @Test
    public void canonicalQuerySortsDecodedPairs() {
        Map<String, String> query = new LinkedHashMap<>();
        query.put("b", "2");
        query.put("a", "1");
        query.put("c", "3");
        assertEquals("a=1&b=2&c=3", RequestSigner.canonicalQuery(query));
        // Sorted by key, then value; empty query is the empty string.
        Map<String, String> sameKeyBase = new LinkedHashMap<>();
        sameKeyBase.put("k", "y");
        sameKeyBase.put("j", "z");
        assertEquals("j=z&k=y", RequestSigner.canonicalQuery(sameKeyBase));
        assertEquals("", RequestSigner.canonicalQuery(null));
        assertEquals("", RequestSigner.canonicalQuery(new HashMap<>()));
        // Decoded (non-ASCII) values are joined as-is, never re-encoded.
        Map<String, String> unicode = new HashMap<>();
        unicode.put("k", "\u00e9");
        assertEquals("k=\u00e9", RequestSigner.canonicalQuery(unicode));
    }

    @Test
    public void canonicalQueryFromEncodedMirrorsDaemonParser() {
        // %20 decodes to a space, '+' stays literal, %2F decodes to '/'; a duplicate key
        // keeps only its first occurrence (daemon std::map::emplace), so "a=+" is dropped.
        assertEquals("a= &b=2&x=/",
                RequestSigner.canonicalQueryFromEncoded("b=2&a=%20&a=+&x=%2F"));
        // A malformed escape keeps the whole raw component (daemon behavior).
        assertEquals("k=%zz", RequestSigner.canonicalQueryFromEncoded("k=%zz"));
        // A duplicate key keeps its first occurrence (std::map::emplace semantics).
        assertEquals("a=1", RequestSigner.canonicalQueryFromEncoded("a=1&a=2"));
        // A pair without '=' contributes an empty value.
        assertEquals("a=1&flag=", RequestSigner.canonicalQueryFromEncoded("flag&a=1"));
        assertEquals("", RequestSigner.canonicalQueryFromEncoded(null));
        // Non-ASCII round-trips through UTF-8 percent escapes.
        assertEquals("k=\u00e9", RequestSigner.canonicalQueryFromEncoded("k=%C3%A9"));
    }

    @Test
    public void attachProducesVerifiableHeaders() {
        RequestSigner signer = new RequestSigner(KEY_ID, SECRET);
        Map<String, String> headers = new HashMap<>();
        byte[] body = "{\"command\":\"true\"}".getBytes(StandardCharsets.UTF_8);
        signer.attach(headers, "POST", "/appmesh/app/demo", "a=1", body, "1700000000", "n-12345");
        assertEquals(KEY_ID, headers.get(RequestSigner.KEY_ID_HEADER));
        assertEquals("1700000000", headers.get(RequestSigner.TIMESTAMP_HEADER));
        assertEquals("n-12345", headers.get(RequestSigner.NONCE_HEADER));
        // Re-derive the signature from the headers: the daemon-side verification step.
        String canonical = RequestSigner.canonicalString("POST", "/appmesh/app/demo", "a=1",
                RequestSigner.sha256Hex(body), "1700000000", "n-12345");
        assertEquals(signer.sign(canonical), headers.get(RequestSigner.SIGNATURE_HEADER));
    }

    @Test
    public void fileEndpointsSignEmptyBodyHashEvenWithBody() {
        RequestSigner signer = new RequestSigner(KEY_ID, SECRET);
        // {request path, canonical signing path}: the WSS data-channel "/ws" routes sign
        // the stripped route (daemon canonicalFileRoute).
        String[][] cases = {
            {"/appmesh/file/upload", "/appmesh/file/upload"},
            {"/appmesh/file/download", "/appmesh/file/download"},
            {"/appmesh/file/delete", "/appmesh/file/delete"},
            {"/appmesh/file/upload/ws", "/appmesh/file/upload"},
            {"/appmesh/file/download/ws", "/appmesh/file/download"},
        };
        for (String[] tc : cases) {
            Map<String, String> headers = new HashMap<>();
            signer.attach(headers, "POST", tc[0], "",
                    "streamed file bytes".getBytes(StandardCharsets.UTF_8), "1700000000", "n-1");
            String canonical = RequestSigner.canonicalString("POST", tc[1], "",
                    EMPTY_SHA256, "1700000000", "n-1");
            assertEquals(signer.sign(canonical), headers.get(RequestSigner.SIGNATURE_HEADER),
                    "streamed body must not be bound for " + tc[0]);
        }
        // A non-file path binds the body.
        Map<String, String> headers = new HashMap<>();
        byte[] body = "x".getBytes(StandardCharsets.UTF_8);
        signer.attach(headers, "POST", "/appmesh/app", "", body, "1700000000", "n-1");
        assertFalse(headers.get(RequestSigner.SIGNATURE_HEADER)
                .equals(signer.sign(RequestSigner.canonicalString("POST", "/appmesh/app", "",
                        EMPTY_SHA256, "1700000000", "n-1"))));
    }

    @Test
    public void wsDataChannelRouteSignsStrippedPathWithEmptyHash() {
        // The trailing "/ws" selects the WSS transfer channel, not the signed resource:
        // the canonical signing path drops it (daemon canonicalFileRoute,
        // docs/source/Security.md "Request replay protection and signatures").
        assertEquals("/appmesh/file/download", RequestSigner.canonicalSigningPath("/appmesh/file/download/ws"));
        assertEquals("/appmesh/file/upload", RequestSigner.canonicalSigningPath("/appmesh/file/upload/ws"));
        assertEquals("/appmesh/file/delete", RequestSigner.canonicalSigningPath("/appmesh/file/delete"));
        assertEquals("/appmesh/applications", RequestSigner.canonicalSigningPath("/appmesh/applications"));

        RequestSigner signer = new RequestSigner(KEY_ID, SECRET);
        Map<String, String> headers = new HashMap<>();
        signer.attach(headers, "GET", "/appmesh/file/download/ws", "",
                "file bytes are not bound".getBytes(StandardCharsets.UTF_8), "1700000000", "n-1");
        // Signs exactly the stripped route with the empty-body hash.
        String canonical = RequestSigner.canonicalString("GET", "/appmesh/file/download", "",
                EMPTY_SHA256, "1700000000", "n-1");
        assertEquals(signer.sign(canonical), headers.get(RequestSigner.SIGNATURE_HEADER),
                "the /ws route must sign the stripped path with the empty-body hash");
    }

    @Test
    public void secretIsNeverExposed() {
        RequestSigner signer = new RequestSigner(KEY_ID, SECRET);
        assertFalse(signer.toString().contains(SECRET), "toString must redact the secret");
        assertEquals("RequestSigner[keyId=" + KEY_ID + "]", signer.toString());
    }

    /**
     * End-to-end over the HTTP transport: the four headers must be on the wire and the
     * signature must verify against what the server actually received (method, raw path,
     * decoded query, body bytes) — the exact inputs the daemon verifies with.
     */
    @Test
    public void httpTransportAttachesVerifiableSignature() throws Exception {
        AtomicReference<String> observedSignature = new AtomicReference<>();
        AtomicReference<String> observedKey = new AtomicReference<>();
        AtomicReference<String> observedTimestamp = new AtomicReference<>();
        AtomicReference<String> observedNonce = new AtomicReference<>();
        AtomicReference<String> observedMethod = new AtomicReference<>();
        AtomicReference<String> observedPath = new AtomicReference<>();
        AtomicReference<String> observedQuery = new AtomicReference<>();
        AtomicReference<byte[]> observedBody = new AtomicReference<>();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", (HttpExchange exchange) -> {
            observedSignature.set(exchange.getRequestHeaders().getFirst("X-Signature"));
            observedKey.set(exchange.getRequestHeaders().getFirst("X-Request-Key"));
            observedTimestamp.set(exchange.getRequestHeaders().getFirst("X-Timestamp"));
            observedNonce.set(exchange.getRequestHeaders().getFirst("X-Nonce"));
            observedMethod.set(exchange.getRequestMethod());
            observedPath.set(exchange.getRequestURI().getRawPath());
            observedQuery.set(exchange.getRequestURI().getRawQuery());
            InputStream in = exchange.getRequestBody();
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[512];
            int read;
            while ((read = in.read(chunk)) >= 0) {
                buffer.write(chunk, 0, read);
            }
            observedBody.set(buffer.toByteArray());
            byte[] reply = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type", "text/plain");
            exchange.sendResponseHeaders(200, reply.length);
            exchange.getResponseBody().write(reply);
            exchange.close();
        });
        server.start();

        AppMeshClient client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .requestSignature(KEY_ID, SECRET)
                .build();
        try {
            Map<String, String> params = new HashMap<>();
            params.put("b", "2");
            params.put("a", "1");
            // Reading the response code forces the exchange to complete, so the
            // captures above are from a fully delivered request.
            HttpURLConnection first = client.request("POST", "/appmesh/app/demo", "hello body", null, params);
            assertEquals(200, first.getResponseCode());
            first.disconnect();

            assertNotNull(observedKey.get(), "X-Request-Key header missing");
            assertEquals(KEY_ID, observedKey.get());
            assertTrue(observedTimestamp.get().matches("\\d+"), "X-Timestamp must be unix seconds");
            assertFalse(observedNonce.get().isEmpty(), "X-Nonce must be present");
            assertEquals("POST", observedMethod.get());
            assertEquals("/appmesh/app/demo", observedPath.get());

            // Daemon-side verification with the same secret.
            RequestSigner verifier = new RequestSigner(KEY_ID, SECRET);
            String canonical = RequestSigner.canonicalString(observedMethod.get(), observedPath.get(),
                    RequestSigner.canonicalQueryFromEncoded(observedQuery.get()),
                    RequestSigner.sha256Hex(observedBody.get()),
                    observedTimestamp.get(), observedNonce.get());
            assertEquals(verifier.sign(canonical), observedSignature.get(),
                    "signature must verify against the received request");

            // Clearing the signer removes the headers entirely (opt-in, opt-out).
            client.clearRequestSignature();
            assertFalse(client.isRequestSignatureEnabled());
            HttpURLConnection second = client.request("GET", "/appmesh/app/demo", null, null, null);
            assertEquals(200, second.getResponseCode());
            second.disconnect();
            assertNull(observedSignature.get(), "signature must be opt-in");
            assertNull(observedKey.get(), "key id must disappear with the signer");
        } finally {
            client.close();
        }
    }

    /** The framed (TCP/WSS) seam: header map + decoded query + exact frame body. */
    @Test
    public void framedTransportSignsRequestMessageInputs() throws Exception {
        // Constructors do not connect; only the signing seam is exercised.
        AppMeshClientTCP tcpClient = new AppMeshClientTCP("127.0.0.1", 6059);
        tcpClient.setRequestSignature(KEY_ID, SECRET);
        assertTrue(tcpClient.isRequestSignatureEnabled());

        RequestMessage req = new RequestMessage();
        req.httpMethod = "PUT";
        req.requestUri = "/appmesh/app/demo";
        req.body = "{\"command\":\"true\"}".getBytes(StandardCharsets.UTF_8);
        req.query.put("b", "2");
        req.query.put("a", "1");
        tcpClient.applyRequestSignature(req.headers, req.httpMethod, req.requestUri, req.query, req.body);

        assertEquals(KEY_ID, req.headers.get(RequestSigner.KEY_ID_HEADER));
        String timestamp = req.headers.get(RequestSigner.TIMESTAMP_HEADER);
        String nonce = req.headers.get(RequestSigner.NONCE_HEADER);
        assertTrue(timestamp.matches("\\d+"));
        assertFalse(nonce.isEmpty());
        // Verify with the framed inputs exactly as the daemon sees the message.
        RequestSigner verifier = new RequestSigner(KEY_ID, SECRET);
        String canonical = RequestSigner.canonicalString("PUT", "/appmesh/app/demo", "a=1&b=2",
                RequestSigner.sha256Hex(req.body), timestamp, nonce);
        assertEquals(verifier.sign(canonical), req.headers.get(RequestSigner.SIGNATURE_HEADER));

        // A TCP file-transfer control request carries no body: it signs the empty hash.
        RequestMessage fileReq = new RequestMessage();
        fileReq.httpMethod = "GET";
        fileReq.requestUri = "/appmesh/file/download";
        tcpClient.applyRequestSignature(fileReq.headers, fileReq.httpMethod, fileReq.requestUri,
                fileReq.query, fileReq.body);
        String fileCanonical = RequestSigner.canonicalString("GET", "/appmesh/file/download", "",
                EMPTY_SHA256, fileReq.headers.get(RequestSigner.TIMESTAMP_HEADER),
                fileReq.headers.get(RequestSigner.NONCE_HEADER));
        assertEquals(verifier.sign(fileCanonical), fileReq.headers.get(RequestSigner.SIGNATURE_HEADER));

        // WSS uses the same seam; the gateway's bearer handling must not strip the headers.
        AppMeshClientWSS wssClient = new AppMeshClientWSS("127.0.0.1", 6058);
        wssClient.setRequestSignature(KEY_ID, SECRET);
        Map<String, String> wssHeaders = new HashMap<>();
        wssHeaders.put("Authorization", "Bearer t");
        wssHeaders = AppMeshClientWSS.assembleRequestHeaders(wssHeaders, null, "Bearer t");
        wssClient.applyRequestSignature(wssHeaders, "GET", "/appmesh/applications",
                new HashMap<>(), new byte[0]);
        String wssCanonical = RequestSigner.canonicalString("GET", "/appmesh/applications", "",
                RequestSigner.sha256Hex(new byte[0]), wssHeaders.get(RequestSigner.TIMESTAMP_HEADER),
                wssHeaders.get(RequestSigner.NONCE_HEADER));
        assertEquals(verifier.sign(wssCanonical), wssHeaders.get(RequestSigner.SIGNATURE_HEADER));
        assertNotNull(wssHeaders.get(RequestSigner.KEY_ID_HEADER));

        tcpClient.close();
        wssClient.close();
    }
}
