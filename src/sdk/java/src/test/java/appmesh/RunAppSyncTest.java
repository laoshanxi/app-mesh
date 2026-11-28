package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.apache.commons.lang3.tuple.Pair;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Sync-run output paging against a scripted daemon (no real engine): the first page arrives in the
 * sync-run reply, the following ones are read from the output endpoint, the run is deleted after.
 */
public class RunAppSyncTest {
    private static final int PAGE = AppMeshClient.SYNC_RUN_OUTPUT_PAGE_BYTES;
    private static final String RUN = "sync-run-instance";

    private HttpServer server;
    private AppMeshClient client;

    @AfterEach
    public void tearDown() {
        if (client != null) client.close();
        if (server != null) server.stop(0);
    }

    /** One scripted reply of the daemon. */
    private static final class Reply {
        final int status;
        final Map<String, String> headers = new HashMap<>();
        byte[] body = new byte[0];

        Reply(int status) {
            this.status = status;
        }

        Reply header(String name, String value) {
            headers.put(name, value);
            return this;
        }

        Reply body(byte[] body) {
            this.body = body;
            return header("Content-Type", "text/plain; charset=utf-8");
        }

        Reply text(String body, Charset charset) {
            this.body = body.getBytes(charset);
            return header("Content-Type", "text/plain; charset=" + charset.name());
        }
    }

    /** What the daemon is scripted to answer, plus a log of what the client sent. */
    private static final class Daemon {
        final List<String> requests = Collections.synchronizedList(new ArrayList<>());
        /** Output pages following the first one. */
        final List<Reply> pages = new ArrayList<>();
        /** No scripted pages: the output endpoint answers 404. */
        void noPages() {
            this.pages.clear();
        }

        /** Status of the run DELETE (200, or a failure). */
        int deleteStatus = 200;
        String method;
        String path;
        String query;

        Reply syncRun(int exitCode, byte[] firstPage, boolean truncated) {
            Reply reply = new Reply(200).body(firstPage)
                    .header("X-Exit-Code", String.valueOf(exitCode));
            if (truncated) {
                reply.header("X-App-Name", RUN).header("X-Output-Truncated", "1")
                        .header("X-Output-Position", String.valueOf(firstPage.length));
            }
            return reply;
        }

        /** Pages after the first one; each full page also echoes the next position. */
        void pages(byte[]... pages) {
            this.pages.clear();
            long position = 0;
            for (byte[] page : pages) {
                position += page.length;
                this.pages.add(new Reply(200).body(page).header("X-Output-Position", String.valueOf(position)));
            }
        }

        void delete(int status) {
            this.deleteStatus = status;
        }

        /** Route one request; the output endpoint answers the pages in order and an empty page last. */
        Reply route(String method, String path, String query) {
            this.method = method;
            this.path = path;
            this.query = query;
            if ("POST".equals(method) && "/appmesh/app/syncrun".equals(path)) {
                requests.add("syncrun");
                return this.syncReply;
            }
            if ("GET".equals(method) && path.startsWith("/appmesh/app/" + RUN + "/output")) {
                requests.add("output " + query);
                if (this.pages.isEmpty()) {
                    // the run instance is gone (expired or removed): the endpoint answers 404
                    return new Reply(404).text("app not found", StandardCharsets.UTF_8);
                }
                int index = Math.min(outputReads++, this.pages.size() - 1);
                return this.pages.get(index);
            }
            if ("DELETE".equals(method) && path.equals("/appmesh/app/" + RUN)) {
                requests.add("delete");
                return new Reply(this.deleteStatus).text("{}", StandardCharsets.UTF_8);
            }
            return new Reply(404).text("not found: " + method + " " + path, StandardCharsets.UTF_8);
        }

        Reply syncReply;
        int outputReads;
    }

    /** Split a raw query string into its {@code key=value} pairs (order is not significant). */
    private static java.util.Set<String> splitQuery(String query) {
        return new java.util.HashSet<>(Arrays.asList(query.split("&")));
    }

    private static byte[] repeat(byte b, int count) {
        byte[] result = new byte[count];
        Arrays.fill(result, b);
        return result;
    }

    /** Plain HTTP client backed by the scripted daemon through a local stub server. */
    private AppMeshClient httpClient(final Daemon daemon) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", (HttpExchange exchange) -> {
            URI uri = exchange.getRequestURI();
            String query = uri.getRawQuery() == null ? "" : uri.getRawQuery();
            Reply reply = daemon.route(exchange.getRequestMethod(), uri.getPath(), query);
            // drain the request body
            byte[] buffer = new byte[4096];
            while (exchange.getRequestBody().read(buffer) != -1) {
                // discard
            }
            exchange.getResponseHeaders().set("Content-Type", reply.headers.get("Content-Type"));
            for (Map.Entry<String, String> header : reply.headers.entrySet()) {
                exchange.getResponseHeaders().add(header.getKey(), header.getValue());
            }
            exchange.sendResponseHeaders(reply.status, reply.body.length == 0 ? -1 : reply.body.length);
            if (reply.body.length != 0) {
                try (OutputStream os = exchange.getResponseBody()) {
                    os.write(reply.body);
                }
            }
            exchange.close();
        });
        server.start();
        return new AppMeshClient.Builder().baseURL("http://127.0.0.1:" + server.getAddress().getPort()).build();
    }

    /** A framed-transport client (TCP/WSS) whose requests are answered by the scripted daemon. */
    private AppMeshClient framedClient(final Daemon daemon, final boolean wss) {
        return wss ? wssClient(daemon) : tcpClient(daemon);
    }

    private AppMeshClient tcpClient(final Daemon daemon) {
        return new AppMeshClientTCP("127.0.0.1", 6062) {
            @Override
            public HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
                    Map<String, String> params) throws IOException {
                return framedReply(daemon, method, path, params);
            }
        };
    }

    private AppMeshClient wssClient(final Daemon daemon) {
        return new AppMeshClientWSS("127.0.0.1", 6063) {
            @Override
            public HttpURLConnection request(String method, String path, Object body, Map<String, String> headers,
                    Map<String, String> params) throws IOException {
                return framedReply(daemon, method, path, params);
            }
        };
    }

    /** Answer as the framed transports do: a {@link TransportHttpURLConnection} over a {@link ResponseMessage}. */
    private HttpURLConnection framedReply(Daemon daemon, String method, String path, Map<String, String> params) {
        StringBuilder query = new StringBuilder();
        if (params != null) {
            for (Map.Entry<String, String> e : params.entrySet()) {
                if (query.length() > 0) {
                    query.append('&');
                }
                query.append(e.getKey()).append('=').append(e.getValue());
            }
        }
        Reply reply = daemon.route(method, path, query.toString());
        ResponseMessage message = new ResponseMessage();
        message.httpStatus = reply.status;
        message.body = reply.body;
        message.headers.putAll(reply.headers);
        try {
            return new TransportHttpURLConnection(new URI("http://appmesh.local" + path).toURL(), message);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] fullPage(byte fill) {
        return repeat(fill, PAGE);
    }

    // -------- not truncated: the reply page is the whole result --------

    @Test
    public void testUntruncatedOutputIsUnchanged() throws Exception {
        Daemon daemon = new Daemon();
        byte[] hello = "hello\n".getBytes(StandardCharsets.UTF_8);
        daemon.syncReply = daemon.syncRun(3, hello, false);
        client = httpClient(daemon);

        Pair<Integer, String> result = client.runAppSync(new JSONObject().put("command", "echo hello"), 60);

        assertEquals(Integer.valueOf(3), result.getLeft());
        assertEquals("hello\n", result.getValue());
        assertEquals(Collections.singletonList("syncrun"), daemon.requests);
        assertEquals(Collections.singleton("timeout=60"), splitQuery(daemon.query));
    }

    @Test
    public void testUntruncatedOutputWithLifecycleKeepsQuery() throws Exception {
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, "x".getBytes(StandardCharsets.UTF_8), false);
        client = httpClient(daemon);

        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 5, 30, 1024);

        assertEquals(Integer.valueOf(0), result.getLeft());
        assertEquals("x", result.getValue());
        assertEquals(new java.util.HashSet<>(Arrays.asList("timeout=5", "lifecycle=30")), splitQuery(daemon.query));
        assertEquals(Collections.singletonList("syncrun"), daemon.requests);
    }

    @Test
    public void testTruncatedFlagWithoutRunNameIsNotFollowed() throws Exception {
        Daemon daemon = new Daemon();
        daemon.syncReply = new Reply(200).text("partial", StandardCharsets.UTF_8)
                .header("X-Output-Truncated", "1").header("X-Output-Position", "7");
        client = httpClient(daemon);

        assertEquals("partial", client.runAppSync(new JSONObject(), 60).getValue());
        assertEquals(Collections.singletonList("syncrun"), daemon.requests);
    }

    // -------- truncated: pages are concatenated, then the run is deleted --------

    @Test
    public void testPagesAreConcatenatedAndPositionAdvancesByBytes() throws Exception {
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(1, fullPage((byte) 'a'), true);
        daemon.pages(fullPage((byte) 'b'), fullPage((byte) 'c'), "tail".getBytes(StandardCharsets.UTF_8),
                new byte[0]);
        client = httpClient(daemon);

        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 60);

        char[] expected = new char[PAGE];
        Arrays.fill(expected, 'a');
        String a = new String(expected);
        Arrays.fill(expected, 'b');
        String b = new String(expected);
        Arrays.fill(expected, 'c');
        assertEquals(Integer.valueOf(1), result.getLeft());
        assertEquals(a + b + new String(expected) + "tail", result.getValue());
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE,
                "output stdout_position=" + (2 * PAGE), "output stdout_position=" + (3 * PAGE), "delete"),
                daemon.requests);
    }

    @Test
    public void testMultiByteCharacterSplitAcrossPagesIsDecodedOnce() throws Exception {
        // "é" is 0xC3 0xA9: its first byte closes the reply page, the second opens the next page.
        byte[] first = fullPage((byte) 'a');
        first[PAGE - 1] = (byte) 0xC3;
        byte[] second = new byte[PAGE - 1]; // short: the last page
        Arrays.fill(second, (byte) 'b');
        second[0] = (byte) 0xA9;
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, first, true);
        daemon.pages(second);
        client = httpClient(daemon);

        String output = client.runAppSync(new JSONObject(), 60).getValue();

        char[] expected = new char[PAGE];
        Arrays.fill(expected, 'a');
        String a = new String(expected);
        Arrays.fill(expected, 'b');
        // 1 char (2 bytes) straddles the page boundary: 2 pages of PAGE and PAGE-1 bytes
        // Per-page decoding would produce a replacement character on each side of the boundary.
        String expectedOutput = a.substring(0, PAGE - 1) + "é" + new String(expected, 0, PAGE - 2);
        assertEquals(2 * PAGE - 2, output.length());
        assertEquals(expectedOutput, output);
    }

    @Test
    public void testFirstResponseCharsetIsUsed() throws Exception {
        Charset gbk = Charset.forName("GBK");
        byte[] first = "中文".getBytes(gbk);
        Daemon daemon = new Daemon();
        daemon.syncReply = new Reply(200).text("中文", gbk).header("X-Exit-Code", "2").header("X-App-Name", RUN)
                .header("X-Output-Truncated", "1").header("X-Output-Position", String.valueOf(first.length));
        daemon.pages("输出".getBytes(gbk));
        client = httpClient(daemon);

        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 60);

        assertEquals(Integer.valueOf(2), result.getLeft());
        assertEquals("中文输出", result.getValue());
    }

    @Test
    public void testExactlyOneFullPageEndsWithAnEmptyPage() throws Exception {
        byte[] page = fullPage((byte) 'z');
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(7, page, true);
        daemon.pages(new byte[0]);
        client = httpClient(daemon);

        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 60);

        assertEquals(Integer.valueOf(7), result.getLeft());
        assertEquals(PAGE, result.getValue().length());
        assertEquals('z', result.getValue().charAt(PAGE - 1));
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE, "delete"), daemon.requests);
    }

    @Test
    public void testDeleteFailureIsTolerated() throws Exception {
        byte[] page = fullPage((byte) 'q');
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, page, true);
        daemon.pages("end".getBytes(StandardCharsets.UTF_8));
        daemon.delete(500);
        client = httpClient(daemon);

        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 60);

        assertEquals(Integer.valueOf(0), result.getLeft());
        assertEquals(PAGE + 3, result.getValue().length());
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE, "delete"), daemon.requests);
    }

    // -------- maxOutputBytes --------

    @Test
    public void testMaxOutputExceededThrowsAndKeepsTheRun() throws Exception {
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, fullPage((byte) 'a'), true);
        daemon.pages(fullPage((byte) 'b'), fullPage((byte) 'c'), new byte[0]);
        client = httpClient(daemon);

        IOException error = assertThrows(IOException.class,
                () -> client.runAppSync(new JSONObject(), 60, 0, PAGE + 10));

        assertTrue(error.getMessage().contains("maxOutputBytes=" + (PAGE + 10)), error.getMessage());
        assertTrue(error.getMessage().contains("'" + RUN + "'"), error.getMessage());
        assertTrue(error.getMessage().contains("600 seconds"), error.getMessage());
        // the first extra full page already exceeds the ceiling: nothing further is read
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE), daemon.requests);
    }

    @Test
    public void testOutputExactlyAtCeilingIsReturnedAndRunDeleted() throws Exception {
        byte[] first = fullPage((byte) 'a');
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, first, true);
        daemon.pages("end".getBytes(StandardCharsets.UTF_8));
        client = httpClient(daemon);

        // exactly the ceiling is allowed
        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 60, 0, PAGE + 3);

        assertEquals(PAGE + 3, result.getValue().length());
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE, "delete"), daemon.requests);
    }

    @Test
    public void testFirstPageOverCeilingThrowsWithoutPaging() throws Exception {
        byte[] first = fullPage((byte) 'a');
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, first, true);
        daemon.pages("end".getBytes(StandardCharsets.UTF_8));
        client = httpClient(daemon);

        IOException error = assertThrows(IOException.class,
                () -> client.runAppSync(new JSONObject(), 60, 0, PAGE - 1));

        assertTrue(error.getMessage().contains("maxOutputBytes=" + (PAGE - 1)), error.getMessage());
        // the first page alone is over the ceiling: no page is read and the run is kept
        assertEquals(Collections.singletonList("syncrun"), daemon.requests);
    }

    @Test
    public void testOutputOfOneAndAHalfPagesOverCeilingThrowsAndKeepsTheRun() throws Exception {
        byte[] first = fullPage((byte) 'a');
        byte[] shortPage = repeat((byte) 'b', PAGE / 2);
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, first, true);
        daemon.pages(shortPage);
        client = httpClient(daemon);

        IOException error = assertThrows(IOException.class,
                () -> client.runAppSync(new JSONObject(), 60, 0, PAGE + 10));

        assertTrue(error.getMessage().contains("maxOutputBytes=" + (PAGE + 10)), error.getMessage());
        assertTrue(error.getMessage().contains("'" + RUN + "'"), error.getMessage());
        // one page GET, and the run is kept because the short final page crossed the ceiling
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE), daemon.requests);
    }

    @Test
    public void testShortFinalPageCrossingCeilingThrowsByOneByte() throws Exception {
        byte[] first = fullPage((byte) 'a');
        byte[] shortPage = repeat((byte) 'b', 10);
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, first, true);
        daemon.pages(shortPage);
        client = httpClient(daemon);

        IOException error = assertThrows(IOException.class,
                () -> client.runAppSync(new JSONObject(), 60, 0, PAGE + 9));

        assertTrue(error.getMessage().contains("maxOutputBytes=" + (PAGE + 9)), error.getMessage());
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE), daemon.requests);
    }

    @Test
    public void testFailingPageReadPropagatesAndKeepsTheRun() throws Exception {
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(0, fullPage((byte) 'a'), true);
        daemon.noPages();
        client = httpClient(daemon);

        IOException error = assertThrows(IOException.class, () -> client.runAppSync(new JSONObject(), 60));

        assertTrue(error.getMessage().contains(RUN), error.getMessage());
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE), daemon.requests);
    }

    // -------- framed transports (TCP / WSS) share the same paging --------

    @Test
    public void testTcpTransportFollowsPages() throws Exception {
        assertFramedFollowsPages(false);
    }

    @Test
    public void testWssTransportFollowsPages() throws Exception {
        assertFramedFollowsPages(true);
    }

    private void assertFramedFollowsPages(boolean wss) throws Exception {
        Daemon daemon = new Daemon();
        daemon.syncReply = daemon.syncRun(4, fullPage((byte) 'a'), true);
        daemon.pages("tail".getBytes(StandardCharsets.UTF_8));
        client = framedClient(daemon, wss);

        Pair<Integer, String> result = client.runAppSync(new JSONObject(), 60, 0);

        assertEquals(Integer.valueOf(4), result.getLeft());
        assertEquals(PAGE + 4, result.getValue().length());
        assertEquals(Arrays.asList("syncrun", "output stdout_position=" + PAGE, "delete"), daemon.requests);
    }
}
