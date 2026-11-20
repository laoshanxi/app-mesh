package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Iterator;
import java.util.NoSuchElementException;
import java.util.concurrent.atomic.AtomicInteger;

import org.junit.jupiter.api.Test;

/**
 * Offline framing and error-mapping coverage for {@link SseStream} (no daemon, no sockets);
 * vectors mirror the wire examples in docs/source/Streaming.md and the Python iter_sse_events parser.
 */
public class SseStreamTest {

    /** Minimal read-only connection answering a fixed body with HTTP 200. */
    private static final class FakeConnection extends HttpURLConnection {
        private final byte[] body;

        FakeConnection(String body) {
            super(null);
            this.body = body.getBytes(StandardCharsets.UTF_8);
            this.connected = true;
        }

        @Override
        public void connect() {
        }

        @Override
        public void disconnect() {
            this.connected = false;
        }

        @Override
        public boolean usingProxy() {
            return false;
        }

        @Override
        public InputStream getInputStream() {
            return new ByteArrayInputStream(body);
        }

        @Override
        public int getResponseCode() {
            return HTTP_OK;
        }
    }

    private static SseStream outputStream(String wire) throws IOException {
        return new SseStream(new FakeConnection(wire), "stdout", "output", null, null);
    }

    private static SseStream taskStream(String wire) throws IOException {
        return new SseStream(new FakeConnection(wire), "partial", "data", "final", "result");
    }

    @Test
    public void yieldsStdoutChunksAndExitEnd() throws IOException {
        String wire = "event: stdout\r\n"
                + "data: {\"position\":0,\"output\":\"token1 token2 \"}\r\n"
                + "\r\n"
                + ": ping\r\n"
                + "\r\n"
                + "event: stdout\n"
                + "data: {\"position\":14,\"output\":\"token3\"}\n"
                + "\n"
                + "event: end\n"
                + "data: {\"reason\":\"exit\",\"exit_code\":0,\"position\":21}\n"
                + "\n";
        try (SseStream stream = outputStream(wire)) {
            assertEquals("token1 token2 ", stream.nextChunk());
            assertEquals("token3", stream.nextChunk());
            assertNull(stream.nextChunk(), "stream ended after the end event");
            SseEnd end = stream.getEnd();
            assertEquals("exit", end.getReason());
            assertEquals(Integer.valueOf(0), end.getExitCode());
            assertEquals(Long.valueOf(21), end.getPosition());
            assertNull(end.getResult());
        }
    }

    @Test
    public void multiLineDataFramesAreJoined() throws IOException {
        String wire = "event: stdout\n"
                + "data: {\"position\":0,\n"
                + "data:  \"output\":\"chunk\"}\n"
                + "\n"
                + "event: end\n"
                + "data: {\"reason\":\"eof\"}\n"
                + "\n";
        try (SseStream stream = outputStream(wire)) {
            assertEquals("chunk", stream.nextChunk());
            assertNull(stream.nextChunk());
            assertEquals("eof", stream.getEnd().getReason());
        }
    }

    @Test
    public void taskStreamCapturesFinalResult() throws IOException {
        String wire = "event: partial\n"
                + "data: {\"data\":\"to\"}\n"
                + "\n"
                + "event: partial\n"
                + "data: {\"data\":\"ken\"}\n"
                + "\n"
                + "event: final\n"
                + "data: {\"result\":\"{\\\"answer\\\": 42}\"}\n"
                + "\n"
                + "event: end\n"
                + "data: {\"reason\":\"final\"}\n"
                + "\n";
        try (SseStream stream = taskStream(wire)) {
            assertEquals("to", stream.nextChunk());
            assertEquals("ken", stream.nextChunk());
            assertNull(stream.nextChunk());
            SseEnd end = stream.getEnd();
            assertEquals("final", end.getReason());
            assertEquals("{\"answer\": 42}", end.getResult());
        }
    }

    @Test
    public void timeoutEndThrowsSocketTimeout() throws IOException {
        String wire = "event: end\n"
                + "data: {\"reason\":\"timeout\",\"message\":\"stream timed out\"}\n"
                + "\n";
        try (SseStream stream = outputStream(wire)) {
            SocketTimeoutException e = assertThrows(SocketTimeoutException.class, stream::nextChunk);
            assertEquals("stream timed out", e.getMessage());
            assertEquals("timeout", stream.getEnd().getReason());
        }
    }

    @Test
    public void errorEndThrowsIOException() throws IOException {
        String wire = "event: end\n"
                + "data: {\"reason\":\"error\",\"status\":404,\"message\":\"app not found\"}\n"
                + "\n";
        try (SseStream stream = taskStream(wire)) {
            IOException e = assertThrows(IOException.class, stream::nextChunk);
            assertEquals("app not found", e.getMessage());
            assertEquals(Integer.valueOf(404), stream.getEnd().getStatus());
        }
    }

    @Test
    public void malformedFrameThrowsIOException() throws IOException {
        String wire = "event: stdout\n"
                + "data: not-json\n"
                + "\n";
        try (SseStream stream = outputStream(wire)) {
            IOException e = assertThrows(IOException.class, stream::nextChunk);
            assertTrue(e.getMessage().contains("malformed SSE frame (stdout)"));
        }
    }

    @Test
    public void peerCutWithoutEndReportsClosed() throws IOException {
        try (SseStream stream = outputStream("event: stdout\ndata: {\"output\":\"x\"}\n\n")) {
            assertEquals("x", stream.nextChunk());
            assertNull(stream.nextChunk());
            assertEquals("closed", stream.getEnd().getReason());
        }
    }

    @Test
    public void iteratorBridgeDrainsAndStops() throws IOException {
        String wire = "event: partial\n"
                + "data: {\"data\":\"a\"}\n"
                + "\n"
                + "event: partial\n"
                + "data: {\"data\":\"b\"}\n"
                + "\n"
                + "event: end\n"
                + "data: {\"reason\":\"final\"}\n"
                + "\n";
        SseStream stream = taskStream(wire);
        Iterator<String> it = stream;
        assertTrue(it.hasNext());
        assertEquals("a", it.next());
        assertEquals("b", it.next());
        assertFalse(it.hasNext());
        assertThrows(NoSuchElementException.class, it::next);
        stream.close();
    }

    @Test
    public void iteratorBridgeWrapsErrorEnd() throws IOException {
        String wire = "event: end\ndata: {\"reason\":\"error\"}\n\n";
        try (SseStream stream = taskStream(wire)) {
            assertThrows(UncheckedIOException.class, () -> {
                while (stream.hasNext()) {
                    stream.next();
                }
            });
        }
    }

    @Test
    public void completionRunsOnNaturalEndAndEarlyClose() throws IOException {
        AtomicInteger natural = new AtomicInteger();
        try (SseStream stream = outputStream(
                "event: end\ndata: {\"reason\":\"eof\"}\n\n")) {
            stream.onCompletion(natural::incrementAndGet);
            assertNull(stream.nextChunk());
            assertEquals(1, natural.get(), "terminal end runs the completion action");
        }

        AtomicInteger abandoned = new AtomicInteger();
        try (SseStream stream = outputStream("")) {
            stream.onCompletion(abandoned::incrementAndGet);
            assertEquals(0, abandoned.get());
            stream.close();
            assertEquals(1, abandoned.get(), "close() runs the completion action exactly once");
        }
    }
}
