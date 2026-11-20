package appmesh;

import java.io.BufferedReader;
import java.io.Closeable;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UncheckedIOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Iterator;
import java.util.NoSuchElementException;

import org.json.JSONException;
import org.json.JSONObject;

/**
 * Incremental server-sent-events stream returned by the streaming client APIs
 * ({@code followOutput}, {@code runTaskStream}, {@code streamRun}). Read chunks with
 * {@link #nextChunk()} (null once ended); the terminal marker stays available through
 * {@link #getEnd()} after a thrown exception: reason {@code timeout} throws
 * {@link SocketTimeoutException}, reason {@code error} throws {@link IOException}
 * (Python SDK mapping).
 *
 * <p>The {@link Iterator} bridge wraps checked exceptions in {@link UncheckedIOException};
 * always {@link #close()} an abandoned stream.
 */
public class SseStream implements Iterator<String>, Closeable {
    private static final String DEFAULT_EVENT = "message";
    private static final String END_EVENT = "end";
    private static final String EVENT_PREFIX = "event:";
    private static final String DATA_PREFIX = "data:";
    private static final String REASON_CLOSED = "closed";
    private static final String REASON_TIMEOUT = "timeout";
    private static final String REASON_ERROR = "error";
    // Terminal reasons that end a stream without an exception.
    private static final java.util.Set<String> OK_REASONS = new java.util.HashSet<>(
            Arrays.asList("exit", "removed", "eof", "final", "disconnected", REASON_CLOSED));

    private final HttpURLConnection connection;
    private final BufferedReader reader;
    /** SSE event whose payload is yielded as a chunk (stdout / partial). */
    private final String dataEvent;
    /** JSON field of the data event carrying the chunk text (output / data). */
    private final String dataField;
    /** Event carrying the final payload into {@link SseEnd#getResult()} (null for output streams). */
    private final String finalEvent;
    private final String finalField;

    private String finalResult;
    private String pendingChunk;
    private SseEnd end;
    private Runnable completionAction;
    private boolean closed;

    /**
     * Wrap a connected HTTP 200 stream connection, following the daemon's SSE framing:
     * blank line dispatches a frame, {@code event:}/{@code data:} build it, {@code :} lines are heartbeats.
     */
    SseStream(HttpURLConnection connection, String dataEvent, String dataField, String finalEvent,
            String finalField) throws IOException {
        this.connection = connection;
        this.dataEvent = dataEvent;
        this.dataField = dataField;
        this.finalEvent = finalEvent;
        this.finalField = finalField;
        this.reader = new BufferedReader(
                new InputStreamReader(connection.getInputStream(), StandardCharsets.UTF_8));
    }

    /** Run {@code action} once the stream terminates or is closed (streamRun deletes its temporary app). */
    void onCompletion(Runnable action) {
        this.completionAction = action;
    }

    /**
     * Return the next incremental chunk, or null when the stream ended.
     *
     * @throws SocketTimeoutException the terminal end carried reason "timeout"
     * @throws IOException the terminal end carried reason "error", or a frame was malformed
     */
    public String nextChunk() throws IOException {
        String chunk = peekChunk();
        if (chunk != null) {
            pendingChunk = null;
        }
        return chunk;
    }

    /** The terminal marker, or null while the stream is still open. */
    public SseEnd getEnd() {
        return end;
    }

    @Override
    public boolean hasNext() {
        try {
            return peekChunk() != null;
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @Override
    public String next() {
        if (!hasNext()) {
            throw new NoSuchElementException("stream ended");
        }
        try {
            return nextChunk();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    /** Close the stream and the underlying connection; runs the completion action when not yet run. */
    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        closed = true;
        try {
            reader.close();
        } finally {
            connection.disconnect();
            runCompletion();
        }
    }

    /** Read ahead one chunk without consuming it; null once the stream ended. */
    private String peekChunk() throws IOException {
        if (pendingChunk != null) {
            return pendingChunk;
        }
        if (end != null) {
            return null;
        }
        fill();
        return pendingChunk;
    }

    /** Read frames until the next data chunk or the terminal end event arrives. */
    private void fill() throws IOException {
        String eventName = DEFAULT_EVENT;
        StringBuilder data = new StringBuilder();
        boolean hasData = false;
        while (pendingChunk == null && end == null) {
            String line = reader.readLine();
            if (line == null) {
                // The peer cut the stream without a terminal end event.
                finish(new SseEnd(REASON_CLOSED, null, null, null, null, finalResult));
                return;
            }
            if (line.isEmpty()) {
                if (!DEFAULT_EVENT.equals(eventName) || hasData) {
                    handleEvent(eventName, hasData ? data.toString() : "");
                    if (end != null) {
                        return;
                    }
                }
                eventName = DEFAULT_EVENT;
                data.setLength(0);
                hasData = false;
                continue;
            }
            if (line.startsWith(":")) {
                continue; // heartbeat comment (": ping" every 15 seconds)
            }
            if (line.startsWith(EVENT_PREFIX)) {
                eventName = line.substring(EVENT_PREFIX.length()).trim();
            } else if (line.startsWith(DATA_PREFIX)) {
                if (hasData) {
                    data.append('\n');
                }
                data.append(lstrip(line.substring(DATA_PREFIX.length())));
                hasData = true;
            }
        }
    }

    /** Apply one dispatched frame to the stream state. */
    private void handleEvent(String eventName, String data) throws IOException {
        JSONObject payload;
        try {
            payload = data.isEmpty() ? new JSONObject() : new JSONObject(data);
        } catch (JSONException e) {
            throw new IOException("malformed SSE frame (" + eventName + "): " + e.getMessage(), e);
        }
        if (dataEvent.equals(eventName)) {
            pendingChunk = payload.optString(dataField, "");
        } else if (finalEvent != null && finalEvent.equals(eventName)) {
            finalResult = payload.isNull(finalField) ? null : String.valueOf(payload.get(finalField));
        } else if (END_EVENT.equals(eventName)) {
            finish(endFromPayload(payload, finalResult));
        }
    }

    /** Record the terminal marker, run the completion action, then map error reasons to exceptions. */
    private void finish(SseEnd terminal) throws IOException {
        this.end = terminal;
        runCompletion();
        if (REASON_TIMEOUT.equals(terminal.getReason())) {
            throw new SocketTimeoutException(
                    terminal.getMessage() != null ? terminal.getMessage() : "stream timed out");
        }
        if (REASON_ERROR.equals(terminal.getReason())) {
            throw new IOException(
                    terminal.getMessage() != null ? terminal.getMessage() : "stream failed with an error");
        }
        if (!OK_REASONS.contains(terminal.getReason())) {
            throw new IOException("stream ended with unknown reason: " + terminal.getReason());
        }
    }

    /** Build the terminal marker from an {@code end} frame payload. */
    private static SseEnd endFromPayload(JSONObject payload, String result) {
        return new SseEnd(
                payload.optString("reason", REASON_CLOSED),
                payload.isNull("exit_code") ? null : Integer.valueOf(payload.getInt("exit_code")),
                payload.isNull("position") ? null : Long.valueOf(payload.getLong("position")),
                payload.isNull("status") ? null : Integer.valueOf(payload.getInt("status")),
                payload.isNull("message") ? null : payload.getString("message"),
                result);
    }

    /** Run the completion action exactly once, also when the caller abandons the stream early. */
    private void runCompletion() {
        Runnable action = completionAction;
        if (action != null) {
            completionAction = null;
            action.run();
        }
    }

    /** Strip leading whitespace (Python {@code lstrip} parity for {@code data:} lines). */
    private static String lstrip(String value) {
        int start = 0;
        while (start < value.length() && Character.isWhitespace(value.charAt(start))) {
            start++;
        }
        return value.substring(start);
    }
}
