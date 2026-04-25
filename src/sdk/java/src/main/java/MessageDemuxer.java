import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

/**
 * Routes incoming messages from a transport connection to either pending
 * request waiters (by UUID) or registered event subscription callbacks.
 *
 * <p>This solves the multiplexing problem where background event delivery
 * and request-response traffic share a single transport connection.
 * Matches the Go SDK {@code MessageDemuxer} pattern.
 */
public class MessageDemuxer {
    private static final Logger LOGGER = Logger.getLogger(MessageDemuxer.class.getName());
    static final String EVENT_URI = "/appmesh/event";

    /**
     * Synthetic event_type pushed to every registered callback when the demuxer
     * stops or the underlying transport disconnects. Lets long-running waits
     * (e.g. wait_for_async_run) unblock instead of hanging forever.
     */
    public static final String EVENT_TYPE_DISCONNECTED = "__disconnected__";

    private final MessageReader reader;
    private final ConcurrentHashMap<String, PendingRequest> pending = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, EventCallback> eventCallbacks = new ConcurrentHashMap<>();
    private final AtomicBoolean started = new AtomicBoolean(false);
    private volatile Thread readerThread;

    /**
     * Functional interface for reading a single framed message from the transport.
     */
    @FunctionalInterface
    public interface MessageReader {
        /**
         * Read the next message from the transport.
         *
         * @return raw message bytes, or null for EOF/empty frame
         * @throws IOException on transport error
         */
        byte[] readMessage() throws Exception;
    }

    /**
     * Callback interface for event notifications.
     */
    @FunctionalInterface
    public interface EventCallback {
        void onEvent(AppEvent event);
    }

    /**
     * Represents a server-push event notification.
     */
    public static class AppEvent {
        public String subscriptionId;
        public String eventType;
        public String appName;
        public long timestamp;
        public long sequence;
        public JSONObject data;

        @Override
        public String toString() {
            return "AppEvent{subscriptionId='" + subscriptionId + "'"
                    + ", eventType='" + eventType + "'"
                    + ", appName='" + appName + "'"
                    + ", timestamp=" + timestamp
                    + ", sequence=" + sequence
                    + "}";
        }
    }

    /**
     * Contains the server's response to a subscribe request.
     */
    public static class SubscriptionResult {
        public String subscriptionId;
        public String appName;
        public List<String> events;

        @Override
        public String toString() {
            return "SubscriptionResult{subscriptionId='" + subscriptionId + "'"
                    + ", appName='" + appName + "'"
                    + ", events=" + events
                    + "}";
        }
    }

    /**
     * Internal holder for a pending request-response pair.
     */
    private static class PendingRequest {
        final CountDownLatch latch = new CountDownLatch(1);
        volatile ResponseMessage response;
    }

    /**
     * Create a new demuxer backed by the given message reader.
     *
     * @param reader transport-specific read function
     */
    public MessageDemuxer(MessageReader reader) {
        this.reader = reader;
    }

    /**
     * Start the background reader thread.
     * If already started, this is a no-op.
     */
    public void start() {
        if (!started.compareAndSet(false, true)) {
            return;
        }
        readerThread = new Thread(this::readLoop, "appmesh-demuxer");
        readerThread.setDaemon(true);
        readerThread.start();
    }

    /**
     * Stop the background reader thread and wake all pending waiters.
     */
    public void stop() {
        if (!started.compareAndSet(true, false)) {
            return;
        }

        // Broadcast a synthetic disconnect event to all registered event callbacks
        // so long-running waits can unblock cleanly.
        broadcastDisconnect();

        Thread t = readerThread;
        if (t != null) {
            t.interrupt();
        }
        readerThread = null;

        // Wake all pending waiters with null responses
        for (PendingRequest pr : pending.values()) {
            pr.latch.countDown();
        }
        pending.clear();
    }

    /**
     * Push a synthetic disconnect event to every registered event callback.
     */
    private void broadcastDisconnect() {
        // Snapshot to avoid re-entrant modification during callback
        List<Map.Entry<String, EventCallback>> snapshot = new ArrayList<>(eventCallbacks.entrySet());
        for (Map.Entry<String, EventCallback> entry : snapshot) {
            final AppEvent event = new AppEvent();
            event.subscriptionId = entry.getKey();
            event.eventType = EVENT_TYPE_DISCONNECTED;
            event.appName = "";
            event.timestamp = 0;
            event.sequence = 0;
            event.data = null;
            final EventCallback cb = entry.getValue();
            Thread t = new Thread(() -> {
                try {
                    cb.onEvent(event);
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Disconnect callback error for " + event.subscriptionId, e);
                }
            });
            t.setDaemon(true);
            t.start();
        }
    }

    /**
     * Whether the background reader is running.
     */
    public boolean isRunning() {
        return started.get();
    }

    /**
     * Register a pending request before sending, so the demuxer can route the
     * response even if it arrives before the caller starts waiting.
     *
     * <p>Typical usage:
     * <pre>
     *   demuxer.registerPending(uuid);
     *   try {
     *       transport.sendMessage(data);
     *       ResponseMessage resp = demuxer.waitForResponse(uuid, 60);
     *   } finally {
     *       demuxer.unregisterPending(uuid);
     *   }
     * </pre>
     *
     * @param uuid the request UUID to register
     */
    public void registerPending(String uuid) {
        pending.put(uuid, new PendingRequest());
    }

    /**
     * Remove a pending request registration.
     *
     * @param uuid the request UUID to unregister
     */
    public void unregisterPending(String uuid) {
        pending.remove(uuid);
    }

    /**
     * Wait for the matching response by UUID. The request must be registered
     * via {@link #registerPending(String)} before calling this method.
     *
     * @param uuid           the request UUID to match
     * @param timeoutSeconds maximum time to wait for the response
     * @return the matched response, or null on timeout or if not registered
     */
    public ResponseMessage waitForResponse(String uuid, int timeoutSeconds) {
        PendingRequest pr = pending.get(uuid);
        if (pr == null) {
            return null;
        }
        try {
            if (pr.latch.await(timeoutSeconds, TimeUnit.SECONDS)) {
                return pr.response;
            }
            return null;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return null;
        } finally {
            pending.remove(uuid);
        }
    }

    /**
     * Register a callback for events with the given subscription ID.
     *
     * @param subscriptionId the subscription ID returned by the subscribe API
     * @param callback       invoked on a daemon thread for each matching event
     */
    public void registerEventCallback(String subscriptionId, EventCallback callback) {
        eventCallbacks.put(subscriptionId, callback);
    }

    /**
     * Unregister the event callback for a subscription ID.
     *
     * @param subscriptionId the subscription ID to unregister
     */
    public void unregisterEventCallback(String subscriptionId) {
        eventCallbacks.remove(subscriptionId);
    }

    /**
     * Background read loop. Continuously reads messages from the transport
     * and dispatches them as either events or request responses.
     */
    private void readLoop() {
        while (started.get() && !Thread.currentThread().isInterrupted()) {
            try {
                byte[] data = reader.readMessage();
                if (data == null || data.length == 0) {
                    LOGGER.fine("Demuxer received EOF from transport");
                    break;
                }

                ResponseMessage resp = ResponseMessage.deserialize(data);

                if (EVENT_URI.equals(resp.request_uri)) {
                    dispatchEvent(resp);
                } else {
                    dispatchResponse(resp);
                }
            } catch (Exception e) {
                if (started.get()) {
                    LOGGER.log(Level.WARNING, "Demuxer read error", e);
                }
                break;
            }
        }

        // Connection lost — stop() handles broadcast + pending cleanup
        stop();
    }

    /**
     * Parse and dispatch an event message to the matching subscription callback.
     */
    private void dispatchEvent(ResponseMessage resp) {
        try {
            String bodyStr = new String(resp.body, StandardCharsets.UTF_8);
            JSONObject json = new JSONObject(bodyStr);

            AppEvent event = new AppEvent();
            event.subscriptionId = json.optString("subscription_id", "");
            event.eventType = json.optString("event_type", "");
            event.appName = json.optString("app_name", "");
            event.timestamp = json.optLong("timestamp", 0);
            event.sequence = json.optLong("sequence", 0);
            event.data = json.has("data") ? json.getJSONObject("data") : null;

            // Fall back to header if body doesn't have subscription_id
            String resolvedSubId = event.subscriptionId;
            if (resolvedSubId.isEmpty() && resp.headers != null) {
                String headerSubId = resp.headers.get("X-Subscription-Id");
                if (headerSubId != null) {
                    resolvedSubId = headerSubId;
                    event.subscriptionId = resolvedSubId;
                }
            }

            final String subId = resolvedSubId;
            EventCallback cb = eventCallbacks.get(subId);
            if (cb != null) {
                // Invoke callback on a separate daemon thread to avoid blocking the reader
                Thread callbackThread = new Thread(() -> {
                    try {
                        cb.onEvent(event);
                    } catch (Exception e) {
                        LOGGER.log(Level.WARNING, "Event callback error for subscription " + subId, e);
                    }
                }, "appmesh-event-" + subId);
                callbackThread.setDaemon(true);
                callbackThread.start();
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to dispatch event", e);
        }
    }

    /**
     * Route a response message to the pending waiter by UUID.
     */
    private void dispatchResponse(ResponseMessage resp) {
        PendingRequest pr = pending.remove(resp.uuid);
        if (pr != null) {
            pr.response = resp;
            pr.latch.countDown();
        }
    }
}
