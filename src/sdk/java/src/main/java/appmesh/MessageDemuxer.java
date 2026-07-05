package appmesh;

import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.RejectedExecutionException;
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

    /**
     * Bound the pre-registration event buffer (atomic-subscribe race window) so a
     * subscription whose callback never registers cannot grow memory without limit.
     */
    private static final int MAX_BUFFERED_SUBS = 64;
    private static final int MAX_BUFFERED_EVENTS_PER_SUB = 1000;

    private final MessageReader reader;
    private final ConcurrentHashMap<String, PendingRequest> pending = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, EventCallback> eventCallbacks = new ConcurrentHashMap<>();
    /**
     * Guards the callback-map / buffer interaction so flush-on-register cannot
     * reorder buffered events with concurrent live events for the same sub_id.
     */
    private final Object eventLock = new Object();
    /**
     * Events that arrive between server-side subscription and the client registering
     * its callback (e.g. atomic addApp(subscribeEvents) on a fast app, whose output is
     * pushed before addApp returns). Held per sub_id and flushed on
     * registerEventCallback so no events are lost. Guarded by {@link #eventLock}.
     */
    private final Map<String, Deque<AppEvent>> eventBuffers = new HashMap<>();
    /**
     * One single-threaded executor per subscription so events of a subscription are
     * delivered to its callback in arrival order. Guarded by {@link #eventLock}.
     */
    private final Map<String, ExecutorService> eventExecutors = new HashMap<>();
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

        // Drop events buffered for subs whose callback never registered, and let
        // per-subscription executors drain their queued events then terminate.
        synchronized (eventLock) {
            eventBuffers.clear();
            for (ExecutorService exec : eventExecutors.values()) {
                exec.shutdown();
            }
            eventExecutors.clear();
        }

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
            // Route through deliver() so the disconnect event is ordered after
            // any events already queued for the same subscription.
            deliver(entry.getKey(), entry.getValue(), event);
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
     *       ResponseMessage resp = demuxer.waitForResponse(uuid);
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
     * Wait for the matching response by UUID with no client-side wait cap; null means the
     * demuxer stopped (disconnect), never a slow request — {@link #stop()} counts down every
     * pending latch. Register via {@link #registerPending(String)} before calling.
     *
     * @param uuid the request UUID to match
     * @return the matched response, or null on disconnect/interrupt or if not registered
     */
    public ResponseMessage waitForResponse(String uuid) {
        PendingRequest pr = pending.get(uuid);
        if (pr == null) {
            return null;
        }
        try {
            pr.latch.await();
            return pr.response;
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
        synchronized (eventLock) {
            eventCallbacks.put(subscriptionId, callback);
            // Flush events that arrived before registration (atomic-subscribe race).
            // Dispatched under the lock so the buffered callback threads are started
            // before any concurrent live event for this sub_id can pass the lock.
            Deque<AppEvent> buf = eventBuffers.remove(subscriptionId);
            if (buf != null) {
                for (AppEvent event : buf) {
                    deliver(subscriptionId, callback, event);
                }
            }
        }
    }

    /**
     * Unregister the event callback for a subscription ID.
     *
     * @param subscriptionId the subscription ID to unregister
     */
    public void unregisterEventCallback(String subscriptionId) {
        synchronized (eventLock) {
            eventCallbacks.remove(subscriptionId);
            eventBuffers.remove(subscriptionId); // discard any buffered events
            ExecutorService exec = eventExecutors.remove(subscriptionId);
            if (exec != null) {
                exec.shutdown(); // drain already-queued events, then terminate
            }
        }
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
            EventCallback cb;
            synchronized (eventLock) {
                cb = eventCallbacks.get(subId);
                if (cb == null && !subId.isEmpty()) {
                    // Callback not registered yet (atomic-subscribe race): buffer
                    // instead of dropping. Flushed on registerEventCallback.
                    bufferEventLocked(subId, event);
                }
            }
            if (cb != null) {
                deliver(subId, cb, event);
            }
        } catch (Exception e) {
            LOGGER.log(Level.WARNING, "Failed to dispatch event", e);
        }
    }

    /**
     * Buffer an event whose callback has not registered yet. Caller holds {@link #eventLock}.
     */
    private void bufferEventLocked(String subId, AppEvent event) {
        Deque<AppEvent> buf = eventBuffers.get(subId);
        if (buf == null) {
            if (eventBuffers.size() >= MAX_BUFFERED_SUBS) {
                return; // cap distinct unregistered subs to bound memory
            }
            buf = new ArrayDeque<>();
            eventBuffers.put(subId, buf);
        }
        if (buf.size() >= MAX_BUFFERED_EVENTS_PER_SUB) {
            buf.pollFirst(); // drop-oldest
        }
        buf.addLast(event);
    }

    /**
     * Queue the callback on the subscription's single-threaded executor: the reader
     * thread is never blocked and events of one subscription keep arrival order.
     */
    private void deliver(final String subId, final EventCallback cb, final AppEvent event) {
        ExecutorService exec;
        synchronized (eventLock) {
            exec = eventExecutors.get(subId);
            if (exec == null) {
                if (!eventCallbacks.containsKey(subId)) {
                    return; // unregistered concurrently — drop the event
                }
                exec = Executors.newSingleThreadExecutor(r -> {
                    Thread t = new Thread(r, "appmesh-event-" + subId);
                    t.setDaemon(true);
                    return t;
                });
                eventExecutors.put(subId, exec);
            }
        }
        try {
            exec.execute(() -> {
                try {
                    cb.onEvent(event);
                } catch (Exception e) {
                    LOGGER.log(Level.WARNING, "Event callback error for subscription " + subId, e);
                }
            });
        } catch (RejectedExecutionException ignored) {
            // Executor shut down concurrently (unsubscribe/stop)
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
