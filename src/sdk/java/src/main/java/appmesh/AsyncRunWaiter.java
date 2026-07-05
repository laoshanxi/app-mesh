package appmesh;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONObject;

/**
 * Shared event-driven implementation of {@code waitForAsyncRun} for demux-capable
 * transports (TCP/WSS): subscribes to STDOUT/EXIT/REMOVED events, backfills output
 * emitted before the subscription took effect, deduplicates by byte offset, and
 * waits for the process to finish or the connection to drop.
 */
final class AsyncRunWaiter {
    private static final Logger LOGGER = Logger.getLogger(AsyncRunWaiter.class.getName());

    private AsyncRunWaiter() {
    }

    /** First-writer-wins terminal outcome: exactly one of {@code exitCode} (may be negative) or {@code failure} is set. */
    private static final class Outcome {
        final Integer exitCode;
        final Exception failure;

        Outcome(Integer exitCode, Exception failure) {
            this.exitCode = exitCode;
            this.failure = failure;
        }
    }

    /**
     * Wait for an async run via event subscription.
     *
     * <p>Returns the real process exit code, or {@code null} on caller-side timeout.
     * No sentinel exit codes: throws {@link AppRemovedException} (app removed before exit),
     * {@link TransportDisconnectedException} (demuxer dropped mid-wait), or {@link IOException}
     * (EXIT event with unparseable {@code exit_code}). The forwarding host captured on the
     * run is applied per-request; shared client state is not mutated.
     */
    static Integer waitViaEvents(AppMeshClient client, AppMeshClient.AppRun run,
            AppMeshClient.OutputHandler stdoutHandler, int timeoutSeconds) throws Exception {
        if (run == null) {
            return null;
        }

        Map<String, String> forwardHeaders = client.forwardHeaders(run.getForwardingHost());

        final AtomicReference<Outcome> outcome = new AtomicReference<>();
        final AtomicLong deliveredUntil = new AtomicLong(0);
        final CountDownLatch done = new CountDownLatch(1);
        final Object deliverLock = new Object();

        // Event callback: routes STDOUT / EXIT / REMOVED / __disconnected__
        MessageDemuxer.EventCallback callback = (event) -> {
            switch (event.eventType) {
                case "STDOUT":
                    if (event.data != null) {
                        long pos = event.data.optLong("position", 0);
                        String output = event.data.optString("output", "");
                        deliverOutput(output, pos, deliveredUntil, deliverLock, stdoutHandler);
                    }
                    break;
                case "EXIT":
                    Integer code = null;
                    if (event.data != null && event.data.has("exit_code") && !event.data.isNull("exit_code")) {
                        try {
                            code = event.data.getInt("exit_code");
                        } catch (org.json.JSONException ignored) {
                        }
                    }
                    if (code != null) {
                        outcome.compareAndSet(null, new Outcome(code, null));
                    } else {
                        // Malformed EXIT must not masquerade as app removal or a real exit code
                        outcome.compareAndSet(null, new Outcome(null, new IOException(
                                "EXIT event for '" + run.getAppName() + "' carried an unparseable exit_code")));
                    }
                    done.countDown();
                    break;
                case "REMOVED":
                    outcome.compareAndSet(null, new Outcome(null, new AppRemovedException(
                            "app '" + run.getAppName() + "' was removed before its exit was observed")));
                    done.countDown();
                    break;
                case MessageDemuxer.EVENT_TYPE_DISCONNECTED:
                    outcome.compareAndSet(null, new Outcome(null, new TransportDisconnectedException(
                            "transport disconnected while waiting for '" + run.getAppName() + "' to exit")));
                    done.countDown();
                    break;
                default:
                    break;
            }
        };

        JSONObject sub = client.subscribe(run.getAppName(),
                new String[] { "STDOUT", "EXIT", "REMOVED" }, callback, forwardHeaders);
        String subscriptionId = sub.optString("subscription_id", "");

        try {
            // Backfill bytes emitted before subscribe took effect
            try {
                AppMeshClient.AppOutput backfill = client.getAppOutput(run.getAppName(), 0, 0, 0,
                        run.getProcessUuid(), 0, forwardHeaders);
                if (backfill.getOutput() != null && !backfill.getOutput().isEmpty()) {
                    deliverOutput(backfill.getOutput(), 0, deliveredUntil, deliverLock, stdoutHandler);
                }
                if (backfill.getExitCode() != null) {
                    outcome.compareAndSet(null, new Outcome(backfill.getExitCode(), null));
                    done.countDown();
                }
            } catch (Exception e) {
                LOGGER.log(Level.WARNING, "Backfill failed for " + run.getAppName(), e);
            }

            // Wait for done signal
            if (timeoutSeconds > 0) {
                done.await(timeoutSeconds, TimeUnit.SECONDS);
            } else {
                done.await();
            }
        } finally {
            // Unsubscribe
            try {
                if (!subscriptionId.isEmpty()) {
                    client.unsubscribe(subscriptionId, forwardHeaders);
                }
            } catch (Exception ignored) {
            }
            // Best-effort delete on a real exit only; on REMOVED/disconnect the app is already gone
            Outcome finalOutcome = outcome.get();
            if (finalOutcome != null && finalOutcome.failure == null && finalOutcome.exitCode != null) {
                try {
                    client.deleteApp(run.getAppName(), forwardHeaders);
                } catch (Exception ignored) {
                }
            }
        }

        Outcome result = outcome.get();
        if (result == null) {
            return null; // caller-side timeout
        }
        if (result.failure != null) {
            throw result.failure;
        }
        return result.exitCode;
    }

    /**
     * Deliver stdout output with deduplication by byte offset.
     */
    private static void deliverOutput(String chunk, long pos, AtomicLong deliveredUntil,
            Object lock, AppMeshClient.OutputHandler stdoutHandler) {
        if (chunk == null || chunk.isEmpty()) {
            return;
        }
        byte[] chunkBytes = chunk.getBytes(StandardCharsets.UTF_8);
        synchronized (lock) {
            long current = deliveredUntil.get();
            long end = pos + chunkBytes.length;
            if (end <= current) {
                return; // already delivered
            }
            long startPos;
            String toDeliver;
            if (pos < current) {
                // Partial overlap: trim the already-delivered prefix
                int skip = (int) (current - pos);
                startPos = current;
                toDeliver = new String(chunkBytes, skip, chunkBytes.length - skip, StandardCharsets.UTF_8);
            } else {
                startPos = pos;
                toDeliver = chunk;
            }
            deliveredUntil.set(end);
            if (stdoutHandler != null && !toDeliver.isEmpty()) {
                stdoutHandler.handle(toDeliver, startPos);
            }
        }
    }
}
