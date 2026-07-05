package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * SDKContract conformance tests for the subscribe-based wait path
 * (docs/source/SDKContract.md) — no daemon needed.
 */
public class AsyncRunWaiterTest {

    /**
     * Scripted client, no network: {@code injectEvent} is fired from the backfill call,
     * after subscribe has registered the callback (mirrors an event arriving mid-wait).
     */
    private static class StubClient extends AppMeshClient {
        final AtomicReference<MessageDemuxer.EventCallback> callback = new AtomicReference<>();
        volatile MessageDemuxer.AppEvent injectEvent;
        volatile boolean deleted = false;

        StubClient() {
            super(new Builder().disableSSLVerify());
        }

        @Override
        JSONObject subscribe(String appName, String[] events, MessageDemuxer.EventCallback cb,
                Map<String, String> extraHeaders) {
            callback.set(cb);
            return new JSONObject().put("subscription_id", "sub-1");
        }

        @Override
        AppOutput getAppOutput(String appName, long stdoutPosition, int stdoutIndex, int stdoutMaxsize,
                String processUuid, int timeout, Map<String, String> extraHeaders) {
            MessageDemuxer.EventCallback cb = callback.get();
            if (cb != null && injectEvent != null) {
                cb.onEvent(injectEvent);
            }
            AppOutput out = new AppOutput();
            out.httpSuccess = true;
            out.httpBody = "";
            return out;
        }

        @Override
        boolean unsubscribe(String subscriptionId, Map<String, String> extraHeaders) {
            return true;
        }

        @Override
        boolean deleteApp(String appName, Map<String, String> extraHeaders) {
            deleted = true;
            return true;
        }
    }

    private static MessageDemuxer.AppEvent event(String eventType, JSONObject data) {
        MessageDemuxer.AppEvent event = new MessageDemuxer.AppEvent();
        event.subscriptionId = "sub-1";
        event.eventType = eventType;
        event.appName = "waitapp";
        event.data = data;
        return event;
    }

    // Conformance: S6 — a negative exit code (signal kill) is returned as the exit code,
    // never conflated with an error sentinel (docs/source/SDKContract.md)
    @Test
    public void testNegativeExitCodeReturnedAsExitCode() throws Exception {
        StubClient client = new StubClient();
        client.injectEvent = event("EXIT", new JSONObject().put("exit_code", -2));

        Integer code = AsyncRunWaiter.waitViaEvents(client,
                new AppMeshClient.AppRun(client, "waitapp", "proc-1"), null, 5);

        assertEquals(Integer.valueOf(-2), code);
        assertTrue(client.deleted, "run app must be deleted after a real observed exit");
    }

    // Conformance: S2 — transport disconnect mid-wait throws TransportDisconnectedException
    // promptly instead of hanging (docs/source/SDKContract.md)
    @Test
    public void testDisconnectUnblocksWait() {
        StubClient client = new StubClient();
        client.injectEvent = event(MessageDemuxer.EVENT_TYPE_DISCONNECTED, null);

        assertThrows(TransportDisconnectedException.class, () -> AsyncRunWaiter.waitViaEvents(client,
                new AppMeshClient.AppRun(client, "waitapp", "proc-1"), null, 30));
        assertFalse(client.deleted, "must not delete the run app after a disconnect");
    }
}
