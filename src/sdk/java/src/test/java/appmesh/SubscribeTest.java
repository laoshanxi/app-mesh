package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONObject;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for event subscription message types.
 * These tests verify serialization/deserialization and event model correctness
 * without requiring a running server.
 */
public class SubscribeTest {

    private static final String EVENT_URI = "/appmesh/event";

    @Test
    public void testResponseMessageDeserialization() throws IOException {
        // Build a ResponseMessage with event payload
        ResponseMessage original = new ResponseMessage();
        original.uuid = "evt-uuid-1";
        original.request_uri = EVENT_URI;
        original.http_status = 200;
        original.body_msg_type = "application/json";

        JSONObject eventBody = new JSONObject();
        eventBody.put("subscription_id", "sub-test");
        eventBody.put("event_type", "EXIT");
        eventBody.put("app_name", "myapp");
        eventBody.put("timestamp", 1714000000);
        eventBody.put("sequence", 42);
        eventBody.put("data", new JSONObject().put("exit_code", 1).put("pid", 12345));

        original.body = eventBody.toString().getBytes("UTF-8");
        original.headers = new HashMap<>();
        original.headers.put("X-Subscription-Id", "sub-test");
        original.headers.put("X-Event-Type", "EXIT");
        original.headers.put("X-App-Name", "myapp");

        // Serialize and deserialize
        byte[] serialized = original.serialize();
        assertNotNull(serialized);
        assertTrue(serialized.length > 0);

        ResponseMessage decoded = ResponseMessage.deserialize(serialized);
        assertEquals("evt-uuid-1", decoded.uuid);
        assertEquals(EVENT_URI, decoded.request_uri);
        assertEquals(200, decoded.http_status);
        assertEquals("sub-test", decoded.headers.get("X-Subscription-Id"));
        assertEquals("EXIT", decoded.headers.get("X-Event-Type"));
        assertEquals("myapp", decoded.headers.get("X-App-Name"));

        // Parse the body back as JSON
        String bodyStr = new String(decoded.body, "UTF-8");
        JSONObject parsedBody = new JSONObject(bodyStr);
        assertEquals("sub-test", parsedBody.getString("subscription_id"));
        assertEquals("EXIT", parsedBody.getString("event_type"));
        assertEquals("myapp", parsedBody.getString("app_name"));
        assertEquals(1, parsedBody.getJSONObject("data").getInt("exit_code"));
    }

    @Test
    public void testEventUriConstant() {
        assertEquals("/appmesh/event", EVENT_URI);
    }

    @Test
    public void testRequestMessageForSubscribe() throws IOException {
        // Build a subscribe request
        RequestMessage req = new RequestMessage();
        req.uuid = "req-uuid-sub";
        req.request_uri = "/appmesh/app/myapp/subscribe";
        req.http_method = "POST";
        req.client_addr = "test-client";
        req.headers = new HashMap<>();
        req.headers.put("Authorization", "Bearer test-token");
        req.query = new HashMap<>();
        req.query.put("events", "START,EXIT,STDOUT");

        byte[] serialized = req.serialize();
        assertNotNull(serialized);
        assertTrue(serialized.length > 0);
    }

    /** Scripted mock transport: framed messages fed through a queue; an empty array reads as EOF. */
    private static MessageDemuxer.MessageReader queueReader(BlockingQueue<byte[]> queue) {
        return () -> {
            byte[] data = queue.take();
            return data.length == 0 ? null : data;
        };
    }

    // Conformance: S7 (partial) — waiter registered before the response arrives is routed by UUID (docs/source/SDKContract.md)
    @Test
    public void testDemuxerRoutesResponseToPreRegisteredWaiter() throws Exception {
        BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
        MessageDemuxer demuxer = new MessageDemuxer(queueReader(queue));
        demuxer.start();
        try {
            ResponseMessage resp = new ResponseMessage();
            resp.uuid = "req-s7";
            resp.request_uri = "/appmesh/app/test";
            resp.http_status = 200;
            resp.body = "{}".getBytes("UTF-8");
            resp.headers = new HashMap<>();

            demuxer.registerPending("req-s7");
            queue.put(resp.serialize()); // response arrives right after "send"

            ResponseMessage got = demuxer.waitForResponse("req-s7");
            assertNotNull(got, "response arriving right after send must not be dropped");
            assertEquals("req-s7", got.uuid);
            assertEquals(200, got.http_status);
        } finally {
            demuxer.stop();
        }
    }

    // Conformance: S2 (demuxer) — transport EOF broadcasts __disconnected__ to every callback
    // and wakes pending waiters with null instead of hanging (docs/source/SDKContract.md)
    @Test
    public void testDemuxerDisconnectBroadcastUnblocksWaiters() throws Exception {
        BlockingQueue<byte[]> queue = new LinkedBlockingQueue<>();
        MessageDemuxer demuxer = new MessageDemuxer(queueReader(queue));
        demuxer.start();

        final CountDownLatch disconnected = new CountDownLatch(1);
        final AtomicReference<MessageDemuxer.AppEvent> received = new AtomicReference<>();
        demuxer.registerEventCallback("sub-s2", event -> {
            received.set(event);
            disconnected.countDown();
        });

        demuxer.registerPending("req-s2");
        final CountDownLatch waiterDone = new CountDownLatch(1);
        final AtomicReference<ResponseMessage> waiterResult = new AtomicReference<>();
        Thread waiter = new Thread(() -> {
            waiterResult.set(demuxer.waitForResponse("req-s2"));
            waiterDone.countDown();
        });
        waiter.start();

        queue.put(new byte[0]); // transport EOF

        assertTrue(disconnected.await(5, TimeUnit.SECONDS), "disconnect broadcast not delivered");
        assertEquals(MessageDemuxer.EVENT_TYPE_DISCONNECTED, received.get().eventType);
        assertEquals("sub-s2", received.get().subscriptionId);

        assertTrue(waiterDone.await(5, TimeUnit.SECONDS), "pending waiter not woken on disconnect");
        assertNull(waiterResult.get(), "disconnect wakes the waiter with null, never a response");
    }

    @Test
    public void testEventResponseHeaders() throws IOException {
        ResponseMessage resp = new ResponseMessage();
        resp.uuid = "evt-2";
        resp.request_uri = EVENT_URI;
        resp.http_status = 200;
        resp.body = "{}".getBytes("UTF-8");
        resp.headers = new HashMap<>();
        resp.headers.put("X-Subscription-Id", "sub-123");
        resp.headers.put("X-Event-Type", "HEALTH");
        resp.headers.put("X-App-Name", "test-app");

        byte[] buf = resp.serialize();
        ResponseMessage decoded = ResponseMessage.deserialize(buf);

        assertEquals("sub-123", decoded.headers.get("X-Subscription-Id"));
        assertEquals("HEALTH", decoded.headers.get("X-Event-Type"));
        assertEquals("test-app", decoded.headers.get("X-App-Name"));
    }
}
