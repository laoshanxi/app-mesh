package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/**
 * Node forwarding on the streaming (SSE) side channel: the stream carries the forward
 * target, a forwarded framed side channel dials the agent REST listener, and failures
 * name their fix.
 */
public class StreamForwardTest {
    private static final String TASK_STREAM = "/appmesh/app/worker/task/stream";
    private static final String SSE_TASK_WIRE =
            "event: final\ndata: {\"result\":\"node-b\"}\n\nevent: end\ndata: {\"reason\":\"final\"}\n\n";

    private HttpServer server;
    private AppMeshClient client;

    @AfterEach
    public void tearDown() {
        if (client != null) client.close();
        if (server != null) server.stop(0);
    }

    /** What the stub saw: per-request X-Target-Host and Authorization of the stream route. */
    private static final class StreamRecorder {
        final List<String> targets = Collections.synchronizedList(new ArrayList<>());
        final List<String> authorizations = Collections.synchronizedList(new ArrayList<>());
        final AtomicInteger count = new AtomicInteger();
        volatile int status = 200;

        void serve(HttpExchange exchange) throws IOException {
            targets.add(exchange.getRequestHeaders().getFirst("X-Target-Host"));
            authorizations.add(exchange.getRequestHeaders().getFirst("Authorization"));
            count.incrementAndGet();
            byte[] buffer = new byte[4096];
            while (exchange.getRequestBody().read(buffer) != -1) {
                // discard
            }
            byte[] body = status == 200 ? SSE_TASK_WIRE.getBytes(StandardCharsets.UTF_8) : "stub refusal".getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().set("Content-Type",
                    status == 200 ? "text/event-stream" : "text/plain; charset=utf-8");
            exchange.sendResponseHeaders(status, body.length);
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body);
            }
            exchange.close();
        }
    }

    /** Plain HTTP stub the client streams from, recording what it received. */
    private AppMeshClient httpClient(StreamRecorder recorder) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", recorder::serve);
        server.start();
        client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .jwtToken("token")
                .build();
        return client;
    }

    /** Drain a stream to its end frame and return the final result. */
    private static String drain(SseStream stream) throws IOException {
        try {
            while (stream.hasNext()) {
                stream.next();
            }
        } finally {
            stream.close();
        }
        return stream.getEnd().getResult();
    }

    @Test
    public void runTaskStreamCarriesForwardTargetOnHTTPTransport() throws IOException {
        StreamRecorder agent = new StreamRecorder();
        httpClient(agent).setForwardTo("appmesh_slave1");

        assertEquals("node-b", drain(client.runTaskStream("worker", "payload", 30)));
        assertEquals("appmesh_slave1", agent.targets.get(0));
        assertEquals("Bearer token", agent.authorizations.get(0));
    }

    @Test
    public void localStreamSendsNoTarget() throws IOException {
        StreamRecorder engine = new StreamRecorder();
        httpClient(engine);

        drain(client.runTaskStream("worker", "payload", 30));
        assertEquals(null, engine.targets.get(0));
    }

    @Test
    public void forwardedStreamOnEngineListenerNamesTheLimitation() throws IOException {
        StreamRecorder engine = new StreamRecorder();
        engine.status = 400;
        httpClient(engine).setForwardTo("appmesh_slave1");

        IOException error = assertThrows(IOException.class, () -> client.runTaskStream("worker", "payload", 30));
        assertTrue(error.getMessage().contains("does not relay forwarded streams"), error.getMessage());
        assertTrue(error.getMessage().contains("agent REST listener"), error.getMessage());
        assertTrue(error.getMessage().contains("6060"), error.getMessage());
        assertEquals("appmesh_slave1", engine.targets.get(0), "the refusal must come from a forwarded request");
    }

    @Test
    public void forwardedStreamToTCPPortNamesTheFix() throws IOException {
        StreamRecorder agent = new StreamRecorder();
        agent.status = 405;
        httpClient(agent).setForwardTo("appmesh_slave1:6062");

        IOException error = assertThrows(IOException.class, () -> client.runTaskStream("worker", "payload", 30));
        assertTrue(error.getMessage().contains("'appmesh_slave1:6062' names a listener without stream routes"),
                error.getMessage());
        assertTrue(error.getMessage().contains("bare host"), error.getMessage());
    }

    @Test
    public void unforwardedErrorKeepsPlainMessage() throws IOException {
        StreamRecorder engine = new StreamRecorder();
        engine.status = 400;
        httpClient(engine);

        IOException error = assertThrows(IOException.class, () -> client.runTaskStream("worker", "payload", 30));
        assertTrue(error.getMessage().contains("status 400"), error.getMessage());
        assertTrue(!error.getMessage().contains("agent REST listener"), error.getMessage());
    }

    /** The framed side-channel routing decision: forwarded dials the agent listener. */
    @Test
    public void framedSideChannelDialsAgentPortWhenForwarded() {
        AppMeshClientTCP tcp = new AppMeshClientTCP.Builder().host("gateway.local").port(6062)
                .restPort(6063).agentPort(7060).build();
        tcp.setForwardTo("appmesh_slave1");
        assertEquals("https://gateway.local:7060", tcp.sseRequestBaseURL());
        tcp.setForwardTo(null);
        assertEquals("https://gateway.local:6063", tcp.sseRequestBaseURL());
        tcp.close();

        AppMeshClientWSS wss = new AppMeshClientWSS.Builder().host("gateway.local").port(6063).agentPort(7060).build();
        wss.setForwardTo("appmesh_slave1");
        assertEquals("https://gateway.local:7060", wss.sseRequestBaseURL());
        wss.setForwardTo(null);
        assertEquals("https://gateway.local:6063", wss.directRequestBaseURL());
        wss.close();
    }

    /** The agent port defaults to 6060 on both framed builders. */
    @Test
    public void agentPortDefaultsTo6060() {
        AppMeshClientTCP tcp = new AppMeshClientTCP.Builder().host("gateway.local").build();
        tcp.setForwardTo("appmesh_slave1");
        assertEquals("https://gateway.local:6060", tcp.sseRequestBaseURL());
        tcp.close();

        AppMeshClientWSS wss = new AppMeshClientWSS.Builder().host("gateway.local").build();
        wss.setForwardTo("appmesh_slave1");
        assertEquals("https://gateway.local:6060", wss.sseRequestBaseURL());
        wss.close();
    }
}
