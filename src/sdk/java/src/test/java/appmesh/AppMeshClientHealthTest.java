package appmesh;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

/**
 * Daemon-free coverage for checkAppHealth error semantics and the JSON request
 * content type, served by a loopback HTTP stub.
 *
 * <p>Intent: only the daemon's health verdict (HTTP 200 body "0"/"1") maps to a
 * boolean; auth/missing-app/server errors must throw instead of reading as
 * "unhealthy" (matches the Python/Rust SDKs).
 */
public class AppMeshClientHealthTest {
    private HttpServer server;
    private AppMeshClient client;
    private final AtomicReference<String> lastRequestContentType = new AtomicReference<>();

    @BeforeEach
    public void setup() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/appmesh/app/healthy/health", ex -> respond(ex, 200, "text/plain", "0"));
        server.createContext("/appmesh/app/sick/health", ex -> respond(ex, 200, "text/plain", " 1 "));
        server.createContext("/appmesh/app/denied/health",
                ex -> respond(ex, 401, "application/json", "{\"message\": \"Unauthorized\"}"));
        server.createContext("/appmesh/app/ping", ex -> {
            lastRequestContentType.set(ex.getRequestHeaders().getFirst("Content-Type"));
            respond(ex, 200, "application/json", "{}");
        });
        server.start();
        client = new AppMeshClient.Builder()
                .baseURL("http://127.0.0.1:" + server.getAddress().getPort())
                .build();
    }

    @AfterEach
    public void tearDown() {
        if (client != null) client.close();
        if (server != null) server.stop(0);
    }

    @Test
    public void healthVerdictZeroIsHealthy() throws IOException {
        assertTrue(client.checkAppHealth("healthy"));
    }

    @Test
    public void healthVerdictNonZeroIsUnhealthy() throws IOException {
        assertFalse(client.checkAppHealth("sick"));
    }

    @Test
    public void authErrorThrowsInsteadOfUnhealthy() {
        IOException error = assertThrows(IOException.class, () -> client.checkAppHealth("denied"));
        assertTrue(error.getMessage().contains("401"), "status missing from: " + error.getMessage());
        assertTrue(error.getMessage().contains("Unauthorized"), "error body missing from: " + error.getMessage());
    }

    @Test
    public void jsonBodyCarriesPlainApplicationJsonContentType() throws IOException {
        client.addApp("ping", new JSONObject().put("command", "true"));
        assertEquals("application/json", lastRequestContentType.get());
    }

    private static void respond(HttpExchange exchange, int status, String contentType, String body)
            throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", contentType);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}
