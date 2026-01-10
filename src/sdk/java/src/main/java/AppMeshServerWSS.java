/**
 * WSS (WebSocket Secure) server wrapper for App Mesh Java SDK.
 *
 * This class reuses an `AppMeshClient`-compatible client. If you have a
 * WSS-based client implementation that presents the same request() API as
 * `AppMeshClient`, construct it and pass it to this constructor.
 */
public class AppMeshServerWSS extends AppMeshServer {
    public AppMeshServerWSS(AppMeshClient wssClient) {
        super(wssClient);
    }

    public AppMeshServerWSS(String host, int port) {
        super(new AppMeshClientWSS(host, port));
    }

    public AppMeshServerWSS() {
        // default to localhost:6058 to mirror Python defaults
        this("127.0.0.1", 6058);
    }
}
