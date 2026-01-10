/**
 * TCP server wrapper for App Mesh Java SDK.
 *
 * This class reuses an `AppMeshClient`-compatible client. If you have a
 * TCP-based client implementation that presents the same request() API as
 * `AppMeshClient`, construct it and pass it to this constructor.
 */
public class AppMeshServerTCP extends AppMeshServer {
    public AppMeshServerTCP(AppMeshClient tcpClient) {
        super(tcpClient);
    }

    public AppMeshServerTCP(String host, int port) {
        super(new AppMeshClientTCP(host, port));
    }

    public AppMeshServerTCP() {
        // default to localhost:6059 to mirror Python defaults
        this("127.0.0.1", 6059);
    }
}
