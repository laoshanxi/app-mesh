package appmesh;

/**
 * TCP worker wrapper for App Mesh Java SDK.
 *
 * This class reuses an `AppMeshClient`-compatible client. If you have a
 * TCP-based client implementation that presents the same request() API as
 * `AppMeshClient`, construct it and pass it to this constructor.
 */
public class AppMeshWorkerTCP extends AppMeshWorker {
    public AppMeshWorkerTCP(AppMeshClient tcpClient) {
        super(tcpClient);
    }

    public AppMeshWorkerTCP(String host, int port) {
        // Worker endpoints use APP_MESH_PROCESS_KEY; AppMeshClient Builder defaults autoRefreshToken=false.
        super(new AppMeshClientTCP(host, port));
    }

    public AppMeshWorkerTCP() {
        // default to localhost:6059 to mirror Python defaults
        this("127.0.0.1", 6059);
    }
}
