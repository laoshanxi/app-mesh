package appmesh;

/**
 * WSS (WebSocket Secure) worker wrapper for App Mesh Java SDK.
 *
 * This class reuses an `AppMeshClient`-compatible client. If you have a
 * WSS-based client implementation that presents the same request() API as
 * `AppMeshClient`, construct it and pass it to this constructor.
 */
public class AppMeshWorkerWSS extends AppMeshWorker {
    public AppMeshWorkerWSS(AppMeshClient wssClient) {
        super(wssClient);
    }

    public AppMeshWorkerWSS(String host, int port) {
        // Worker endpoints use APP_MESH_PROCESS_KEY; AppMeshClient Builder defaults autoRefreshToken=false.
        super(new AppMeshClientWSS(host, port));
    }

    public AppMeshWorkerWSS() {
        // default to localhost:6058 to mirror Python defaults
        this("127.0.0.1", 6058);
    }
}
