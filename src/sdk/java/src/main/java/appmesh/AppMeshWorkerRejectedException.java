package appmesh;

/**
 * Thrown when the App Mesh service reports (HTTP 400) that it permanently
 * rejected a worker task request. The hosting application should stop its
 * task loop; retrying will not succeed. Extends {@link IllegalStateException}
 * so existing catch blocks keep working.
 */
public class AppMeshWorkerRejectedException extends IllegalStateException {
    private static final long serialVersionUID = 1L;

    public AppMeshWorkerRejectedException(String message) {
        super(message);
    }
}
