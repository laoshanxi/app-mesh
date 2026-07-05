package appmesh;

/**
 * Thrown when the App Mesh service reports (HTTP 412) that this process's
 * {@code APP_MESH_PROCESS_KEY} no longer matches, i.e. the process has been
 * superseded by a newer instance. The hosting application should stop its
 * task loop; the SDK never terminates the host JVM itself.
 */
public class ProcessSupersededException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public ProcessSupersededException(String message) {
        super(message);
    }
}
