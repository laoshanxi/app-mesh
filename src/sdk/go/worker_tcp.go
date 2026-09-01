package appmesh

// WorkerTCPContext provides an App Mesh worker interface (a worker-side task loop, not a server)
// that communicates over a TCP transport.
type WorkerTCPContext struct {
	WorkerHTTPContext
}

// NewTCPContext creates a server-side task context over TCP. Server endpoints
// authenticate via APP_MESH_PROCESS_KEY; the worker is not an OAuth client.
func NewTCPContext(options Option) (*WorkerTCPContext, error) {
	tcpClient, err := NewTCPClient(options)
	if err != nil {
		return nil, err
	}
	return &WorkerTCPContext{
		WorkerHTTPContext: WorkerHTTPContext{client: tcpClient.AppMeshClient},
	}, nil
}

// CloseConnection closes the TCP connection.
func (r *WorkerTCPContext) CloseConnection() {
	r.client.req.Close()
}
