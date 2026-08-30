package appmesh

// WorkerWSSContext provides an App Mesh worker interface (a worker-side task loop, not a server)
// that communicates over a WSS transport.
type WorkerWSSContext struct {
	WorkerHTTPContext
}

// NewWSSContext creates a server-side task context over WSS. Server endpoints
// authenticate via APP_MESH_PROCESS_KEY; the worker is not an OAuth client.
func NewWSSContext(options Option) (*WorkerWSSContext, error) {
	wssClient, err := NewWSSClient(options)
	if err != nil {
		return nil, err
	}

	server, err := newHTTPContextWithRequester(options, wssClient.wssReq)
	if err != nil {
		return nil, err
	}

	return &WorkerWSSContext{WorkerHTTPContext: *server}, nil
}

// CloseConnection closes the underlying WSS connection used by this server context.
func (r *WorkerWSSContext) CloseConnection() {
	r.client.req.Close()
}
