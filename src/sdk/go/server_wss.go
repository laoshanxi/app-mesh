package appmesh

// AppMeshServerWssContext provides an App Mesh server interface that communicates over a WSS transport
type AppMeshServerWssContext struct {
	AppMeshServerHttpContext
}

// NewWSSContext creates a new AppMeshServer that routes all HTTP requests through a WSS-based executor.
func NewWSSContext(options Option) (*AppMeshServerWssContext, error) {
	wssClient, err := NewWSSClient(options)
	if err != nil {
		return nil, err
	}

	server, err := newHTTPContextWithRequester(options, wssClient.wssReq)
	if err != nil {
		return nil, err
	}

	return &AppMeshServerWssContext{AppMeshServerHttpContext: *server}, nil
}

// CloseConnection closes the underlying WSS connection used by this server context.
func (r *AppMeshServerWssContext) CloseConnection() {
	r.client.req.Close()
}
