package appmesh

// AppMeshServerWssContext provides an App Mesh server interface that communicates over a WSS transport
type AppMeshServerWssContext struct {
	AppMeshServerHttpContext
}

// NewWSSContext creates a server-side task context over WSS. Server endpoints
// authenticate via APP_MESH_PROCESS_KEY, not JWT, so token refresh is forced off.
func NewWSSContext(options Option) (*AppMeshServerWssContext, error) {
	options.AutoRefreshToken = false
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
