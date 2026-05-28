package appmesh

// AppMeshServerTcpContext provides an App Mesh server interface that communicates over a TCP transport
type AppMeshServerTcpContext struct {
	AppMeshServerHttpContext
}

// NewTCPContext creates a server-side task context over TCP. Server endpoints
// authenticate via APP_MESH_PROCESS_KEY, not JWT, so token refresh is forced off.
func NewTCPContext(options Option) (*AppMeshServerTcpContext, error) {
	options.AutoRefreshToken = false
	tcpClient, err := NewTCPClient(options)
	if err != nil {
		return nil, err
	}
	return &AppMeshServerTcpContext{
		AppMeshServerHttpContext: AppMeshServerHttpContext{client: tcpClient.AppMeshClient},
	}, nil
}

// CloseConnection closes the TCP connection.
func (r *AppMeshServerTcpContext) CloseConnection() {
	r.client.req.Close()
}
