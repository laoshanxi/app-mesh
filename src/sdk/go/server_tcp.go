package appmesh

// AppMeshServerTcpContext provides an App Mesh server interface that communicates over a TCP transport
type AppMeshServerTcpContext struct {
	AppMeshServerHttpContext
}

// NewTCPContext creates a new AppMeshServer that routes all HTTP requests through a TCP-based executor.
func NewTCPContext(options Option) (*AppMeshServerTcpContext, error) {
	tcpClient, err := NewTCPClient(options) // Use TCP Executor from TcpClient
	if err != nil {
		return nil, err
	}

	server, err := newHTTPContextWithRequester(options, tcpClient.tcpReq)
	if err != nil {
		return nil, err
	}

	return &AppMeshServerTcpContext{AppMeshServerHttpContext: *server}, err
}

// CloseConnection closes the TCP connection.
func (r *AppMeshServerTcpContext) CloseConnection() {
	r.client.req.Close()
}
