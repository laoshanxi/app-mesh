package appmesh

// AppMeshServerTcpContext provides an App Mesh server interface that communicates over a TCP transport
type AppMeshServerTcpContext struct {
	AppMeshServerHttpContext
}

// NewTcpContext creates a new AppMeshServer that routes all HTTP requests through a TCP-based executor.
func NewTcpContext(options Option) (*AppMeshServerTcpContext, error) {
	tcpClient, err := NewTcpClient(options) // Use TCP Executor from TcpClient

	server := NewHttpContext(options)
	server.client.Proxy = tcpClient.TcpExecutor
	return &AppMeshServerTcpContext{AppMeshServerHttpContext: *server}, err
}

// CloseConnection closes the TCP connection.
func (r *AppMeshServerTcpContext) CloseConnection() {
	r.client.Proxy.Close()
}
