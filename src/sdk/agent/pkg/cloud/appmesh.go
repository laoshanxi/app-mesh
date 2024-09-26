package cloud

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/agent"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	sdk "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/rs/xid"
)

type AppMesh struct {
	*sdk.AppMeshClientTCP
	socketConn *net.Conn
	mu         sync.Mutex
}

// NewTcpClient creates a new AppMeshClientTCP instance for interacting with a TCP server.
func NewAppMeshClient() *AppMesh {
	var tcpConn *net.Conn

	connectAddr := config.ConfigData.REST.RestListenAddress + ":" + strconv.Itoa(config.ConfigData.REST.RestTcpPort)
	// connect to TCP rest server
	targetHost := strings.Replace(connectAddr, "0.0.0.0", "127.0.0.1", 1)
	conn, err := sdk.ConnectAppMeshServer(targetHost, config.ConfigData.REST.SSL.VerifyServer, &config.ConfigData.REST.SSL)
	if err != nil {
		log.Fatalf("failed to connect to appmesh service: %v", err)
	}
	log.Printf("Establish Cloud client connection to TCP server <%s>", connectAddr)
	tcpConn = &conn

	client := &AppMesh{socketConn: tcpConn}
	client.AppMeshClientTCP = &sdk.AppMeshClientTCP{AppMeshClient: sdk.NewHttpClient(sdk.Option{})}
	client.AppMeshClientTCP.TcpExecutor = &sdk.ClientRequesterTcp{BaseURL: sdk.DEFAULT_HTTP_URI, SocketConn: *tcpConn}
	client.AppMeshClientTCP.AppMeshClient.Proxy = client.AppMeshClientTCP.TcpExecutor
	return client
}

// GetResource gets resources
func (r *AppMesh) GetCloudResource() (string, error) {
	data := r.generateRequest()
	data.HttpMethod = "GET"
	data.RequestUri = "/appmesh/cloud/resources"

	resp, err := r.request(data)
	if resp != nil && resp.HttpStatus == http.StatusOK {
		body, jsonErr := sdk.PrettyJSON(resp.Body)
		if jsonErr != nil {
			log.Printf("PrettyJSON failed with error: %v", jsonErr)
		}
		return body, err
	}
	return "", err
}

func (r *AppMesh) generateRequest() *agent.Request {
	data := new(agent.Request)
	data.Uuid = xid.New().String()
	data.Headers = make(map[string]string)
	data.Queries = make(map[string]string)
	return data
}

// request sends a request over TCP
func (r *AppMesh) request(data *agent.Request) (*sdk.Response, error) {

	if err := data.SetHMACVerify(); err != nil {
		return nil, err
	}
	// Serialize the request
	buf, err := data.Serialize()
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	// Send the data over TCP
	if err := r.AppMeshClientTCP.TcpExecutor.SendData(buf); err != nil {
		return nil, err
	}

	// Receive the response
	respData, err := r.AppMeshClientTCP.TcpExecutor.RecvData()
	if err != nil {
		return nil, err
	}

	// Deserialize the response
	respMsg := &sdk.Response{}
	if err := respMsg.Deserialize(respData); err != nil {
		return nil, err
	}
	return respMsg, nil
}
