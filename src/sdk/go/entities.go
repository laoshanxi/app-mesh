package appmesh

import (
	"io"
	"net/http"
	"net/url"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	DEFAULT_HTTP_URI             = "https://localhost:6060"
	DEFAULT_TCP_URI              = "localhost:6059"
	DEFAULT_CLIENT_CERT_FILE     = "/opt/appmesh/ssl/client.pem"
	DEFAULT_CLIENT_CERT_KEY_FILE = "/opt/appmesh/ssl/client-key.pem"
	DEFAULT_CA_FILE              = "/opt/appmesh/ssl/ca.pem"

	HTTP_USER_AGENT_HEADER_NAME        = "User-Agent"
	HTTP_USER_AGENT                    = "appmesh/golang"
	HTTP_USER_AGENT_TCP                = "appmesh/golang/tcp"
	HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = "X-Send-File-Socket"
	HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = "X-Recv-File-Socket"

	DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24) // default 7 day(s)
)

// Requester interface
type ClientRequester interface {
	doRequest(method string, apiPath string, queries url.Values, headers map[string]string, body io.Reader, token string, forwardingHost string) (int, []byte, http.Header, error)
}

// Application json
type Application struct {
	// main definition
	Name           string  `json:"name"`
	Owner          *string `json:"owner"`
	Permission     *int    `json:"permission"`
	ShellMode      *bool   `json:"shell"`
	SessionLogin   *bool   `json:"session_login"`
	Command        *string `json:"command"`
	Description    *string `json:"description"`
	WorkingDir     *string `json:"working_dir"`
	HealthCheckCMD *string `json:"health_check_cmd"`
	Status         int     `json:"status"`
	StdoutCacheNum *int    `json:"stdout_cache_num"`
	Metadata       *string `json:"metadata"`

	// time
	StartTime     *int64 `json:"start_time"`
	EndTime       *int64 `json:"end_time"`
	LastStartTime *int64 `json:"last_start_time"`
	LastExitTime  *int64 `json:"last_exit_time"`
	NextStartTime *int64 `json:"next_start_time"`
	RegisterTime  *int64 `json:"register_time"`

	StopRetention *string   `json:"retention"`
	Behavior      *Behavior `json:"behavior"`
	// short running definition
	StartIntervalSeconds       *string `json:"start_interval_seconds"`
	StartIntervalSecondsIsCron *bool   `json:"cron"`

	// runtime attributes
	Pid            *int    `json:"pid"`
	ReturnCode     *int    `json:"return_code"`
	Health         *int    `json:"health"`
	FileDescritors *int    `json:"fd"`
	Starts         *int    `json:"starts"`
	PsTree         *string `json:"pstree"`
	ContainerID    *string `json:"container_id"`

	CPU             *float64 `json:"cpu"`
	Memory          *int     `json:"memory"`
	Uuid            *string  `json:"process_uuid"` // for run application
	StdoutCacheSize *int     `json:"stdout_cache_size"`

	Version   *int    `json:"version"`
	LastError *string `json:"last_error"`

	DockerImage *string `json:"docker_image"`

	DailyLimit    *DailyLimitation    `json:"daily_limitation"`
	ResourceLimit *ResourceLimitation `json:"resource_limit"`
	Env           *Environments       `json:"env"`
	SecEnv        *Environments       `json:"sec_env"`
}

// Behavior
type Behavior struct {
	Exit string `json:"exit"`
}

// Daily time limitation
type DailyLimitation struct {
	DailyStart string `json:"daily_start"`
	DailyEnd   string `json:"daily_end"`
}

// CPU & Memory limitation
type ResourceLimitation struct {
	MemoryMb        int `json:"memory_mb"`
	MemoryVirtualMb int `json:"memory_virt_mb"`
	CpuShares       int `json:"cpu_shares"`
}

// JWT Response
type JWTResponse struct {
	AccessToken   string `json:"Access-Token"`
	ExpireSeconds int    `json:"expire_seconds"`
	ExpireTime    int    `json:"expire_time"`
	Profile       struct {
		AuthTime int    `json:"auth_time"`
		Name     string `json:"name"`
	} `json:"profile"`
	TokenType string `json:"token_type"`
}

type AppOutput struct {
	HttpSuccess    bool
	HttpBody       string
	OutputPosition *int64
	ExitCode       *int
	Error          error
}

// Env json
type Environments = map[string]string

// Label json
type Labels = map[string]string

// REST Headers
type Headers = map[string]string

type SSLConfig struct {
	VerifyClient                bool   `yaml:"VerifyClient"`
	VerifyServer                bool   `yaml:"VerifyServer"`
	VerifyServerDelegate        bool   `yaml:"VerifyServerDelegate"`
	SSLCaPath                   string `yaml:"SSLCaPath"`
	SSLCertificateFile          string `yaml:"SSLCertificateFile"`
	SSLCertificateKeyFile       string `yaml:"SSLCertificateKeyFile"`
	SSLClientCertificateFile    string `yaml:"SSLClientCertificateFile"`
	SSLClientCertificateKeyFile string `yaml:"SSLClientCertificateKeyFile"`
}

// Request represents the message sent over TCP
type Request struct {
	Uuid          string            `msg:"uuid" msgpack:"uuid"`
	RequestUri    string            `msg:"request_uri" msgpack:"request_uri"`
	HttpMethod    string            `msg:"http_method" msgpack:"http_method"`
	ClientAddress string            `msg:"client_addr" msgpack:"client_addr"`
	Body          string            `msg:"body" msgpack:"body"`
	Headers       map[string]string `msg:"headers" msgpack:"headers"`
	Queries       map[string]string `msg:"querys" msgpack:"querys"`
}

func (r *Request) Serialize() ([]byte, error) {
	return msgpack.Marshal(r)
}

// Response represents the message received over TCP
type Response struct {
	Uuid        string            `msg:"uuid" msgpack:"uuid"`
	RequestUri  string            `msg:"request_uri" msgpack:"request_uri"`
	HttpStatus  int               `msg:"http_status" msgpack:"http_status"`
	BodyMsgType string            `msg:"body_msg_type" msgpack:"body_msg_type"`
	Body        string            `msg:"body" msgpack:"body"`
	Headers     map[string]string `msg:"headers" msgpack:"headers"`
}

func (r *Response) Deserialize(data []byte) error {
	return msgpack.Unmarshal(data, r)
}
