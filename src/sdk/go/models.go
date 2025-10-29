package appmesh

import (
	"path/filepath"
	"runtime"

	"github.com/rs/xid"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	DEFAULT_HTTP_URI                   = "https://127.0.0.1:6060"
	DEFAULT_TCP_URI                    = "127.0.0.1:6059"
	DEFAULT_TOKEN_EXPIRE_SECONDS       = 7 * (60 * 60 * 24) // default 7 day(s)
	DEFAULT_JWT_AUDIENCE               = "appmesh-service"
	HTTP_USER_AGENT_HEADER_NAME        = "User-Agent"
	HTTP_HEADER_NAME_CSRF_TOKEN        = "X-CSRF-Token"
	HTTP_HEADER_JWT_SET_COOKIE         = "X-Set-Cookie"
	COOKIE_CSRF_TOKEN                  = "appmesh_csrf_token"
	HTTP_USER_AGENT                    = "appmesh/golang"
	HTTP_USER_AGENT_TCP                = "appmesh/golang/tcp"
	HTTP_HEADER_KEY_X_SEND_FILE_SOCKET = "X-Send-File-Socket"
	HTTP_HEADER_KEY_X_RECV_FILE_SOCKET = "X-Recv-File-Socket"
	HTTP_HEADER_KEY_File_Path          = "X-File-Path"
	TOKEN_REFRESH_INTERVAL_SECONDS     = 300 // 5 minutes
	TOKEN_REFRESH_OFFSET_SECONDS       = 30  // 30 seconds before expiry
)

var (
	// Platform-aware default SSL paths
	_DEFAULT_SSL_DIR             string
	DEFAULT_CLIENT_CERT_FILE     string
	DEFAULT_CLIENT_CERT_KEY_FILE string
	DEFAULT_CA_FILE              string
)

func init() {
	if runtime.GOOS == "windows" {
		_DEFAULT_SSL_DIR = "c:/local/appmesh/ssl"
	} else {
		_DEFAULT_SSL_DIR = "/opt/appmesh/ssl"
	}

	DEFAULT_CLIENT_CERT_FILE = filepath.Join(_DEFAULT_SSL_DIR, "client.pem")
	DEFAULT_CLIENT_CERT_KEY_FILE = filepath.Join(_DEFAULT_SSL_DIR, "client-key.pem")
	DEFAULT_CA_FILE = filepath.Join(_DEFAULT_SSL_DIR, "ca.pem")
}

// Application represents the application configuration and status.
type Application struct {
	// Main definition
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

	// Time
	StartTime     *int64 `json:"start_time"`
	EndTime       *int64 `json:"end_time"`
	LastStartTime *int64 `json:"last_start_time"`
	LastExitTime  *int64 `json:"last_exit_time"`
	NextStartTime *int64 `json:"next_start_time"`
	RegisterTime  *int64 `json:"register_time"`

	StopRetention *string   `json:"retention"`
	Behavior      *Behavior `json:"behavior"`
	// Short running definition
	StartIntervalSeconds       *string `json:"start_interval_seconds"`
	StartIntervalSecondsIsCron *bool   `json:"cron"`

	// Runtime attributes
	Pid            *int    `json:"pid"`
	User           *string `json:"pid_user"`
	ReturnCode     *int    `json:"return_code"`
	Health         *int    `json:"health"`
	FileDescritors *int    `json:"fd"`
	Starts         *int    `json:"starts"`
	PsTree         *string `json:"pstree"`
	ContainerID    *string `json:"container_id"`

	CPU             *float64 `json:"cpu"`
	Memory          *int     `json:"memory"`
	Uuid            *string  `json:"process_uuid"` // For run application
	StdoutCacheSize *int     `json:"stdout_cache_size"`

	Version   *int    `json:"version"`
	LastError *string `json:"last_error"`

	DockerImage *string `json:"docker_image"`

	DailyLimit    *DailyLimitation    `json:"daily_limitation"`
	ResourceLimit *ResourceLimitation `json:"resource_limit"`
	Env           *Environments       `json:"env"`
	SecEnv        *Environments       `json:"sec_env"`

	TaskId     *string `json:"task_id"`
	TaskStatus *string `json:"task_status"`
}

// AppRun represents the state of an asynchronous application run.
type AppRun struct {
	AppName   string
	ProcUid   string
	ForwardTo string
}

// Behavior represents the behavior configuration of an application.
type Behavior struct {
	Exit string `json:"exit"`
}

// DailyLimitation represents the daily time limitation for an application.
type DailyLimitation struct {
	DailyStart string `json:"daily_start"`
	DailyEnd   string `json:"daily_end"`
}

// ResourceLimitation represents the CPU and memory limitations for an application.
type ResourceLimitation struct {
	MemoryMb        int `json:"memory_mb"`
	MemoryVirtualMb int `json:"memory_virt_mb"`
	CpuShares       int `json:"cpu_shares"`
}

// JWTResponse represents the response containing JWT token information.
type JWTResponse struct {
	AccessToken   string `json:"access_token"`
	ExpireSeconds int    `json:"expire_seconds"`
	ExpireTime    int    `json:"expire_time"`
	Profile       struct {
		AuthTime int    `json:"auth_time"`
		Name     string `json:"name"`
	} `json:"profile"`
	TokenType string `json:"token_type"`
}

// AppOutput represents the output of an application.
type AppOutput struct {
	HttpSuccess    bool
	HttpBody       string
	OutputPosition *int64
	ExitCode       *int
	Error          error
}

// Environments represents a map of environment variables.
type Environments = map[string]string

// Labels represents a map of labels.
type Labels = map[string]string

// Headers represents a map of HTTP headers.
type Headers = map[string]string

// SSLConfig represents the SSL configuration.
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

// JWT Config
type JWTConfig struct {
	JWTSalt string `yaml:"JWTSalt"`
}

// Request represents the message sent over TCP.
type Request struct {
	UUID          string            `msgpack:"uuid"`
	RequestUri    string            `msgpack:"request_uri"`
	HttpMethod    string            `msgpack:"http_method"`
	ClientAddress string            `msgpack:"client_addr"`
	Body          []byte            `msgpack:"body"`
	Headers       map[string]string `msgpack:"headers"`
	Query         map[string]string `msgpack:"query"`
}

// NewRequest creates a Request with all fields initialized.
func NewRequest() *Request {
	return &Request{
		UUID:          xid.New().String(),
		RequestUri:    "",
		HttpMethod:    "",
		ClientAddress: "",
		Body:          []byte{},
		Headers:       map[string]string{},
		Query:         map[string]string{},
	}
}

// Serialize serializes the Request into a byte slice.
func (r *Request) Serialize() ([]byte, error) {
	return msgpack.Marshal(r)
}

// Response represents the message received over TCP.
type Response struct {
	UUID        string            `msgpack:"uuid"`
	RequestUri  string            `msgpack:"request_uri"`
	HttpStatus  int               `msgpack:"http_status"`
	BodyMsgType string            `msgpack:"body_msg_type"`
	Body        []byte            `msgpack:"body"`
	Headers     map[string]string `msgpack:"headers"`
}

// Deserialize deserializes the byte slice into a Response.
func (r *Response) Deserialize(data []byte) error {
	return msgpack.Unmarshal(data, r)
}
