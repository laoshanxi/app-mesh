package appmesh

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"

	"github.com/rs/xid"
	"github.com/vmihailenco/msgpack/v5"
)

// Client-facing defaults.
const (
	DefaultHTTPURI            = "https://127.0.0.1:6060"
	DefaultTCPURI             = "127.0.0.1:6059"
	DefaultTokenExpireSeconds = 7 * (60 * 60 * 24) // default 7 day(s)
	DefaultJWTAudience        = "appmesh-service"
)

// Internal wire-protocol constants (headers, cookies, user agents).
const (
	userAgentHeaderName         = "User-Agent"
	headerCSRFToken             = "X-CSRF-Token"
	headerJWTSetCookie          = "X-Set-Cookie"
	cookieToken                 = "appmesh_auth_token"
	cookieCSRFToken             = "appmesh_csrf_token"
	userAgent                   = "appmesh/golang"
	userAgentTCP                = "appmesh/golang/tcp"
	userAgentWSS                = "appmesh/golang/wss"
	headerSendFileSocket        = "X-Send-File-Socket"
	headerRecvFileSocket        = "X-Recv-File-Socket"
	headerFilePath              = "X-File-Path"
	headerTargetHost            = "X-Target-Host"
	tokenRefreshIntervalSeconds = 300 // 5 minutes
	tokenRefreshOffsetSeconds   = 30  // 30 seconds before expiry
)

// Platform-aware default SSL paths.
var (
	defaultSSLDir            string
	DefaultClientCertFile    string
	DefaultClientCertKeyFile string
	DefaultCAFile            string
)

func init() {
	if runtime.GOOS == "windows" {
		defaultSSLDir = "c:/local/appmesh/ssl"
	} else {
		defaultSSLDir = "/opt/appmesh/ssl"
	}

	DefaultClientCertFile = filepath.Join(defaultSSLDir, "client.pem")
	DefaultClientCertKeyFile = filepath.Join(defaultSSLDir, "client-key.pem")
	DefaultCAFile = filepath.Join(defaultSSLDir, "ca.pem")
}

// Application represents the application configuration and status.
type Application struct {
	// Main definition
	Name           string           `json:"name"`
	Owner          *string          `json:"owner"`
	Permission     *int             `json:"permission"`
	ShellMode      *bool            `json:"shell"`
	SessionLogin   *bool            `json:"session_login"`
	Command        *string          `json:"command"`
	Description    *string          `json:"description"`
	WorkingDir     *string          `json:"working_dir"`
	HealthCheckCMD *string          `json:"health_check_cmd"`
	Status         int              `json:"status"`
	StdoutCacheNum *int             `json:"stdout_cache_num"`
	Metadata       *json.RawMessage `json:"metadata,omitempty"`

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
	StartIntervalSeconds *string `json:"start_interval_seconds"`
	// StartIntervalSecondsIsCron indicates StartIntervalSeconds is a cron expression;
	// it maps to the "cron" wire key.
	StartIntervalSecondsIsCron *bool `json:"cron"`

	// Runtime attributes
	Pid        *int    `json:"pid"`
	User       *string `json:"pid_user"`
	ReturnCode *int    `json:"return_code"`
	Health     *int    `json:"health"`
	// FileDescriptors is the process file descriptor count (JSON tag "fd" is wire-fixed).
	FileDescriptors *int    `json:"fd"`
	Starts          *int    `json:"starts"`
	PsTree          *string `json:"pstree"`
	ContainerID     *string `json:"container_id"`

	CPU    *float64 `json:"cpu"`
	Memory *int     `json:"memory"`
	// UUID identifies a run-application process.
	UUID            *string `json:"process_uuid"` // For run application
	StdoutCacheSize *int    `json:"stdout_cache_size"`

	Version   *int    `json:"version"`
	LastError *string `json:"last_error"`

	DockerImage *string `json:"docker_image"`

	DailyLimit    *DailyLimitation    `json:"daily_limitation"`
	ResourceLimit *ResourceLimitation `json:"resource_limit"`
	Env           *Environments       `json:"env"`
	SecEnv        *Environments       `json:"sec_env"`

	TaskId     *int    `json:"task_id"`
	TaskStatus *string `json:"task_status"`

	SubscriptionID string `json:"subscription_id,omitempty"`
}

// AppRun represents the state of an asynchronous application run.
// ForwardTo snapshots the client's forwarding target so Wait can keep polling the same node.
type AppRun struct {
	AppName   string
	ProcUid   string
	ForwardTo string
}

// Behavior represents the behavior configuration of an application.
type Behavior struct {
	Exit    string            `json:"exit"`
	Control map[string]string `json:"control,omitempty"`
}

// DailyLimitation represents the daily time limitation for an application.
type DailyLimitation struct {
	DailyStart *int64 `json:"daily_start"`
	DailyEnd   *int64 `json:"daily_end"`
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

// AppOutput represents the result of an AppMeshClient.GetAppOutput call.
type AppOutput struct {
	// HttpSuccess is true only when the server responded with HTTP 200 OK.
	HttpSuccess bool
	// HttpBody is the raw response body: output text on success, the server error text otherwise.
	HttpBody string
	// OutputPosition is the next read cursor (X-Output-Position header), when present.
	OutputPosition *int64
	// ExitCode is the process exit code (X-Exit-Code header), populated once the process has finished.
	ExitCode *int
	// Error is non-nil on transport failure or any non-200 HTTP status.
	Error error
}

// Environments represents a map of environment variables.
type Environments = map[string]string

// Labels represents a map of labels.
type Labels = map[string]string

// Headers represents a map of HTTP headers.
type Headers = map[string]string

// OutputHandler is a callback for incremental stdout output.
// data is the text chunk; position is the byte offset in the full output stream.
type OutputHandler func(data string, position int64)

// PrintOutputHandler is a convenience OutputHandler that prints data to stdout.
func PrintOutputHandler(data string, position int64) {
	fmt.Print(data)
}

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
// Wire-protocol internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
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
// Wire-protocol internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
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
// Wire-protocol internal shared with the App Mesh agent; not covered by SDK compatibility guarantees.
type Response struct {
	UUID        string            `msgpack:"uuid"`
	RequestUri  string            `msgpack:"request_uri"`
	HttpStatus  int               `msgpack:"http_status"`
	BodyMsgType string            `msgpack:"body_msg_type"`
	Body        []byte            `msgpack:"body"`
	Headers     map[string]string `msgpack:"headers"`
}

// Serialize serializes the Response into a byte slice.
func (r *Response) Serialize() ([]byte, error) {
	return msgpack.Marshal(r)
}

// Deserialize deserializes the byte slice into a Response.
func (r *Response) Deserialize(data []byte) error {
	return msgpack.Unmarshal(data, r)
}

// iso8601DurationRe matches ISO 8601 duration strings like P1W, P2DT12H, PT5M30S, P1Y2M3DT4H5M6S.
var iso8601DurationRe = regexp.MustCompile(
	`^P(?:(\d+)Y)?(?:(\d+)M)?(?:(\d+)W)?(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?)?$`,
)

// ParseDuration parses a duration string that is either an integer (seconds) or an ISO 8601
// duration (e.g. "P1W", "P2DT12H", "PT5M30S"). Returns the total number of seconds.
// Approximate conversion: 1 month ≈ 30 days, 1 year ≈ 365 days.
func ParseDuration(s string) (int, error) {
	s = strings.TrimSpace(s)
	// Try integer first
	if secs, err := strconv.Atoi(s); err == nil {
		return secs, nil
	}
	// Try ISO 8601 duration
	s = strings.ToUpper(s)
	m := iso8601DurationRe.FindStringSubmatch(s)
	if m == nil {
		return 0, fmt.Errorf("invalid duration: %q (expected integer seconds or ISO 8601 duration like P1W, P2DT12H)", s)
	}
	atoi := func(v string) int {
		n, _ := strconv.Atoi(v)
		return n
	}
	years := atoi(m[1])
	months := atoi(m[2])
	weeks := atoi(m[3])
	days := atoi(m[4])
	hours := atoi(m[5])
	minutes := atoi(m[6])
	seconds := atoi(m[7])

	total := years*365*86400 + months*30*86400 + weeks*7*86400 + days*86400 + hours*3600 + minutes*60 + seconds
	return total, nil
}
