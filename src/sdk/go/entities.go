package appmesh

const (
	DefaultServerUri         = "https://localhost:6060"
	DefaultClientCertFile    = "/opt/appmesh/ssl/client.pem"
	DefaultClientCertKeyFile = "/opt/appmesh/ssl/client-key.pem"
	DefaultCAFile            = "/opt/appmesh/ssl/ca.pem"

	HTTP_USER_AGENT_HEADER_NAME = "User-Agent"
	HTTP_USER_AGENT             = "appmesh/golang"

	DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24) // default 7 day(s)
)

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

// https://mholt.github.io/json-to-go/
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
