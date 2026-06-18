package models

// StepType identifies what kind of step this is.
type StepType int

const (
	StepCommand StepType = iota
	StepApp
	StepMessage
	StepWorkflow
)

// Status values shared by Step and Job.
const (
	StatusPending = "pending"
	StatusRunning = "running"
	StatusSuccess = "success"
	StatusFailure = "failure"
	StatusSkipped = "skipped"
)

type RetryPolicy struct {
	Max      int    `yaml:"max"`
	Backoff  string `yaml:"backoff"`  // "fixed" or "exponential"
	Interval int    `yaml:"interval"` // seconds
}

type MessageConfig struct {
	App     string `yaml:"app"`
	Payload string `yaml:"payload"`
	// ForwardToken injects the run's caller JWT into the JSON payload's "token" field
	// before RunTask (opt-in). Used by identity-forwarding targets like llm-agent that
	// read the caller token from the payload body. No-op for auto/recovered runs (no
	// caller token) or non-object payloads; an author-set "token" wins.
	ForwardToken bool `yaml:"forward_token,omitempty"`
}

type StepResult struct {
	Status   string
	ExitCode *int
	Stdout   string
	Response string
	Outputs  map[string]string
	Duration float64
}

type Step struct {
	Name        string            `yaml:"name"`
	Type        StepType          `yaml:"-"`
	Command     string            `yaml:"command,omitempty"`
	App         string            `yaml:"app,omitempty"`
	Message     *MessageConfig    `yaml:"message,omitempty"`
	WorkflowRef string            `yaml:"workflow,omitempty"`
	With        map[string]string `yaml:"with,omitempty"`
	Workdir     string            `yaml:"workdir,omitempty"`
	Shell       *bool             `yaml:"shell,omitempty"`
	DockerImage string            `yaml:"docker_image,omitempty"`
	Condition   string            `yaml:"if,omitempty"`
	Timeout     int               `yaml:"timeout,omitempty"`
	Retry       *RetryPolicy      `yaml:"retry,omitempty"`
	ContinueOnError bool          `yaml:"continue-on-error,omitempty"`
	Env         map[string]string `yaml:"env,omitempty"`
	SecEnv      map[string]string `yaml:"sec_env,omitempty"`
	Result      StepResult        `yaml:"-"`
}

type Job struct {
	Name      string            `yaml:"-"`
	Needs     []string          `yaml:"needs,omitempty"`
	Condition string            `yaml:"if,omitempty"`
	NodeLabel map[string]string `yaml:"node_label,omitempty"`
	Env       map[string]string `yaml:"env,omitempty"`
	SecEnv    map[string]string `yaml:"sec_env,omitempty"`
	Steps     []Step            `yaml:"steps"`
	Finally   []Step            `yaml:"finally,omitempty"`
	Status    string            `yaml:"-"`
}

type TriggerAppEvent struct {
	App       string   `yaml:"app"`
	Events    []string `yaml:"events"`
	Condition string   `yaml:"condition,omitempty"`
}

// ScheduleTrigger is parsed but NOT dispatched by the engine.
// Cron scheduling should be done externally via App Mesh cron apps (see ADR 0004).
type ScheduleTrigger struct {
	Cron string `yaml:"cron"`
}

type InputParam struct {
	Type        string      `yaml:"type"`
	Required    bool        `yaml:"required,omitempty"`
	Default     interface{} `yaml:"default,omitempty"`
	Description string      `yaml:"description,omitempty"`
}

type OutputParam struct {
	Value string `yaml:"value"`
}

type TriggerConfig struct {
	AppEvent     *TriggerAppEvent     `yaml:"app_event,omitempty"`
	Schedule     []ScheduleTrigger    `yaml:"schedule,omitempty"`
	Manual       *ManualTrigger       `yaml:"manual,omitempty"`
	WorkflowCall *WorkflowCallTrigger `yaml:"workflow_call,omitempty"`
}

type ManualTrigger struct {
	Inputs map[string]InputParam `yaml:"inputs,omitempty"`
}

type WorkflowCallTrigger struct {
	Inputs  map[string]InputParam  `yaml:"inputs,omitempty"`
	Outputs map[string]OutputParam `yaml:"outputs,omitempty"`
}

type ConcurrencyConfig struct {
	Group            string `yaml:"group"`
	CancelInProgress bool   `yaml:"cancel-in-progress,omitempty"`
}

type Workflow struct {
	Name        string             `yaml:"name"`
	Owner       string             `yaml:"owner,omitempty"`
	Permission  int                `yaml:"permission,omitempty"`
	On          *TriggerConfig     `yaml:"on,omitempty"`
	Concurrency *ConcurrencyConfig `yaml:"concurrency,omitempty"`
	Env         map[string]string  `yaml:"env,omitempty"`
	SecEnv      map[string]string  `yaml:"sec_env,omitempty"`
	Jobs        map[string]*Job    `yaml:"jobs"`
}
