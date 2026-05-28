package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/rs/xid"
)

const (
	maxStdoutCapture = 65536
	maxWorkflowDepth = 4
	defaultMaxTime   = 172800
)

// StepAppPrefix tags daemon Apps spawned for command steps. The trigger service
// uses it to sweep orphans on startup; the executor uses it to decide whether
// to RemoveApp at step end.
const StepAppPrefix = "wf-cmd-"

type StepExecutor struct {
	Client         *appmesh.AppMeshClient
	Ctx            *expression.Context
	JobName        string
	Depth          int
	ClusterNodes   []string // known cluster node addresses for label-based routing
	TargetHost     string   // resolved target host for current job (set by engine per-job)
	ServerURI      string   // base server URI for creating forwarding clients
	OnAppStart     func(appName string)
	OnAppEnd       func(appName string)
	StepLogPath    string                                                                                                 // path to write streaming step log (set per-step by engine)
	CancelCtx      context.Context                                                                                        // workflow cancel context (nil = background)
	RunSubWorkflow func(ctx context.Context, wfName string, inputs map[string]string, depth int) (int, map[string]string) // in-process sub-workflow execution (set by engine)

	remoteClient *appmesh.AppMeshClientTCP // per-job cached remote connection (nil = local)
}

// Close releases the per-job remote TCP connection if one was opened.
func (e *StepExecutor) Close() {
	if e.remoteClient != nil {
		e.remoteClient.CloseConnection()
		e.remoteClient = nil
	}
}

func (e *StepExecutor) Execute(step *models.Step, env, secEnv map[string]string) models.StepResult {
	resolved := resolveEnv(env, e.Ctx, e.JobName)
	resolvedSec := resolveEnv(secEnv, e.Ctx, e.JobName)

	switch step.Type {
	case models.StepCommand:
		return e.execCommand(step, resolved, resolvedSec)
	case models.StepApp:
		return e.execApp(step, resolved, resolvedSec)
	case models.StepMessage:
		return e.execMessage(step)
	case models.StepWorkflow:
		return e.execWorkflow(step, resolved, resolvedSec)
	default:
		return fail(1, "unknown step type", 0)
	}
}

func (e *StepExecutor) execCommand(step *models.Step, env, secEnv map[string]string) models.StepResult {
	shell := true
	if step.Shell != nil {
		shell = *step.Shell
	}
	appName := StepAppPrefix + xid.New().String()
	app := appmesh.Application{
		Name:      appName,
		Command:   strPtr(step.Command),
		ShellMode: &shell,
		Env:       envPtr(env),
		SecEnv:    envPtr(secEnv),
	}
	if step.Workdir != "" {
		app.WorkingDir = &step.Workdir
	}
	if step.DockerImage != "" {
		app.DockerImage = &step.DockerImage
	}
	return e.runAndWait(app, step.Timeout)
}

func (e *StepExecutor) execApp(step *models.Step, env, secEnv map[string]string) models.StepResult {
	app := appmesh.Application{
		Name:   step.App,
		Env:    envPtr(env),
		SecEnv: envPtr(secEnv),
	}
	return e.runAndWait(app, step.Timeout)
}

func (e *StepExecutor) execMessage(step *models.Step) models.StepResult {
	if step.Message == nil {
		return fail(1, "no message config", 0)
	}
	payload := expression.SubstituteForJob(step.Message.Payload, e.Ctx, e.JobName)
	timeout := step.Timeout
	if timeout <= 0 {
		timeout = 300
	}
	client, connErr := e.clientForTarget()
	if connErr != nil {
		return fail(1, connErr.Error(), 0)
	}
	start := time.Now()

	type taskResult struct {
		resp string
		err  error
	}
	ch := make(chan taskResult, 1)
	go func() {
		resp, err := client.RunTask(step.Message.App, payload, timeout)
		ch <- taskResult{resp, err}
	}()

	ctx := e.cancelContext()
	select {
	case r := <-ch:
		dur := time.Since(start).Seconds()
		if r.err != nil {
			return fail(1, r.err.Error(), dur)
		}
		code := 0
		return models.StepResult{
			Status:   models.StatusSuccess,
			ExitCode: &code,
			Stdout:   truncate(r.resp, maxStdoutCapture),
			Response: r.resp,
			Duration: dur,
		}
	case <-ctx.Done():
		return fail(1, "cancelled", time.Since(start).Seconds())
	}
}

func (e *StepExecutor) execWorkflow(step *models.Step, _, _ map[string]string) models.StepResult {
	if e.Depth >= maxWorkflowDepth {
		return fail(1, fmt.Sprintf("max workflow nesting depth (%d) exceeded", maxWorkflowDepth), 0)
	}
	if e.RunSubWorkflow == nil {
		return fail(1, "sub-workflow execution not available", 0)
	}

	resolvedInputs := make(map[string]string)
	for k, v := range step.With {
		resolvedInputs[k] = expression.SubstituteForJob(v, e.Ctx, e.JobName)
	}

	maxTime := step.Timeout
	if maxTime <= 0 {
		maxTime = defaultMaxTime
	}
	subCtx, subCancel := context.WithTimeout(e.cancelContext(), time.Duration(maxTime)*time.Second)
	defer subCancel()

	start := time.Now()
	exitCode, outputs := e.RunSubWorkflow(subCtx, step.WorkflowRef, resolvedInputs, e.Depth+1)
	dur := time.Since(start).Seconds()

	// Only report a cancel/timeout error if the sub-workflow was actually disrupted
	// (exit != 0). A cancel that arrives after the sub finishes its last layer is
	// too late to affect the result — match engine.go's between-layer cancel semantics.
	if subCtx.Err() != nil && exitCode != 0 {
		if subCtx.Err() == context.DeadlineExceeded {
			return fail(1, "sub-workflow timeout", dur)
		}
		return fail(1, "cancelled", dur)
	}

	status := models.StatusSuccess
	if exitCode != 0 {
		status = models.StatusFailure
	}
	return models.StepResult{
		Status:   status,
		ExitCode: &exitCode,
		Outputs:  outputs,
		Duration: dur,
	}
}

func (e *StepExecutor) runAndWait(app appmesh.Application, timeout int) models.StepResult {
	start := time.Now()
	maxTime := timeout
	if maxTime <= 0 {
		maxTime = defaultMaxTime
	}

	client, connErr := e.clientForTarget()
	if connErr != nil {
		return fail(1, connErr.Error(), 0)
	}

	run, err := client.RunAppAsync(app, maxTime, maxTime+3600)
	if err != nil {
		return fail(1, err.Error(), time.Since(start).Seconds())
	}

	isNewApp := strings.HasPrefix(app.Name, StepAppPrefix)
	if e.OnAppStart != nil {
		e.OnAppStart(run.AppName)
	}

	var (
		mu      sync.Mutex
		stdout  strings.Builder
		logFile *os.File
		fenced  bool // set true after we read stdout/closed logFile; blocks late writes
	)
	if e.StepLogPath != "" {
		os.MkdirAll(filepath.Dir(e.StepLogPath), 0700)
		if f, err := os.OpenFile(e.StepLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			logFile = f
		} else {
			logger.Error(fmt.Sprintf("cannot open step log %q: %v (stdout still captured in run record)", e.StepLogPath, err))
		}
	}

	onOutput := func(data string, position int64) {
		mu.Lock()
		defer mu.Unlock()
		if fenced {
			return // WaitForAsyncRun already returned; ignore late goroutine
		}
		if stdout.Len() < maxStdoutCapture {
			stdout.WriteString(data)
		}
		if logFile != nil {
			logFile.WriteString(data)
		}
	}

	exitCode, waitErr := client.WaitForAsyncRun(e.cancelContext(), run, onOutput, time.Duration(maxTime)*time.Second)

	// Fence: prevent any late onOutput goroutines from touching stdout/logFile.
	mu.Lock()
	fenced = true
	out := stdout.String()
	f := logFile
	logFile = nil
	mu.Unlock()
	if f != nil {
		f.Close()
	}

	dur := time.Since(start).Seconds()
	if e.OnAppEnd != nil {
		e.OnAppEnd(run.AppName)
	}

	disconnected := errors.Is(waitErr, appmesh.ErrTransportDisconnected)

	ec := -1
	if exitCode != nil {
		ec = *exitCode
	}
	if disconnected {
		if e.remoteClient != nil {
			e.remoteClient.CloseConnection()
			e.remoteClient = nil
		}
	} else if isNewApp {
		client.RemoveApp(run.AppName)
	}

	status := models.StatusSuccess
	if ec != 0 {
		status = models.StatusFailure
	}
	return models.StepResult{
		Status:   status,
		ExitCode: &ec,
		Stdout:   truncate(strings.TrimSpace(out), maxStdoutCapture),
		Duration: dur,
	}
}

func (e *StepExecutor) cancelContext() context.Context {
	if e.CancelCtx != nil {
		return e.CancelCtx
	}
	return context.Background()
}

// clientForTarget returns the TCP client for the target node.
// For local execution returns the shared client. For remote execution,
// creates a forwarding client once per job and caches it (closed via Close()).
// Pushes the latest local token on every call so the remote client doesn't
// hold an obsolete JWT after the local client's auto-refresh rotates it
// (the daemon blacklists rotated tokens).
func (e *StepExecutor) clientForTarget() (*appmesh.AppMeshClient, error) {
	if e.TargetHost == "" {
		return e.Client, nil
	}
	token := e.Client.GetToken()
	if e.remoteClient != nil {
		e.remoteClient.SetToken(token)
		return e.remoteClient.AppMeshClient, nil
	}
	noVerify := ""
	c, err := appmesh.NewTCPClient(appmesh.Option{
		AppMeshUri:   e.ServerURI,
		ForwardTo:    e.TargetHost,
		JwtToken:     token,
		SslTrustedCA: &noVerify,
	})
	if err != nil {
		return nil, fmt.Errorf("connect to remote node %s: %w", e.TargetHost, err)
	}
	e.remoteClient = c
	return c.AppMeshClient, nil
}

func resolveEnv(env map[string]string, ctx *expression.Context, jobName string) map[string]string {
	out := make(map[string]string, len(env))
	for k, v := range env {
		out[k] = expression.SubstituteForJob(v, ctx, jobName)
	}
	return out
}

func fail(code int, msg string, dur float64) models.StepResult {
	return models.StepResult{
		Status:   models.StatusFailure,
		ExitCode: &code,
		Stdout:   truncate(msg, maxStdoutCapture),
		Duration: dur,
	}
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max]
	}
	return s
}

func strPtr(s string) *string { return &s }

func envPtr(m map[string]string) *appmesh.Environments {
	if len(m) == 0 {
		return nil
	}
	e := appmesh.Environments(m)
	return &e
}
