package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/xid"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/tlsconf"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

const (
	maxStdoutCapture = 65536
	maxWorkflowDepth = 4
	defaultMaxTime   = 172800
	// maxStepLogFileSize caps the archived step log (the streamed file keeps the
	// full output; the in-memory Stdout stays capped by maxStdoutCapture).
	maxStepLogFileSize = 50 << 20
)

// StepAppPrefix tags daemon Apps spawned for command steps. Workflow startup
// reconciliation uses this prefix together with Engine-auditable metadata; the
// executor uses it to decide whether to DeleteApp at step end.
const StepAppPrefix = "wf-cmd-"

type StepExecutor struct {
	Client      *appmesh.AppMeshClient
	Ctx         *expression.Context
	JobName     string
	Depth       int
	CallerToken string // human caller Dex bearer only; internal capabilities are never injected into payloads
	ProcessUUID string // current managed Workflow process; used only to tag local temporary Apps
	// Capability-bound identity for temporary App metadata: sub-workflows keep the
	// top-level run identity because the capability is issued for the top-level run only.
	CapabilityWorkflowID string
	CapabilityRunID      string
	ClusterNodes         []string // known cluster node addresses for label-based routing
	TargetHost           string   // resolved target host for current job (set by engine per-job)
	ServerURI            string   // base server URI for creating forwarding clients
	OnAppStart           func(appName string)
	OnAppEnd             func(appName string)
	// path to write streaming step log (set per-step by engine)
	StepLogPath string
	// Finally marks a finally section; KillAll spares these cleanup steps.
	Finally bool
	// workflow cancel context (nil = background)
	CancelCtx      context.Context
	RunSubWorkflow func(ctx context.Context, wfName string, inputs map[string]string, depth int) (int,
		map[string]string, string, string) // exit code, outputs, sub run id, pre-run failure reason

	remoteClient *appmesh.AppMeshClientTCP // per-job cached remote connection (nil = local)
}

// Close releases the per-job remote TCP connection if one was opened.
func (e *StepExecutor) Close() {
	if e.remoteClient != nil {
		e.remoteClient.CloseConnection()
		e.remoteClient = nil
	}
}

func (e *StepExecutor) Execute(step *models.Step, env, secretEnv map[string]string) models.StepResult {
	resolved, err := resolveEnv(env, e.Ctx, e.JobName)
	if err != nil {
		return fail(1, err.Error(), 0)
	}
	resolvedSecretEnv, err := resolveEnv(secretEnv, e.Ctx, e.JobName)
	if err != nil {
		return fail(1, err.Error(), 0)
	}

	switch step.Type {
	case models.StepCommand:
		return e.execCommand(step, resolved, resolvedSecretEnv)
	case models.StepApp:
		return e.execApp(step, resolved, resolvedSecretEnv)
	default:
		result := e.execLocal(step, resolved, resolvedSecretEnv)
		// Workflow/message steps have no streaming app output; archive it to the step log.
		e.archiveStepLog(result.Stdout)
		return result
	}
}

// execLocal runs the step types that produce no on-demand App.
func (e *StepExecutor) execLocal(step *models.Step, env, secretEnv map[string]string) models.StepResult {
	switch step.Type {
	case models.StepMessage:
		return e.execMessage(step)
	case models.StepWorkflow:
		return e.execWorkflow(step, env, secretEnv)
	default:
		return fail(1, "unknown step type", 0)
	}
}

// archiveStepLog appends non-streamed step stdout to the step log file.
func (e *StepExecutor) archiveStepLog(content string) {
	if e.StepLogPath == "" || content == "" {
		return
	}
	os.MkdirAll(filepath.Dir(e.StepLogPath), 0700)
	if f, err := os.OpenFile(e.StepLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
		f.WriteString(content)
		f.Close()
	}
}

func (e *StepExecutor) execCommand(step *models.Step, env, secretEnv map[string]string) models.StepResult {
	shell := true
	if step.Shell != nil {
		shell = *step.Shell
	}
	appName := StepAppPrefix + xid.New().String()
	var command string
	var exprEnv map[string]string
	var err error
	if shell {
		// Shell commands receive expression values through $WF_E<N> environment
		// variables: a value like "a; rm -rf /" must never become command text.
		command, exprEnv, err = expression.SubstituteForCommand(step.Command, e.Ctx, e.JobName)
	} else {
		// No shell expands the variable, so keep direct substitution.
		command, err = expression.SubstituteForJobChecked(step.Command, e.Ctx, e.JobName)
	}
	if err != nil {
		return fail(1, err.Error(), 0)
	}
	if len(exprEnv) > 0 {
		// Fresh map: the caller's env is the job's and must not be mutated.
		merged := make(map[string]string, len(env)+len(exprEnv))
		maps.Copy(merged, env)
		maps.Copy(merged, exprEnv)
		env = merged
	}
	metadata := stepAppMetadata(e.CapabilityWorkflowID, e.CapabilityRunID, e.Ctx, e.ProcessUUID)
	app := appmesh.Application{
		Name:      appName,
		Command:   &command,
		ShellMode: &shell,
		Env:       envPtr(env),
		SecretEnv: envPtr(secretEnv),
		Metadata:  &metadata,
	}
	if step.Workdir != "" {
		workdir, err := expression.SubstituteForJobChecked(step.Workdir, e.Ctx, e.JobName)
		if err != nil {
			return fail(1, err.Error(), 0)
		}
		app.WorkingDir = &workdir
	}
	if step.DockerImage != "" {
		image, err := expression.SubstituteForJobChecked(step.DockerImage, e.Ctx, e.JobName)
		if err != nil {
			return fail(1, err.Error(), 0)
		}
		app.DockerImage = &image
	}
	return e.runAndWait(app, step.Timeout)
}

func (e *StepExecutor) execApp(step *models.Step, env, secretEnv map[string]string) models.StepResult {
	app := appmesh.Application{
		Name:      step.App,
		Env:       envPtr(env),
		SecretEnv: envPtr(secretEnv),
	}
	return e.runAndWait(app, step.Timeout)
}

func (e *StepExecutor) execMessage(step *models.Step) models.StepResult {
	if step.Message == nil {
		return fail(1, "no message config", 0)
	}
	payload, err := expression.SubstituteForJobChecked(step.Message.Payload, e.Ctx, e.JobName)
	if err != nil {
		return fail(1, err.Error(), 0)
	}
	if step.Message.ForwardToken && e.CallerToken != "" {
		payload = injectToken(payload, e.CallerToken) // identity for llm-agent-style targets; never logged
	}
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
		// App-level error: a target that follows the platform task-response convention
		// ({"status":"error","message":...}, used by llm-agent and the engine itself)
		// reports a logical failure with a transport-success RPC. Surface it as a failed
		// step so downstream `if:`/`needs` see it, instead of silently treating it as
		// success. Non-conforming responses (other JSON, plain text) are unaffected.
		if msg, isErr := appLevelError(r.resp); isErr {
			res := fail(1, msg, dur)
			res.Response = r.resp // keep the full body for ${{ steps.<name>.response }}
			return res
		}
		code := 0
		return models.StepResult{
			Status:   models.StatusSuccess,
			ExitCode: &code,
			Stdout:   truncate(r.resp, maxStdoutCapture),
			Response: r.resp,
			Outputs:  appLevelAnswer(r.resp),
			Duration: dur,
		}
	case <-ctx.Done():
		// Best-effort cancel: the DELETE task API can't abort the target's in-flight work
		// (and may hit another caller's task on a shared App). Drain the abandoned RunTask
		// so its eventual result is logged, not leaked.
		go func() {
			r := <-ch
			if r.err != nil {
				logger.Info("cancelled message step to app '" + step.Message.App + "' finished with error: " + r.err.Error())
			} else {
				logger.Info("cancelled message step to app '" + step.Message.App +
					"' completed after cancellation; response discarded")
			}
		}()
		return fail(1, "cancelled", time.Since(start).Seconds())
	}
}

// appLevelError reports whether a message-step response is the platform error envelope
// {"status":"error", ...} and returns its message. Only a JSON object whose "status" is
// exactly "error" counts; non-JSON, arrays, or other statuses are not failures.
func appLevelError(resp string) (string, bool) {
	var env struct {
		Status  string `json:"status"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(resp), &env); err != nil || env.Status != "error" {
		return "", false
	}
	if env.Message == "" {
		return "app returned status=error", true
	}
	return env.Message, true
}

// appLevelAnswer extracts the platform task-response convention's answer field
// ({"status":"ok","data":{"answer":...}}, used by llm-agent) so pipelines can use
// ${{ steps.<name>.outputs.answer }} instead of parsing the JSON envelope in shell.
// nil when the response does not carry one.
func appLevelAnswer(resp string) map[string]string {
	var env struct {
		Data struct {
			Answer string `json:"answer"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(resp), &env); err != nil || env.Data.Answer == "" {
		return nil
	}
	return map[string]string{"answer": env.Data.Answer}
}

// injectToken adds the run's Dex bearer as the "token" field of a JSON-object payload, for
// message steps with forward_token. It is a no-op when the payload is not a JSON object
// or already carries a "token" (an author-set value wins). Field order is not preserved
// (irrelevant for JSON). The caller guarantees token != "".
func injectToken(payload, token string) string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(payload), &obj); err != nil || obj == nil {
		return payload // not a JSON object → leave untouched
	}
	if _, ok := obj["token"]; ok {
		return payload // explicit author value wins
	}
	tok, err := json.Marshal(token)
	if err != nil {
		return payload
	}
	obj["token"] = tok
	out, err := json.Marshal(obj)
	if err != nil {
		return payload
	}
	return string(out)
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
		val, err := expression.SubstituteForJobChecked(v, e.Ctx, e.JobName)
		if err != nil {
			return fail(1, err.Error(), 0)
		}
		resolvedInputs[k] = val
	}

	maxTime := step.Timeout
	if maxTime <= 0 {
		maxTime = defaultMaxTime
	}
	subCtx, subCancel := context.WithTimeout(e.cancelContext(), time.Duration(maxTime)*time.Second)
	defer subCancel()

	start := time.Now()
	exitCode, outputs, subRunID, subErr := e.RunSubWorkflow(subCtx, step.WorkflowRef, resolvedInputs, e.Depth+1)
	dur := time.Since(start).Seconds()
	// The sub run id makes the sub run findable from the parent step.
	failed := func(msg string) models.StepResult {
		return fail(1, fmt.Sprintf("%s (sub run: %s)", msg, subRunID), dur)
	}
	if subErr != "" {
		if subRunID == "" {
			return fail(1, subErr, dur) // the sub run never started
		}
		return failed(subErr)
	}

	// Only report a cancel/timeout error if the sub-workflow was actually disrupted
	// (exit != 0). A cancel that arrives after the sub finishes its last layer is
	// too late to affect the result — match engine.go's between-layer cancel semantics.
	if subCtx.Err() != nil && exitCode != 0 {
		if subCtx.Err() == context.DeadlineExceeded {
			return failed("sub-workflow timeout")
		}
		return failed("cancelled")
	}

	if exitCode != 0 {
		return failed(fmt.Sprintf("sub-workflow failed with exit %d", exitCode))
	}
	return models.StepResult{
		Status:   models.StatusSuccess,
		ExitCode: &exitCode,
		Outputs:  outputs,
		Duration: dur,
	}
}

// stepAppMetadata binds a temporary command-step App to the run capability.
// The daemon rejects an App whose metadata does not equal the capability claims
// exactly, so a sub-workflow must stamp the top-level run identity here even
// though its expression context carries the sub-workflow identity.
func stepAppMetadata(capabilityWorkflowID, capabilityRunID string, ectx *expression.Context,
	processUUID string) json.RawMessage {
	workflowID, runID := capabilityWorkflowID, capabilityRunID
	if workflowID == "" {
		workflowID = ectx.WfName
	}
	if runID == "" {
		runID = ectx.WfRunID
	}
	metadataBytes, _ := json.Marshal(map[string]string{
		"type":         "workflow-step",
		"workflow_id":  workflowID,
		"run_id":       runID,
		"process_uuid": processUUID,
	})
	return metadataBytes
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
		// logBytes caps the archived step log so a runaway step cannot fill the disk.
		logBytes int64
	)
	if e.StepLogPath != "" {
		os.MkdirAll(filepath.Dir(e.StepLogPath), 0700)
		if f, err := os.OpenFile(e.StepLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600); err == nil {
			logFile = f
		} else {
			logger.Error(fmt.Sprintf("cannot open step log %q: %v (stdout still captured in run record)", e.StepLogPath,
				err))
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
		if logFile != nil && logBytes < maxStepLogFileSize {
			if logBytes+int64(len(data)) > maxStepLogFileSize {
				n := maxStepLogFileSize - logBytes
				logFile.WriteString(data[:n])
				logFile.WriteString("\n[step log truncated at " +
					strconv.FormatInt(maxStepLogFileSize, 10) + " bytes]\n")
				logBytes = maxStepLogFileSize
			} else {
				logFile.WriteString(data)
				logBytes += int64(len(data))
			}
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
		client.DeleteApp(run.AppName)
	}

	status := models.StatusSuccess
	if ec != 0 {
		status = models.StatusFailure
	}
	// The daemon kills a run at its max time, surfacing as SIGKILL (exit 9)
	// rather than a client-side error; label it so a timeout is tellable from
	// an ordinary crash exit.
	var reason string
	if !disconnected {
		switch {
		case exitCode == nil && e.cancelContext().Err() != nil:
			reason = "step cancelled before exit"
		case exitCode == nil && waitErr != nil:
			reason = fmt.Sprintf("step ended without an exit code: %v", waitErr)
		case exitCode == nil:
			reason = fmt.Sprintf("step killed by timeout after %ds", maxTime)
		case ec == 9 && dur >= float64(maxTime)-0.5:
			reason = fmt.Sprintf("step killed by timeout after %ds", maxTime)
		}
	}
	return models.StepResult{
		Status:   status,
		ExitCode: &ec,
		Stdout:   truncate(strings.TrimSpace(out), maxStdoutCapture),
		Response: reason,
		Duration: dur,
		// The streamed file (if any) holds the uncapped archive; flag it so the
		// engine does not overwrite it with this capped Stdout.
		StreamedLog: f != nil,
	}
}

func (e *StepExecutor) cancelContext() context.Context {
	if e.CancelCtx != nil {
		return e.CancelCtx
	}
	return context.Background()
}

// clientForTarget uses the node-local run capability only for local execution.
// A remote request carries the transient human caller bearer, which is valid on
// every node sharing the same Dex issuer. The local capability is never copied.
func (e *StepExecutor) clientForTarget() (*appmesh.AppMeshClient, error) {
	if e.TargetHost == "" {
		return e.Client, nil
	}
	if e.CallerToken == "" {
		return nil, fmt.Errorf("cross-node execution to %s requires a transient caller Dex bearer", e.TargetHost)
	}
	if e.remoteClient != nil {
		e.remoteClient.SetToken(e.CallerToken)
		return e.remoteClient.AppMeshClient, nil
	}
	option := appmesh.Option{
		AppMeshURI: e.ServerURI,
		ForwardTo:  e.TargetHost,
		JWTToken:   e.CallerToken,
	}
	tlsconf.Apply(&option)
	c, err := appmesh.NewTCPClient(option)
	if err != nil {
		return nil, fmt.Errorf("connect to remote node %s: %w", e.TargetHost, err)
	}
	e.remoteClient = c
	return c.AppMeshClient, nil
}

func resolveEnv(env map[string]string, ctx *expression.Context, jobName string) (map[string]string, error) {
	out := make(map[string]string, len(env))
	for k, v := range env {
		val, err := expression.SubstituteForJobChecked(v, ctx, jobName)
		if err != nil {
			return nil, err
		}
		out[k] = val
	}
	return out, nil
}

func fail(code int, msg string, dur float64) models.StepResult {
	msg = truncate(msg, maxStdoutCapture)
	return models.StepResult{
		Status:   models.StatusFailure,
		ExitCode: &code,
		Stdout:   msg,
		Response: msg,
		Duration: dur,
	}
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) > max {
		return s[:max] + fmt.Sprintf("\n[stdout truncated at %d bytes]", max)
	}
	return s
}

func envPtr(m map[string]string) *appmesh.Environments {
	if len(m) == 0 {
		return nil
	}
	e := appmesh.Environments(m)
	return &e
}
