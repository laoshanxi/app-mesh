package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/dag"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/executor"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/parser"
	"github.com/rs/xid"
)

// JobCallback is called after each job completes for checkpoint updates.
// steps contains per-step results (stdout, exit_code, status) for recovery.
type JobCallback func(jobName, status, targetHost string, steps map[string]map[string]any)

// StepCallback is called after each step completes for stdout archival.
type StepCallback func(jobName, stepName, stdout string)

// activeApp tracks a running step's daemon app and its target node.
type activeApp struct {
	appName    string
	targetHost string // empty = local node
}

// ActiveSteps tracks currently running step app names for cancel propagation.
type ActiveSteps struct {
	mu        sync.Mutex
	apps      map[string]activeApp // "job.step" → app info
	client    *appmesh.AppMeshClient
	serverURI string
}

func NewActiveSteps(client *appmesh.AppMeshClient, serverURI string) *ActiveSteps {
	return &ActiveSteps{
		apps:      make(map[string]activeApp),
		client:    client,
		serverURI: serverURI,
	}
}

func (a *ActiveSteps) Set(jobName, stepName, appName, targetHost string) {
	a.mu.Lock()
	a.apps[jobName+"."+stepName] = activeApp{appName: appName, targetHost: targetHost}
	a.mu.Unlock()
}

func (a *ActiveSteps) Remove(jobName, stepName string) {
	a.mu.Lock()
	delete(a.apps, jobName+"."+stepName)
	a.mu.Unlock()
}

// KillAll deletes all tracked running step apps from daemon (local and remote).
// Remote kills run in parallel to avoid one unreachable node blocking the rest.
func (a *ActiveSteps) KillAll() {
	a.mu.Lock()
	apps := make(map[string]activeApp, len(a.apps))
	for k, v := range a.apps {
		apps[k] = v
	}
	a.apps = make(map[string]activeApp)
	a.mu.Unlock()

	var wg sync.WaitGroup
	for _, app := range apps {
		if app.appName == "" {
			continue
		}
		if app.targetHost == "" {
			a.client.RemoveApp(app.appName)
		} else {
			wg.Add(1)
			go func(aa activeApp) {
				defer wg.Done()
				noVerify := ""
				c, err := appmesh.NewTCPClient(appmesh.Option{
					AppMeshUri:   a.serverURI,
					ForwardTo:    aa.targetHost,
					JwtToken:     a.client.GetToken(),
					SslTrustedCA: &noVerify,
				})
				if err == nil {
					c.RemoveApp(aa.appName)
					c.CloseConnection()
				}
			}(app)
		}
	}
	wg.Wait()
}

// Options configures workflow execution.
type Options struct {
	ClusterNodes      []string                              // known cluster node addresses
	ServerURI         string                                // TCP server address for forwarding clients
	DefaultTargetHost string                                // inherited target from parent job (sub-workflows)
	CompletedJobs     map[string]string                     // jobs to skip on recovery
	RecoveredSteps    map[string]map[string]map[string]any  // job → step → {stdout, exit_code, status, response}
	OnJobDone         JobCallback                           // checkpoint update
	OnStepDone        StepCallback                          // stdout archival (called after step, with full stdout)
	StepLogPathFn     func(jobName, stepName string) string // returns file path for streaming step log
	Log               logger.Log                            // per-run logger (nil = global stdout)
	ActiveSteps       *ActiveSteps                          // cancel tracking (nil = no tracking)
	CancelCtx         context.Context                       // workflow cancel context (passed to executors)
	WorkflowBaseDir   string                                // base directory for workflow YAML files
}

func (o *Options) log() logger.Log {
	if o.Log != nil {
		return o.Log
	}
	return logger.Global()
}

// RunWithContext executes a workflow with cancellation support and options.
// Returns exit code and the expression context (for output evaluation).
func RunWithContext(cancelCtx context.Context, wf *models.Workflow, client *appmesh.AppMeshClient, inputs map[string]string, runID string, depth int, opts Options) (int, *expression.Context) {
	log := opts.log()

	// Deep-copy Jobs so concurrent runs of the same workflow don't share
	// mutable Job.Status / Step.Result fields.
	wf = cloneWorkflow(wf)

	// Set up cancel tracking.
	if opts.ActiveSteps == nil {
		opts.ActiveSteps = NewActiveSteps(client, opts.ServerURI)
	}
	opts.CancelCtx = cancelCtx

	// Apply input defaults and validate required inputs.
	if inputs == nil {
		inputs = make(map[string]string)
	}
	if wf.On != nil {
		// Merge workflow_call + manual inputs. On key collision, manual wins
		// (the user-facing trigger), so a workflow exposed both ways has a single
		// coherent input surface.
		inputDefs := make(map[string]models.InputParam)
		if wf.On.WorkflowCall != nil {
			for k, v := range wf.On.WorkflowCall.Inputs {
				inputDefs[k] = v
			}
		}
		if wf.On.Manual != nil {
			for k, v := range wf.On.Manual.Inputs {
				inputDefs[k] = v
			}
		}
		for k, def := range inputDefs {
			if _, ok := inputs[k]; !ok {
				if def.Default != nil {
					inputs[k] = fmt.Sprintf("%v", def.Default)
				} else if def.Required {
					log.Error(fmt.Sprintf("required input %q not provided", k))
					log.WorkflowCompleted(wf.Name, runID, "failure", 0)
					return 1, nil
				}
			}
		}
	}

	ectx := expression.NewContext()
	ectx.WfName = wf.Name
	ectx.WfRunID = runID
	ectx.Inputs = inputs
	if wf.Env != nil {
		ectx.Env = wf.Env
	}

	log.WorkflowStarted(wf.Name, runID)
	start := time.Now()

	layers, err := dag.TopoSort(wf.Jobs)
	if err != nil {
		log.Error(err.Error())
		log.WorkflowCompleted(wf.Name, runID, "failure", time.Since(start).Seconds())
		return 1, ectx
	}

	var jobStatusMu sync.RWMutex
	failed := false

	for _, layer := range layers {
		if cancelCtx.Err() != nil {
			opts.ActiveSteps.KillAll()
			failed = true
			break
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		for _, name := range layer {
			wg.Add(1)
			go func(jobName string) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						log.Error(fmt.Sprintf("panic in job '%s': %v", jobName, r))
						mu.Lock()
						failed = true
						mu.Unlock()
					}
				}()
				job := wf.Jobs[jobName]
				exec, err := newExec(client, ectx, depth, opts, job)
				if err != nil {
					log.Error(err.Error())
					mu.Lock()
					failed = true
					mu.Unlock()
					return
				}
				defer exec.Close()
				if !runJob(job, exec, ectx, wf, &jobStatusMu, &opts, log) {
					mu.Lock()
					failed = true
					mu.Unlock()
				}
			}(name)
		}
		wg.Wait()
	}

	dur := time.Since(start).Seconds()
	status := "success"
	if failed {
		status = "failure"
	}
	log.WorkflowCompleted(wf.Name, runID, status, dur)

	if failed {
		return 1, ectx
	}
	return 0, ectx
}

func newExec(client *appmesh.AppMeshClient, ectx *expression.Context, depth int, opts Options, job *models.Job) (*executor.StepExecutor, error) {
	exec := &executor.StepExecutor{
		Client:       client,
		Ctx:          ectx,
		JobName:      job.Name,
		Depth:        depth,
		ClusterNodes: opts.ClusterNodes,
		ServerURI:    opts.ServerURI,
		CancelCtx:    opts.CancelCtx,
	}
	exec.RunSubWorkflow = func(ctx context.Context, wfName string, inputs map[string]string, subDepth int) (int, map[string]string) {
		subOpts := opts
		subOpts.DefaultTargetHost = exec.TargetHost
		subOpts.CancelCtx = ctx
		return runSubWorkflow(ctx, client, wfName, inputs, subDepth, subOpts)
	}
	if len(job.NodeLabel) > 0 {
		target, err := executor.ResolveTargetNode(client, opts.ServerURI, job.NodeLabel, opts.ClusterNodes)
		if err != nil {
			return nil, fmt.Errorf("node resolution failed for job '%s': %w", job.Name, err)
		}
		exec.TargetHost = target
	} else if opts.DefaultTargetHost != "" {
		exec.TargetHost = opts.DefaultTargetHost
	}
	return exec, nil
}

func skipJob(job *models.Job, ectx *expression.Context, statusMu *sync.RWMutex, opts *Options, log logger.Log, reason string) bool {
	statusMu.Lock()
	job.Status = models.StatusSkipped
	statusMu.Unlock()
	ectx.SetJobStatusForJob(job.Name, models.StatusSkipped)
	ectx.SetJobResult(job.Name, ectx.SnapshotJobSteps(job.Name), models.StatusSkipped)
	log.JobSkipped(job.Name, reason)
	if opts.OnJobDone != nil {
		opts.OnJobDone(job.Name, models.StatusSkipped, "", nil)
	}
	return true
}

func runJob(job *models.Job, exec *executor.StepExecutor, ectx *expression.Context, wf *models.Workflow, statusMu *sync.RWMutex, opts *Options, log logger.Log) bool {
	// Skip jobs already completed in a previous run (checkpoint recovery).
	if prev, ok := opts.CompletedJobs[job.Name]; ok {
		statusMu.Lock()
		job.Status = prev
		statusMu.Unlock()
		ectx.SetJobStatusForJob(job.Name, prev)

		// Restore step context from checkpoint so cross-job expressions work.
		if opts.RecoveredSteps != nil {
			if jobSteps, ok := opts.RecoveredSteps[job.Name]; ok {
				for stepName, data := range jobSteps {
					exitCode := toIntFromAny(data["exit_code"])
					stdout, _ := data["stdout"].(string)
					status, _ := data["status"].(string)
					response, _ := data["response"].(string)
					outputs, _ := data["outputs"].(map[string]string)
					ectx.SetStepResult(job.Name, stepName, stdout, exitCode, status, response, outputs)
				}
			}
		}
		ectx.SetJobResult(job.Name, ectx.SnapshotJobSteps(job.Name), prev)
		log.JobSkipped(job.Name, "recovered from checkpoint: "+prev)
		return prev != models.StatusFailure
	}

	needsSucceeded, needsFailed, depReason := evaluateNeeds(job, wf, statusMu)
	if job.Condition != "" {
		if !needsSucceeded && !hasStatusFunction(job.Condition) {
			return skipJob(job, ectx, statusMu, opts, log, depReason)
		}
		if !expression.EvalConditionForJobWithStatus(
			job.Condition, ectx, job.Name,
			func() bool { return needsSucceeded },
			func() bool { return needsFailed },
		) {
			return skipJob(job, ectx, statusMu, opts, log, "condition: "+job.Condition)
		}
	} else if !needsSucceeded {
		return skipJob(job, ectx, statusMu, opts, log, depReason)
	}

	statusMu.Lock()
	job.Status = models.StatusRunning
	statusMu.Unlock()
	ectx.SetJobStatusForJob(job.Name, models.StatusRunning)
	log.JobStarted(job.Name)

	mergedEnv := mergeEnv(wf.Env, job.Env)
	mergedSecEnv := mergeEnv(wf.SecEnv, job.SecEnv)

	jobFailed := false
	for i := range job.Steps {
		// Stop scheduling new steps once cancel is observed.
		if opts.CancelCtx != nil && opts.CancelCtx.Err() != nil {
			jobFailed = true
			markStepsSkipped(job.Steps[i:], ectx, job.Name, "cancelled", log)
			break
		}
		if !runStep(&job.Steps[i], exec, ectx, mergedEnv, mergedSecEnv, job.Name, opts, log) {
			jobFailed = true
			if job.Steps[i].ContinueOnError {
				jobFailed = false
				continue
			}
			markStepsSkipped(job.Steps[i+1:], ectx, job.Name, "previous step failed", log)
			break
		}
	}

	if len(job.Finally) > 0 {
		if jobFailed {
			ectx.SetJobStatusForJob(job.Name, models.StatusFailure)
		} else {
			ectx.SetJobStatusForJob(job.Name, models.StatusSuccess)
		}
		// Finally is cleanup — it must run to completion even when the workflow
		// was cancelled. Detach this (per-job) executor from the cancel context;
		// each finally step is still bounded by its own timeout.
		exec.CancelCtx = context.Background()
		log.JobFinallyStarted(job.Name)
		for i := range job.Finally {
			ectx.MarkFinallyStep(job.Name, job.Finally[i].Name)
			runStep(&job.Finally[i], exec, ectx, mergedEnv, mergedSecEnv, job.Name, opts, log)
		}
		log.JobFinallyCompleted(job.Name)
	}

	statusMu.Lock()
	if jobFailed {
		job.Status = models.StatusFailure
	} else {
		job.Status = models.StatusSuccess
	}
	finalStatus := job.Status
	statusMu.Unlock()

	ectx.SetJobStatusForJob(job.Name, finalStatus)
	log.JobCompleted(job.Name, finalStatus)
	stepSnap := ectx.SnapshotJobSteps(job.Name)
	ectx.SetJobResult(job.Name, stepSnap, finalStatus)

	if opts.OnJobDone != nil {
		opts.OnJobDone(job.Name, finalStatus, exec.TargetHost, stepSnap)
	}

	return !jobFailed
}

// markStepsSkipped records the given steps as skipped so they appear in run
// detail consistently with if-gated skips, instead of being silently absent.
func markStepsSkipped(steps []models.Step, ectx *expression.Context, jobName, reason string, log logger.Log) {
	for i := range steps {
		zero := 0
		steps[i].Result.Status = models.StatusSkipped
		steps[i].Result.ExitCode = &zero
		ectx.SetStepResult(jobName, steps[i].Name, "", zero, models.StatusSkipped, "", nil)
		log.StepSkipped(steps[i].Name, reason)
	}
}

func runStep(step *models.Step, exec *executor.StepExecutor, ectx *expression.Context, env, secEnv map[string]string, jobName string, opts *Options, log logger.Log) bool {
	if step.Condition != "" {
		if !expression.EvalConditionForJob(step.Condition, ectx, jobName) {
			step.Result.Status = models.StatusSkipped
			exitCode := 0
			step.Result.ExitCode = &exitCode
			ectx.SetStepResult(jobName, step.Name, "", exitCode, models.StatusSkipped, "", nil)
			log.StepSkipped(step.Name, "condition: "+step.Condition)
			return true
		}
	}

	stepEnv := mergeEnv(env, step.Env)
	stepSecEnv := mergeEnv(secEnv, step.SecEnv)

	maxAttempts := 1
	if step.Retry != nil {
		maxAttempts += step.Retry.Max
	}
	interval := 10
	backoff := "fixed"
	if step.Retry != nil {
		if step.Retry.Interval > 0 {
			interval = step.Retry.Interval
		}
		if step.Retry.Backoff != "" {
			backoff = step.Retry.Backoff
		}
	}

	for attempt := 0; attempt < maxAttempts; attempt++ {
		if attempt > 0 {
			wait := interval
			if backoff == "exponential" {
				shift := attempt - 1
				if shift < 30 {
					wait = interval * (1 << shift)
				} else {
					wait = 3600
				}
				if wait > 3600 {
					wait = 3600
				}
			}
			log.StepRetry(step.Name, attempt, step.Retry.Max)
			if opts.CancelCtx != nil {
				timer := time.NewTimer(time.Duration(wait) * time.Second)
				select {
				case <-timer.C:
				case <-opts.CancelCtx.Done():
					timer.Stop()
					return false
				}
			} else {
				time.Sleep(time.Duration(wait) * time.Second)
			}
		}

		// Set cancel tracking callbacks with correct step name and target host.
		if opts.ActiveSteps != nil {
			targetHost := exec.TargetHost
			stepName := step.Name
			exec.OnAppStart = func(appName string) { opts.ActiveSteps.Set(jobName, stepName, appName, targetHost) }
			exec.OnAppEnd = func(appName string) { opts.ActiveSteps.Remove(jobName, stepName) }
		}

		// Set step log path for streaming stdout collection.
		if opts.StepLogPathFn != nil {
			exec.StepLogPath = opts.StepLogPathFn(jobName, step.Name)
		}

		log.StepStarted(step.Name)
		result := exec.Execute(step, stepEnv, stepSecEnv)
		step.Result = result

		exitCode := 0
		if result.ExitCode != nil {
			exitCode = *result.ExitCode
		}

		ectx.SetStepResult(jobName, step.Name, result.Stdout, exitCode, result.Status, result.Response, result.Outputs)

		if result.Status == models.StatusSuccess {
			log.StepCompleted(step.Name, exitCode, result.Duration)
			if opts.OnStepDone != nil {
				opts.OnStepDone(jobName, step.Name, result.Stdout)
			}
			return true
		}
		log.StepFailed(step.Name, exitCode, result.Duration)
		// Don't burn through remaining retry attempts after cancel.
		if opts.CancelCtx != nil && opts.CancelCtx.Err() != nil {
			break
		}
	}

	// Archive stdout even on final failure.
	if opts.OnStepDone != nil {
		opts.OnStepDone(jobName, step.Name, step.Result.Stdout)
	}
	return false
}

func mergeEnv(base, overlay map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(overlay))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range overlay {
		out[k] = v
	}
	return out
}

// evaluateNeeds checks dependency statuses following GitHub Actions semantics:
//   - succeeded: all deps are "success" (skipped counts as not-succeeded)
//   - failed: at least one dep is "failure" (skipped does NOT count as failed)
//   - skipped deps are neutral: they block success() but don't trigger failure()
func evaluateNeeds(job *models.Job, wf *models.Workflow, statusMu *sync.RWMutex) (succeeded, failed bool, reason string) {
	succeeded = true
	for _, dep := range job.Needs {
		statusMu.RLock()
		depStatus := ""
		if d, ok := wf.Jobs[dep]; ok {
			depStatus = d.Status
		}
		statusMu.RUnlock()

		switch depStatus {
		case models.StatusSuccess:
			continue
		case models.StatusFailure:
			succeeded = false
			failed = true
			if reason == "" {
				reason = "dependency '" + dep + "' failed"
			}
		case models.StatusSkipped:
			// Skipped is neutral: not succeeded (blocks default run), not failed
			succeeded = false
			if reason == "" {
				reason = "dependency '" + dep + "' was skipped"
			}
		default:
			// pending/running/unknown — treat as not succeeded
			succeeded = false
			if reason == "" {
				reason = "dependency '" + dep + "' was " + depStatus
			}
		}
	}
	return succeeded, failed, reason
}

func hasStatusFunction(condition string) bool {
	return strings.Contains(condition, "always()") ||
		strings.Contains(condition, "success()") ||
		strings.Contains(condition, "failure()")
}

// runSubWorkflow executes a sub-workflow in-process and returns exit code + outputs.
func runSubWorkflow(ctx context.Context, client *appmesh.AppMeshClient, wfName string, inputs map[string]string, depth int, opts Options) (int, map[string]string) {
	baseDir := opts.WorkflowBaseDir
	if baseDir == "" {
		baseDir, _ = os.Getwd()
	}
	yamlPath := filepath.Join(baseDir, wfName, "workflow.yaml")
	wf, err := parser.LoadWorkflow(yamlPath)
	if err != nil {
		logger.Error(fmt.Sprintf("sub-workflow %q: load failed: %v", wfName, err))
		return 1, nil
	}
	if wf.On == nil || wf.On.WorkflowCall == nil {
		logger.Error(fmt.Sprintf("sub-workflow %q: not callable (missing on.workflow_call)", wfName))
		return 1, nil
	}

	runID := fmt.Sprintf("sub-%s-%s", wfName, xid.New().String())
	// Drop OnJobDone / OnStepDone / StepLogPathFn because each closes over the
	// parent's wfName+runID at registration time and would route sub-workflow
	// checkpoint/log state into the parent's files. Log is kept — its messages
	// embed the sub's runID, so they're identifiable even when written to the
	// parent's flow.log.
	// ActiveSteps IS shared so that cancelling the parent run propagates
	// KillAll to apps spawned by the sub-workflow's steps (it only tracks
	// {job.step -> appName}, not parent run identity). Caveat: if a parent and
	// sub job+step share the same name and run concurrently, the shared key
	// collides — still strictly better than not tracking sub steps at all.
	// TODO: a per-run callback factory would let the sub use its own runID.
	subOpts := Options{
		ClusterNodes:      opts.ClusterNodes,
		ServerURI:         opts.ServerURI,
		DefaultTargetHost: opts.DefaultTargetHost,
		Log:               opts.Log,
		WorkflowBaseDir:   opts.WorkflowBaseDir,
		ActiveSteps:       opts.ActiveSteps,
	}

	exitCode, subCtx := RunWithContext(ctx, wf, client, inputs, runID, depth, subOpts)

	// Evaluate workflow_call outputs from the sub-workflow's expression context.
	var outputs map[string]string
	if subCtx != nil && wf.On.WorkflowCall != nil && len(wf.On.WorkflowCall.Outputs) > 0 {
		outputs = make(map[string]string)
		for name, out := range wf.On.WorkflowCall.Outputs {
			outputs[name] = expression.SubstituteForJob(out.Value, subCtx, "")
		}
	}

	return exitCode, outputs
}

func toIntFromAny(v any) int {
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	}
	return 0
}

// cloneWorkflow returns a deep copy of the Workflow so each run has its own
// mutable state (Job.Status, Step.Result) and isolated env maps.
func cloneWorkflow(wf *models.Workflow) *models.Workflow {
	cp := *wf
	cp.Env = cloneStringMap(wf.Env)
	cp.SecEnv = cloneStringMap(wf.SecEnv)
	cp.Jobs = make(map[string]*models.Job, len(wf.Jobs))
	for name, job := range wf.Jobs {
		jc := *job
		jc.Env = cloneStringMap(job.Env)
		jc.SecEnv = cloneStringMap(job.SecEnv)
		jc.Steps = cloneSteps(job.Steps)
		jc.Finally = cloneSteps(job.Finally)
		cp.Jobs[name] = &jc
	}
	return &cp
}

func cloneSteps(src []models.Step) []models.Step {
	out := make([]models.Step, len(src))
	for i, s := range src {
		s.Env = cloneStringMap(s.Env)
		s.SecEnv = cloneStringMap(s.SecEnv)
		s.With = cloneStringMap(s.With)
		out[i] = s
	}
	return out
}

func cloneStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
