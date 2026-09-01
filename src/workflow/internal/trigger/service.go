package trigger

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/engine"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/tlsconf"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/workdir"
	"github.com/rs/xid"
)

const scanInterval = 30 * time.Second

// Consecutive non-auth scan failures before renewing the control capability; auth failures
// bypass this entirely (see scan).
const scanFailsBeforeControlRefresh = 3

// Ceiling on the backoff between failed control-capability requests.
const controlRefreshMaxBackoff = 5 * time.Minute

// Deadline for daemon calls made from the Run loop. They share one goroutine, so any of
// them hanging stalls the whole trigger service.
const scanRequestTimeout = 20 * time.Second

// CapabilityRequestTimeout bounds local Engine capability issuance.
const CapabilityRequestTimeout = scanRequestTimeout

// CapabilityLifetime is the Engine-enforced maximum. Runs renew one minute
// before expiry, so workflow duration is not limited to five minutes.
const CapabilityLifetime = 5 * time.Minute
const CapabilityRefreshMargin = time.Minute

var runCapabilityOperations = []string{
	"app-run-async",
	"app-view",
	"app-output-view",
	"app-delete",
	"app-run-task",
	"app-subscribe",
	"label-view",
}

type CapabilityIssuer func(ctx context.Context, workflowID, runID string, operations []string) (appmesh.WorkflowCapability, error)

type Service struct {
	client       *appmesh.AppMeshClient
	clusterNodes []string
	serverURI    string
	registry     *Registry
	runMgr       *RunManager
	events       *EventListener
	checkpoint   *Checkpoint
	wdir         *workdir.Manager
	processUUID  string

	mu          sync.Mutex
	cancelFns   map[string]context.CancelFunc
	activeSteps map[string]*engine.ActiveSteps // runID → active steps tracker

	issueCapability CapabilityIssuer
	refreshControl  func(context.Context) error
	scanFails       int // consecutive scan failures

	// Backoff for repeated Engine capability issuance failures.
	controlRefreshFails    int
	controlRefreshCooldown time.Time // no further attempts before this instant
}

func NewService(client *appmesh.AppMeshClient, serverURI string, clusterNodes []string, workflowDir string) *Service {
	wdir := workdir.NewManager(workflowDir, 10)
	s := &Service{
		client:       client,
		clusterNodes: clusterNodes,
		serverURI:    serverURI,
		registry:     NewRegistry(),
		runMgr:       NewRunManager(),
		cancelFns:    make(map[string]context.CancelFunc),
		activeSteps:  make(map[string]*engine.ActiveSteps),
		checkpoint:   NewCheckpoint(wdir),
		wdir:         wdir,
	}
	s.events = NewEventListener(client, s.registry, s.triggerRun)
	return s
}

func (s *Service) Run(ctx context.Context) {
	logger.Info("TRIGGER service started (goroutine mode, TCP transport)")

	stale := s.checkpoint.RecoverStale(s.wdir.BaseDir())
	if len(stale) > 0 {
		logger.Info(fmt.Sprintf("TRIGGER found %d stale run(s), resuming...", len(stale)))
		s.scan()
		for _, rec := range stale {
			wf := s.registry.Get(rec.Workflow)
			if wf == nil {
				logger.Error("TRIGGER cannot resume workflow '" + rec.Workflow + "': not found")
				continue
			}
			completedJobs := s.checkpoint.CompletedJobs(rec.Workflow, rec.RunID)
			s.resumeRun(wf, rec.RunID, rec.Source, rec.Actor, rec.Inputs, completedJobs)
		}
	}

	// Reconcile index entries left in "running"/"pending" state by a prior crash:
	// if no checkpoint or checkpoint marked complete, mark the index entry accordingly.
	s.reconcileIndex()

	scanTicker := time.NewTicker(scanInterval)
	defer scanTicker.Stop()

	s.scan()
	s.events.SyncSubscriptions()

	for {
		select {
		case <-ctx.Done():
			s.events.Cleanup()
			logger.Info("TRIGGER service stopped")
			return
		case <-scanTicker.C:
			s.scan()
			s.events.SyncSubscriptions()
		}
	}
}

// Wdir returns the workdir manager for API access.
func (s *Service) Wdir() *workdir.Manager { return s.wdir }

// Checkpoint returns the checkpoint manager for API access.
func (s *Service) Checkpoint() *Checkpoint { return s.checkpoint }

// Registry returns the workflow registry for API access.
func (s *Service) Registry() *Registry { return s.registry }

// SetCapabilityIssuer installs the local Engine capability issuance callback.
func (s *Service) SetCapabilityIssuer(fn CapabilityIssuer) {
	s.issueCapability = fn
}

// SetControlRefresh renews the process-bound registry/event capability.
func (s *Service) SetControlRefresh(fn func(context.Context) error) {
	s.refreshControl = fn
}

// SetProcessUUID binds temporary step metadata and renewed capabilities to the
// current App Mesh-managed Workflow process instance.
func (s *Service) SetProcessUUID(processUUID string) {
	s.processUUID = processUUID
}

// resolveExecCredential issues the run-scoped Engine capability that every run
// — manual, automatic, or recovered — executes under. The caller's Dex bearer
// authenticates the trigger, authorizes shared-Dex cross-node forwarding, and
// (for message steps with forward_token) supplies the payload identity. A user
// bearer cannot be renewed without persisting
// user credentials (forbidden by ADR 0006/0009), so a manual run longer than
// the access-token TTL would die mid-run with 401s. The capability instead is
// bound to this workflow/run/owner and current managed process and is renewed
// for the whole run lifetime (see startCapabilityRenewal).
func (s *Service) resolveExecCredential(ctx context.Context, workflowID, runID string) (string, appmesh.WorkflowCapability, error) {
	if s.issueCapability == nil {
		return "", appmesh.WorkflowCapability{}, fmt.Errorf("workflow capability issuer is unavailable")
	}
	requestCtx, cancel := context.WithTimeout(ctx, CapabilityRequestTimeout)
	defer cancel()
	capability, err := s.issueCapability(requestCtx, workflowID, runID, runCapabilityOperations)
	if err != nil {
		return "", appmesh.WorkflowCapability{}, fmt.Errorf("issue workflow run capability: %w", err)
	}
	owner := s.registry.Owner(workflowID)
	if owner == "" || capability.OwnerPrincipalID != owner {
		return "", appmesh.WorkflowCapability{}, fmt.Errorf("Engine capability owner does not match the registered workflow owner")
	}
	if s.processUUID == "" || capability.ProcessUUID != s.processUUID {
		return "", appmesh.WorkflowCapability{}, fmt.Errorf("Engine capability is not bound to the current Workflow process")
	}
	return capability.Capability, capability, nil
}

// stepStateToAny serializes a checkpointed StepState into the engine's
// generic step-data shape used by RecoveredSteps and the OnJobDone callback.
func stepStateToAny(ss StepState) map[string]any {
	return map[string]any{
		"stdout":    ss.Stdout,
		"exit_code": ss.ExitCode,
		"status":    ss.Status,
		"response":  ss.Response,
		"outputs":   ss.Outputs,
	}
}

// loadRecoveredSteps reads per-job step state from the checkpoint for the
// given completed jobs and returns both the typed map (for caller's bookkeeping)
// and the engine's generic shape.
func (s *Service) loadRecoveredSteps(wfName, runID string, completedJobs map[string]string) (map[string]map[string]StepState, map[string]map[string]map[string]any) {
	saved := make(map[string]map[string]StepState)
	recovered := make(map[string]map[string]map[string]any)
	for jobName := range completedJobs {
		cpSteps := s.checkpoint.GetJobSteps(wfName, runID, jobName)
		if len(cpSteps) == 0 {
			continue
		}
		saved[jobName] = cpSteps
		jobSteps := make(map[string]map[string]any, len(cpSteps))
		for stepName, ss := range cpSteps {
			jobSteps[stepName] = stepStateToAny(ss)
		}
		recovered[jobName] = jobSteps
	}
	return saved, recovered
}

// reconcileIndex syncs runs.json with checkpoint state for crash recovery.
// Index entries left as "running"/"pending" but whose checkpoint is gone or
// already marked terminal are updated; running entries with terminal checkpoints
// inherit the checkpoint's final status.
func (s *Service) reconcileIndex() {
	for name := range s.registry.All() {
		runs := s.wdir.ListRuns(name)
		for _, r := range runs {
			if r.Status != "running" && r.Status != "pending" {
				continue
			}
			rec := s.checkpoint.GetRunRecord(name, r.RunID)
			if rec == nil {
				s.wdir.UpdateRunInIndex(name, r.RunID, "cancelled", 0)
				logger.Info(fmt.Sprintf("RECONCILE marked %s/%s as cancelled (no checkpoint)", name, r.RunID))
				continue
			}
			if rec.Status != "running" {
				s.wdir.UpdateRunInIndex(name, r.RunID, rec.Status, 0)
				logger.Info(fmt.Sprintf("RECONCILE synced %s/%s index to %s (checkpoint terminal)", name, r.RunID, rec.Status))
			}
		}
	}
}

// isAuthError reports whether the daemon rejected our token. Only 401 counts: a 403
// means the credential is fine but the permission is missing, so re-logging in would
// just replay the same denial.
func isAuthError(err error) bool {
	var apiErr *appmesh.APIError
	return errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized
}

func (s *Service) scan() {
	err := ScanWorkflows(s.client, s.registry)
	if err == nil {
		s.scanFails = 0
		return
	}

	// A rejected capability does not heal by waiting, so refresh on the first 401.
	// Other failures (daemon restarting, connection reset) usually do heal, so they
	// keep the consecutive-failure grace period.
	if isAuthError(err) && s.refreshControl != nil {
		s.refreshControlCapability("capability rejected")
		return
	}

	s.scanFails++
	if s.scanFails >= scanFailsBeforeControlRefresh && s.refreshControl != nil {
		s.refreshControlCapability("scan failed consecutively")
	}
}

// refreshControlCapability reacquires the narrow registry/event capability.
func (s *Service) refreshControlCapability(reason string) {
	// Check the cooldown before touching scanFails: resetting it on a suppressed attempt
	// would restart the three-strike count, so the non-auth path could never fire again
	// while a cooldown is active.
	if time.Now().Before(s.controlRefreshCooldown) {
		return
	}
	s.scanFails = 0

	logger.Info("attempting workflow control capability refresh: " + reason)
	ctx, cancel := context.WithTimeout(context.Background(), CapabilityRequestTimeout)
	defer cancel()
	if err := s.refreshControl(ctx); err != nil {
		s.controlRefreshFails++
		backoff := scanInterval << min(s.controlRefreshFails-1, 5)
		if backoff > controlRefreshMaxBackoff {
			backoff = controlRefreshMaxBackoff
		}
		s.controlRefreshCooldown = time.Now().Add(backoff)
		logger.Error(fmt.Sprintf("workflow control capability refresh failed (attempt %d, next try in %s): %s", s.controlRefreshFails, backoff, err.Error()))
		return
	}
	s.controlRefreshFails = 0
	s.controlRefreshCooldown = time.Time{}
	logger.Info("workflow control capability refresh succeeded")
}

// triggerRun creates an automatic event run. Cron remains an external trigger
// (ADR 0004). The run executes under a short-lived, run-scoped Engine capability
// rather than an OAuth service identity.
func (s *Service) triggerRun(wf *models.Workflow, source string, inputs map[string]string) (string, string) {
	return s.triggerRunToken(wf, source, inputs, "", "internal:workflow-trigger")
}

// triggerRunToken creates a run and returns its ID and status ("running" or "pending").
// token is the caller's Dex access token (empty for automatic triggers). It is held in
// memory only for shared-Dex cross-node forwarding and forward_token message identity —
// never as the local execution credential, which every run obtains from the Engine as a
// run-scoped capability (see resolveExecCredential). actor is the immutable Principal ID recorded for audit
// (`internal:workflow-trigger` for automatic triggers).
func (s *Service) triggerRunToken(wf *models.Workflow, source string, inputs map[string]string, token, actor string) (string, string) {
	runID := xid.New().String()
	group := ""
	cancelInProgress := false
	if wf.Concurrency != nil {
		ectx := expression.NewContext()
		if inputs != nil {
			ectx.Inputs = inputs
		}
		group = expression.Substitute(wf.Concurrency.Group, ectx)
		cancelInProgress = wf.Concurrency.CancelInProgress
	}

	if group != "" {
		ok, toCancel := s.runMgr.TryStart(group, runID, cancelInProgress)
		if !ok {
			s.runMgr.Enqueue(group, runID, wf.Name, source, inputs, token, actor)
			s.wdir.AddRunToIndex(wf.Name, workdir.RunIndex{
				RunID: runID, Workflow: wf.Name, Status: "pending",
				Source: source, Actor: actor, StartedAt: workdir.NowTimestamp(), Inputs: inputs,
			})
			logger.Info(fmt.Sprintf("TRIGGER workflow '%s' run=%s queued (group=%s)", wf.Name, runID, group))
			return runID, "pending"
		}
		for _, id := range toCancel {
			s.cancelRun(id)
		}
	} else {
		s.runMgr.MarkRunning("", runID)
	}

	s.startRun(wf, runID, group, source, inputs, token, actor)
	return runID, "running"
}

func (s *Service) startRun(wf *models.Workflow, runID, group, source string, inputs map[string]string, token, actor string) {
	jobNames := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		jobNames = append(jobNames, name)
	}
	s.checkpoint.SaveRunning(wf.Name, runID, source, actor, inputs, jobNames)

	s.wdir.AddRunToIndex(wf.Name, workdir.RunIndex{
		RunID: runID, Workflow: wf.Name, Status: "running",
		Source: source, Actor: actor, StartedAt: workdir.NowTimestamp(), Inputs: inputs,
	})
	s.wdir.CleanOldRuns(wf.Name)

	s.launchRun(wf, runID, group, source, inputs, nil, nil, token)
}

func (s *Service) resumeRun(wf *models.Workflow, runID, source, actor string, inputs map[string]string, completedJobs map[string]string) {
	logger.Info(fmt.Sprintf("TRIGGER resuming workflow '%s' run=%s (skipping %d completed jobs)", wf.Name, runID, len(completedJobs)))

	// Load step results from checkpoint for cross-job expression recovery.
	savedSteps, recoveredSteps := s.loadRecoveredSteps(wf.Name, runID, completedJobs)

	// Build a single atomic checkpoint with both pending and completed jobs,
	// so a crash between write and update cannot lose completed state.
	s.checkpoint.SaveRunningWithCompleted(wf.Name, runID, source, actor, inputs, wf.Jobs, completedJobs, savedSteps)

	// Ensure index entry exists (the prior crash may have happened before AddRunToIndex).
	s.wdir.AddRunToIndex(wf.Name, workdir.RunIndex{
		RunID: runID, Workflow: wf.Name, Status: "running",
		Source: source, Actor: actor, StartedAt: workdir.NowTimestamp(), Inputs: inputs,
	})

	// Restore concurrency group from workflow definition.
	// Use TryStart (not MarkRunning) so that if another stale run for the
	// same group was already resumed, this one is queued instead of running
	// in parallel — preserving the concurrency=1 guarantee.
	group := ""
	if wf.Concurrency != nil {
		ectx := expression.NewContext()
		if inputs != nil {
			ectx.Inputs = inputs
		}
		group = expression.Substitute(wf.Concurrency.Group, ectx)
	}
	if group != "" {
		ok, _ := s.runMgr.TryStart(group, runID, false)
		if !ok {
			s.runMgr.Enqueue(group, runID, wf.Name, source, inputs, "", actor)
			// Demote index entry to pending since this resumed run is queued.
			s.wdir.UpdateRunInIndex(wf.Name, runID, "pending", 0)
			logger.Info(fmt.Sprintf("TRIGGER resume: workflow '%s' run=%s queued (group=%s busy)", wf.Name, runID, group))
			return
		}
	} else {
		s.runMgr.MarkRunning("", runID)
	}
	// Caller tokens are never persisted. Recovered runs request a fresh capability
	// bound to this same workflow/run and its current Engine-owned owner metadata.
	s.launchRun(wf, runID, group, source, inputs, completedJobs, recoveredSteps, "")
}

func (s *Service) launchRun(wf *models.Workflow, runID, group, source string, inputs map[string]string, completedJobs map[string]string, recoveredSteps map[string]map[string]map[string]any, token string) {
	ctx, cancel := context.WithCancel(context.Background())
	active := engine.NewActiveSteps(s.client, s.serverURI)

	s.mu.Lock()
	s.cancelFns[runID] = cancel
	s.activeSteps[runID] = active
	s.mu.Unlock()

	// Create per-run logger.
	flowLogPath := s.wdir.FlowLogPath(wf.Name, runID)
	runLog, err := logger.NewRunLogger(flowLogPath, true)
	if err != nil {
		logger.Error("failed to create run logger: " + err.Error())
		runLog = nil
	}

	logger.Info(fmt.Sprintf("TRIGGER starting workflow '%s' run=%s source=%s", wf.Name, runID, source))

	go func() {
		var (
			finalStatus    = "failure"
			dur            float64
			callerTCP      *appmesh.AppMeshClientTCP
			stopCapability func()
		)
		defer func() {
			if r := recover(); r != nil {
				logger.Error(fmt.Sprintf("workflow '%s' run=%s panicked: %v", wf.Name, runID, r))
			}
			cancel()
			if stopCapability != nil {
				stopCapability()
			}
			if callerTCP != nil {
				callerTCP.CloseConnection()
			}
			if runLog != nil {
				runLog.Close()
			}

			s.checkpoint.MarkComplete(wf.Name, runID, finalStatus)
			s.wdir.UpdateRunInIndex(wf.Name, runID, finalStatus, dur)

			s.mu.Lock()
			delete(s.cancelFns, runID)
			delete(s.activeSteps, runID)
			s.mu.Unlock()

			// Promote queued runs. Complete() has already registered `next` in
			// the concurrency group (to keep the group non-empty across the gap),
			// so each `next` must be either launched or released via another
			// Complete() call — otherwise the group stays occupied forever.
			for next := s.runMgr.Complete(group, runID); next != nil; {
				nextWf := s.registry.Get(next.wfName)
				if nextWf == nil {
					// Workflow disappeared between enqueue and dequeue. Finalize it
					// and release its slot, promoting the following queued run.
					s.checkpoint.MarkComplete(next.wfName, next.runID, "cancelled")
					s.wdir.UpdateRunInIndex(next.wfName, next.runID, "cancelled", 0)
					logger.Error(fmt.Sprintf("TRIGGER dequeued run=%s but workflow '%s' no longer exists", next.runID, next.wfName))
					next = s.runMgr.Complete(group, next.runID)
					continue
				}
				// If this is a resumed run (checkpoint already exists with completed
				// jobs), don't overwrite it — preserve progress through the dequeue.
				existing := s.checkpoint.GetRunRecord(next.wfName, next.runID)
				var nextCompleted map[string]string
				var nextRecovered map[string]map[string]map[string]any
				if existing != nil && len(existing.Jobs) > 0 {
					nextCompleted = s.checkpoint.CompletedJobs(next.wfName, next.runID)
					if len(nextCompleted) > 0 {
						_, nextRecovered = s.loadRecoveredSteps(next.wfName, next.runID, nextCompleted)
					}
				} else {
					jobNames := make([]string, 0, len(nextWf.Jobs))
					for name := range nextWf.Jobs {
						jobNames = append(jobNames, name)
					}
					s.checkpoint.SaveRunning(nextWf.Name, next.runID, next.source, next.actor, next.inputs, jobNames)
				}
				s.wdir.UpdateRunInIndex(nextWf.Name, next.runID, "running", 0)
				s.launchRun(nextWf, next.runID, group, next.source, next.inputs, nextCompleted, nextRecovered, next.token)
				break
			}
		}()

		if inputs == nil {
			inputs = make(map[string]string)
		}

		// Every run — manual included — executes under a renewed run-scoped
		// capability that is never persisted or forwarded as caller identity.
		// The caller bearer (token) is used only for shared-Dex cross-node
		// forwarding and explicit forward_token message payloads.
		execToken, capability, ierr := s.resolveExecCredential(ctx, wf.Name, runID)
		if ierr != nil {
			msg := fmt.Sprintf("run=%s cannot start: %v", runID, ierr)
			logger.Error("TRIGGER " + msg)
			if runLog != nil {
				runLog.Error(msg)
			}
			return // defer marks the run failed and promotes the queue
		}

		// Execution-scoped client for steps; control-plane work stays on the engine client.
		// This connection carries the run capability, so it must verify the daemon
		// certificate (fail closed) like every credential-bearing client.
		execClient := s.client
		execOption := appmesh.Option{
			AppMeshUri: s.serverURI,
			JwtToken:   execToken,
		}
		tlsconf.Apply(&execOption)
		if c, err := appmesh.NewTCPClient(execOption); err == nil {
			// Parallel jobs in a run share this client; enable the demuxer so their
			// concurrent step calls can't cross-wire responses on the shared socket.
			c.EnableConcurrency()
			callerTCP = c
			execClient = c.AppMeshClient
			active.SetClient(execClient)
		} else {
			msg := fmt.Sprintf("run=%s: execution client failed: %v", runID, err)
			logger.Error("TRIGGER " + msg)
			if runLog != nil {
				runLog.Error(msg)
			}
			return
		}
		// Renewal failure after the last good capability has expired aborts the
		// run explicitly (credentialExpired) instead of letting every step die
		// with an unrelated 401.
		var credentialExpired atomic.Bool
		stopCapability = s.startCapabilityRenewal(ctx, execClient, wf.Name, runID,
			capability.OwnerPrincipalID, capability.ExpiresAt, func(reason error) {
				credentialExpired.Store(true)
				msg := fmt.Sprintf("run=%s aborted: run credential expired and cannot be renewed: %v", runID, reason)
				logger.Error("TRIGGER " + msg)
				if runLog != nil {
					runLog.Error(msg)
				}
				cancel()
			})

		start := time.Now()
		var log logger.Log
		if runLog != nil {
			log = runLog
		}

		code, _ := engine.RunWithContext(ctx, wf, execClient, inputs, runID, 0, engine.Options{
			ClusterNodes: s.clusterNodes,
			ServerURI:    s.serverURI,
			// Only a human caller's Dex bearer may cross a node boundary or enter an
			// explicit message payload. Internal capabilities stay on the local Engine.
			CallerToken:         token,
			CompletedJobs:       completedJobs,
			RecoveredSteps:      recoveredSteps,
			Log:                 log,
			ActiveSteps:         active,
			WorkflowBaseDir:     s.wdir.BaseDir(),
			WorkflowProcessUUID: s.processUUID,
			OnJobDone: func(jobName, status, targetHost string, steps map[string]map[string]any) {
				cpSteps := make(map[string]StepState, len(steps))
				for name, data := range steps {
					exitCode, _ := data["exit_code"].(int)
					var outputs map[string]string
					if o, ok := data["outputs"].(map[string]string); ok {
						outputs = o
					}
					cpSteps[name] = StepState{
						Stdout:   fmt.Sprintf("%v", data["stdout"]),
						ExitCode: exitCode,
						Status:   fmt.Sprintf("%v", data["status"]),
						Response: fmt.Sprintf("%v", data["response"]),
						Outputs:  outputs,
					}
				}
				s.checkpoint.UpdateJob(wf.Name, runID, jobName, status, targetHost, cpSteps)
			},
			OnStepDone: func(jobName, stepName, stdout string) {
				s.wdir.WriteStepLog(wf.Name, runID, jobName, stepName, stdout)
			},
			StepLogPathFn: func(jobName, stepName string) string {
				return s.wdir.StepLogPath(wf.Name, runID, jobName, stepName)
			},
		})

		dur = time.Since(start).Seconds()
		// Trust the engine's exit code first. Only label as cancelled when
		// the engine actually failed AND the context was cancelled — a late
		// cancel after a successful return must not mislabel the run. A run
		// aborted because its credential expired and could not be renewed is
		// a failure with its own recorded reason, not a cancellation.
		switch {
		case code == 0:
			finalStatus = "success"
		case credentialExpired.Load():
			finalStatus = "failure"
		case ctx.Err() != nil:
			finalStatus = "cancelled"
		default:
			finalStatus = "failure"
			logger.Info(fmt.Sprintf("TRIGGER workflow '%s' run=%s failed (exit %d)", wf.Name, runID, code))
		}
	}()
}

// startCapabilityRenewal keeps long runs alive without a long-lived
// credential. Every renewal repeats the local process-key proof at the Engine
// issuance endpoint. Transient failures retry about once a second while the
// current capability is still usable; once the last good capability has
// expired and renewal still cannot recover, onExpired is invoked (the run is
// aborted with an explicit failure) and the loop stops. The returned stop
// function is synchronous so the execution client cannot be closed while a
// renewal is in flight.
func (s *Service) startCapabilityRenewal(parent context.Context, client *appmesh.AppMeshClient,
	workflowID, runID, ownerPrincipalID string, initialExpiresAt int64, onExpired func(error)) func() {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		defer close(done)
		// goodUntil is when the LAST SUCCESSFULLY INSTALLED capability stops
		// working — distinct from the retry schedule, so a failed attempt never
		// extends the run's real deadline.
		goodUntil := time.Unix(initialExpiresAt, 0)
		retry := time.Duration(0)
		fail := func(format string, args ...any) bool {
			err := fmt.Errorf(format, args...)
			if time.Now().After(goodUntil) {
				logger.Error(fmt.Sprintf("run=%s workflow capability expired and renewal cannot recover: %v", runID, err))
				if onExpired != nil {
					onExpired(err)
				}
				return true
			}
			logger.Error(fmt.Sprintf("run=%s workflow capability renewal failed (retrying): %v", runID, err))
			return false
		}
		for {
			wait := time.Until(goodUntil.Add(-CapabilityRefreshMargin))
			if retry > 0 {
				wait = retry
				retry = 0
			}
			if wait < time.Second {
				wait = time.Second
			}
			timer := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}

			requestCtx, requestCancel := context.WithTimeout(ctx, CapabilityRequestTimeout)
			capability, err := s.issueCapability(requestCtx, workflowID, runID, runCapabilityOperations)
			requestCancel()
			if err != nil {
				if fail("issue workflow run capability: %w", err) {
					return
				}
				retry = time.Second
				continue
			}
			if capability.OwnerPrincipalID != ownerPrincipalID {
				if fail("Engine capability owner changed from %s to %s", ownerPrincipalID, capability.OwnerPrincipalID) {
					return
				}
				retry = time.Second
				continue
			}
			if capability.ProcessUUID != s.processUUID {
				if fail("Engine capability process changed; refusing replacement") {
					return
				}
				retry = time.Second
				continue
			}
			client.SetToken(capability.Capability)
			goodUntil = time.Unix(capability.ExpiresAt, 0)
		}
	}()
	return func() {
		cancel()
		<-done
	}
}

func (s *Service) cancelRun(runID string) {
	s.mu.Lock()
	cancel, ok := s.cancelFns[runID]
	active := s.activeSteps[runID]
	s.mu.Unlock()
	if ok {
		// Cancel context first so no new steps can register via OnAppStart,
		// then KillAll to clean up any already-registered apps.
		cancel()
		if active != nil {
			active.KillAll()
		}
		logger.Info(fmt.Sprintf("TRIGGER cancelled run=%s", runID))
	}
}

func (s *Service) TriggerManual(wfName string, inputs map[string]string, token, actor string) (string, string, error) {
	wf := s.registry.Get(wfName)
	if wf == nil {
		return "", "", fmt.Errorf("workflow '%s' not found", wfName)
	}
	runID, status := s.triggerRunToken(wf, "manual", inputs, token, actor)
	return runID, status, nil
}

// CancelByWorkflow cancels all active runs for a workflow
// and drains any queued runs to prevent dequeue after removal.
func (s *Service) CancelByWorkflow(wfName string) {
	// Drain concurrency queue so cancelled goroutines cannot dequeue new runs.
	// Update each drained run's index entry to "cancelled" so it doesn't sit
	// as "pending" forever (reconcileIndex only runs at startup).
	for _, runID := range s.runMgr.DrainQueueByWorkflow(wfName) {
		s.wdir.UpdateRunInIndex(wfName, runID, "cancelled", 0)
	}

	// Snapshot active run IDs without holding mu during ListRuns.
	s.mu.Lock()
	activeIDs := make(map[string]bool, len(s.cancelFns))
	for runID := range s.cancelFns {
		activeIDs[runID] = true
	}
	s.mu.Unlock()

	var toCancel []string
	for _, r := range s.wdir.ListRuns(wfName) {
		if activeIDs[r.RunID] {
			toCancel = append(toCancel, r.RunID)
		}
	}
	for _, id := range toCancel {
		s.cancelRun(id)
	}
}

// CancelByRunID cancels a running workflow by its run ID. A run still queued
// on its concurrency group has no cancel context yet, so it is removed from
// the queue and finalized directly.
func (s *Service) CancelByRunID(runID string) error {
	s.mu.Lock()
	_, ok := s.cancelFns[runID]
	s.mu.Unlock()
	if ok {
		s.cancelRun(runID)
		return nil
	}
	if wfName, queued := s.runMgr.RemoveQueued(runID); queued {
		s.checkpoint.MarkComplete(wfName, runID, "cancelled")
		s.wdir.UpdateRunInIndex(wfName, runID, "cancelled", 0)
		logger.Info(fmt.Sprintf("TRIGGER cancelled queued run=%s", runID))
		return nil
	}
	return fmt.Errorf("run '%s' not found or not running", runID)
}
