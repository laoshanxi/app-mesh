package trigger

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/engine"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/executor"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/expression"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/workdir"
	"github.com/rs/xid"
)

const scanInterval = 30 * time.Second

type Service struct {
	client       *appmesh.AppMeshClient
	clusterNodes []string
	serverURI    string
	registry     *Registry
	runMgr       *RunManager
	events       *EventListener
	checkpoint   *Checkpoint
	wdir         *workdir.Manager

	mu          sync.Mutex
	cancelFns   map[string]context.CancelFunc
	activeSteps map[string]*engine.ActiveSteps // runID → active steps tracker

	reAuth    func() error // re-login callback for token expiry recovery
	scanFails int          // consecutive scan failures
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

	// Clean up orphaned step Apps from previous crash.
	s.cleanOrphanedStepApps()

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
			s.resumeRun(wf, rec.RunID, rec.Source, rec.Inputs, completedJobs)
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

// SetReAuth sets the callback for re-authentication on token expiry.
func (s *Service) SetReAuth(fn func() error) {
	s.reAuth = fn
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

func (s *Service) scan() {
	if err := ScanWorkflows(s.client, s.registry); err != nil {
		s.scanFails++
		if s.scanFails >= 3 && s.reAuth != nil {
			logger.Info("scan failed consecutively, attempting re-authentication")
			if rerr := s.reAuth(); rerr != nil {
				logger.Error("re-authentication failed: " + rerr.Error())
			} else {
				logger.Info("re-authentication succeeded")
			}
			s.scanFails = 0
		}
		return
	}
	s.scanFails = 0
}

// cleanOrphanedStepApps removes leftover step Apps from a previous crash.
func (s *Service) cleanOrphanedStepApps() {
	apps, err := s.client.ListApps()
	if err != nil {
		return
	}
	count := 0
	for _, app := range apps {
		if strings.HasPrefix(app.Name, executor.StepAppPrefix) {
			s.client.RemoveApp(app.Name)
			count++
		}
	}
	if count > 0 {
		logger.Info(fmt.Sprintf("TRIGGER cleaned %d orphaned step App(s) from previous crash", count))
	}
}

// triggerRun creates a run and returns its ID and status ("running" or "pending").
func (s *Service) triggerRun(wf *models.Workflow, source string, inputs map[string]string) (string, string) {
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
			s.runMgr.Enqueue(group, runID, wf.Name, source, inputs)
			s.wdir.AddRunToIndex(wf.Name, workdir.RunIndex{
				RunID: runID, Workflow: wf.Name, Status: "pending",
				Source: source, StartedAt: workdir.NowTimestamp(), Inputs: inputs,
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

	s.startRun(wf, runID, group, source, inputs)
	return runID, "running"
}

func (s *Service) startRun(wf *models.Workflow, runID, group, source string, inputs map[string]string) {
	jobNames := make([]string, 0, len(wf.Jobs))
	for name := range wf.Jobs {
		jobNames = append(jobNames, name)
	}
	s.checkpoint.SaveRunning(wf.Name, runID, source, inputs, jobNames)

	s.wdir.AddRunToIndex(wf.Name, workdir.RunIndex{
		RunID: runID, Workflow: wf.Name, Status: "running",
		Source: source, StartedAt: workdir.NowTimestamp(), Inputs: inputs,
	})
	s.wdir.CleanOldRuns(wf.Name)

	s.launchRun(wf, runID, group, source, inputs, nil, nil)
}

func (s *Service) resumeRun(wf *models.Workflow, runID, source string, inputs map[string]string, completedJobs map[string]string) {
	logger.Info(fmt.Sprintf("TRIGGER resuming workflow '%s' run=%s (skipping %d completed jobs)", wf.Name, runID, len(completedJobs)))

	// Load step results from checkpoint for cross-job expression recovery.
	savedSteps, recoveredSteps := s.loadRecoveredSteps(wf.Name, runID, completedJobs)

	// Build a single atomic checkpoint with both pending and completed jobs,
	// so a crash between write and update cannot lose completed state.
	s.checkpoint.SaveRunningWithCompleted(wf.Name, runID, source, inputs, wf.Jobs, completedJobs, savedSteps)

	// Ensure index entry exists (the prior crash may have happened before AddRunToIndex).
	s.wdir.AddRunToIndex(wf.Name, workdir.RunIndex{
		RunID: runID, Workflow: wf.Name, Status: "running",
		Source: source, StartedAt: workdir.NowTimestamp(), Inputs: inputs,
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
			s.runMgr.Enqueue(group, runID, wf.Name, source, inputs)
			// Demote index entry to pending since this resumed run is queued.
			s.wdir.UpdateRunInIndex(wf.Name, runID, "pending", 0)
			logger.Info(fmt.Sprintf("TRIGGER resume: workflow '%s' run=%s queued (group=%s busy)", wf.Name, runID, group))
			return
		}
	} else {
		s.runMgr.MarkRunning("", runID)
	}
	s.launchRun(wf, runID, group, source, inputs, completedJobs, recoveredSteps)
}

func (s *Service) launchRun(wf *models.Workflow, runID, group, source string, inputs map[string]string, completedJobs map[string]string, recoveredSteps map[string]map[string]map[string]any) {
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
			finalStatus = "failure"
			dur         float64
		)
		defer func() {
			if r := recover(); r != nil {
				logger.Error(fmt.Sprintf("workflow '%s' run=%s panicked: %v", wf.Name, runID, r))
			}
			cancel()
			if runLog != nil {
				runLog.Close()
			}

			s.checkpoint.MarkComplete(wf.Name, runID, finalStatus)
			s.wdir.UpdateRunInIndex(wf.Name, runID, finalStatus, dur)

			s.mu.Lock()
			delete(s.cancelFns, runID)
			delete(s.activeSteps, runID)
			s.mu.Unlock()

			if next := s.runMgr.Complete(group, runID); next != nil {
				nextWf := s.registry.Get(next.wfName)
				if nextWf != nil {
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
						s.checkpoint.SaveRunning(nextWf.Name, next.runID, next.source, next.inputs, jobNames)
					}
					s.runMgr.MarkRunning(group, next.runID)
					s.wdir.UpdateRunInIndex(nextWf.Name, next.runID, "running", 0)
					s.launchRun(nextWf, next.runID, group, next.source, next.inputs, nextCompleted, nextRecovered)
				} else {
					// Workflow disappeared between enqueue and dequeue.
					// Finalize both checkpoint and index so the orphan doesn't recur on restart.
					s.checkpoint.MarkComplete(next.wfName, next.runID, "cancelled")
					s.wdir.UpdateRunInIndex(next.wfName, next.runID, "cancelled", 0)
					logger.Error(fmt.Sprintf("TRIGGER dequeued run=%s but workflow '%s' no longer exists", next.runID, next.wfName))
				}
			}
		}()

		if inputs == nil {
			inputs = make(map[string]string)
		}

		start := time.Now()
		var log logger.Log
		if runLog != nil {
			log = runLog
		}

		code, _ := engine.RunWithContext(ctx, wf, s.client, inputs, runID, 0, engine.Options{
			ClusterNodes:    s.clusterNodes,
			ServerURI:       s.serverURI,
			CompletedJobs:   completedJobs,
			RecoveredSteps:  recoveredSteps,
			Log:             log,
			ActiveSteps:     active,
			WorkflowBaseDir: s.wdir.BaseDir(),
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
		// cancel after a successful return must not mislabel the run.
		switch {
		case code == 0:
			finalStatus = "success"
		case ctx.Err() != nil:
			finalStatus = "cancelled"
		default:
			finalStatus = "failure"
			logger.Info(fmt.Sprintf("TRIGGER workflow '%s' run=%s failed (exit %d)", wf.Name, runID, code))
		}
	}()
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

func (s *Service) TriggerManual(wfName string, inputs map[string]string) (string, string, error) {
	wf := s.registry.Get(wfName)
	if wf == nil {
		return "", "", fmt.Errorf("workflow '%s' not found", wfName)
	}
	runID, status := s.triggerRun(wf, "manual", inputs)
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

// CancelByRunID cancels a running workflow by its run ID.
func (s *Service) CancelByRunID(runID string) error {
	s.mu.Lock()
	_, ok := s.cancelFns[runID]
	s.mu.Unlock()
	if !ok {
		return fmt.Errorf("run '%s' not found or not running", runID)
	}
	s.cancelRun(runID)
	return nil
}
