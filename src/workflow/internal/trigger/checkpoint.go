package trigger

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/workdir"
)

// JobState records the completion status of a single job.
// StepState stores step results for cross-job expression recovery.
type StepState struct {
	Stdout   string            `json:"stdout,omitempty"`
	ExitCode int               `json:"exit_code"`
	Status   string            `json:"status"`
	Response string            `json:"response,omitempty"`
	Outputs  map[string]string `json:"outputs,omitempty"`
}

type JobState struct {
	Status     string               `json:"status"`
	Node       string               `json:"node,omitempty"`       // target host that executed this job
	FinishedAt string               `json:"finished_at,omitempty"`
	Steps      map[string]StepState `json:"steps,omitempty"` // step name → result
}

// RunRecord is the checkpoint data for a single workflow run.
type RunRecord struct {
	RunID     string              `json:"run_id"`
	Workflow  string              `json:"workflow"`
	Source    string              `json:"source"`
	Status    string              `json:"status"`
	StartedAt string              `json:"started_at"`
	Inputs    map[string]string   `json:"inputs,omitempty"`
	Jobs      map[string]JobState `json:"jobs"`
}

// Checkpoint persists run state to disk for crash recovery.
type Checkpoint struct {
	wdir *workdir.Manager
	mu   sync.Mutex
}

func NewCheckpoint(wdir *workdir.Manager) *Checkpoint {
	return &Checkpoint{wdir: wdir}
}

// SaveRunning writes a checkpoint for a started run.
func (c *Checkpoint) SaveRunning(wfName, runID, source string, inputs map[string]string, jobNames []string) {
	jobs := make(map[string]JobState, len(jobNames))
	for _, name := range jobNames {
		jobs[name] = JobState{Status: "pending"}
	}
	rec := RunRecord{
		RunID:     runID,
		Workflow:  wfName,
		Source:    source,
		Status:    "running",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Inputs:    inputs,
		Jobs:      jobs,
	}
	c.write(wfName, runID, &rec)
}

// SaveRunningWithCompleted atomically writes a checkpoint that includes both
// pending jobs and already-completed jobs from a previous run (for crash recovery).
func (c *Checkpoint) SaveRunningWithCompleted(wfName, runID, source string, inputs map[string]string, allJobs map[string]*models.Job, completedJobs map[string]string, savedSteps map[string]map[string]StepState) {
	jobs := make(map[string]JobState, len(allJobs))
	for name := range allJobs {
		if status, ok := completedJobs[name]; ok {
			jobs[name] = JobState{
				Status:     status,
				FinishedAt: time.Now().UTC().Format(time.RFC3339),
				Steps:      savedSteps[name],
			}
		} else {
			jobs[name] = JobState{Status: "pending"}
		}
	}
	rec := RunRecord{
		RunID:     runID,
		Workflow:  wfName,
		Source:    source,
		Status:    "running",
		StartedAt: time.Now().UTC().Format(time.RFC3339),
		Inputs:    inputs,
		Jobs:      jobs,
	}
	c.write(wfName, runID, &rec)
}

// UpdateJob updates a single job's status in the checkpoint file.
func (c *Checkpoint) UpdateJob(wfName, runID, jobName, status, node string, steps map[string]StepState) {
	c.mu.Lock()
	defer c.mu.Unlock()

	rec := c.read(wfName, runID)
	if rec == nil {
		return
	}
	rec.Jobs[jobName] = JobState{
		Status:     status,
		Node:       node,
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Steps:      steps,
	}
	c.writeUnsafe(wfName, runID, rec)
}

// GetJobSteps returns saved step results for a completed job (for recovery).
func (c *Checkpoint) GetJobSteps(wfName, runID, jobName string) map[string]StepState {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.read(wfName, runID)
	if rec == nil {
		return nil
	}
	if js, ok := rec.Jobs[jobName]; ok {
		return js.Steps
	}
	return nil
}

// GetRunRecord returns the full checkpoint record for a run, or nil if not found.
func (c *Checkpoint) GetRunRecord(wfName, runID string) *RunRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.read(wfName, runID)
}

// MarkComplete updates the checkpoint status to the final state.
// The file is preserved so run_detail can return job/step data for completed runs.
func (c *Checkpoint) MarkComplete(wfName, runID, finalStatus string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	rec := c.read(wfName, runID)
	if rec == nil {
		return
	}
	rec.Status = finalStatus
	c.writeUnsafe(wfName, runID, rec)
}

// CompletedJobs returns job names that finished (success, failure, or skipped).
func (c *Checkpoint) CompletedJobs(wfName, runID string) map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()

	rec := c.read(wfName, runID)
	if rec == nil {
		return nil
	}
	result := make(map[string]string)
	for name, state := range rec.Jobs {
		if state.Status == "success" || state.Status == "skipped" || state.Status == "failure" {
			result[name] = state.Status
		}
	}
	return result
}

// RecoverStale scans all workflow dirs for runs that were "running" at crash time.
func (c *Checkpoint) RecoverStale(baseDir string) []RunRecord {
	wfEntries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil
	}

	var stale []RunRecord
	for _, wfEntry := range wfEntries {
		if !wfEntry.IsDir() {
			continue
		}
		runsDir := filepath.Join(baseDir, wfEntry.Name(), "runs")
		runEntries, err := os.ReadDir(runsDir)
		if err != nil {
			continue
		}
		for _, runEntry := range runEntries {
			if !runEntry.IsDir() {
				continue
			}
			cpPath := filepath.Join(runsDir, runEntry.Name(), "checkpoint.json")
			data, err := os.ReadFile(cpPath)
			if err != nil {
				continue
			}
			var rec RunRecord
			if err := json.Unmarshal(data, &rec); err != nil {
				continue
			}
			if rec.Status == "running" {
				stale = append(stale, rec)
				done := 0
				for _, js := range rec.Jobs {
					if js.Status == "success" || js.Status == "skipped" {
						done++
					}
				}
				logger.Error(fmt.Sprintf("CHECKPOINT stale run: workflow='%s' run=%s jobs=%d/%d completed",
					rec.Workflow, rec.RunID, done, len(rec.Jobs)))
			}
		}
	}
	return stale
}

func (c *Checkpoint) write(wfName, runID string, rec *RunRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeUnsafe(wfName, runID, rec)
}

func (c *Checkpoint) writeUnsafe(wfName, runID string, rec *RunRecord) {
	path := c.wdir.CheckpointPath(wfName, runID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		logger.Error("checkpoint mkdir failed: " + err.Error())
		return
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		logger.Error("checkpoint marshal failed: " + err.Error())
		return
	}
	tmp := path + ".tmp"
	if err := writeFileSynced(tmp, data); err != nil {
		logger.Error("checkpoint write failed: " + err.Error())
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		logger.Error("checkpoint rename failed: " + err.Error())
	}
}

// writeFileSynced writes data and fsyncs the file before close.
// This ensures the data is durable on disk before a subsequent rename.
func writeFileSynced(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return f.Sync()
}

func (c *Checkpoint) read(wfName, runID string) *RunRecord {
	data, err := os.ReadFile(c.wdir.CheckpointPath(wfName, runID))
	if err != nil {
		return nil
	}
	var rec RunRecord
	if err := json.Unmarshal(data, &rec); err != nil {
		logger.Error("checkpoint unmarshal failed for " + wfName + "/" + runID + ": " + err.Error())
		return nil
	}
	return &rec
}
