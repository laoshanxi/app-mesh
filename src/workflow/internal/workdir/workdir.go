// Package workdir manages the per-workflow directory structure for logs,
// checkpoints, and step stdout archives.
//
// Layout:
//
//	{baseDir}/
//	├── {workflow-name}/
//	│   ├── workflow.yaml
//	│   ├── runs.json               (run history index)
//	│   └── runs/
//	│       └── {run-id}/
//	│           ├── checkpoint.json
//	│           ├── flow.log
//	│           └── steps/
//	│               ├── {job}.{step}.log
//	│               └── ...
package workdir

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const defaultMaxRuns = 10

// RunIndex is a single entry in the run history index.
type RunIndex struct {
	RunID     string            `json:"run_id"`
	Workflow  string            `json:"workflow"`
	Status    string            `json:"status"`
	Source    string            `json:"source"`
	StartedAt string            `json:"started_at"`
	Duration  float64           `json:"duration,omitempty"`
	Inputs    map[string]string `json:"inputs,omitempty"`
}

// Manager handles directory creation, run indexing, and retention cleanup.
type Manager struct {
	baseDir string
	maxRuns int
	indexMu sync.Mutex // protects runs.json read-modify-write
}

func NewManager(baseDir string, maxRuns int) *Manager {
	if maxRuns <= 0 {
		maxRuns = defaultMaxRuns
	}
	return &Manager{baseDir: baseDir, maxRuns: maxRuns}
}

// BaseDir returns the root workflow directory.
func (m *Manager) BaseDir() string {
	return m.baseDir
}

// RunDir returns and creates the directory for a specific run.
func (m *Manager) RunDir(wfName, runID string) string {
	dir := filepath.Join(m.baseDir, wfName, "runs", runID)
	os.MkdirAll(dir, 0700)
	return dir
}

// StepsDir returns and creates the steps log directory for a run.
func (m *Manager) StepsDir(wfName, runID string) string {
	dir := filepath.Join(m.RunDir(wfName, runID), "steps")
	os.MkdirAll(dir, 0700)
	return dir
}

// FlowLogPath returns the path to the flow.log file for a run.
func (m *Manager) FlowLogPath(wfName, runID string) string {
	return filepath.Join(m.RunDir(wfName, runID), "flow.log")
}

// StepLogPath returns the path to a step's stdout log file.
func (m *Manager) StepLogPath(wfName, runID, jobName, stepName string) string {
	return filepath.Join(m.StepsDir(wfName, runID), jobName+"."+stepName+".log")
}

// CheckpointPath returns the path to the checkpoint file for a run.
func (m *Manager) CheckpointPath(wfName, runID string) string {
	return filepath.Join(m.RunDir(wfName, runID), "checkpoint.json")
}

// AddRunToIndex adds a run entry to the workflow's runs.json index.
// Idempotent: if a run with the same RunID exists, it is replaced.
func (m *Manager) AddRunToIndex(wfName string, entry RunIndex) {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	indexPath := filepath.Join(m.baseDir, wfName, "runs.json")
	entries := m.loadIndex(indexPath)
	for i := range entries {
		if entries[i].RunID == entry.RunID {
			entries[i] = entry
			m.saveIndex(indexPath, entries)
			return
		}
	}
	entries = append(entries, entry)
	m.saveIndex(indexPath, entries)
}

// UpdateRunInIndex updates an existing run's status and duration.
func (m *Manager) UpdateRunInIndex(wfName, runID, status string, duration float64) {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	indexPath := filepath.Join(m.baseDir, wfName, "runs.json")
	entries := m.loadIndex(indexPath)
	for i := range entries {
		if entries[i].RunID == runID {
			entries[i].Status = status
			entries[i].Duration = duration
			break
		}
	}
	m.saveIndex(indexPath, entries)
}

// ListRuns returns the run history for a workflow, newest first.
func (m *Manager) ListRuns(wfName string) []RunIndex {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	indexPath := filepath.Join(m.baseDir, wfName, "runs.json")
	entries := m.loadIndex(indexPath)
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedAt > entries[j].StartedAt
	})
	return entries
}

// CleanOldRuns removes run directories beyond the retention limit.
func (m *Manager) CleanOldRuns(wfName string) {
	m.indexMu.Lock()
	defer m.indexMu.Unlock()
	indexPath := filepath.Join(m.baseDir, wfName, "runs.json")
	entries := m.loadIndex(indexPath)

	// Sort oldest first.
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].StartedAt < entries[j].StartedAt
	})

	if len(entries) <= m.maxRuns {
		return
	}

	// Only remove completed runs; never delete running/pending runs.
	var removable []RunIndex
	var protected []RunIndex
	for _, e := range entries {
		if e.Status == "running" || e.Status == "pending" {
			protected = append(protected, e)
		} else {
			removable = append(removable, e)
		}
	}

	if len(removable)+len(protected) <= m.maxRuns {
		return
	}

	keep := m.maxRuns - len(protected)
	if keep < 0 {
		keep = 0
	}
	var toRemove []RunIndex
	if len(removable) > keep {
		toRemove = removable[:len(removable)-keep]
		removable = removable[len(removable)-keep:]
	}

	for _, entry := range toRemove {
		runDir := filepath.Join(m.baseDir, wfName, "runs", entry.RunID)
		os.RemoveAll(runDir)
	}

	kept := append(protected, removable...)
	m.saveIndex(indexPath, kept)
}

// EnsureWorkflowDir creates the workflow directory structure.
func (m *Manager) EnsureWorkflowDir(wfName string) {
	os.MkdirAll(filepath.Join(m.baseDir, wfName, "runs"), 0700)
}

// WriteStepLog writes step stdout to the archived log file.
func (m *Manager) WriteStepLog(wfName, runID, jobName, stepName, content string) {
	path := m.StepLogPath(wfName, runID, jobName, stepName)
	os.MkdirAll(filepath.Dir(path), 0700)
	os.WriteFile(path, []byte(content), 0600)
}

// ReadStepLog reads an archived step log. Returns empty string if not found.
func (m *Manager) ReadStepLog(wfName, runID, jobName, stepName string) string {
	data, err := os.ReadFile(m.StepLogPath(wfName, runID, jobName, stepName))
	if err != nil {
		return ""
	}
	return string(data)
}

// NowTimestamp returns the current UTC time formatted for indexes.
func NowTimestamp() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func (m *Manager) loadIndex(path string) []RunIndex {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var entries []RunIndex
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("WARNING: failed to parse %s: %v", path, err)
	}
	return entries
}

func (m *Manager) saveIndex(path string, entries []RunIndex) {
	os.MkdirAll(filepath.Dir(path), 0700)
	data, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		log.Printf("WARNING: failed to marshal index: %v", err)
		return
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Printf("WARNING: failed to open %s: %v", tmp, err)
		return
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		log.Printf("WARNING: failed to write %s: %v", tmp, err)
		return
	}
	if err := f.Sync(); err != nil {
		f.Close()
		log.Printf("WARNING: failed to sync %s: %v", tmp, err)
		return
	}
	f.Close()
	if err := os.Rename(tmp, path); err != nil {
		log.Printf("WARNING: failed to rename %s: %v", tmp, err)
	}
}
