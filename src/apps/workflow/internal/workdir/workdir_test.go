package workdir

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunDir_Creates(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	dir := m.RunDir("my-wf", "run-1")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("RunDir should create directory")
	}
}

func TestStepsDir_Creates(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	dir := m.StepsDir("my-wf", "run-1")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("StepsDir should create directory")
	}
}

func TestPaths(t *testing.T) {
	m := NewManager("/base", 10)
	if got := m.FlowLogPath("wf", "r1"); got != "/base/wf/runs/r1/flow.log" {
		t.Errorf("flow log: %q", got)
	}
	if got := m.StepLogPath("wf", "r1", "build", "compile"); got != "/base/wf/runs/r1/steps/build.compile.log" {
		t.Errorf("step log: %q", got)
	}
	if got := m.CheckpointPath("wf", "r1"); got != "/base/wf/runs/r1/checkpoint.json" {
		t.Errorf("checkpoint: %q", got)
	}
}

func TestWriteAndReadStepLog(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	m.WriteStepLog("wf", "r1", "build", "compile", "hello world\n")
	got := m.ReadStepLog("wf", "r1", "build", "compile")
	if got != "hello world\n" {
		t.Errorf("got %q", got)
	}
}

func TestReadStepLog_NotFound(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	if got := m.ReadStepLog("wf", "r1", "nope", "nope"); got != "" {
		t.Errorf("got %q", got)
	}
}

func TestRunIndex_AddListUpdate(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	m.EnsureWorkflowDir("wf")

	m.AddRunToIndex("wf", RunIndex{RunID: "r1", Workflow: "wf", Status: "running", StartedAt: "2026-05-22T10:00:00Z"})
	m.AddRunToIndex("wf", RunIndex{RunID: "r2", Workflow: "wf", Status: "running", StartedAt: "2026-05-22T11:00:00Z"})

	runs := m.ListRuns("wf")
	if len(runs) != 2 {
		t.Fatalf("want 2 runs, got %d", len(runs))
	}
	if runs[0].RunID != "r2" {
		t.Error("newest should be first")
	}

	m.UpdateRunInIndex("wf", "r1", "success", 30.5)
	runs = m.ListRuns("wf")
	for _, r := range runs {
		if r.RunID == "r1" {
			if r.Status != "success" || r.Duration != 30.5 {
				t.Errorf("r1: status=%q dur=%f", r.Status, r.Duration)
			}
		}
	}
}

func TestCleanOldRuns(t *testing.T) {
	m := NewManager(t.TempDir(), 2) // keep only 2

	for i := 0; i < 5; i++ {
		id := "run-" + string(rune('a'+i))
		m.RunDir("wf", id) // create the dir
		m.AddRunToIndex("wf", RunIndex{
			RunID: id, Workflow: "wf", Status: "success",
			StartedAt: "2026-05-22T1" + string(rune('0'+i)) + ":00:00Z",
		})
	}

	m.CleanOldRuns("wf")

	runs := m.ListRuns("wf")
	if len(runs) != 2 {
		t.Fatalf("want 2 after cleanup, got %d", len(runs))
	}

	// Oldest 3 dirs should be removed.
	for _, id := range []string{"run-a", "run-b", "run-c"} {
		dir := filepath.Join(m.BaseDir(), "wf", "runs", id)
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Errorf("dir %s should be removed", id)
		}
	}
}

func TestCleanOldRuns_UnderLimit(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	m.AddRunToIndex("wf", RunIndex{RunID: "r1", Status: "success", StartedAt: "2026-05-22T10:00:00Z"})
	m.CleanOldRuns("wf") // should not crash or remove anything
	if len(m.ListRuns("wf")) != 1 {
		t.Error("should keep the only run")
	}
}

func TestEnsureWorkflowDir(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	m.EnsureWorkflowDir("new-wf")
	dir := filepath.Join(m.BaseDir(), "new-wf", "runs")
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		t.Error("should create runs subdir")
	}
}

// The persisted schedule instant must survive write+read and overwrite in place;
// workflows without state (or with corrupt state) are simply absent.
func TestScheduleStateRoundTrip(t *testing.T) {
	m := NewManager(t.TempDir(), 10)
	first := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	if err := m.WriteScheduleState("wf", first); err != nil {
		t.Fatalf("write: %v", err)
	}
	second := first.Add(90 * time.Second)
	if err := m.WriteScheduleState("wf", second); err != nil {
		t.Fatalf("overwrite: %v", err)
	}
	states := m.ReadScheduleStates()
	if got, ok := states["wf"]; !ok || !got.Equal(second) {
		t.Fatalf("read: got %v (%v), want %v", got, ok, second)
	}

	// Corrupt and empty-value files must be skipped, not fail the whole scan.
	if err := os.WriteFile(filepath.Join(m.BaseDir(), "wf", "schedule-state.json"),
		[]byte("{truncated"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteScheduleState("zero", time.UnixMilli(0)); err != nil {
		t.Fatal(err)
	}
	if states = m.ReadScheduleStates(); len(states) != 0 {
		t.Fatalf("corrupt/zero states must be dropped, got %v", states)
	}
}
