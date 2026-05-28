package trigger

import (
	"testing"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/workdir"
)

func wf(name string, appEvent *models.TriggerAppEvent, schedules []models.ScheduleTrigger, conc *models.ConcurrencyConfig) *models.Workflow {
	return &models.Workflow{
		Name:        name,
		Owner:       "admin",
		On:          &models.TriggerConfig{AppEvent: appEvent, Schedule: schedules},
		Concurrency: conc,
	}
}

// --- Registry ---

func TestRegistry_AddGet(t *testing.T) {
	r := NewRegistry()
	w := wf("test", nil, nil, nil)
	r.Update("test", w)
	if got := r.Get("test"); got != w {
		t.Error("get failed")
	}
}

func TestRegistry_Remove(t *testing.T) {
	r := NewRegistry()
	r.Update("test", wf("test", nil, nil, nil))
	r.Remove("test")
	if r.Get("test") != nil {
		t.Error("remove failed")
	}
}

func TestRegistry_All(t *testing.T) {
	r := NewRegistry()
	r.Update("a", wf("a", nil, nil, nil))
	r.Update("b", wf("b", nil, nil, nil))
	if len(r.All()) != 2 {
		t.Errorf("got %d", len(r.All()))
	}
}

func TestRegistry_WatchingApp_Match(t *testing.T) {
	r := NewRegistry()
	r.Update("deploy", wf("deploy", &models.TriggerAppEvent{App: "collector", Events: []string{"EXIT"}}, nil, nil))
	matches := r.WatchingApp("collector", "EXIT")
	if len(matches) != 1 || matches[0].Name != "deploy" {
		t.Errorf("matches: %v", matches)
	}
}

func TestRegistry_WatchingApp_NoMatch_WrongEvent(t *testing.T) {
	r := NewRegistry()
	r.Update("deploy", wf("deploy", &models.TriggerAppEvent{App: "collector", Events: []string{"EXIT"}}, nil, nil))
	if len(r.WatchingApp("collector", "START")) != 0 {
		t.Error("should not match")
	}
}

func TestRegistry_WatchingApp_NoMatch_WrongApp(t *testing.T) {
	r := NewRegistry()
	r.Update("deploy", wf("deploy", &models.TriggerAppEvent{App: "collector", Events: []string{"EXIT"}}, nil, nil))
	if len(r.WatchingApp("other", "EXIT")) != 0 {
		t.Error("should not match")
	}
}

func TestRegistry_WatchingApp_NoTrigger(t *testing.T) {
	r := NewRegistry()
	r.Update("plain", &models.Workflow{Name: "plain"})
	if len(r.WatchingApp("anything", "EXIT")) != 0 {
		t.Error("should not match")
	}
}

func TestRegistry_MultipleWorkflowsSameApp(t *testing.T) {
	r := NewRegistry()
	r.Update("a", wf("a", &models.TriggerAppEvent{App: "collector", Events: []string{"EXIT"}}, nil, nil))
	r.Update("b", wf("b", &models.TriggerAppEvent{App: "collector", Events: []string{"EXIT", "START"}}, nil, nil))
	if len(r.WatchingApp("collector", "EXIT")) != 2 {
		t.Error("should match 2")
	}
	if len(r.WatchingApp("collector", "START")) != 1 {
		t.Error("should match 1")
	}
}

// --- RunManager ---

func TestRunManager_TryStart_NoGroup(t *testing.T) {
	rm := NewRunManager()
	ok, cancel := rm.TryStart("", "run-1", false)
	if !ok || len(cancel) != 0 {
		t.Error("should start")
	}
}

func TestRunManager_TryStart_FirstInGroup(t *testing.T) {
	rm := NewRunManager()
	ok, cancel := rm.TryStart("deploy", "run-1", false)
	if !ok || len(cancel) != 0 {
		t.Error("first should start")
	}
}

func TestRunManager_TryStart_BlockedByRunning(t *testing.T) {
	rm := NewRunManager()
	rm.TryStart("deploy", "run-1", false)
	ok, _ := rm.TryStart("deploy", "run-2", false)
	if ok {
		t.Error("should be blocked")
	}
}

func TestRunManager_TryStart_CancelInProgress(t *testing.T) {
	rm := NewRunManager()
	rm.TryStart("deploy", "run-1", false)
	ok, toCancel := rm.TryStart("deploy", "run-2", true)
	if !ok {
		t.Error("should start with cancel")
	}
	if len(toCancel) != 1 || toCancel[0] != "run-1" {
		t.Errorf("toCancel: %v", toCancel)
	}
}

func TestRunManager_Enqueue_Dequeue(t *testing.T) {
	rm := NewRunManager()
	rm.TryStart("deploy", "run-1", false)
	rm.Enqueue("deploy", "run-2", "wf-next", "queued", nil)

	next := rm.Complete("deploy", "run-1")
	if next == nil || next.wfName != "wf-next" || next.runID != "run-2" {
		t.Errorf("next: %+v", next)
	}
}

func TestRunManager_Complete_NoQueue(t *testing.T) {
	rm := NewRunManager()
	rm.TryStart("deploy", "run-1", false)
	next := rm.Complete("deploy", "run-1")
	if next != nil {
		t.Error("should be nil")
	}
}

// --- Event condition ---

func TestEvalEventCondition_Equals(t *testing.T) {
	data := []byte(`{"exit_code": 0}`)
	if !evalEventCondition("exit_code == 0", data) {
		t.Error("should match")
	}
}

func TestEvalEventCondition_NotEquals(t *testing.T) {
	data := []byte(`{"exit_code": 1}`)
	if !evalEventCondition("exit_code != 0", data) {
		t.Error("should match")
	}
}

func TestEvalEventCondition_Fails(t *testing.T) {
	data := []byte(`{"exit_code": 1}`)
	if evalEventCondition("exit_code == 0", data) {
		t.Error("should not match")
	}
}

// --- Checkpoint ---

func newTestCheckpoint(t *testing.T) (*Checkpoint, *workdir.Manager, string) {
	t.Helper()
	dir := t.TempDir()
	wdir := workdir.NewManager(dir, 10)
	return NewCheckpoint(wdir), wdir, dir
}

func TestCheckpoint_SaveAndRecover(t *testing.T) {
	cp, _, baseDir := newTestCheckpoint(t)
	cp.SaveRunning("deploy", "run-1", "cron:* * * * *", map[string]string{"env": "prod"}, []string{"build", "test", "deploy"})

	stale := cp.RecoverStale(baseDir)
	if len(stale) != 1 {
		t.Fatalf("want 1 stale, got %d", len(stale))
	}
	if stale[0].RunID != "run-1" || stale[0].Workflow != "deploy" {
		t.Errorf("stale: %+v", stale[0])
	}
	if len(stale[0].Jobs) != 3 {
		t.Errorf("jobs: %d", len(stale[0].Jobs))
	}
}

func TestCheckpoint_UpdateJobAndCompletedJobs(t *testing.T) {
	cp, _, _ := newTestCheckpoint(t)
	cp.SaveRunning("pipeline", "run-2", "manual", nil, []string{"build", "test", "deploy"})
	cp.UpdateJob("pipeline", "run-2", "build", "success", "", nil)
	cp.UpdateJob("pipeline", "run-2", "test", "success", "", nil)

	completed := cp.CompletedJobs("pipeline", "run-2")
	if len(completed) != 2 {
		t.Fatalf("want 2 completed, got %d", len(completed))
	}
	if completed["build"] != "success" || completed["test"] != "success" {
		t.Errorf("completed: %v", completed)
	}
	if _, ok := completed["deploy"]; ok {
		t.Error("deploy should not be completed")
	}
}

func TestCheckpoint_MarkCompletePreservesFile(t *testing.T) {
	cp, _, baseDir := newTestCheckpoint(t)
	cp.SaveRunning("wf", "run-3", "cli", nil, []string{"a"})
	cp.UpdateJob("wf", "run-3", "a", "success", "", nil)
	cp.MarkComplete("wf", "run-3", "success")

	// Completed checkpoint is preserved but not recovered as stale.
	stale := cp.RecoverStale(baseDir)
	if len(stale) != 0 {
		t.Errorf("want 0 stale after complete, got %d", len(stale))
	}
	// run_detail can still read job data.
	rec := cp.GetRunRecord("wf", "run-3")
	if rec == nil || rec.Status != "success" {
		t.Errorf("want completed record, got %v", rec)
	}
	if rec.Jobs["a"].Status != "success" {
		t.Errorf("want job a success, got %s", rec.Jobs["a"].Status)
	}
}

func TestCheckpoint_SkippedJobsIncluded(t *testing.T) {
	cp, _, _ := newTestCheckpoint(t)
	cp.SaveRunning("wf", "run-4", "event", nil, []string{"a", "b"})
	cp.UpdateJob("wf", "run-4", "a", "skipped", "", nil)
	cp.UpdateJob("wf", "run-4", "b", "success", "", nil)

	completed := cp.CompletedJobs("wf", "run-4")
	if len(completed) != 2 {
		t.Fatalf("want 2, got %d", len(completed))
	}
	if completed["a"] != "skipped" {
		t.Errorf("a: %q", completed["a"])
	}
}

func TestCheckpoint_FailedJobInCompleted(t *testing.T) {
	cp, _, _ := newTestCheckpoint(t)
	cp.SaveRunning("wf", "run-5", "event", nil, []string{"a", "b"})
	cp.UpdateJob("wf", "run-5", "a", "success", "", nil)
	cp.UpdateJob("wf", "run-5", "b", "failure", "", nil)

	completed := cp.CompletedJobs("wf", "run-5")
	if len(completed) != 2 {
		t.Fatalf("want 2, got %d", len(completed))
	}
	if completed["b"] != "failure" {
		t.Errorf("want failure, got %q", completed["b"])
	}
}

func TestCheckpoint_EmptyDir(t *testing.T) {
	cp, _, baseDir := newTestCheckpoint(t)
	stale := cp.RecoverStale(baseDir)
	if len(stale) != 0 {
		t.Errorf("want 0, got %d", len(stale))
	}
}

func TestCheckpoint_NonexistentRunID(t *testing.T) {
	cp, _, _ := newTestCheckpoint(t)
	completed := cp.CompletedJobs("wf", "nonexistent")
	if completed != nil {
		t.Errorf("want nil, got %v", completed)
	}
}
