package trigger

import (
	"sync"
)

// RunManager tracks running workflow goroutines and handles concurrency control.
type RunManager struct {
	mu      sync.Mutex
	running map[string]map[string]struct{} // group → set of run IDs
	queued  map[string][]pendingRun
}

type pendingRun struct {
	runID  string
	wfName string
	source string
	inputs map[string]string
	token  string // caller JWT (in-memory only; never persisted), empty for auto triggers
	actor  string // triggering username for audit, empty for auto triggers
}

func NewRunManager() *RunManager {
	return &RunManager{
		running: make(map[string]map[string]struct{}),
		queued:  make(map[string][]pendingRun),
	}
}

// TryStart checks concurrency rules. Returns true if the run can proceed.
// If cancel-in-progress, returns run IDs to cancel.
func (rm *RunManager) TryStart(group, runID string, cancelInProgress bool) (ok bool, toCancel []string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if group == "" {
		return true, nil
	}

	active := rm.running[group]
	if len(active) == 0 {
		if rm.running[group] == nil {
			rm.running[group] = make(map[string]struct{})
		}
		rm.running[group][runID] = struct{}{}
		return true, nil
	}

	if cancelInProgress {
		var ids []string
		for id := range active {
			ids = append(ids, id)
		}
		rm.running[group] = map[string]struct{}{runID: {}}
		return true, ids
	}

	return false, nil
}

// Enqueue adds a run to the wait queue for a concurrency group.
func (rm *RunManager) Enqueue(group, runID, wfName, source string, inputs map[string]string, token, actor string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.queued[group] = append(rm.queued[group], pendingRun{runID: runID, wfName: wfName, source: source, inputs: inputs, token: token, actor: actor})
}

// Complete marks a run as finished and returns the next queued run if any.
// Only dequeues when this runID was the LAST active member of the group.
// Stale completers (evicted by cancel-in-progress, or arriving after the
// group has already been drained) return nil so the queue is not popped twice.
func (rm *RunManager) Complete(group, runID string) *pendingRun {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	active, ok := rm.running[group]
	if !ok {
		// Group no longer exists — either we never registered (no-op caller)
		// or another completer has already drained it. Don't pop the queue.
		return nil
	}
	if _, was := active[runID]; !was {
		// runID was evicted (cancel-in-progress) or never registered here.
		return nil
	}
	delete(active, runID)
	if len(active) != 0 {
		// Other runs still active in this group.
		return nil
	}

	// Atomically promote the next queued run INTO `running` before releasing
	// the lock. If we instead deleted the group and let the caller re-register
	// later (via MarkRunning), a concurrent TryStart landing in that window
	// would see an empty group and start in parallel — violating concurrency=1.
	// The caller MUST either launch the returned run or call Complete again to
	// release it (e.g. if its workflow no longer exists), otherwise the group
	// stays occupied forever.
	if q, ok := rm.queued[group]; ok && len(q) > 0 {
		next := q[0]
		rm.queued[group] = q[1:]
		if len(rm.queued[group]) == 0 {
			delete(rm.queued, group)
		}
		rm.running[group] = map[string]struct{}{next.runID: {}}
		return &next
	}

	delete(rm.running, group)
	return nil
}

// MarkRunning manually registers a run ID in a group.
func (rm *RunManager) MarkRunning(group, runID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if rm.running[group] == nil {
		rm.running[group] = make(map[string]struct{})
	}
	rm.running[group][runID] = struct{}{}
}

// RemoveQueued removes a single queued run by its run ID and returns its
// workflow name. Used to cancel a run that is still waiting on its
// concurrency group (it has no cancel context yet).
func (rm *RunManager) RemoveQueued(runID string) (wfName string, found bool) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for group, q := range rm.queued {
		for i, p := range q {
			if p.runID != runID {
				continue
			}
			rm.queued[group] = append(q[:i:i], q[i+1:]...)
			if len(rm.queued[group]) == 0 {
				delete(rm.queued, group)
			}
			return p.wfName, true
		}
	}
	return "", false
}

// DrainQueueByWorkflow removes all queued runs belonging to the given workflow
// across all concurrency groups and returns the drained run IDs so the caller
// can finalize their persistent state.
func (rm *RunManager) DrainQueueByWorkflow(wfName string) []string {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	var drained []string
	for group, q := range rm.queued {
		var kept []pendingRun
		for _, p := range q {
			if p.wfName == wfName {
				drained = append(drained, p.runID)
			} else {
				kept = append(kept, p)
			}
		}
		if len(kept) == 0 {
			delete(rm.queued, group)
		} else {
			rm.queued[group] = kept
		}
	}
	return drained
}
