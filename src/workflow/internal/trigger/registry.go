package trigger

import (
	"sync"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

// Registry tracks loaded workflow definitions and their owners.
type Registry struct {
	mu        sync.RWMutex
	workflows map[string]*models.Workflow
	owners    map[string]string // workflow name -> owner username (from the wf-<name> App)
}

func NewRegistry() *Registry {
	return &Registry{
		workflows: make(map[string]*models.Workflow),
		owners:    make(map[string]string),
	}
}

func (r *Registry) Update(name string, wf *models.Workflow, owner string) {
	r.mu.Lock()
	r.workflows[name] = wf
	r.owners[name] = owner
	r.mu.Unlock()
}

func (r *Registry) Remove(name string) {
	r.mu.Lock()
	delete(r.workflows, name)
	delete(r.owners, name)
	r.mu.Unlock()
}

// Owner returns the recorded owner of a workflow, or "" if unknown. Local lookup
// (populated by the scan and on registration) — no daemon round-trip.
func (r *Registry) Owner(name string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.owners[name]
}

func (r *Registry) Get(name string) *models.Workflow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.workflows[name]
}

func (r *Registry) All() map[string]*models.Workflow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]*models.Workflow, len(r.workflows))
	for k, v := range r.workflows {
		out[k] = v
	}
	return out
}

// WatchingApp returns workflows whose app_event trigger matches the given app and event type.
func (r *Registry) WatchingApp(appName, eventType string) []*models.Workflow {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var result []*models.Workflow
	for _, wf := range r.workflows {
		if wf.On == nil || wf.On.AppEvent == nil {
			continue
		}
		ae := wf.On.AppEvent
		if ae.App != appName {
			continue
		}
		for _, ev := range ae.Events {
			if ev == eventType {
				result = append(result, wf)
				break
			}
		}
	}
	return result
}
