package trigger

import (
	"sync"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

// Registry tracks loaded workflow definitions.
type Registry struct {
	mu        sync.RWMutex
	workflows map[string]*models.Workflow
}

func NewRegistry() *Registry {
	return &Registry{workflows: make(map[string]*models.Workflow)}
}

func (r *Registry) Update(name string, wf *models.Workflow) {
	r.mu.Lock()
	r.workflows[name] = wf
	r.mu.Unlock()
}

func (r *Registry) Remove(name string) {
	r.mu.Lock()
	delete(r.workflows, name)
	r.mu.Unlock()
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
