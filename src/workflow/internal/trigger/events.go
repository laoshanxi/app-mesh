package trigger

import (
	"encoding/json"
	"strconv"
	"sync"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

// EventListener subscribes to App Mesh events and dispatches to matching workflows.
type EventListener struct {
	client      *appmesh.AppMeshClient
	registry    *Registry
	runCallback func(wf *models.Workflow, source string, inputs map[string]string) (string, string)

	mu            sync.Mutex
	subscriptions map[string]string // app name → subscription ID
	generation    uint64            // incremented on disconnect; subscribes from old generations are discarded
}

func NewEventListener(client *appmesh.AppMeshClient, registry *Registry,
	cb func(*models.Workflow, string, map[string]string) (string, string)) *EventListener {
	return &EventListener{
		client:        client,
		registry:      registry,
		runCallback:   cb,
		subscriptions: make(map[string]string),
	}
}

// SyncSubscriptions updates subscriptions to match current workflow triggers.
func (el *EventListener) SyncSubscriptions() {
	needed := make(map[string]bool)
	for _, wf := range el.registry.All() {
		if wf.On != nil && wf.On.AppEvent != nil {
			needed[wf.On.AppEvent.App] = true
		}
	}

	el.mu.Lock()
	current := make(map[string]string, len(el.subscriptions))
	for k, v := range el.subscriptions {
		current[k] = v
	}
	el.mu.Unlock()

	for appName := range needed {
		if _, ok := current[appName]; ok {
			continue
		}
		el.subscribe(appName)
	}

	for appName, subID := range current {
		if needed[appName] {
			continue
		}
		el.unsubscribe(appName, subID)
	}
}

func (el *EventListener) subscribe(appName string) {
	el.mu.Lock()
	gen := el.generation
	el.mu.Unlock()

	sub, err := el.client.Subscribe(
		appmesh.SubscribeOption{
			AppName: appName,
			Events:  []string{"START", "EXIT", "HEALTH", "STATUS", "REMOVED"},
		},
		el.onEvent,
	)
	if err != nil {
		logger.Error("failed to subscribe to app '" + appName + "': " + err.Error())
		return
	}

	el.mu.Lock()
	// Discard if a disconnect happened during the subscribe RPC; the sub_id
	// would be stale on the server side.
	if el.generation != gen {
		el.mu.Unlock()
		_ = el.client.Unsubscribe(sub.SubscriptionID)
		return
	}
	el.subscriptions[appName] = sub.SubscriptionID
	el.mu.Unlock()

	logger.Info("TRIGGER subscribed to app '" + appName + "' (sub_id=" + sub.SubscriptionID + ")")
}

func (el *EventListener) unsubscribe(appName, subID string) {
	el.mu.Lock()
	delete(el.subscriptions, appName)
	el.mu.Unlock()

	if err := el.client.Unsubscribe(subID); err != nil {
		logger.Error("failed to unsubscribe from app '" + appName + "': " + err.Error())
	}
}

func (el *EventListener) onEvent(event appmesh.AppEvent) {
	if event.EventType == "__disconnected__" {
		logger.Error("event connection disconnected, will reconnect on next scan")
		el.mu.Lock()
		el.subscriptions = make(map[string]string)
		el.generation++
		el.mu.Unlock()
		return
	}

	workflows := el.registry.WatchingApp(event.AppName, event.EventType)
	for _, wf := range workflows {
		ae := wf.On.AppEvent
		if ae.Condition != "" {
			if !evalEventCondition(ae.Condition, event.Data) {
				continue
			}
		}
		el.runCallback(wf, "app_event:"+event.AppName+":"+event.EventType, nil)
	}
}

func evalEventCondition(condition string, data json.RawMessage) bool {
	var vars map[string]any
	if err := json.Unmarshal(data, &vars); err != nil {
		return false
	}

	exitCode := 0
	if v, ok := vars["exit_code"]; ok {
		exitCode = toInt(v)
	} else if v, ok := vars["return_code"]; ok {
		exitCode = toInt(v)
	}

	// Simple evaluation: replace known variable names with values.
	// return_code is accepted as an alias since event payloads use either key.
	expr := condition
	expr = replaceVar(expr, "exit_code", strconv.Itoa(exitCode))
	expr = replaceVar(expr, "return_code", strconv.Itoa(exitCode))

	// Evaluate simple "N == M" / "N != M" patterns.
	return evalSimple(expr)
}

func replaceVar(expr, name, value string) string {
	// Only replace whole-word occurrences.
	result := ""
	for len(expr) > 0 {
		idx := indexOf(expr, name)
		if idx < 0 {
			result += expr
			break
		}
		result += expr[:idx] + value
		expr = expr[idx+len(name):]
	}
	return result
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			if i > 0 && isAlnum(s[i-1]) {
				continue
			}
			end := i + len(sub)
			if end < len(s) && isAlnum(s[end]) {
				continue
			}
			return i
		}
	}
	return -1
}

func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '_'
}

func evalSimple(expr string) bool {
	for _, op := range []string{"==", "!="} {
		if idx := findOp(expr, op); idx >= 0 {
			left := trimAll(expr[:idx])
			right := trimAll(expr[idx+len(op):])
			li, lErr := strconv.Atoi(left)
			ri, rErr := strconv.Atoi(right)
			if lErr == nil && rErr == nil {
				if op == "==" {
					return li == ri
				}
				return li != ri
			}
			if op == "==" {
				return left == right
			}
			return left != right
		}
	}
	return false
}

func findOp(s, op string) int {
	for i := 0; i <= len(s)-len(op); i++ {
		if s[i:i+len(op)] == op {
			if op == "==" && i > 0 && s[i-1] == '!' {
				continue
			}
			return i
		}
	}
	return -1
}

func trimAll(s string) string {
	result := make([]byte, 0, len(s))
	for i := range len(s) {
		if s[i] != ' ' {
			result = append(result, s[i])
		}
	}
	return string(result)
}

func toInt(v any) int {
	switch n := v.(type) {
	case float64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

// Cleanup unsubscribes from all events.
func (el *EventListener) Cleanup() {
	el.mu.Lock()
	subs := make(map[string]string, len(el.subscriptions))
	for k, v := range el.subscriptions {
		subs[k] = v
	}
	el.subscriptions = make(map[string]string)
	el.mu.Unlock()

	for _, subID := range subs {
		_ = el.client.Unsubscribe(subID)
	}
}
