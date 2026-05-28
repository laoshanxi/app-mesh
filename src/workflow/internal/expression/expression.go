package expression

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

var exprPattern = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)

// Context holds runtime state for expression evaluation. Thread-safe.
type Context struct {
	mu           sync.RWMutex
	Steps        map[string]map[string]any // key: "jobName.stepName" (scoped)
	Jobs         map[string]map[string]any
	JobStatuses  map[string]string
	finallySteps map[string]bool // steps in finally section (excluded from success()/failure())
	WfName       string
	WfRunID      string
	Inputs       map[string]string
	Env          map[string]string
}

func NewContext() *Context {
	return &Context{
		Steps:        make(map[string]map[string]any),
		Jobs:         make(map[string]map[string]any),
		JobStatuses:  make(map[string]string),
		finallySteps: make(map[string]bool),
		Inputs:       make(map[string]string),
		Env:          make(map[string]string),
	}
}

// MarkFinallyStep marks a step as belonging to the finally section.
// Such steps are excluded from success()/failure() evaluation.
func (c *Context) MarkFinallyStep(jobName, stepName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.finallySteps[jobName+"."+stepName] = true
}

// SetStepResult stores a step result scoped by job name.
// Within YAML expressions, `steps.<name>` resolves against the caller-supplied jobName.
// Cross-job references use `jobs.<job>.steps.<step>`.
func (c *Context) SetStepResult(jobName, stepName, stdout string, exitCode int, status, response string, outputs map[string]string) {
	key := jobName + "." + stepName
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Steps[key] = map[string]any{
		"stdout":    strings.TrimSpace(stdout),
		"exit_code": exitCode,
		"status":    status,
		"response":  response,
		"outputs":   outputs,
	}
}

func (c *Context) SetJobResult(name string, steps map[string]map[string]any, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Jobs[name] = map[string]any{"steps": steps, "status": status}
	c.JobStatuses[name] = status
}

func (c *Context) SetJobStatusForJob(jobName, status string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.JobStatuses[jobName] = status
}

func (c *Context) resolveForJob(path, jobName string) (any, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.resolveUnsafe(path, jobName)
}

func (c *Context) resolveUnsafe(path, jobName string) (any, bool) {
	parts := strings.Split(path, ".")
	if len(parts) == 0 {
		return nil, false
	}

	switch parts[0] {
	case "steps":
		if len(parts) >= 3 {
			key := jobName + "." + parts[1]
			s, ok := c.Steps[key]
			if !ok {
				return "", true
			}
			if parts[2] == "outputs" && len(parts) >= 4 {
				if outs, ok := s["outputs"].(map[string]string); ok {
					return outs[parts[3]], true
				}
				return "", true
			}
			v, ok := s[parts[2]]
			if !ok {
				return "", true
			}
			return v, true
		}
	case "jobs":
		if len(parts) >= 3 {
			j, ok := c.Jobs[parts[1]]
			if !ok {
				return "", true
			}
			if parts[2] == "status" {
				return j["status"], true
			}
			if parts[2] == "steps" && len(parts) >= 5 {
				stepsMap, ok := j["steps"].(map[string]map[string]any)
				if !ok {
					return "", true
				}
				step, ok := stepsMap[parts[3]]
				if !ok {
					return "", true
				}
				// Handle jobs.X.steps.Y.outputs.Z — drill into outputs map.
				if parts[4] == "outputs" && len(parts) >= 6 {
					if outs, ok := step["outputs"].(map[string]string); ok {
						return outs[parts[5]], true
					}
					return "", true
				}
				return step[parts[4]], true
			}
		}
	case "job":
		if len(parts) == 2 && parts[1] == "status" {
			if status, ok := c.JobStatuses[jobName]; ok {
				return status, true
			}
			return "", true
		}
	case "workflow":
		if len(parts) == 2 {
			switch parts[1] {
			case "name":
				return c.WfName, true
			case "run_id":
				return c.WfRunID, true
			}
		}
	case "inputs":
		if len(parts) == 2 {
			return c.Inputs[parts[1]], true
		}
	case "env":
		if len(parts) == 2 {
			return c.Env[parts[1]], true
		}
	}
	return nil, false
}

// SnapshotJobSteps returns a deep copy of steps belonging to the given job,
// with the job prefix stripped from keys (e.g., "build.compile" → "compile").
// Used for SetJobResult so cross-job references resolve by step name only.
func (c *Context) SnapshotJobSteps(jobName string) map[string]map[string]any {
	c.mu.RLock()
	defer c.mu.RUnlock()
	prefix := jobName + "."
	out := make(map[string]map[string]any)
	for k, v := range c.Steps {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		stepName := strings.TrimPrefix(k, prefix)
		cp := make(map[string]any, len(v))
		for kk, vv := range v {
			if outs, ok := vv.(map[string]string); ok {
				outsCopy := make(map[string]string, len(outs))
				for ok2, ov := range outs {
					outsCopy[ok2] = ov
				}
				cp[kk] = outsCopy
			} else {
				cp[kk] = vv
			}
		}
		out[stepName] = cp
	}
	return out
}

// Substitute replaces all ${{ expr }} in a string with resolved values.
func Substitute(template string, ctx *Context) string {
	return SubstituteForJob(template, ctx, "")
}

func SubstituteForJob(template string, ctx *Context, jobName string) string {
	return exprPattern.ReplaceAllStringFunc(template, func(match string) string {
		inner := exprPattern.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		expr := strings.TrimSpace(inner[1])
		val, ok := ctx.resolveForJob(expr, jobName)
		if !ok {
			return match
		}
		return fmt.Sprintf("%v", val)
	})
}

func EvalConditionForJob(expr string, ctx *Context, jobName string) bool {
	return evalCondition(expr, ctx, jobName, nil)
}

type statusFuncs struct {
	success func() bool
	failure func() bool
}

func EvalConditionForJobWithStatus(expr string, ctx *Context, jobName string, successFn, failureFn func() bool) bool {
	return evalCondition(expr, ctx, jobName, &statusFuncs{success: successFn, failure: failureFn})
}

func evalCondition(expr string, ctx *Context, jobName string, status *statusFuncs) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true
	}
	expr = substituteInline(expr, ctx, jobName)

	switch expr {
	case "always()":
		return true
	case "success()":
		if status != nil && status.success != nil {
			return status.success()
		}
		return allStepsSucceeded(ctx, jobName)
	case "failure()":
		if status != nil && status.failure != nil {
			return status.failure()
		}
		return !allStepsSucceeded(ctx, jobName)
	}

	// Handle || before && so && binds tighter (standard precedence).
	if strings.Contains(expr, "||") {
		for _, part := range strings.Split(expr, "||") {
			if evalCondition(strings.TrimSpace(part), ctx, jobName, status) {
				return true
			}
		}
		return false
	}
	if strings.Contains(expr, "&&") {
		for _, part := range strings.Split(expr, "&&") {
			if !evalCondition(strings.TrimSpace(part), ctx, jobName, status) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(expr, "!") {
		return !evalCondition(strings.TrimPrefix(expr, "!"), ctx, jobName, status)
	}

	return evalComparison(expr, ctx, jobName)
}

func substituteInline(expr string, ctx *Context, jobName string) string {
	return exprPattern.ReplaceAllStringFunc(expr, func(match string) string {
		inner := exprPattern.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		val, ok := ctx.resolveForJob(strings.TrimSpace(inner[1]), jobName)
		if !ok {
			return match
		}
		return fmt.Sprintf("%v", val)
	})
}

func allStepsSucceeded(ctx *Context, jobName string) bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	prefix := jobName + "."
	for key, s := range ctx.Steps {
		if !strings.HasPrefix(key, prefix) {
			continue
		}
		if ctx.finallySteps[key] {
			continue // finally steps don't count toward job success/failure
		}
		if s["status"] == "failure" {
			return false
		}
	}
	return true
}

type cmpOp struct {
	sym string
	fn  func(a, b float64) bool
}

var cmpOps = []cmpOp{
	{">=", func(a, b float64) bool { return a >= b }},
	{"<=", func(a, b float64) bool { return a <= b }},
	{"!=", func(a, b float64) bool { return a != b }},
	{"==", func(a, b float64) bool { return a == b }},
	{">", func(a, b float64) bool { return a > b }},
	{"<", func(a, b float64) bool { return a < b }},
}

func evalComparison(expr string, ctx *Context, jobName string) bool {
	for _, op := range cmpOps {
		idx := strings.Index(expr, op.sym)
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+len(op.sym):])
		lv := coerce(left, ctx, jobName)
		rv := coerce(right, ctx, jobName)

		lf, lok := toFloat(lv)
		rf, rok := toFloat(rv)
		if lok && rok {
			return op.fn(lf, rf)
		}
		ls := fmt.Sprintf("%v", lv)
		rs := fmt.Sprintf("%v", rv)
		switch op.sym {
		case "==":
			return ls == rs
		case "!=":
			return ls != rs
		}
		return false
	}
	return coerce(expr, ctx, jobName) != ""
}

func coerce(token string, ctx *Context, jobName string) any {
	token = strings.TrimSpace(token)
	if (strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`)) ||
		(strings.HasPrefix(token, `'`) && strings.HasSuffix(token, `'`)) {
		return token[1 : len(token)-1]
	}
	if i, err := strconv.Atoi(token); err == nil {
		return i
	}
	if f, err := strconv.ParseFloat(token, 64); err == nil {
		return f
	}
	if val, ok := ctx.resolveForJob(token, jobName); ok {
		return val
	}
	return token
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(n, 64)
		return f, err == nil
	}
	return 0, false
}
