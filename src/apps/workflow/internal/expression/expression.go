package expression

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/logger"
)

var exprPattern = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)
var toJSONPattern = regexp.MustCompile(`^toJSON\((.+)\)$`)

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
	// Strict fails unresolved value substitution instead of embedding it; set before the run starts.
	Strict bool
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
func (c *Context) SetStepResult(jobName, stepName, stdout string, exitCode int, status, response string,
	outputs map[string]string) {
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
				// An unknown step name must surface (literal kept / strict error),
				// never silently substitute empty.
				return nil, false
			}
			if parts[2] == "outputs" && len(parts) >= 4 {
				if outs, ok := s["outputs"].(map[string]string); ok {
					if v, ok := outs[parts[3]]; ok {
						return v, true
					}
				}
				return nil, false
			}
			v, ok := s[parts[2]]
			if !ok {
				return nil, false
			}
			return v, true
		}
	case "jobs":
		if len(parts) >= 3 {
			j, ok := c.Jobs[parts[1]]
			if !ok {
				return nil, false
			}
			if parts[2] == "status" {
				return j["status"], true
			}
			if parts[2] == "steps" && len(parts) >= 5 {
				stepsMap, ok := j["steps"].(map[string]map[string]any)
				if !ok {
					return nil, false
				}
				step, ok := stepsMap[parts[3]]
				if !ok {
					return nil, false
				}
				// Handle jobs.X.steps.Y.outputs.Z — drill into outputs map.
				if parts[4] == "outputs" && len(parts) >= 6 {
					if outs, ok := step["outputs"].(map[string]string); ok {
						if v, ok := outs[parts[5]]; ok {
							return v, true
						}
					}
					return nil, false
				}
				v, ok := step[parts[4]]
				if !ok {
					return nil, false
				}
				return v, true
			}
			return nil, false
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

// Substitute replaces each ${{ expr }} with its value; unresolved ones warn
// and stay literal (see SubstituteForJobChecked).
func Substitute(template string, ctx *Context) string {
	s, _ := SubstituteForJobChecked(template, ctx, "")
	return s
}

func SubstituteForJob(template string, ctx *Context, jobName string) string {
	s, _ := SubstituteForJobChecked(template, ctx, jobName)
	return s
}

// SubstituteForJobChecked returns an error on the first unresolved expression
// when ctx.Strict; condition (if:) operands always stay lenient.
func SubstituteForJobChecked(template string, ctx *Context, jobName string) (string, error) {
	var strictErr error
	out := exprPattern.ReplaceAllStringFunc(template, func(match string) string {
		inner := exprPattern.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		resolved, ok := resolveExpr(strings.TrimSpace(inner[1]), match, ctx, jobName)
		if !ok {
			if ctx.Strict {
				if strictErr == nil {
					strictErr = fmt.Errorf("unresolved expression %s", match)
				}
			} else {
				logger.Warn("expression: unresolved " + match + " embedded literally")
			}
			return match
		}
		return resolved
	})
	if strictErr != nil {
		return "", strictErr
	}
	return out, nil
}

// SubstituteForCommand rewrites every ${{ expr }} in a shell command into a
// $WF_E<N> environment reference and returns the bindings for those variables.
// Values then reach the shell only through the environment, so input like
// "a; rm -rf /" can never inject shell syntax into the command text.
// An expression inside a single-quoted span is the exception — the shell never
// expands variables there — so it is substituted textually with single quotes
// escaped (see emitExpr).
func SubstituteForCommand(template string, ctx *Context, jobName string) (string, map[string]string, error) {
	// $WF_E<N> is a reserved reference; if the command already uses one, a
	// generated binding would shadow it. Fall back to direct substitution.
	if strings.Contains(template, "$WF_E") {
		s, err := SubstituteForJobChecked(template, ctx, jobName)
		return s, nil, err
	}
	bindings := make(map[string]string)
	byExpr := make(map[string]string)
	var buildErr error
	emitExpr := func(match, exprText string, inSingle bool) string {
		resolved, ok := resolveExpr(exprText, match, ctx, jobName)
		if !ok {
			if ctx.Strict {
				if buildErr == nil {
					buildErr = fmt.Errorf("unresolved expression %s", match)
				}
			} else {
				logger.Warn("expression: unresolved " + match + " embedded literally")
			}
			return match
		}
		if inSingle {
			return strings.ReplaceAll(resolved, "'", `'\''`)
		}
		if ref, seen := byExpr[exprText]; seen {
			return ref
		}
		ref := fmt.Sprintf("$WF_E%d", len(byExpr))
		byExpr[exprText] = ref
		bindings[ref[1:]] = resolved
		return ref
	}
	// Expression spans are transparent to the quote state.
	const exprOpen, exprClose = "${{", "}}"
	var b strings.Builder
	inSingle, inDouble := false, false
	for i := 0; i < len(template); {
		if strings.HasPrefix(template[i:], exprOpen) {
			if rel := strings.Index(template[i:], exprClose); rel >= len(exprOpen) {
				match := template[i : i+rel+len(exprClose)]
				if exprText := strings.TrimSpace(template[i+len(exprOpen) : i+rel]); exprText != "" {
					b.WriteString(emitExpr(match, exprText, inSingle))
					i += len(match)
					continue
				}
			}
		}
		switch template[i] {
		case '\\':
			b.WriteByte(template[i])
			if !inSingle && i+1 < len(template) {
				b.WriteByte(template[i+1])
				i += 2
				continue
			}
			i++
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
			b.WriteByte(template[i])
			i++
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
			b.WriteByte(template[i])
			i++
		default:
			b.WriteByte(template[i])
			i++
		}
	}
	if buildErr != nil {
		return "", nil, buildErr
	}
	out := b.String()
	if len(bindings) == 0 {
		return out, nil, nil
	}
	return out, bindings, nil
}

// resolveExpr renders one expression; ok is false when its path is unresolved.
// toJSON(path) emits a quoted JSON literal so values cannot break the document.
func resolveExpr(expr, orig string, ctx *Context, jobName string) (string, bool) {
	if m := toJSONPattern.FindStringSubmatch(expr); m != nil {
		val, ok := ctx.resolveForJob(strings.TrimSpace(m[1]), jobName)
		if !ok {
			return "", false
		}
		if enc, err := json.Marshal(val); err == nil {
			return string(enc), true
		}
		return orig, true
	}
	val, ok := ctx.resolveForJob(expr, jobName)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%v", val), true
}

// substituteExpr renders one condition operand; unresolved ones warn and stay literal.
func substituteExpr(expr string, ctx *Context, jobName, orig string) string {
	resolved, ok := resolveExpr(expr, orig, ctx, jobName)
	if !ok {
		logger.Warn("expression: unresolved " + orig + " embedded literally")
		return orig
	}
	return resolved
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

	// Unwrap ${{ }} to its inner expression text so operators inside the
	// braces take effect (GitHub Actions semantics). The braces hold
	// author-written YAML text, not an interpolated value, so this adds no
	// operator injection.
	if strings.Contains(expr, "${{") {
		expr = exprPattern.ReplaceAllStringFunc(expr, func(match string) string {
			if inner := exprPattern.FindStringSubmatch(match); len(inner) == 2 {
				return strings.TrimSpace(inner[1])
			}
			return match
		})
		expr = strings.TrimSpace(expr)
		if expr == "" {
			return true
		}
	}

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
	// splitTopLevel ignores operators inside quotes or ${{ }} blocks, so a value
	// interpolated into an operand cannot inject a new operator (see coerce).
	if parts := splitTopLevel(expr, "||"); len(parts) > 1 {
		for _, part := range parts {
			if evalCondition(strings.TrimSpace(part), ctx, jobName, status) {
				return true
			}
		}
		return false
	}
	if parts := splitTopLevel(expr, "&&"); len(parts) > 1 {
		for _, part := range parts {
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
		return substituteExpr(strings.TrimSpace(inner[1]), ctx, jobName, match)
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

// splitTopLevel splits s on sep, ignoring occurrences inside single/double
// quotes or inside ${{ }} blocks. This keeps an interpolated operand value from
// injecting boolean operators that would restructure the condition.
func splitTopLevel(s, sep string) []string {
	var parts []string
	var buf strings.Builder
	var inSingle, inDouble bool
	tmpl := 0
	for i := 0; i < len(s); {
		if tmpl == 0 && !inSingle && !inDouble && strings.HasPrefix(s[i:], "${{") {
			tmpl++
			buf.WriteString("${{")
			i += 3
			continue
		}
		if tmpl > 0 && strings.HasPrefix(s[i:], "}}") {
			tmpl--
			buf.WriteString("}}")
			i += 2
			continue
		}
		if tmpl == 0 {
			c := s[i]
			if !inDouble && c == '\'' {
				inSingle = !inSingle
			} else if !inSingle && c == '"' {
				inDouble = !inDouble
			}
			if !inSingle && !inDouble && strings.HasPrefix(s[i:], sep) {
				parts = append(parts, buf.String())
				buf.Reset()
				i += len(sep)
				continue
			}
		}
		buf.WriteByte(s[i])
		i++
	}
	parts = append(parts, buf.String())
	return parts
}

// indexTopLevel returns the index of the first occurrence of sym in s that is
// not inside quotes or a ${{ }} block, or -1 if none.
func indexTopLevel(s, sym string) int {
	var inSingle, inDouble bool
	tmpl := 0
	for i := 0; i < len(s); {
		if tmpl == 0 && !inSingle && !inDouble && strings.HasPrefix(s[i:], "${{") {
			tmpl++
			i += 3
			continue
		}
		if tmpl > 0 && strings.HasPrefix(s[i:], "}}") {
			tmpl--
			i += 2
			continue
		}
		if tmpl == 0 {
			c := s[i]
			if !inDouble && c == '\'' {
				inSingle = !inSingle
				i++
				continue
			}
			if !inSingle && c == '"' {
				inDouble = !inDouble
				i++
				continue
			}
			if !inSingle && !inDouble && strings.HasPrefix(s[i:], sym) {
				return i
			}
		}
		i++
	}
	return -1
}

// HasStatusFunction reports whether the condition references one of the status
// functions always()/success()/failure() outside quoted operands and ${{ }}
// blocks, so literal text like `== 'success()'` does not count.
func HasStatusFunction(condition string) bool {
	for _, fn := range []string{"always()", "success()", "failure()"} {
		if indexTopLevel(condition, fn) >= 0 {
			return true
		}
	}
	return false
}

func evalComparison(expr string, ctx *Context, jobName string) bool {
	for _, op := range cmpOps {
		idx := indexTopLevel(expr, op.sym)
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
	return truthy(coerce(expr, ctx, jobName))
}

// truthy follows GitHub Actions semantics: false, 0 and "" are falsy.
// A resolved string "false" is also falsy since inputs and step outputs are
// carried as strings in this engine.
func truthy(v any) bool {
	switch n := v.(type) {
	case bool:
		return n
	case int:
		return n != 0
	case float64:
		return n != 0
	case string:
		return n != "" && !strings.EqualFold(n, "false")
	}
	return v != nil
}

func coerce(token string, ctx *Context, jobName string) any {
	token = strings.TrimSpace(token)
	// Resolve any ${{ }} references first so the result is treated as a plain
	// operand value — it is never re-parsed for operators, which is what
	// prevents an interpolated value from injecting into the condition.
	if strings.Contains(token, "${{") {
		token = strings.TrimSpace(substituteInline(token, ctx, jobName))
	}
	if (strings.HasPrefix(token, `"`) && strings.HasSuffix(token, `"`)) ||
		(strings.HasPrefix(token, `'`) && strings.HasSuffix(token, `'`)) {
		return token[1 : len(token)-1]
	}
	if token == "true" {
		return true
	}
	if token == "false" {
		return false
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
