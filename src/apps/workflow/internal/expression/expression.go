package expression

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
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
	messageSteps map[string]bool // message steps, for the plain-text outputs miss check
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
		messageSteps: make(map[string]bool),
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

// MarkMessageStep records a message step, so a later outputs.<key> reference to
// one that completed without outputs (plain-text reply) fails with a clear error.
func (c *Context) MarkMessageStep(jobName, stepName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.messageSteps[jobName+"."+stepName] = true
}

// MarkContinueOnError flags a failure tolerated by continue-on-error:
// steps.<name>.status keeps the raw outcome, but success()/failure() treat
// the step as non-failed (GitHub Actions conclusion semantics).
func (c *Context) MarkContinueOnError(jobName, stepName string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if s, ok := c.Steps[jobName+"."+stepName]; ok {
		s["continue_on_error"] = true
	}
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
	s, _, err := substituteChecked(template, ctx, jobName)
	return s, err
}

// substituteChecked is SubstituteForJobChecked plus the first message-outputs miss (empty when none).
func substituteChecked(template string, ctx *Context, jobName string) (string, string, error) {
	var strictErr error
	miss := ""
	out := exprPattern.ReplaceAllStringFunc(template, func(match string) string {
		inner := exprPattern.FindStringSubmatch(match)
		if len(inner) < 2 {
			return match
		}
		expr := strings.TrimSpace(inner[1])
		resolved, ok := resolveExpr(expr, match, ctx, jobName)
		if !ok {
			if ctx.Strict {
				if strictErr == nil {
					strictErr = fmt.Errorf("unresolved expression %s", match)
				}
			} else if msg := messageOutputMiss(match, expr, ctx, jobName); msg != "" {
				if miss == "" {
					miss = msg
				}
			} else {
				logger.Warn("expression: unresolved " + match + " embedded literally")
			}
			return match
		}
		return resolved
	})
	if strictErr != nil {
		return "", "", strictErr
	}
	return out, miss, nil
}

// SubstituteCommandText substitutes shell=false command text; like
// SubstituteForCommand it fails on a message-outputs miss.
func SubstituteCommandText(template string, ctx *Context, jobName string) (string, error) {
	s, miss, err := substituteChecked(template, ctx, jobName)
	if err == nil && miss != "" {
		return "", errors.New(miss)
	}
	return s, err
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
		s, miss, err := substituteChecked(template, ctx, jobName)
		if err == nil && miss != "" {
			return "", nil, errors.New(miss)
		}
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
			} else if msg := messageOutputMiss(match, exprText, ctx, jobName); msg != "" {
				// Always an author mistake: fail the step, not the shell.
				if buildErr == nil {
					buildErr = errors.New(msg)
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

// SubstituteMessagePayload substitutes ${{ expr }} into a message-step payload.
// A payload that is a JSON document substitutes with values JSON-escaped inside
// string literals, so quotes or backslashes in an input cannot break the
// document; any other payload substitutes textually (SubstituteForJobChecked).
func SubstituteMessagePayload(template string, ctx *Context, jobName string) (string, error) {
	if !json.Valid([]byte(template)) {
		return SubstituteForJobChecked(template, ctx, jobName)
	}

	var strictErr error
	const exprOpen, exprClose = "${{", "}}"
	var b strings.Builder
	inString := false
	for i := 0; i < len(template); {
		if strings.HasPrefix(template[i:], exprOpen) {
			if rel := strings.Index(template[i:], exprClose); rel >= len(exprOpen) {
				match := template[i : i+rel+len(exprClose)]
				if exprText := strings.TrimSpace(template[i+len(exprOpen) : i+rel]); exprText != "" {
					resolved, ok := resolveExpr(exprText, match, ctx, jobName)
					if !ok {
						if ctx.Strict {
							if strictErr == nil {
								strictErr = fmt.Errorf("unresolved expression %s", match)
							}
						} else {
							logger.Warn("expression: unresolved " + match + " embedded literally")
						}
						b.WriteString(match)
					} else if inString {
						b.WriteString(jsonEscapeStringContent(resolved))
					} else {
						b.WriteString(resolved)
					}
					i += len(match)
					continue
				}
			}
		}
		switch template[i] {
		case '\\':
			b.WriteByte(template[i])
			if inString && i+1 < len(template) {
				b.WriteByte(template[i+1])
				i += 2
				continue
			}
			i++
		case '"':
			inString = !inString
			b.WriteByte(template[i])
			i++
		default:
			b.WriteByte(template[i])
			i++
		}
	}
	if strictErr != nil {
		return "", strictErr
	}
	return b.String(), nil
}

// jsonEscapeStringContent renders s as the body of a JSON string literal.
func jsonEscapeStringContent(s string) string {
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(s); err != nil {
		return s
	}
	out := strings.TrimSuffix(b.String(), "\n")
	return out[1 : len(out)-1]
}

// messageOutputMiss reports an outputs reference at a completed message step
// with no outputs (its App replied in plain text). Empty for anything else.
func messageOutputMiss(match, expr string, ctx *Context, jobName string) string {
	path := expr
	if m := toJSONPattern.FindStringSubmatch(expr); m != nil {
		path = strings.TrimSpace(m[1])
	}
	parts := strings.Split(path, ".")
	var stepKey, stepID string
	switch {
	case parts[0] == "steps" && len(parts) == 4 && parts[2] == "outputs":
		stepKey, stepID = jobName+"."+parts[1], parts[1]
	case parts[0] == "jobs" && len(parts) == 6 && parts[2] == "steps" && parts[4] == "outputs":
		stepKey, stepID = parts[1]+"."+parts[3], parts[3]
	default:
		return ""
	}
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	if !ctx.messageSteps[stepKey] {
		return ""
	}
	s, ok := ctx.Steps[stepKey]
	// Only a completed step qualifies; a skipped or failed one is already reported.
	if !ok || s["status"] != models.StatusSuccess {
		return ""
	}
	if outs, ok := s["outputs"].(map[string]string); ok && len(outs) > 0 {
		return ""
	}
	return fmt.Sprintf("unresolved expression %s: message step %q produced no answer "+
		"(plain-text responders expose stdout)", match, stepID)
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

// EvalConditionForJob evaluates a job/step condition. An error means the
// condition is malformed (for example unbalanced parentheses) and must be
// reported, never silently treated as false.
func EvalConditionForJob(expr string, ctx *Context, jobName string) (bool, error) {
	return evalCondition(expr, ctx, jobName, nil)
}

type statusFuncs struct {
	success func() bool
	failure func() bool
}

func EvalConditionForJobWithStatus(expr string, ctx *Context, jobName string, successFn, failureFn func() bool) (bool, error) {
	return evalCondition(expr, ctx, jobName, &statusFuncs{success: successFn, failure: failureFn})
}

func evalCondition(expr string, ctx *Context, jobName string, status *statusFuncs) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true, nil
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
			return true, nil
		}
	}

	// Parentheses are author grouping. Unbalanced ones are an author mistake:
	// answer with an error instead of silently evaluating to false.
	if err := checkBalancedParens(expr); err != nil {
		return false, err
	}
	// Recursively drop pairs that wrap the whole expression, so a grouped
	// condition like "(a == 'x')" evaluates like "a == 'x'" instead of being
	// read as one opaque (truthy) operand.
	original := expr
	for {
		inner, unwrapped := unwrapParens(expr)
		if !unwrapped {
			break
		}
		expr = strings.TrimSpace(inner)
		if expr == "" {
			return false, fmt.Errorf("empty parentheses in condition %q", original)
		}
	}

	switch expr {
	case "always()":
		return true, nil
	case "success()":
		if status != nil && status.success != nil {
			return status.success(), nil
		}
		return allStepsSucceeded(ctx, jobName), nil
	case "failure()":
		if status != nil && status.failure != nil {
			return status.failure(), nil
		}
		return !allStepsSucceeded(ctx, jobName), nil
	}

	// Handle || before && so && binds tighter (standard precedence).
	// splitTopLevel ignores operators inside quotes, ${{ }} blocks, or
	// parentheses, so a value interpolated into an operand cannot inject a new
	// operator (see coerce) and grouped operands stay together.
	if parts := splitTopLevel(expr, "||"); len(parts) > 1 {
		for _, part := range parts {
			met, err := evalCondition(strings.TrimSpace(part), ctx, jobName, status)
			if err != nil {
				return false, err
			}
			if met {
				return true, nil
			}
		}
		return false, nil
	}
	if parts := splitTopLevel(expr, "&&"); len(parts) > 1 {
		for _, part := range parts {
			met, err := evalCondition(strings.TrimSpace(part), ctx, jobName, status)
			if err != nil {
				return false, err
			}
			if !met {
				return false, nil
			}
		}
		return true, nil
	}
	if strings.HasPrefix(expr, "!") {
		met, err := evalCondition(strings.TrimSpace(strings.TrimPrefix(expr, "!")), ctx, jobName, status)
		if err != nil {
			return false, err
		}
		return !met, nil
	}

	return evalComparison(expr, ctx, jobName), nil
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
		if s["status"] == "failure" && s["continue_on_error"] != true {
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

// conditionScanner is the shared condition lexer state: single/double-quoted
// literals and ${{ }} expression spans are transparent to operators, and
// parentheses nest on top (an operator inside parentheses belongs to the
// sub-expression, so splits and symbol searches stop at depth 0).
type conditionScanner struct {
	inSingle   bool
	inDouble   bool
	tmpl       int
	parenDepth int
	negParens  bool // a ')' appeared with no matching '('
}

// step consumes s[i] (and a whole ${{ or }} token when present), returning
// the next index and whether i sits at the top level: outside quotes and
// ${{ }} spans, and at parenthesis depth 0.
func (cs *conditionScanner) step(s string, i int) (int, bool) {
	if cs.tmpl == 0 && !cs.inSingle && !cs.inDouble && strings.HasPrefix(s[i:], "${{") {
		cs.tmpl++
		return i + 3, false
	}
	if cs.tmpl > 0 && strings.HasPrefix(s[i:], "}}") {
		cs.tmpl--
		return i + 2, false
	}
	if cs.tmpl > 0 {
		return i + 1, false
	}
	switch c := s[i]; c {
	case '\'':
		if !cs.inDouble {
			cs.inSingle = !cs.inSingle
		}
	case '"':
		if !cs.inSingle {
			cs.inDouble = !cs.inDouble
		}
	case '(':
		// Parentheses are grouping only outside quoted literals.
		if !cs.inSingle && !cs.inDouble {
			cs.parenDepth++
		}
	case ')':
		if !cs.inSingle && !cs.inDouble {
			cs.parenDepth--
			if cs.parenDepth < 0 {
				cs.negParens = true
			}
		}
	}
	return i + 1, !cs.inSingle && !cs.inDouble && cs.parenDepth == 0
}

// splitTopLevel splits s on sep, ignoring occurrences inside single/double
// quotes, inside ${{ }} blocks, or inside parentheses. This keeps an
// interpolated operand value from injecting boolean operators that would
// restructure the condition, and lets grouped operands like
// `a && (b || c)` split on the top-level operator only.
func splitTopLevel(s, sep string) []string {
	var parts []string
	var buf strings.Builder
	var scanner conditionScanner
	for i := 0; i < len(s); {
		next, topLevel := scanner.step(s, i)
		if topLevel && strings.HasPrefix(s[i:], sep) {
			parts = append(parts, buf.String())
			buf.Reset()
			// The separator bytes carry no lexer state (only quotes,
			// parentheses, and ${{ }} do); skip the whole token.
			i += len(sep)
			continue
		}
		buf.WriteString(s[i:next])
		i = next
	}
	parts = append(parts, buf.String())
	return parts
}

// indexTopLevel returns the index of the first occurrence of sym in s that is
// not inside quotes, a ${{ }} block, or parentheses, or -1 if none.
func indexTopLevel(s, sym string) int {
	var scanner conditionScanner
	for i := 0; i < len(s); {
		next, topLevel := scanner.step(s, i)
		if topLevel && strings.HasPrefix(s[i:], sym) {
			return i
		}
		i = next
	}
	return -1
}

// indexOutsideQuotes returns the first index of sym in s that is not inside a
// quoted literal or a ${{ }} block; parentheses do not hide it. Used for
// status-function detection, which must see through author grouping like
// `(success() || always())`.
func indexOutsideQuotes(s, sym string) int {
	var scanner conditionScanner
	for i := 0; i < len(s); {
		inSpan := scanner.tmpl > 0
		next, _ := scanner.step(s, i)
		if !inSpan && !scanner.inSingle && !scanner.inDouble && strings.HasPrefix(s[i:], sym) {
			return i
		}
		i = next
	}
	return -1
}

// checkBalancedParens reports an error when the condition's parentheses do not
// balance outside quoted literals and ${{ }} spans. An unbalanced condition is
// an author mistake and must surface, never silently evaluate to false.
func checkBalancedParens(s string) error {
	var scanner conditionScanner
	for i := 0; i < len(s); {
		next, _ := scanner.step(s, i)
		i = next
	}
	if scanner.negParens {
		return fmt.Errorf("unbalanced ')' in condition %q", s)
	}
	if scanner.parenDepth > 0 {
		return fmt.Errorf("missing %d closing ')' in condition %q", scanner.parenDepth, s)
	}
	return nil
}

// unwrapParens strips one pair of parentheses that encloses the whole string —
// "(a && b)" → "a && b", including across ${{ }} spans. The pair must be
// balanced against the rest of the expression, so "(a) && b" stays unchanged.
// Parentheses inside quoted literals are lexer-transparent and never match.
func unwrapParens(s string) (string, bool) {
	if !strings.HasPrefix(s, "(") {
		return s, false
	}
	var scanner conditionScanner
	for i := 0; i < len(s); {
		next, _ := scanner.step(s, i)
		if scanner.parenDepth == 0 {
			// i (inclusive) .. next (exclusive) consumed the ')' that closes
			// the leading '(': only a trailing position unwraps.
			if s[next-1] == ')' && next == len(s) {
				return s[1 : next-1], true
			}
			return s, false
		}
		i = next
	}
	return s, false // unbalanced; the caller reports it via checkBalancedParens
}

// HasStatusFunction reports whether the condition references one of the status
// functions always()/success()/failure() outside quoted operands and ${{ }}
// blocks, so literal text like `== 'success()'` does not count. Author
// grouping parentheses do not hide the call.
func HasStatusFunction(condition string) bool {
	for _, fn := range []string{"always()", "success()", "failure()"} {
		if indexOutsideQuotes(condition, fn) >= 0 {
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
	// Author grouping around an operand, as in `(a) == (b)`: unwrap before the
	// value is read, mirroring the whole-condition unwrap in evalCondition.
	for {
		inner, unwrapped := unwrapParens(token)
		if !unwrapped {
			break
		}
		token = strings.TrimSpace(inner)
		if token == "" {
			return token
		}
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
