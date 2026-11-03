package parser

import (
	"bytes"
	"fmt"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/schedule"
)

var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// inputKeyPattern: input keys must be usable as env var names.
var inputKeyPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// LoadWorkflow reads and parses a workflow YAML file.
func LoadWorkflow(path string) (*models.Workflow, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read workflow file: %w", err)
	}

	// First unmarshal into raw map to handle YAML 'on' key (parsed as bool true).
	var raw map[any]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}

	// Fix the 'on' key: YAML parses bare `on:` as boolean true.
	if v, ok := raw[true]; ok {
		raw["on"] = v
		delete(raw, true)
	}

	// Re-marshal the fixed map, then unmarshal into the Workflow struct.
	fixed, err := yaml.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("re-marshal YAML: %w", err)
	}

	// Strict decode: reject unknown fields so a typo (e.g. `neeeds:`) fails
	// loudly at registration instead of being silently dropped.
	var wf models.Workflow
	dec := yaml.NewDecoder(bytes.NewReader(fixed))
	dec.KnownFields(true)
	if err := dec.Decode(&wf); err != nil {
		return nil, fmt.Errorf("parse workflow: %s", rewriteYamlFieldErrors(err.Error()))
	}

	// GA compatibility: `workflow_dispatch` is GitHub Actions' name for the
	// manual trigger; normalize it to `manual` (an explicit `manual` wins) and
	// clear the alias so downstream code only ever looks at `manual`.
	if wf.On != nil && wf.On.WorkflowDispatch != nil {
		if wf.On.Manual == nil {
			wf.On.Manual = wf.On.WorkflowDispatch
		}
		wf.On.WorkflowDispatch = nil
	}

	if wf.Name == "" {
		return nil, fmt.Errorf("workflow YAML must have a 'name' field")
	}
	if !safeNamePattern.MatchString(wf.Name) {
		return nil, fmt.Errorf("workflow name %q must match [a-zA-Z0-9_-]+", wf.Name)
	}
	if len(wf.Jobs) == 0 {
		return nil, fmt.Errorf("workflow must have at least one job")
	}

	for name, job := range wf.Jobs {
		if !safeNamePattern.MatchString(name) {
			return nil, fmt.Errorf("job name %q must match [a-zA-Z0-9_-]+", name)
		}
		if len(job.Steps) == 0 {
			return nil, fmt.Errorf("job %q must have at least one step", name)
		}
		job.Name = name
		job.Status = models.StatusPending
		seenSteps := make(map[string]string)
		if err := resolveStepTypes(job.Steps, false, name, "steps", seenSteps); err != nil {
			return nil, err
		}
		if err := resolveStepTypes(job.Finally, true, name, "finally", seenSteps); err != nil {
			return nil, err
		}
	}

	// Concurrency requires a non-empty group; otherwise the field has no effect
	// and the user's intent (serialize runs) would be silently lost.
	if wf.Concurrency != nil && wf.Concurrency.Group == "" {
		return nil, fmt.Errorf("concurrency.group is required when concurrency is set")
	}

	// Validate input keys are safe identifiers and types are from the documented enum.
	validateInputs := func(section string, inputs map[string]models.InputParam) error {
		for k, p := range inputs {
			if !inputKeyPattern.MatchString(k) {
				return fmt.Errorf("%s input key %q must match [a-zA-Z_][a-zA-Z0-9_]*", section, k)
			}
			switch p.Type {
			case "", "string", "number", "boolean":
			default:
				return fmt.Errorf("%s input %q type must be string, number or boolean", section, k)
			}
		}
		return nil
	}
	if wf.On != nil {
		if wf.On.Manual != nil {
			if err := validateInputs("manual", wf.On.Manual.Inputs); err != nil {
				return nil, err
			}
		}
		if wf.On.WorkflowCall != nil {
			if err := validateInputs("workflow_call", wf.On.WorkflowCall.Inputs); err != nil {
				return nil, err
			}
		}
		// app_event without app/events can never fire; fail loudly instead of
		// registering a trigger that silently does nothing.
		if wf.On.AppEvent != nil {
			if wf.On.AppEvent.App == "" || len(wf.On.AppEvent.Events) == 0 {
				return nil, fmt.Errorf("app_event trigger requires app and events")
			}
		}
	}
	// Validate env keys wherever declared (workflow, job, step): env keys become
	// process environment variables; `with` keys follow the same rule.
	checkKeys := func(owner, label string, keys map[string]string) error {
		for k := range keys {
			if !inputKeyPattern.MatchString(k) {
				return fmt.Errorf("%s %s key %q must match [a-zA-Z_][a-zA-Z0-9_]*", owner, label, k)
			}
		}
		return nil
	}
	if err := checkKeys("workflow", "env", wf.Env); err != nil {
		return nil, err
	}
	if err := checkKeys("workflow", "secret_env", wf.SecretEnv); err != nil {
		return nil, err
	}
	for _, job := range wf.Jobs {
		jobOwner := fmt.Sprintf("job %q", job.Name)
		if err := checkKeys(jobOwner, "env", job.Env); err != nil {
			return nil, err
		}
		if err := checkKeys(jobOwner, "secret_env", job.SecretEnv); err != nil {
			return nil, err
		}
		for _, steps := range [][]models.Step{job.Steps, job.Finally} {
			for _, step := range steps {
				stepOwner := fmt.Sprintf("%s step %q", jobOwner, step.Name)
				for _, m := range []struct {
					label string
					keys  map[string]string
				}{{"with", step.With}, {"env", step.Env}, {"secret_env", step.SecretEnv}} {
					if err := checkKeys(stepOwner, m.label, m.keys); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	// Validate cron syntax here too: a schedule typo must fail the load, not
	// silently never fire (the trigger service also revalidates on scan).
	if wf.On != nil {
		for _, sched := range wf.On.Schedule {
			if _, err := schedule.Parse(sched.Cron); err != nil {
				return nil, err
			}
		}
	}

	if err := validateExpressionRefs(&wf); err != nil {
		return nil, err
	}

	return &wf, nil
}

// exprRefPattern and toJSONRefPattern mirror the expression engine's syntax.
var (
	exprRefPattern    = regexp.MustCompile(`\$\{\{\s*(.+?)\s*\}\}`)
	toJSONRefPattern  = regexp.MustCompile(`^toJSON\((.+)\)$`)
	stepFieldPattern  = regexp.MustCompile(`^(stdout|exit_code|status|response|outputs)$`)
	workflowRefFields = map[string]bool{"name": true, "run_id": true}

	// conditionExprPattern matches what the runtime evaluator accepts in an
	// `if:` block beyond a plain path: status functions, operators, literals.
	// Value fields (command, env, ...) resolve paths only and stay strict.
	conditionExprPattern = regexp.MustCompile(`\b(?:always|success|failure)\(\)|\|\||&&|==|[<>!]|^(?:true|false)$|^-?\d+(?:\.\d+)?$`)
	// conditionRefPattern extracts the resolvable references out of such an
	// expression, e.g. `steps.build.exit_code` from `steps.build.exit_code >= 0`.
	conditionRefPattern = regexp.MustCompile(`\b(?:steps|jobs|inputs|env|workflow|job)(?:\.[A-Za-z0-9_-]+)+`)
)

// validateExpressionRefs fails a workflow whose ${{ }} paths reference names
// that do not exist: a step from the wrong job, an unknown job, an undeclared
// input or env key. The runtime resolver would substitute empty for such
// references, silently corrupting commands (e.g. deploying an empty tag).
func validateExpressionRefs(wf *models.Workflow) error {
	declaredInputs := make(map[string]bool)
	if wf.On != nil {
		if wf.On.Manual != nil {
			for k := range wf.On.Manual.Inputs {
				declaredInputs[k] = true
			}
		}
		if wf.On.WorkflowCall != nil {
			for k := range wf.On.WorkflowCall.Inputs {
				declaredInputs[k] = true
			}
		}
	}
	wfEnvKeys := make(map[string]bool)
	for _, m := range []map[string]string{wf.Env, wf.SecretEnv} {
		for k := range m {
			wfEnvKeys[k] = true
		}
	}

	jobStepNames := func(job *models.Job) map[string]bool {
		names := make(map[string]bool)
		for _, steps := range [][]models.Step{job.Steps, job.Finally} {
			for _, s := range steps {
				names[s.Name] = true
			}
		}
		return names
	}
	jobStep := func(job *models.Job, name string) *models.Step {
		for _, steps := range [][]models.Step{job.Steps, job.Finally} {
			for i := range steps {
				if steps[i].Name == name {
					return &steps[i]
				}
			}
		}
		return nil
	}
	// outputs is produced by sub-workflow steps (author-defined keys) and by
	// message steps (the platform answer field); a reference through any other
	// step can never resolve and must fail the load, not pass the literal.
	checkOutputsRef := func(name string, step *models.Step, key string) error {
		if key == "" {
			return fmt.Errorf("outputs requires a key: outputs.<key>")
		}
		switch {
		case step == nil || step.Type == models.StepCommand || step.Type == models.StepApp:
			return fmt.Errorf("step %q has no outputs: only workflow and message steps produce outputs", name)
		case step.Type == models.StepMessage && key != "answer":
			return fmt.Errorf("message step %q only produces outputs.answer", name)
		}
		return nil
	}

	// checkPath validates one ${{ ... }} inner path. jobName scopes `steps.` refs
	// ("" = cross-job only, used for workflow_call output values).
	checkPath := func(where, path, jobName string) error {
		inner := strings.TrimSpace(path)
		if m := toJSONRefPattern.FindStringSubmatch(inner); m != nil {
			inner = strings.TrimSpace(m[1])
		}
		parts := strings.Split(inner, ".")
		fail := func(reason string) error {
			return fmt.Errorf("%s: unresolved expression reference ${{ %s }}: %s", where, inner, reason)
		}
		switch parts[0] {
		case "success", "failure", "job":
			return nil // condition helpers / own-job status; runtime keeps them lenient
		case "workflow":
			if len(parts) == 2 && workflowRefFields[parts[1]] {
				return nil
			}
			return fail("workflow supports name and run_id")
		case "inputs":
			if len(parts) == 2 && declaredInputs[parts[1]] {
				return nil
			}
			return fail("input is not declared under on.manual/on.workflow_call")
		case "env":
			if len(parts) == 2 && wfEnvKeys[parts[1]] {
				return nil
			}
			return fail("key is not declared in workflow env/secret_env")
		case "steps":
			if jobName == "" {
				return fail("steps.<name> is job-local; reference jobs.<job>.steps.<name> instead")
			}
			if len(parts) >= 3 {
				job := wf.Jobs[jobName]
				if !jobStepNames(job)[parts[1]] {
					return fail(fmt.Sprintf("step %q is not defined in job %q", parts[1], jobName))
				}
				if !stepFieldPattern.MatchString(parts[2]) {
					return fail("step fields are stdout, exit_code, status, response, outputs")
				}
				if parts[2] == "outputs" {
					key := ""
					if len(parts) >= 4 {
						key = parts[3]
					}
					if err := checkOutputsRef(parts[1], jobStep(job, parts[1]), key); err != nil {
						return fail(err.Error())
					}
				}
				return nil
			}
			return fail("expected steps.<name>.<field>")
		case "jobs":
			if len(parts) >= 3 {
				job, ok := wf.Jobs[parts[1]]
				if !ok {
					return fail(fmt.Sprintf("job %q is not defined", parts[1]))
				}
				if parts[2] == "status" {
					return nil
				}
				if parts[2] == "steps" && len(parts) >= 5 {
					if !jobStepNames(job)[parts[3]] {
						return fail(fmt.Sprintf("step %q is not defined in job %q", parts[3], parts[1]))
					}
					if !stepFieldPattern.MatchString(parts[4]) {
						return fail("step fields are stdout, exit_code, status, response, outputs")
					}
					if parts[4] == "outputs" {
						key := ""
						if len(parts) >= 6 {
							key = parts[5]
						}
						if err := checkOutputsRef(parts[3], jobStep(job, parts[3]), key); err != nil {
							return fail(err.Error())
						}
					}
					return nil
				}
				return fail("expected jobs.<job>.status or jobs.<job>.steps.<name>.<field>")
			}
			return fail("expected jobs.<job>.<...>")
		default:
			return fail("unknown context root (steps, jobs, inputs, env, workflow, job)")
		}
	}

	// checkCondition validates one `if:` block: the runtime evaluator accepts a
	// full expression here, so operator-bearing blocks validate each
	// context-rooted operand instead of the whole text being one path.
	checkCondition := func(where, path, jobName string) error {
		inner := strings.TrimSpace(path)
		if m := toJSONRefPattern.FindStringSubmatch(inner); m != nil {
			inner = strings.TrimSpace(m[1])
		}
		if conditionExprPattern.MatchString(inner) {
			for _, ref := range conditionRefPattern.FindAllString(inner, -1) {
				if err := checkPath(where, ref, jobName); err != nil {
					return err
				}
			}
			return nil
		}
		return checkPath(where, inner, jobName)
	}

	checkString := func(where, s, jobName string) error {
		for _, m := range exprRefPattern.FindAllStringSubmatch(s, -1) {
			if err := checkPath(where, m[1], jobName); err != nil {
				return err
			}
		}
		return nil
	}
	checkConditionString := func(where, s, jobName string) error {
		for _, m := range exprRefPattern.FindAllStringSubmatch(s, -1) {
			if err := checkCondition(where, m[1], jobName); err != nil {
				return err
			}
		}
		return nil
	}
	checkStringMap := func(where string, m map[string]string, jobName string) error {
		for _, v := range m {
			if err := checkString(where, v, jobName); err != nil {
				return err
			}
		}
		return nil
	}

	for _, job := range wf.Jobs {
		jobWhere := fmt.Sprintf("job %q", job.Name)
		if err := checkConditionString(jobWhere+" if", job.Condition, job.Name); err != nil {
			return err
		}
		if err := checkStringMap(jobWhere+" env", job.Env, job.Name); err != nil {
			return err
		}
		if err := checkStringMap(jobWhere+" secret_env", job.SecretEnv, job.Name); err != nil {
			return err
		}
		for _, steps := range []struct {
			label string
			list  []models.Step
		}{{"steps", job.Steps}, {"finally", job.Finally}} {
			for _, step := range steps.list {
				stepWhere := fmt.Sprintf("%s %s step %q", jobWhere, steps.label, step.Name)
				if err := checkConditionString(stepWhere+" if", step.Condition, job.Name); err != nil {
					return err
				}
				for _, field := range []struct {
					label string
					value string
				}{{"command", step.Command}, {"workdir", step.Workdir}, {"docker_image", step.DockerImage}} {
					if err := checkString(fmt.Sprintf("%s %s", stepWhere, field.label), field.value, job.Name); err != nil {
						return err
					}
				}
				if step.Message != nil {
					if err := checkString(stepWhere+" message.payload", step.Message.Payload, job.Name); err != nil {
						return err
					}
				}
				for _, m := range []struct {
					label string
					keys  map[string]string
				}{{"with", step.With}, {"env", step.Env}, {"secret_env", step.SecretEnv}} {
					if err := checkStringMap(fmt.Sprintf("%s %s", stepWhere, m.label), m.keys, job.Name); err != nil {
						return err
					}
				}
			}
		}
	}
	if wf.On != nil && wf.On.WorkflowCall != nil {
		for name, out := range wf.On.WorkflowCall.Outputs {
			// Output values evaluate in this workflow's own context; `steps.` is
			// job-local and ambiguous here, so require cross-job references.
			if err := checkString(fmt.Sprintf("workflow_call output %q", name), out.Value, ""); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveStepTypes(steps []models.Step, defaultContinueOnError bool, jobName, section string,
	seenSteps map[string]string) error {
	for i := range steps {
		s := &steps[i]
		if s.Name == "" {
			return fmt.Errorf("job %q %s[%d] must have a name", jobName, section, i)
		}
		if !safeNamePattern.MatchString(s.Name) {
			return fmt.Errorf("job %q step %q name must match [a-zA-Z0-9_-]+", jobName, s.Name)
		}
		if prevSection, ok := seenSteps[s.Name]; ok {
			return fmt.Errorf("job %q step %q is duplicated in %s and %s", jobName, s.Name, prevSection, section)
		}
		seenSteps[s.Name] = section
		s.Result.Status = models.StatusPending

		var types []models.StepType
		if s.Command != "" {
			types = append(types, models.StepCommand)
		}
		if s.App != "" {
			types = append(types, models.StepApp)
		}
		if s.Message != nil {
			types = append(types, models.StepMessage)
		}
		if s.WorkflowRef != "" {
			types = append(types, models.StepWorkflow)
		}
		if len(types) != 1 {
			return fmt.Errorf("job %q step %q must contain exactly one of command, app, message, workflow", jobName, s.Name)
		}

		s.Type = types[0]
		if s.Type == models.StepWorkflow && !safeNamePattern.MatchString(s.WorkflowRef) {
			return fmt.Errorf("job %q step %q workflow ref %q must match [a-zA-Z0-9_-]+", jobName, s.Name, s.WorkflowRef)
		}
		if s.Type != models.StepWorkflow && len(s.With) > 0 {
			return fmt.Errorf("job %q step %q: 'with' is only valid on workflow steps", jobName, s.Name)
		}

		if s.Message != nil && (s.Message.App == "" || s.Message.Payload == "") {
			return fmt.Errorf("job %q step %q message step requires app and payload", jobName, s.Name)
		}
		if s.Timeout < 0 {
			return fmt.Errorf("job %q step %q timeout must be >= 0", jobName, s.Name)
		}
		if s.Retry != nil {
			if s.Retry.Max < 1 {
				return fmt.Errorf("job %q step %q retry.max must be >= 1", jobName, s.Name)
			}
			if s.Retry.Backoff == "" {
				s.Retry.Backoff = "fixed"
			}
			if s.Retry.Backoff != "fixed" && s.Retry.Backoff != "exponential" {
				return fmt.Errorf("job %q step %q retry.backoff must be fixed or exponential", jobName, s.Name)
			}
			if s.Retry.Interval == 0 {
				s.Retry.Interval = 10
			}
			if s.Retry.Interval < 0 {
				return fmt.Errorf("job %q step %q retry.interval must be >= 1", jobName, s.Name)
			}
		}
		if defaultContinueOnError && !s.ContinueOnError {
			s.ContinueOnError = true
		}
	}
	return nil
}

// yamlFieldErrRe matches gopkg.in/yaml.v3 strict-decode errors such as
// `line 17: field workflow_dispatch not found in type models.TriggerConfig`.
var yamlFieldErrRe = regexp.MustCompile(`line (\d+): field ([^ ]+) not found in type ([^ ]+)`)

// rewriteYamlFieldErrors turns strict-decode internals into user-facing wording;
// unknown types fall through to a generic phrasing.
func rewriteYamlFieldErrors(msg string) string {
	return yamlFieldErrRe.ReplaceAllStringFunc(msg, func(s string) string {
		m := yamlFieldErrRe.FindStringSubmatch(s)
		line, field, typ := m[1], m[2], m[3]
		if typ == "models.TriggerConfig" {
			return fmt.Sprintf("line %s: unsupported trigger %q (triggers: manual, workflow_dispatch, schedule, workflow_call, app_event)", line, field)
		}
		return fmt.Sprintf("line %s: unsupported field %q — check the workflow schema", line, field)
	})
}
