package parser

import (
	"fmt"
	"os"
	"regexp"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
	"gopkg.in/yaml.v3"
)

var safeNamePattern = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

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

	var wf models.Workflow
	if err := yaml.Unmarshal(fixed, &wf); err != nil {
		return nil, fmt.Errorf("parse workflow: %w", err)
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

	// Validate input keys are safe identifiers (must work as env var names).
	var inputKeyPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)
	if wf.On != nil {
		if wf.On.Manual != nil {
			for k := range wf.On.Manual.Inputs {
				if !inputKeyPattern.MatchString(k) {
					return nil, fmt.Errorf("manual input key %q must match [a-zA-Z_][a-zA-Z0-9_]*", k)
				}
			}
		}
		if wf.On.WorkflowCall != nil {
			for k := range wf.On.WorkflowCall.Inputs {
				if !inputKeyPattern.MatchString(k) {
					return nil, fmt.Errorf("workflow_call input key %q must match [a-zA-Z_][a-zA-Z0-9_]*", k)
				}
			}
		}
	}
	// Validate step `with` keys (both steps and finally).
	for _, job := range wf.Jobs {
		for _, steps := range [][]models.Step{job.Steps, job.Finally} {
			for _, step := range steps {
				for k := range step.With {
					if !inputKeyPattern.MatchString(k) {
						return nil, fmt.Errorf("job %q step %q with key %q must match [a-zA-Z_][a-zA-Z0-9_]*", job.Name, step.Name, k)
					}
				}
			}
		}
	}

	// Warn about features that are parsed but not dispatched by the engine.
	if wf.On != nil && len(wf.On.Schedule) > 0 {
		fmt.Fprintf(os.Stderr, "WARNING: workflow %q has on.schedule triggers, but cron is not handled by the engine. Use an external App Mesh cron app to call 'appm workflow run %s' instead.\n", wf.Name, wf.Name)
	}

	return &wf, nil
}

func resolveStepTypes(steps []models.Step, defaultContinueOnError bool, jobName, section string, seenSteps map[string]string) error {
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
