package models

import "testing"

func TestApplyInputDefaults(t *testing.T) {
	wf := &Workflow{On: &TriggerConfig{
		WorkflowCall: &WorkflowCallTrigger{Inputs: map[string]InputParam{
			"region": {Type: "string", Required: true},
		}},
		Manual: &ManualTrigger{Inputs: map[string]InputParam{
			// Same key as workflow_call: the manual definition wins.
			"region": {Type: "string", Required: false, Default: "eu"},
			"dry":    {Type: "boolean", Default: false},
		}},
	}}

	// Defaults applied, manual definition wins on collision.
	got, err := ApplyInputDefaults(wf, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["region"] != "eu" || got["dry"] != "false" {
		t.Errorf("defaults not applied: %v", got)
	}

	// A provided value beats the default; nil inputs is handled.
	got, err = ApplyInputDefaults(wf, map[string]string{"region": "us"})
	if err != nil || got["region"] != "us" {
		t.Errorf("got %v err %v", got, err)
	}

	// A required input with no default and no value is rejected.
	strict := &Workflow{On: &TriggerConfig{Manual: &ManualTrigger{Inputs: map[string]InputParam{
		"code": {Type: "string", Required: true},
	}}}}
	if _, err := ApplyInputDefaults(strict, nil); err == nil || err.Error() != `required input "code" not provided` {
		t.Errorf("expected required-input error, got %v", err)
	}

	// No trigger config: inputs pass through untouched.
	got, err = ApplyInputDefaults(&Workflow{}, map[string]string{"a": "b"})
	if err != nil || got["a"] != "b" {
		t.Errorf("got %v err %v", got, err)
	}
}
