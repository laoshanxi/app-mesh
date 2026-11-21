package models

import (
	"strings"
	"testing"
)

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

// Declared number/boolean types are enforced at trigger time: a non-numeric or
// non-boolean value fails the dispatch with the field and expected type named,
// instead of flowing into the run and corrupting downstream comparisons.
func TestApplyInputDefaultsValidatesTypes(t *testing.T) {
	typed := &Workflow{On: &TriggerConfig{Manual: &ManualTrigger{Inputs: map[string]InputParam{
		"num":   {Type: "number"},
		"ratio": {Type: "number", Default: 1.5},
		"flag":  {Type: "boolean"},
	}}}}

	// Valid numbers (int, negative, float, exponent) and booleans pass.
	got, err := ApplyInputDefaults(typed, map[string]string{"num": "-2", "flag": "false"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got["num"] != "-2" || got["ratio"] != "1.5" || got["flag"] != "false" {
		t.Errorf("valid typed inputs mangled: %v", got)
	}
	if _, err = ApplyInputDefaults(typed, map[string]string{"num": "3.14", "flag": "true", "ratio": "1e3"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// A non-numeric value for a number input is rejected, naming the field.
	_, err = ApplyInputDefaults(typed, map[string]string{"num": "notanumber", "flag": "true"})
	if err == nil || !strings.Contains(err.Error(), `input "num" type is number`) ||
		!strings.Contains(err.Error(), `notanumber`) {
		t.Errorf("expected number-type rejection, got %v", err)
	}

	// An invalid boolean is rejected; booleans are the lowercase literals the
	// condition evaluator reads, so "True"/"1" do not pass.
	for _, bad := range []string{"notabool", "True", "1"} {
		_, err = ApplyInputDefaults(typed, map[string]string{"num": "1", "flag": bad})
		if err == nil || !strings.Contains(err.Error(), `input "flag" type is boolean`) {
			t.Errorf("boolean %q: expected type rejection, got %v", bad, err)
		}
	}

	// A malformed declared default fails the same way (an author error caught
	// at trigger time rather than mid-run).
	badDefault := &Workflow{On: &TriggerConfig{Manual: &ManualTrigger{Inputs: map[string]InputParam{
		"port": {Type: "number", Default: "n/a"},
	}}}}
	if _, err := ApplyInputDefaults(badDefault, nil); err == nil ||
		!strings.Contains(err.Error(), `input "port" type is number`) {
		t.Errorf("expected default-type rejection, got %v", err)
	}
}
