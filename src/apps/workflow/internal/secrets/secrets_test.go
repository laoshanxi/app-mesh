package secrets

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// parseSecretEnvsForTest collects every secret_env mapping (workflow/job/step)
// from a workflow YAML document into one merged map.
func parseSecretEnvsForTest(t *testing.T, doc string) map[string]string {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &node); err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i], n.Content[i+1]
				if key.Value == "secret_env" && val.Kind == yaml.MappingNode {
					for j := 0; j+1 < len(val.Content); j += 2 {
						out[val.Content[j].Value] = val.Content[j+1].Value
					}
				}
				walk(val)
			}
			return
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(&node)
	return out
}

func encodeForTest(workflow, key, value string) string {
	return formatPrefix + base64.RawStdEncoding.EncodeToString([]byte(workflow+"\x00"+key+"\x00"+value))
}

// fakeBroker mirrors the daemon's workflow+key binding.
type fakeBroker struct {
	protectCalls   [][]Entry
	unprotectCalls [][]Entry
	failProtect    bool
	failUnprotect  bool
	shortResponse  bool
}

func (f *fakeBroker) Protect(ctx context.Context, workflow string, values []Entry) ([]Entry, error) {
	f.protectCalls = append(f.protectCalls, append([]Entry(nil), values...))
	if f.failProtect {
		return nil, fmt.Errorf("broker unavailable")
	}
	out := make([]Entry, len(values))
	for i, value := range values {
		out[i] = Entry{Key: value.Key, Value: encodeForTest(workflow, value.Key, value.Value)}
	}
	if f.shortResponse && len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out, nil
}

func (f *fakeBroker) Unprotect(ctx context.Context, workflow string, values []Entry) ([]Entry, error) {
	f.unprotectCalls = append(f.unprotectCalls, append([]Entry(nil), values...))
	if f.failUnprotect {
		return nil, fmt.Errorf("broker unavailable")
	}
	out := make([]Entry, 0, len(values))
	for _, value := range values {
		if !strings.HasPrefix(value.Value, formatPrefix) {
			return nil, fmt.Errorf("workflow secret %s is not protected ciphertext", value.Key)
		}
		raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value.Value, formatPrefix))
		if err != nil {
			return nil, fmt.Errorf("workflow secret %s is malformed", value.Key)
		}
		parts := strings.Split(string(raw), "\x00")
		if len(parts) != 3 || parts[0] != workflow || parts[1] != value.Key {
			return nil, fmt.Errorf("workflow secret %s cannot be decrypted for workflow %s", value.Key, workflow)
		}
		out = append(out, Entry{Key: value.Key, Value: parts[2]})
	}
	return out, nil
}

// ProtectYAML must encrypt every schema level and keep the rest of the document.
func TestProtectYAMLEncryptsAllLevels(t *testing.T) {
	const doc = `name: wf-sec
secret_env:
  SECRETKEY: "supersecret123"
jobs:
  j:
    secret_env:
      JOBSEC: jobsecret
    steps:
      - name: s
        command: echo "$SECRETKEY-$JOBSEC"
        secret_env:
          STEPSEC: stepsecret
`
	broker := &fakeBroker{}
	protected, err := ProtectYAML(context.Background(), broker, doc, "wf-sec")
	if err != nil {
		t.Fatalf("protect YAML: %v", err)
	}
	if strings.Contains(protected, "supersecret123") || strings.Contains(protected, "jobsecret") ||
		strings.Contains(protected, "stepsecret") {
		t.Fatalf("protected YAML still contains plaintext: %s", protected)
	}
	if !strings.Contains(protected, "command: echo") {
		t.Fatalf("non-secret content must be preserved: %s", protected)
	}
	if len(broker.protectCalls) != 1 || len(broker.protectCalls[0]) != 3 {
		t.Fatalf("expected one batched protect call with three values, got %+v", broker.protectCalls)
	}

	values := parseSecretEnvsForTest(t, protected)
	out, err := UnprotectMap(context.Background(), broker, "wf-sec", values)
	if err != nil {
		t.Fatalf("unprotect map: %v", err)
	}
	if out["SECRETKEY"] != "supersecret123" || out["JOBSEC"] != "jobsecret" || out["STEPSEC"] != "stepsecret" {
		t.Fatalf("decrypted values mismatch: %v", out)
	}
}

func TestProtectYAMLIdempotent(t *testing.T) {
	const doc = "name: wf-idem\nsecret_env:\n  K: v\n"
	broker := &fakeBroker{}
	first, err := ProtectYAML(context.Background(), broker, doc, "wf-idem")
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	second, err := ProtectYAML(context.Background(), broker, first, "wf-idem")
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if first != second {
		t.Fatalf("ProtectYAML must be idempotent:\nfirst:  %s\nsecond: %s", first, second)
	}
	if len(broker.unprotectCalls) != 1 {
		t.Fatalf("the second pass must validate ciphertext once, got %+v", broker.unprotectCalls)
	}
}

// Re-adding the same workflow keeps its own ciphertext unchanged.
func TestProtectYAMLKeepsCiphertextForSameWorkflow(t *testing.T) {
	ct := encodeForTest("wf-same", "TOKEN", "reused-secret")
	doc := "name: wf-same\nsecret_env:\n  TOKEN: \"" + ct + "\"\n"
	broker := &fakeBroker{}
	out, err := ProtectYAML(context.Background(), broker, doc, "wf-same")
	if err != nil {
		t.Fatalf("re-add of the same workflow must pass: %v", err)
	}
	if out != doc {
		t.Fatalf("existing ciphertext must keep the document unchanged, got %q", out)
	}
	if len(broker.protectCalls) != 0 {
		t.Fatalf("existing ciphertext must not be re-encrypted: %+v", broker.protectCalls)
	}
	values := parseSecretEnvsForTest(t, out)
	plain, err := UnprotectMap(context.Background(), broker, "wf-same", values)
	if err != nil || plain["TOKEN"] != "reused-secret" {
		t.Fatalf("kept ciphertext must decrypt, got %q, %v", plain["TOKEN"], err)
	}
}

// A renamed workflow carries ciphertext bound to the old name; reject it.
func TestProtectYAMLRejectsCiphertextBoundToAnotherWorkflow(t *testing.T) {
	ct := encodeForTest("wf-old", "TOKEN", "old-secret")
	doc := "name: wf-new\nsecret_env:\n  TOKEN: \"" + ct + "\"\n"
	_, err := ProtectYAML(context.Background(), &fakeBroker{}, doc, "wf-new")
	if err == nil {
		t.Fatal("ciphertext bound to another workflow name must fail registration")
	}
	for _, want := range []string{"TOKEN", "another workflow name", "plaintext"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must mention %q", err.Error(), want)
		}
	}
}

// A literal value with the ciphertext prefix must fail, not be double-protected.
func TestProtectYAMLRejectsLiteralPrefixValue(t *testing.T) {
	const doc = "name: wf-literal\nsecret_env:\n  TOKEN: \"sp1:not-a-ciphertext\"\n"
	_, err := ProtectYAML(context.Background(), &fakeBroker{}, doc, "wf-literal")
	if err == nil {
		t.Fatal("a literal sp1:-prefixed value must fail registration")
	}
	for _, want := range []string{"TOKEN", `"sp1:"`, "plaintext"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q must mention %q", err.Error(), want)
		}
	}
}

// The same key at several levels keeps its own value and ciphertext.
func TestProtectYAMLProtectsSameKeyAtDifferentLevels(t *testing.T) {
	const doc = `name: wf-levels
secret_env:
  TOKEN: outer
jobs:
  j:
    secret_env:
      TOKEN: inner
    steps:
      - name: s
        command: "true"
`
	broker := &fakeBroker{}
	protected, err := ProtectYAML(context.Background(), broker, doc, "wf-levels")
	if err != nil {
		t.Fatalf("protect YAML: %v", err)
	}
	if len(broker.protectCalls) != 1 || len(broker.protectCalls[0]) != 2 {
		t.Fatalf("expected one protect call with both TOKEN slots, got %+v", broker.protectCalls)
	}
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(protected), &node); err != nil {
		t.Fatal(err)
	}
	var values []string
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == "secret_env" {
					for j := 0; j+1 < len(n.Content[i+1].Content); j += 2 {
						values = append(values, n.Content[i+1].Content[j+1].Value)
					}
				}
				walk(n.Content[i+1])
			}
			return
		}
		for _, child := range n.Content {
			walk(child)
		}
	}
	walk(&node)
	if len(values) != 2 || values[0] == values[1] {
		t.Fatalf("each level must keep its own ciphertext, got %v", values)
	}
}

func TestUnprotectMapMixed(t *testing.T) {
	broker := &fakeBroker{}
	ct := encodeForTest("wf-mix", "SEC", "hidden")
	out, err := UnprotectMap(context.Background(), broker, "wf-mix", map[string]string{"SEC": ct, "LEGACY": "open"})
	if err != nil {
		t.Fatalf("unprotect map: %v", err)
	}
	if out["SEC"] != "hidden" || out["LEGACY"] != "open" {
		t.Fatalf("map decrypt mismatch: %v", out)
	}
	if len(broker.unprotectCalls) != 1 || len(broker.unprotectCalls[0]) != 1 ||
		broker.unprotectCalls[0][0].Key != "SEC" {
		t.Fatalf("the broker must receive only ciphertext slots, got %+v", broker.unprotectCalls)
	}
}

func TestLegacyPlaintextPassesThrough(t *testing.T) {
	out, err := UnprotectMap(context.Background(), nil, "wf-old", map[string]string{"K": "plain-value"})
	if err != nil {
		t.Fatalf("legacy plaintext must pass through without a broker: %v", err)
	}
	if out["K"] != "plain-value" {
		t.Fatalf("legacy plaintext mismatch: %v", out)
	}
	if _, err := UnprotectMap(context.Background(), nil, "wf-old",
		map[string]string{"K": "sp1:not-a-ciphertext"}); err == nil {
		t.Fatal("ciphertext without a broker must fail closed")
	}
}

func TestBrokerFailureFailsClosed(t *testing.T) {
	const doc = "name: wf-fail\nsecret_env:\n  K: v\n"
	if _, err := ProtectYAML(context.Background(), &fakeBroker{failProtect: true}, doc, "wf-fail"); err == nil {
		t.Fatal("protect must fail when the broker is unavailable")
	}
	ct := encodeForTest("wf-fail", "K", "v")
	if _, err := UnprotectMap(context.Background(), &fakeBroker{failUnprotect: true}, "wf-fail",
		map[string]string{"K": ct}); err == nil {
		t.Fatal("unprotect must fail when the broker is unavailable")
	}
}

func TestBrokerMismatchedResponseFails(t *testing.T) {
	const doc = "name: wf-short\nsecret_env:\n  K: v\n"
	if _, err := ProtectYAML(context.Background(), &fakeBroker{shortResponse: true}, doc, "wf-short"); err == nil {
		t.Fatal("a short broker response must fail instead of leaving a value plaintext")
	}
}

func TestProtectYAMLWithoutSecretsSkipsBroker(t *testing.T) {
	const doc = "name: wf-plain\njobs:\n  j:\n    steps:\n      - name: s\n        command: \"true\"\n"
	out, err := ProtectYAML(context.Background(), nil, doc, "wf-plain")
	if err != nil {
		t.Fatalf("a workflow without secret_env must not need a broker: %v", err)
	}
	if out != doc {
		t.Fatalf("content changed without secrets: %q", out)
	}
}
