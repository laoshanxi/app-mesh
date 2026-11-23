// Package secrets protects workflow secret_env values through the Engine's
// Workflow secret broker. The daemon owns the node master key and binds each
// ciphertext to the workflow name and key; the Engine never reads the key file.
package secrets

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

const (
	// formatPrefix mirrors the daemon's SecretProtector wire marker.
	formatPrefix = "sp1:"
	// secretEnvKey is the YAML key that holds secrets at every schema level.
	secretEnvKey = "secret_env"
	// brokerRequestTimeout bounds one daemon broker round trip.
	brokerRequestTimeout = 15 * time.Second
)

// Entry is one secret slot; a list preserves duplicate keys across YAML levels.
type Entry struct {
	Key   string
	Value string
}

// Broker encrypts and decrypts workflow secret values; the daemon owns the key.
type Broker interface {
	Protect(ctx context.Context, workflow string, values []Entry) ([]Entry, error)
	Unprotect(ctx context.Context, workflow string, values []Entry) ([]Entry, error)
}

// SDKBroker calls the daemon broker over the Workflow control-capability client.
type SDKBroker struct {
	client *appmesh.AppMeshClient
}

// NewSDKBroker adapts the SDK client used for Workflow control work.
func NewSDKBroker(client *appmesh.AppMeshClient) SDKBroker { return SDKBroker{client: client} }

// Protect encrypts values for at-rest storage in the daemon's SecretProtector
// wire layout: "sp1:" + base64(nonce || tag || ciphertext).
func (b SDKBroker) Protect(ctx context.Context, workflow string, values []Entry) ([]Entry, error) {
	return b.roundTrip(ctx, "protect", workflow, values)
}

// Unprotect decrypts one batch of at-rest values.
func (b SDKBroker) Unprotect(ctx context.Context, workflow string, values []Entry) ([]Entry, error) {
	return b.roundTrip(ctx, "unprotect", workflow, values)
}

func (b SDKBroker) roundTrip(ctx context.Context, op, workflow string, values []Entry) ([]Entry, error) {
	if b.client == nil {
		return nil, fmt.Errorf("workflow secret broker client is unavailable")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, brokerRequestTimeout)
	defer cancel()

	request := make([]appmesh.WorkflowSecretValue, len(values))
	for i, value := range values {
		request[i] = appmesh.WorkflowSecretValue{Key: value.Key, Value: value.Value}
	}
	var result []appmesh.WorkflowSecretValue
	var err error
	if op == "protect" {
		result, err = b.client.ProtectWorkflowSecretsContext(ctx, workflow, request)
	} else {
		result, err = b.client.UnprotectWorkflowSecretsContext(ctx, workflow, request)
	}
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, len(result))
	for i, value := range result {
		entries[i] = Entry{Key: value.Key, Value: value.Value}
	}
	return entries, nil
}

// ProtectYAML rewrites plaintext secret_env values to protected form and
// validates existing ciphertext against this workflow name.
func ProtectYAML(ctx context.Context, broker Broker, content, workflow string) (string, error) {
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(content), &node); err != nil {
		return "", fmt.Errorf("parse YAML: %w", err)
	}
	if node.Kind == 0 {
		return content, nil
	}

	type slot struct {
		node *yaml.Node
		key  string
	}
	var plainSlots []slot
	var protectedSlots []slot
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode {
			for i := 0; i+1 < len(n.Content); i += 2 {
				key, val := n.Content[i], n.Content[i+1]
				if key.Value == secretEnvKey && val.Kind == yaml.MappingNode {
					for j := 0; j+1 < len(val.Content); j += 2 {
						envKey, envVal := val.Content[j], val.Content[j+1]
						if envVal.Kind != yaml.ScalarNode {
							continue
						}
						if strings.HasPrefix(envVal.Value, formatPrefix) {
							protectedSlots = append(protectedSlots, slot{node: envVal, key: envKey.Value})
						} else {
							plainSlots = append(plainSlots, slot{node: envVal, key: envKey.Value})
						}
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
	if len(plainSlots) == 0 && len(protectedSlots) == 0 {
		return content, nil
	}
	if broker == nil {
		return "", fmt.Errorf("workflow secret broker is unavailable")
	}

	// Storing ciphertext bound to another workflow name would fail every run
	// later, so reject it at registration.
	if len(protectedSlots) > 0 {
		values := make([]Entry, len(protectedSlots))
		for i, s := range protectedSlots {
			values[i] = Entry{Key: s.key, Value: s.node.Value}
		}
		if _, err := broker.Unprotect(ctx, workflow, values); err != nil {
			return "", fmt.Errorf("secret_env is already protected ciphertext that does not decrypt for workflow %q "+
				"(%v): it was encrypted for another workflow name or is a literal value with the %q prefix; "+
				"re-enter it as plaintext", workflow, err, formatPrefix)
		}
	}
	if len(plainSlots) == 0 {
		// Re-adding the same workflow: keep the document unchanged.
		return content, nil
	}

	values := make([]Entry, len(plainSlots))
	for i, s := range plainSlots {
		values[i] = Entry{Key: s.key, Value: s.node.Value}
	}
	protected, err := broker.Protect(ctx, workflow, values)
	if err != nil {
		return "", fmt.Errorf("protect secret_env: %w", err)
	}
	if len(protected) != len(plainSlots) {
		return "", fmt.Errorf("protect secret_env: broker returned %d values for %d inputs", len(protected),
			len(plainSlots))
	}
	for i, s := range plainSlots {
		if protected[i].Key != s.key {
			return "", fmt.Errorf("protect secret_env: broker returned %q for %q", protected[i].Key, s.key)
		}
		s.node.Value = protected[i].Value
		s.node.Tag = "!!str"
		s.node.Style = yaml.DoubleQuotedStyle
	}

	var out bytes.Buffer
	enc := yaml.NewEncoder(&out)
	enc.SetIndent(2)
	if err := enc.Encode(&node); err != nil {
		return "", fmt.Errorf("marshal YAML: %w", err)
	}
	if err := enc.Close(); err != nil {
		return "", err
	}
	return out.String(), nil
}

// UnprotectMap decrypts sp1: values and passes legacy plaintext through.
func UnprotectMap(ctx context.Context, broker Broker, workflow string, values map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(values))
	entries := make([]Entry, 0, len(values))
	for key, value := range values {
		if strings.HasPrefix(value, formatPrefix) {
			entries = append(entries, Entry{Key: key, Value: value})
		} else {
			out[key] = value
		}
	}
	if len(entries) == 0 {
		return out, nil
	}
	if broker == nil {
		return nil, fmt.Errorf("workflow secret broker is unavailable")
	}
	plain, err := broker.Unprotect(ctx, workflow, entries)
	if err != nil {
		return nil, err
	}
	if len(plain) != len(entries) {
		return nil, fmt.Errorf("unprotect secret_env: broker returned %d values for %d inputs", len(plain),
			len(entries))
	}
	for i, entry := range plain {
		if entry.Key != entries[i].Key {
			return nil, fmt.Errorf("unprotect secret_env: broker returned %q for %q", entry.Key, entries[i].Key)
		}
		out[entry.Key] = entry.Value
	}
	return out, nil
}
