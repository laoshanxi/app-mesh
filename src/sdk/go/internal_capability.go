package appmesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	WorkflowControlCapabilityAudience = "appmesh-internal-workflow-control"
	WorkflowRunCapabilityAudience     = "appmesh-internal-workflow-run"
)

// WorkflowCapabilityRequest is an internal, loopback-TCP-only request made by
// the managed Workflow process. It is not part of the public REST API.
type WorkflowCapabilityRequest struct {
	Audience   string   `json:"audience"`
	Workflow   string   `json:"workflow_id,omitempty"`
	RunID      string   `json:"run_id,omitempty"`
	Operations []string `json:"operations"`
	ExpiresIn  int      `json:"expires_in"`
}

// WorkflowCapability is an opaque Engine authorization capability. Capability
// must never be decoded, logged, persisted, or forwarded to another service.
type WorkflowCapability struct {
	Capability       string `json:"capability"`
	ExpiresAt        int64  `json:"expires_at"`
	OwnerPrincipalID string `json:"owner_principal_id"`
	ProcessUUID      string `json:"process_uuid"`
}

// RequestWorkflowCapabilityContext is issued to the managed Workflow process
// only. The request is marked with HeaderProcessProof and the transport signs
// it with the pre-shared key from Option.PSK; the Engine accepts this endpoint
// only on a loopback TCP socket and derives all authority server-side.
func (r *AppMeshClient) RequestWorkflowCapabilityContext(ctx context.Context,
	request WorkflowCapabilityRequest) (WorkflowCapability, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return WorkflowCapability{}, fmt.Errorf("marshal workflow capability request: %w", err)
	}
	headers := map[string]string{
		"Content-Type":     "application/json",
		HeaderProcessProof: "1",
	}
	status, raw, _, err := r.req.SendContext(ctx, http.MethodPost,
		"/appmesh/internal/workflow/capability", nil, headers, bytes.NewReader(body))
	if err != nil {
		return WorkflowCapability{}, fmt.Errorf("request workflow capability: %w", err)
	}
	if status != http.StatusOK {
		return WorkflowCapability{}, newAPIError("request workflow capability", status, string(raw))
	}
	var capability WorkflowCapability
	if err := json.Unmarshal(raw, &capability); err != nil {
		return WorkflowCapability{}, fmt.Errorf("decode workflow capability: %w", err)
	}
	if capability.Capability == "" || capability.ExpiresAt <= 0 || capability.OwnerPrincipalID == "" ||
		capability.ProcessUUID == "" {
		return WorkflowCapability{}, fmt.Errorf("Engine returned an incomplete workflow capability")
	}
	return capability, nil
}

// CleanupWorkflowOrphansContext removes only local command-step Apps tagged by
// a prior Workflow process instance. The request is marked with
// HeaderProcessProof and the transport signs it with the pre-shared key from
// Option.PSK; the Engine derives the current process identity from that proof
// and accepts no caller-supplied app names.
func (r *AppMeshClient) CleanupWorkflowOrphansContext(ctx context.Context) (int, error) {
	status, raw, _, err := r.req.SendContext(ctx, http.MethodPost,
		"/appmesh/internal/workflow/cleanup-orphans", nil,
		map[string]string{HeaderProcessProof: "1"}, nil)
	if err != nil {
		return 0, fmt.Errorf("cleanup workflow orphans: %w", err)
	}
	if status != http.StatusOK {
		return 0, newAPIError("cleanup workflow orphans", status, string(raw))
	}
	var response struct {
		Removed int `json:"removed"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return 0, fmt.Errorf("decode workflow orphan cleanup response: %w", err)
	}
	if response.Removed < 0 {
		return 0, fmt.Errorf("Engine returned an invalid workflow orphan cleanup count")
	}
	return response.Removed, nil
}

// WorkflowSecretValue is one secret slot in a Workflow secret broker request.
type WorkflowSecretValue struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ProtectWorkflowSecretsContext encrypts plaintext workflow secret values with
// the daemon's node master key; the engine never reads the key file.
func (r *AppMeshClient) ProtectWorkflowSecretsContext(ctx context.Context, workflow string,
	values []WorkflowSecretValue) ([]WorkflowSecretValue, error) {
	return r.workflowSecretsContext(ctx, "protect", workflow, values)
}

// UnprotectWorkflowSecretsContext decrypts workflow secret values bound to the
// workflow name and key by the daemon.
func (r *AppMeshClient) UnprotectWorkflowSecretsContext(ctx context.Context, workflow string,
	values []WorkflowSecretValue) ([]WorkflowSecretValue, error) {
	return r.workflowSecretsContext(ctx, "unprotect", workflow, values)
}

func (r *AppMeshClient) workflowSecretsContext(ctx context.Context, op, workflow string,
	values []WorkflowSecretValue) ([]WorkflowSecretValue, error) {
	request := struct {
		Op       string                `json:"op"`
		Workflow string                `json:"workflow"`
		Secrets  []WorkflowSecretValue `json:"secrets"`
	}{Op: op, Workflow: workflow, Secrets: values}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("marshal workflow secret request: %w", err)
	}
	status, raw, _, err := r.req.SendContext(ctx, http.MethodPost,
		"/appmesh/internal/workflow/secret", nil, map[string]string{"Content-Type": "application/json"},
		bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("workflow secret %s: %w", op, err)
	}
	if status != http.StatusOK {
		return nil, newAPIError("workflow secret "+op, status, string(raw))
	}
	var response struct {
		Secrets []WorkflowSecretValue `json:"secrets"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode workflow secret response: %w", err)
	}
	if len(response.Secrets) != len(values) {
		return nil, fmt.Errorf("Engine returned %d workflow secrets for %d inputs", len(response.Secrets), len(values))
	}
	for i := range response.Secrets {
		if response.Secrets[i].Key != values[i].Key {
			return nil, fmt.Errorf("Engine returned workflow secret %q in place of %q",
				response.Secrets[i].Key, values[i].Key)
		}
	}
	return response.Secrets, nil
}

// ListWorkflowRegistryContext returns only Engine-registered workflow
// definitions. The endpoint accepts the managed Workflow controller capability
// over loopback TCP and is intentionally narrower than ListAppsContext.
func (r *AppMeshClient) ListWorkflowRegistryContext(ctx context.Context) ([]Application, error) {
	status, raw, _, err := r.req.SendContext(ctx, http.MethodGet,
		"/appmesh/internal/workflow/registry", nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("list workflow registry: %w", err)
	}
	if status != http.StatusOK {
		return nil, newAPIError("list workflow registry", status, string(raw))
	}
	var apps []Application
	if err := json.Unmarshal(raw, &apps); err != nil {
		return nil, fmt.Errorf("decode workflow registry: %w", err)
	}
	return apps, nil
}
