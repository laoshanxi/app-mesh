package appmesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
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

// RequestWorkflowCapabilityContext proves the current App Mesh-managed process
// instance using APP_MESH_PROCESS_KEY. The Engine accepts this endpoint only on
// an actual loopback TCP socket and derives all authority server-side.
func (r *AppMeshClient) RequestWorkflowCapabilityContext(ctx context.Context, request WorkflowCapabilityRequest) (WorkflowCapability, error) {
	processKey := os.Getenv("APP_MESH_PROCESS_KEY")
	if processKey == "" {
		return WorkflowCapability{}, fmt.Errorf("APP_MESH_PROCESS_KEY is required for internal workflow capability issuance")
	}
	body, err := json.Marshal(request)
	if err != nil {
		return WorkflowCapability{}, fmt.Errorf("marshal workflow capability request: %w", err)
	}
	headers := map[string]string{
		"Content-Type":          "application/json",
		"X-AppMesh-Process-Key": processKey,
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
	if capability.Capability == "" || capability.ExpiresAt <= 0 || capability.OwnerPrincipalID == "" || capability.ProcessUUID == "" {
		return WorkflowCapability{}, fmt.Errorf("Engine returned an incomplete workflow capability")
	}
	return capability, nil
}

// CleanupWorkflowOrphansContext removes only local command-step Apps tagged by
// a prior Workflow process instance. The Engine derives the current process
// identity from APP_MESH_PROCESS_KEY and accepts no caller-supplied app names.
func (r *AppMeshClient) CleanupWorkflowOrphansContext(ctx context.Context) (int, error) {
	processKey := os.Getenv("APP_MESH_PROCESS_KEY")
	if processKey == "" {
		return 0, fmt.Errorf("APP_MESH_PROCESS_KEY is required for internal workflow orphan cleanup")
	}
	headers := map[string]string{"X-AppMesh-Process-Key": processKey}
	status, raw, _, err := r.req.SendContext(ctx, http.MethodPost,
		"/appmesh/internal/workflow/cleanup-orphans", nil, headers, nil)
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
