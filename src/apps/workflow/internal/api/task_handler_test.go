// Package api tests: workflow_rm must report not-found instead of success when
// the target workflow does not exist (the CLI turns {"status":"error"} into a
// non-zero exit, so a false "workflow removed" hides typos from automation).
package api

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/trigger"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/workdir"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

func newTestHandler(t *testing.T) *TaskHandler {
	t.Helper()
	base := t.TempDir()
	svc := trigger.NewService(nil, "", nil, base)
	return &TaskHandler{svc: svc, wdir: workdir.NewManager(base, 10)}
}

func writeWorkflowYaml(t *testing.T, h *TaskHandler, name, owner string) {
	t.Helper()
	dir := filepath.Join(h.wdir.BaseDir(), name)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "workflow.yaml"), []byte("name: "+name+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	h.svc.Registry().Update(name, &models.Workflow{Name: name}, owner)
}

func TestWorkflowRmMissingWorkflowIsAnError(t *testing.T) {
	h := newTestHandler(t)

	resp := h.handleWorkflowRm(Request{Workflow: "does-not-exist"}, "")
	if resp.Status != "error" {
		t.Fatalf("rm of a missing workflow must be an error, got %+v", resp)
	}
	if resp.Message != "workflow not found" {
		t.Fatalf("expected the not-found message, got %q", resp.Message)
	}
}

func TestWorkflowRmAuthorizePassesThroughForHandlerNotFound(t *testing.T) {
	h := newTestHandler(t)

	// A non-owner caller must reach the handler (which answers not-found) rather
	// than a misleading ownership denial for a workflow that does not exist.
	if msg := h.authorize("someone", false, Request{Action: "workflow_rm", Workflow: "does-not-exist"}); msg != "" {
		t.Fatalf("authorize should defer to the handler's not-found answer, got %q", msg)
	}
}

func TestWorkflowRmAuthorizeStillDeniesNonOwnerOfExistingWorkflow(t *testing.T) {
	h := newTestHandler(t)
	writeWorkflowYaml(t, h, "mine", "owner-a")

	if msg := h.authorize("someone", false, Request{Action: "workflow_rm", Workflow: "mine"}); msg == "" {
		t.Fatal("authorize must deny a non-owner even though the workflow exists")
	}
	if msg := h.authorize("owner-a", false, Request{Action: "workflow_rm", Workflow: "mine"}); msg != "" {
		t.Fatalf("the owner must pass authorization, got %q", msg)
	}
}

// TestNewPrincipalHTTPClientSchemeFollowsTransport pins the principal-lookup
// endpoint: the default is the local TLS REST listener, plain transport
// switches the scheme to http (a plaintext daemon), and APPMESH_ENGINE_URL
// keeps whatever scheme it specifies.
func TestNewPrincipalHTTPClientSchemeFollowsTransport(t *testing.T) {
	client, engineURL, err := newPrincipalHTTPClient(appmesh.Option{})
	if err != nil {
		t.Fatalf("TLS default must construct: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "https://127.0.0.1:6060" {
		t.Fatalf("default engine URL = %q, want https://127.0.0.1:6060", engineURL)
	}

	client, engineURL, err = newPrincipalHTTPClient(appmesh.Option{PlainTransport: true})
	if err != nil {
		t.Fatalf("plain transport must construct: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "http://127.0.0.1:6060" {
		t.Fatalf("plain engine URL = %q, want http://127.0.0.1:6060", engineURL)
	}

	t.Setenv("APPMESH_ENGINE_URL", "https://engine.example:8443/base")
	client, engineURL, err = newPrincipalHTTPClient(appmesh.Option{PlainTransport: true})
	if err != nil {
		t.Fatalf("APPMESH_ENGINE_URL must override: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "https://engine.example:8443/base" {
		t.Fatalf("override engine URL = %q, want the APPMESH_ENGINE_URL value", engineURL)
	}
}

// TestNewPrincipalHTTPClientPlainIgnoresCAMissing pins that plain mode treats
// CA pinning as a TLS-only concern: a leftover APPMESH_CA path that does not
// exist must not fail engine startup.
func TestNewPrincipalHTTPClientPlainIgnoresCAMissing(t *testing.T) {
	t.Setenv("APPMESH_CA", filepath.Join(t.TempDir(), "absent-ca.pem"))

	if _, _, err := newPrincipalHTTPClient(appmesh.Option{PlainTransport: true}); err != nil {
		t.Fatalf("plain mode must not require the CA file: %v", err)
	}

	// TLS mode keeps the hard failure for a configured but missing CA.
	if _, _, err := newPrincipalHTTPClient(appmesh.Option{}); err == nil {
		t.Fatal("TLS mode must fail on a configured CA that cannot be read")
	}
}
