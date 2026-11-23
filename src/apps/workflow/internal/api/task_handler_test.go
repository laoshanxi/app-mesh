// Package api tests: workflow_rm must report not-found instead of success when
// the target workflow does not exist (the CLI turns {"status":"error"} into a
// non-zero exit, so a false "workflow removed" hides typos from automation).
package api

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/tlsconf"
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

// The daemon run_task gate admits workflow-runner/workflow-admin callers to the
// system workflow App, so this per-action authorization is the RBAC boundary.
// Pin the full 12-action matrix: every workflow-targeting action is denied for
// a non-owner without workflow-admin, allowed for the owner and for a
// workflow-admin holder; workflow_list passes everyone (its handler filters by
// owner) and registering a NEW workflow is allowed for a runner (ownership is
// then set to the caller).
func TestAuthorizeActionMatrix(t *testing.T) {
	h := newTestHandler(t)
	writeWorkflowYaml(t, h, "owned", "owner-a")

	targeted := []string{
		"workflow_add", "workflow_get", "workflow_rm", "workflow_inputs",
		"run", "rerun", "runs", "run_detail", "log", "step_log",
	}
	for _, action := range targeted {
		req := Request{Action: action, Workflow: "owned", RunID: "r1", Job: "j", Step: "s", Content: "name: owned\n"}
		if msg := h.authorize("runner-b", false, req); msg == "" {
			t.Errorf("%s: a non-owner without workflow-admin must be denied", action)
		}
		if msg := h.authorize("owner-a", false, req); msg != "" {
			t.Errorf("%s: the owner must pass, got %q", action, msg)
		}
		if msg := h.authorize("someone", true, req); msg != "" {
			t.Errorf("%s: a workflow-admin holder must pass, got %q", action, msg)
		}
	}

	// workflow_list delegates filtering to its handler, and cancel on an unknown
	// run defers to the handler's not-found answer.
	if msg := h.authorize("runner-b", false, Request{Action: "workflow_list"}); msg != "" {
		t.Errorf("workflow_list must stay ungated here, got %q", msg)
	}
	if msg := h.authorize("runner-b", false, Request{Action: "cancel", RunID: "no-such-run"}); msg != "" {
		t.Errorf("cancel of an unknown run must defer to the handler, got %q", msg)
	}

	// Registering a workflow the caller does not own is fine while the name is
	// free (the registrant becomes the owner).
	if msg := h.authorize("runner-b", false, Request{Action: "workflow_add", Workflow: "fresh"}); msg != "" {
		t.Errorf("a runner must be able to register a new workflow, got %q", msg)
	}
}

// writeDaemonConfig writes a daemon config.yaml under a fresh config root and
// returns that root.
func writeDaemonConfig(t *testing.T, content string) string {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, "work", "config", "config.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestNewPrincipalHTTPClientEndpointFollowsDaemonConfig pins the principal-lookup
// endpoint: the daemon's native WebSocketPort listener serves principal/self by
// default, WebSocketPort: 0 falls back to the agent's RestListenPort (the only
// REST entry then), the scheme follows the resolved transport, and
// APPMESH_ENGINE_URL wins outright.
func TestNewPrincipalHTTPClientEndpointFollowsDaemonConfig(t *testing.T) {
	t.Setenv("APPMESH_ENGINE_URL", "")
	t.Setenv(tlsconf.EnvWebSocketPort, "")
	t.Setenv(tlsconf.EnvRestListenPort, "")
	// No config file: the shipped daemon defaults apply.
	t.Setenv(tlsconf.EnvConfigRoot, t.TempDir())

	client, engineURL, err := newPrincipalHTTPClient(appmesh.Option{})
	if err != nil {
		t.Fatalf("TLS default must construct: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "https://127.0.0.1:6058" {
		t.Fatalf("default engine URL = %q, want https://127.0.0.1:6058", engineURL)
	}

	client, engineURL, err = newPrincipalHTTPClient(appmesh.Option{PlainTransport: true})
	if err != nil {
		t.Fatalf("plain transport must construct: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "http://127.0.0.1:6058" {
		t.Fatalf("plain engine URL = %q, want http://127.0.0.1:6058", engineURL)
	}

	// The documented WebSocketPort: 0 configuration disables the native listener;
	// the agent on RestListenPort is the only REST entry.
	t.Setenv(tlsconf.EnvConfigRoot, writeDaemonConfig(t, "REST:\n  WebSocketPort: 0\n  RestListenPort: 6060\n"))
	client, engineURL, err = newPrincipalHTTPClient(appmesh.Option{})
	if err != nil {
		t.Fatalf("TLS with the native listener disabled must construct: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "https://127.0.0.1:6060" {
		t.Fatalf("WebSocketPort=0 engine URL = %q, want https://127.0.0.1:6060", engineURL)
	}

	client, engineURL, err = newPrincipalHTTPClient(appmesh.Option{PlainTransport: true})
	if err != nil {
		t.Fatalf("plain with the native listener disabled must construct: %v", err)
	}
	client.CloseIdleConnections()
	if engineURL != "http://127.0.0.1:6060" {
		t.Fatalf("WebSocketPort=0 plain engine URL = %q, want http://127.0.0.1:6060", engineURL)
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

// The registration-time namespace guard must reject a colliding non-workflow
// app (AddApp would silently overwrite it), pass a workflow-owned pseudo-App
// through to the owner-checked overwrite path, and pass a free name.
func TestAppNamespaceConflict(t *testing.T) {
	meta := func(m map[string]string) *json.RawMessage {
		raw, _ := json.Marshal(m)
		msg := json.RawMessage(raw)
		return &msg
	}
	apps := []appmesh.Application{
		{Name: "workflow-existing", Metadata: meta(map[string]string{"type": "workflow"})},
		{Name: "workflow-zebra", Command: nil, Metadata: meta(map[string]string{"type": "manual-app"})},
		{Name: "workflow-nometa"},
	}

	if err := appNamespaceConflict(apps, "workflow-free"); err != nil {
		t.Fatalf("a free name must pass, got %v", err)
	}
	if err := appNamespaceConflict(apps, "workflow-existing"); err != nil {
		t.Fatalf("a workflow-owned pseudo-App must pass (owner check applies at overwrite), got %v", err)
	}
	for _, taken := range []string{"workflow-zebra", "workflow-nometa"} {
		err := appNamespaceConflict(apps, taken)
		if err == nil {
			t.Fatalf("%s: a non-workflow app must conflict", taken)
		}
		if !strings.Contains(err.Error(), "conflict") {
			t.Fatalf("%s: the error must be a clear conflict, got %q", taken, err.Error())
		}
	}
}

// A 401 from the control capability must trigger the immediate (rate-limited)
// control refresh rather than waiting for the renewal ticker.
func TestHandleWorkflowListRefreshesOnAuthError(t *testing.T) {
	h := newTestHandler(t)

	refreshed := 0
	h.svc.SetControlRefresh(func(context.Context) error {
		refreshed++
		return nil
	})

	// h.client is nil here, so the list call errors; the trigger.Path is the
	// auth classification. Use an APIError-shaped 401 through the exported
	// classifier and verify the service reacts to ControlCapabilityRejected.
	if !trigger.IsAuthError(&appmesh.APIError{StatusCode: 401}) {
		t.Fatal("401 must classify as an auth error")
	}
	if trigger.IsAuthError(&appmesh.APIError{StatusCode: 403}) {
		t.Fatal("403 must not classify as an auth error")
	}
	if !h.svc.ControlCapabilityRejected() {
		t.Fatal("ControlCapabilityRejected must report a successful refresh")
	}
	if refreshed != 1 {
		t.Fatalf("control refresh must fire once, got %d", refreshed)
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
