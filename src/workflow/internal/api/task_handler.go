// Package api implements a Task API RPC handler for all workflow operations.
// The workflow engine process runs a fetch_task/send_task_result loop
// to receive requests from CLI/GUI via daemon's RunTask API.
//
// Protocol: client sends JSON payload via run_task("workflow", payload).
// Handler parses action, dispatches, and returns JSON response via send_task_result.
//
// 12 actions covering workflow CRUD + run management + observability:
//
//	workflow_add, workflow_get, workflow_list, workflow_rm,
//	workflow_inputs, run, cancel, rerun,
//	runs, run_detail, log, step_log
package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/dag"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/parser"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/trigger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/workdir"
)

const workflowAppPrefix = trigger.WorkflowAppPrefix

var safeID = regexp.MustCompile(`^[a-zA-Z0-9_-]+$`)

// Request is the JSON payload sent by CLI/GUI via run_task.
type Request struct {
	Action   string            `json:"action"`
	Workflow string            `json:"workflow"`
	RunID    string            `json:"run_id,omitempty"`
	Job      string            `json:"job,omitempty"`
	Step     string            `json:"step,omitempty"`
	Inputs   map[string]string `json:"inputs,omitempty"`
	Content  string            `json:"content,omitempty"` // YAML content for workflow_add
	// Token is the caller's JWT. It authenticates the caller (Phase 1 owner authz)
	// and is reused to run the workflow's steps under the caller's identity (Phase 2).
	// It is stripped immediately after authentication and is never persisted or logged.
	Token string `json:"token,omitempty"`
}

// Response is the JSON returned via send_task_result.
type Response struct {
	Status  string      `json:"status"` // "ok" or "error"
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// TaskHandler runs the fetch_task/send_task_result loop.
type TaskHandler struct {
	svc    *trigger.Service
	wdir   *workdir.Manager
	client *appmesh.AppMeshClient // daemon client for CRUD operations (uses JWT)
	server *appmesh.WorkerTCPContext
	admins map[string]bool // workflow admins (manage all workflows)
}

// NewTaskHandler creates a Task RPC handler.
func NewTaskHandler(svc *trigger.Service, wdir *workdir.Manager, client *appmesh.AppMeshClient, opts appmesh.Option) (*TaskHandler, error) {
	server, err := appmesh.NewTCPContext(opts)
	if err != nil {
		return nil, fmt.Errorf("create task context: %w", err)
	}
	return &TaskHandler{svc: svc, wdir: wdir, client: client, server: server, admins: parseAdmins()}, nil
}

// parseAdmins reads the workflow-admin username set from APPMESH_WORKFLOW_ADMINS
// (comma-separated). Admins may manage all workflows; everyone else is limited to
// the workflows they own. Defaults to {"admin"}.
func parseAdmins() map[string]bool {
	admins := map[string]bool{}
	raw := os.Getenv("APPMESH_WORKFLOW_ADMINS")
	if raw == "" {
		raw = "admin"
	}
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			admins[name] = true
		}
	}
	return admins
}

// Run starts the fetch_task/send_task_result loop. Blocks forever, except when the
// daemon reports this engine instance superseded (HTTP 412) — then the process exits.
func (h *TaskHandler) Run() {
	logger.Info("TASK handler started — accepting RPC via run_task")
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		payload, err := h.server.FetchTask()
		if err != nil {
			if errors.Is(err, appmesh.ErrProcessSuperseded) {
				// A newer engine instance replaced this one; staying alive would
				// double-fire triggers alongside the replacement, so terminate.
				logger.Error("fetch_task: engine instance superseded, exiting: " + err.Error())
				os.Exit(1)
			}
			// Back off on persistent errors (daemon down/restart) to avoid a tight CPU/log loop.
			logger.Error("fetch_task error: " + err.Error())
			time.Sleep(backoff)
			backoff *= 2
			if backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second

		resp := h.dispatch(payload)

		data, err := json.Marshal(resp)
		if err != nil {
			logger.Error("response marshal error: " + err.Error())
			data = []byte(`{"status":"error","message":"internal marshal error"}`)
		}
		if err := h.server.SendTaskResult(string(data)); err != nil {
			logger.Error("send_task_result error: " + err.Error())
		}
	}
}

func (h *TaskHandler) dispatch(payload string) Response {
	var req Request
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		return Response{Status: "error", Message: "invalid JSON: " + err.Error()}
	}

	// Authenticate the caller from the token in the payload, then strip it so it is
	// never logged or persisted. The same token is reused to run the workflow's steps
	// under the caller's identity (handleRun/handleRerun -> TriggerManual).
	token := req.Token
	req.Token = ""
	caller, err := h.authenticate(token)
	if err != nil {
		return Response{Status: "error", Message: "authentication failed: " + err.Error()}
	}
	admin := h.isAdmin(caller)

	for field, value := range map[string]string{
		"workflow": req.Workflow, "run_id": req.RunID,
		"job": req.Job, "step": req.Step,
	} {
		if value != "" && !safeID.MatchString(value) {
			return Response{Status: "error", Message: fmt.Sprintf("%s %q contains invalid characters", field, value)}
		}
	}

	if msg := h.authorize(caller, admin, req); msg != "" {
		return Response{Status: "error", Message: msg}
	}

	switch req.Action {
	// Workflow CRUD
	case "workflow_add":
		return h.handleWorkflowAdd(req, caller)
	case "workflow_get":
		return h.handleWorkflowGet(req)
	case "workflow_list":
		return h.handleWorkflowList(req, caller, admin)
	case "workflow_rm":
		return h.handleWorkflowRm(req)
	case "workflow_inputs":
		return h.handleWorkflowInputs(req)
	// Run management
	case "run":
		return h.handleRun(req, token, caller)
	case "cancel":
		return h.handleCancel(req)
	case "rerun":
		return h.handleRerun(req, token, caller)
	// Observability
	case "runs":
		return h.handleRuns(req)
	case "run_detail":
		return h.handleRunDetail(req)
	case "log":
		return h.handleLog(req)
	case "step_log":
		return h.handleStepLog(req)
	default:
		return Response{Status: "error", Message: "unknown action: " + req.Action}
	}
}

// authenticate validates the caller's JWT against the daemon and returns the verified
// username (the token's subject). Invalid/expired/blacklisted tokens fail closed.
func (h *TaskHandler) authenticate(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token required")
	}
	ok, err := h.client.Authenticate(token, "", "", false)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("invalid or expired token")
	}
	user := usernameFromJWT(token)
	if user == "" {
		return "", fmt.Errorf("token has no subject")
	}
	return user, nil
}

// authorize enforces per-workflow ownership: a caller may act on a workflow only if
// they own it or are a workflow admin. Creating a new workflow is always allowed (the
// owner is then set to the caller); overwriting an existing one requires access to it.
// workflow_list is filtered inside its handler.
func (h *TaskHandler) authorize(caller string, admin bool, req Request) string {
	const denied = "permission denied: not the workflow owner"
	switch req.Action {
	case "workflow_list":
		return ""
	case "workflow_add":
		if owner := h.ownerOf(req.Workflow); owner != "" && !canAccess(caller, admin, owner) {
			return "permission denied: workflow is owned by another user"
		}
		return ""
	case "cancel":
		wfName := h.workflowOfRun(req.RunID)
		if wfName == "" {
			return "" // unknown run; the handler reports not-found
		}
		if !canAccess(caller, admin, h.ownerOf(wfName)) {
			return denied
		}
		return ""
	default:
		if req.Workflow != "" && !canAccess(caller, admin, h.ownerOf(req.Workflow)) {
			return denied
		}
		return ""
	}
}

// canAccess returns true if the caller is an admin or the workflow's owner.
func canAccess(caller string, admin bool, owner string) bool {
	return admin || (owner != "" && caller == owner)
}

func (h *TaskHandler) isAdmin(caller string) bool { return h.admins[caller] }

// ownerOf returns the workflow's owner, or "" if unknown. Served from the in-memory
// registry (populated by the periodic scan and on registration) — no daemon round-trip.
func (h *TaskHandler) ownerOf(wfName string) string {
	if wfName == "" {
		return ""
	}
	return h.svc.Registry().Owner(wfName)
}

// workflowOfRun resolves which workflow a run_id belongs to (for cancel authz).
func (h *TaskHandler) workflowOfRun(runID string) string {
	if runID == "" {
		return ""
	}
	for name := range h.svc.Registry().All() {
		for _, r := range h.wdir.ListRuns(name) {
			if r.RunID == runID {
				return name
			}
		}
	}
	return ""
}

// usernameFromJWT extracts the subject (username) from a JWT without verifying it;
// callers must validate the token separately (see authenticate).
func usernameFromJWT(token string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		if raw, err = base64.StdEncoding.DecodeString(parts[1]); err != nil {
			return ""
		}
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	return claims.Sub
}

// --- Workflow CRUD ---

func (h *TaskHandler) handleWorkflowAdd(req Request, caller string) Response {
	if req.Workflow == "" || req.Content == "" {
		return Response{Status: "error", Message: "workflow name and content required"}
	}

	// Validate YAML by parsing it.
	tmpFile, err := os.CreateTemp("", "wf-validate-*.yaml")
	if err != nil {
		return Response{Status: "error", Message: "failed to create temp file: " + err.Error()}
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	if _, err := tmpFile.WriteString(req.Content); err != nil {
		tmpFile.Close()
		return Response{Status: "error", Message: "failed to write temp file: " + err.Error()}
	}
	tmpFile.Close()

	wf, err := parser.LoadWorkflow(tmpPath)
	if err != nil {
		return Response{Status: "error", Message: "invalid workflow YAML: " + err.Error()}
	}
	if req.Workflow != wf.Name {
		return Response{Status: "error", Message: fmt.Sprintf("request name %q does not match YAML name %q", req.Workflow, wf.Name)}
	}
	// Reject cycles / unknown `needs` references at registration instead of
	// letting the workflow fail only when it is first run.
	if _, err := dag.TopoSort(wf.Jobs); err != nil {
		return Response{Status: "error", Message: "invalid workflow DAG: " + err.Error()}
	}

	// Authorize execution_identity binding (ADR 0004): engine must hold the credential,
	// and only that identity itself or a workflow admin may bind it.
	if wf.ExecutionIdentity != "" {
		if !h.svc.IsKnownIdentity(wf.ExecutionIdentity) {
			return Response{Status: "error", Message: fmt.Sprintf("execution_identity %q is not configured on the engine; ask an admin to provision its credential (APPMESH_EXEC_IDENTITIES)", wf.ExecutionIdentity)}
		}
		if wf.ExecutionIdentity != caller && !h.isAdmin(caller) {
			return Response{Status: "error", Message: fmt.Sprintf("not allowed to bind execution_identity %q (only that identity or a workflow admin can)", wf.ExecutionIdentity)}
		}
	}

	// Register the daemon App FIRST. If it succeeds, we then write the YAML.
	// This order avoids orphan YAML on crash between write and AddApp.
	yamlPath := filepath.Join(h.wdir.BaseDir(), wf.Name, "workflow.yaml")
	appName := workflowAppPrefix + req.Workflow
	trueCmd := "true"
	// Workflow ownership lives in engine-controlled metadata, not the App's owner field:
	// the daemon stamps the App owner with the *registering* identity (the engine), so the
	// owner field can't carry the caller. The scan and list read owner back from here.
	metaBytes, err := json.Marshal(map[string]string{"type": "workflow", "yaml_path": yamlPath, "owner": caller})
	if err != nil {
		return Response{Status: "error", Message: "failed to marshal metadata: " + err.Error()}
	}
	metadata := json.RawMessage(metaBytes)
	// Ownership is derived from the authenticated registrant, never from the YAML
	// (trusting YAML owner was spoofable). The owner is what per-workflow authz checks.
	owner := caller
	app := appmesh.Application{
		Name:     appName,
		Command:  &trueCmd,
		Status:   0, // disabled
		Metadata: &metadata,
		Owner:    &owner,
	}
	if wf.Permission != 0 {
		app.Permission = &wf.Permission
	}
	if _, err := h.client.AddApp(app); err != nil {
		return Response{Status: "error", Message: "failed to register App: " + err.Error()}
	}

	// Roll back the App registration if YAML write fails so we don't leave an orphan.
	writeYaml := func() error {
		if err := os.MkdirAll(filepath.Dir(yamlPath), 0755); err != nil {
			return fmt.Errorf("failed to create workflow dir: %w", err)
		}
		tmp := yamlPath + ".tmp"
		if err := os.WriteFile(tmp, []byte(req.Content), 0644); err != nil {
			return fmt.Errorf("failed to save YAML: %w", err)
		}
		if err := os.Rename(tmp, yamlPath); err != nil {
			os.Remove(tmp)
			return fmt.Errorf("failed to rename YAML: %w", err)
		}
		return nil
	}
	if err := writeYaml(); err != nil {
		h.client.DeleteApp(appName)
		return Response{Status: "error", Message: err.Error()}
	}

	h.wdir.EnsureWorkflowDir(req.Workflow)
	h.svc.Registry().Update(req.Workflow, wf, owner)
	return Response{Status: "ok", Message: "workflow registered"}
}

func (h *TaskHandler) handleWorkflowGet(req Request) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	yamlPath := filepath.Join(h.wdir.BaseDir(), req.Workflow, "workflow.yaml")
	content, err := os.ReadFile(yamlPath)
	if err != nil {
		if os.IsNotExist(err) {
			return Response{Status: "error", Message: "workflow not found"}
		}
		return Response{Status: "error", Message: "failed to read workflow: " + err.Error()}
	}
	return Response{Status: "ok", Data: string(content)}
}

func (h *TaskHandler) handleWorkflowList(req Request, caller string, admin bool) Response {
	apps, err := h.client.ListApps()
	if err != nil {
		return Response{Status: "error", Message: "failed to list apps: " + err.Error()}
	}

	type WfInfo struct {
		Name          string `json:"name"`
		Owner         string `json:"owner"`
		LastRunStatus string `json:"last_run_status,omitempty"`
		LastRunAt     string `json:"last_run_at,omitempty"`
	}
	workflows := make([]WfInfo, 0)
	for _, app := range apps {
		if !strings.HasPrefix(app.Name, workflowAppPrefix) {
			continue
		}
		if app.Metadata == nil {
			continue
		}
		var meta map[string]string
		if err := json.Unmarshal(*app.Metadata, &meta); err != nil {
			continue
		}
		if meta["type"] != "workflow" {
			continue
		}
		wfName := strings.TrimPrefix(app.Name, workflowAppPrefix)
		owner := meta["owner"] // engine-tracked owner (see handleWorkflowAdd)
		// Non-admins only see workflows they own.
		if !canAccess(caller, admin, owner) {
			continue
		}
		info := WfInfo{Name: wfName, Owner: owner}
		if runs := h.wdir.ListRuns(wfName); len(runs) > 0 {
			info.LastRunStatus = runs[0].Status
			info.LastRunAt = runs[0].StartedAt
		}
		workflows = append(workflows, info)
	}
	return Response{Status: "ok", Data: workflows}
}

func (h *TaskHandler) handleWorkflowRm(req Request) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	h.svc.CancelByWorkflow(req.Workflow)
	h.svc.Registry().Remove(req.Workflow)
	appName := workflowAppPrefix + req.Workflow
	if _, err := h.client.DeleteApp(appName); err != nil {
		return Response{Status: "error", Message: "failed to remove App: " + err.Error()}
	}
	wfDir := filepath.Join(h.wdir.BaseDir(), req.Workflow)
	if err := os.RemoveAll(wfDir); err != nil {
		logger.Error("failed to remove workflow dir: " + err.Error())
	}
	return Response{Status: "ok", Message: "workflow removed"}
}

func (h *TaskHandler) handleWorkflowInputs(req Request) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	yamlPath := filepath.Join(h.wdir.BaseDir(), req.Workflow, "workflow.yaml")
	wf, err := parser.LoadWorkflow(yamlPath)
	if err != nil {
		return Response{Status: "error", Message: "failed to parse workflow: " + err.Error()}
	}
	if wf.On != nil {
		if wf.On.Manual != nil && len(wf.On.Manual.Inputs) > 0 {
			return Response{Status: "ok", Data: wf.On.Manual.Inputs}
		}
		if wf.On.WorkflowCall != nil && len(wf.On.WorkflowCall.Inputs) > 0 {
			return Response{Status: "ok", Data: wf.On.WorkflowCall.Inputs}
		}
	}
	return Response{Status: "ok", Data: map[string]interface{}{}}
}

// --- Run Management ---

func (h *TaskHandler) handleRun(req Request, token, actor string) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	runID, runStatus, err := h.svc.TriggerManual(req.Workflow, req.Inputs, token, actor)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	return Response{Status: "ok", Message: runStatus, Data: map[string]string{"run_id": runID}}
}

func (h *TaskHandler) handleCancel(req Request) Response {
	if req.RunID == "" {
		return Response{Status: "error", Message: "run_id required"}
	}
	// If the client also names a workflow (CLI -w), verify it matches the run_id.
	if req.Workflow != "" {
		if actual := h.workflowOfRun(req.RunID); actual != "" && actual != req.Workflow {
			return Response{Status: "error", Message: fmt.Sprintf("run '%s' belongs to workflow '%s', not '%s'", req.RunID, actual, req.Workflow)}
		}
	}
	if err := h.svc.CancelByRunID(req.RunID); err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	return Response{Status: "ok", Message: "cancelled"}
}

func (h *TaskHandler) handleRerun(req Request, token, actor string) Response {
	if req.Workflow == "" || req.RunID == "" {
		return Response{Status: "error", Message: "workflow and run_id required"}
	}
	// Read inputs from runs.json first, fall back to checkpoint.
	var inputs map[string]string
	var found bool
	for _, r := range h.wdir.ListRuns(req.Workflow) {
		if r.RunID == req.RunID {
			found = true
			inputs = r.Inputs
			if len(inputs) == 0 {
				if rec := h.svc.Checkpoint().GetRunRecord(req.Workflow, req.RunID); rec != nil {
					inputs = rec.Inputs
				}
			}
			break
		}
	}
	if !found {
		return Response{Status: "error", Message: "run not found"}
	}
	runID, runStatus, err := h.svc.TriggerManual(req.Workflow, inputs, token, actor)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	return Response{Status: "ok", Message: runStatus, Data: map[string]string{"run_id": runID}}
}

// --- Observability ---

func (h *TaskHandler) handleRuns(req Request) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	runs := h.wdir.ListRuns(req.Workflow)
	if runs == nil {
		runs = []workdir.RunIndex{}
	}
	return Response{Status: "ok", Data: runs}
}

func (h *TaskHandler) handleRunDetail(req Request) Response {
	if req.Workflow == "" || req.RunID == "" {
		return Response{Status: "error", Message: "workflow and run_id required"}
	}

	// Try checkpoint first (running run).
	if rec := h.svc.Checkpoint().GetRunRecord(req.Workflow, req.RunID); rec != nil {
		return Response{Status: "ok", Data: rec}
	}

	// Fall back to runs.json for completed runs (basic info only).
	runs := h.wdir.ListRuns(req.Workflow)
	for _, r := range runs {
		if r.RunID == req.RunID {
			return Response{Status: "ok", Data: r}
		}
	}
	return Response{Status: "error", Message: "run not found"}
}

func (h *TaskHandler) handleLog(req Request) Response {
	if req.Workflow == "" || req.RunID == "" {
		return Response{Status: "error", Message: "workflow and run_id required"}
	}
	path := h.wdir.FlowLogPath(req.Workflow, req.RunID)
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Response{Status: "error", Message: "log not found"}
		}
		return Response{Status: "error", Message: "failed to read log: " + err.Error()}
	}
	return Response{Status: "ok", Data: string(content)}
}

func (h *TaskHandler) handleStepLog(req Request) Response {
	if req.Workflow == "" || req.RunID == "" || req.Job == "" || req.Step == "" {
		return Response{Status: "error", Message: "workflow, run_id, job, step required"}
	}
	content := h.wdir.ReadStepLog(req.Workflow, req.RunID, req.Job, req.Step)
	if content == "" {
		return Response{Status: "error", Message: "step log not found"}
	}
	return Response{Status: "ok", Data: content}
}

// Close closes the server-side TCP connection used for fetch_task / send_task_result.
func (h *TaskHandler) Close() {
	h.server.CloseConnection()
}
