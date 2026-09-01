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
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
	// Token is the caller's Dex access token. The Engine verifies it and resolves a
	// stable Principal for owner authorization; a manual run keeps it in memory only
	// as the forward_token identity for message steps (the run itself executes under
	// a renewed Engine capability). It is stripped immediately after authentication
	// and is never persisted or logged.
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
	svc           *trigger.Service
	wdir          *workdir.Manager
	client        *appmesh.AppMeshClient // narrow Workflow control capability (registry/event only)
	server        *appmesh.WorkerTCPContext
	principalHTTP *http.Client
	engineURL     string
	engineOption  appmesh.Option
}

type callerPrincipal struct {
	PrincipalID string   `json:"principal_id"`
	Permissions []string `json:"permissions"`
}

// NewTaskHandler creates a Task RPC handler.
func NewTaskHandler(svc *trigger.Service, wdir *workdir.Manager, client *appmesh.AppMeshClient, opts appmesh.Option) (*TaskHandler, error) {
	server, err := appmesh.NewTCPContext(opts)
	if err != nil {
		return nil, fmt.Errorf("create task context: %w", err)
	}
	principalHTTP, engineURL, err := newPrincipalHTTPClient()
	if err != nil {
		server.CloseConnection()
		return nil, err
	}
	return &TaskHandler{svc: svc, wdir: wdir, client: client, server: server, principalHTTP: principalHTTP, engineURL: engineURL, engineOption: opts}, nil
}

func newPrincipalHTTPClient() (*http.Client, string, error) {
	engineURL := strings.TrimRight(os.Getenv("APPMESH_ENGINE_URL"), "/")
	if engineURL == "" {
		engineURL = "https://127.0.0.1:6060"
	}
	parsed, err := url.Parse(engineURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, "", fmt.Errorf("APPMESH_ENGINE_URL must be an absolute HTTP(S) URL")
	}
	verify := !strings.EqualFold(os.Getenv("APPMESH_ENGINE_TLS_VERIFY"), "false") && os.Getenv("APPMESH_ENGINE_TLS_VERIFY") != "0"
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verify}
	if caPath := os.Getenv("APPMESH_CA"); caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, "", fmt.Errorf("read App Mesh CA: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(pem) {
			return nil, "", fmt.Errorf("App Mesh CA file contains no certificates")
		}
		tlsConfig.RootCAs = roots
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig}, Timeout: 15 * time.Second}, engineURL, nil
}

// Run starts the fetch_task/send_task_result loop. Blocks forever, except when the
// daemon reports this engine instance superseded (HTTP 412) or permanently rejects
// the worker request (HTTP 400) — then the process exits.
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
			if errors.Is(err, appmesh.ErrWorkerRejected) {
				logger.Error("fetch_task permanently rejected, exiting: " + err.Error())
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
	// never logged or persisted. The token travels on to handleRun/handleRerun ->
	// TriggerManual only for shared-Dex cross-node forwarding and explicit
	// forward_token message identity; local steps execute under a renewed
	// Engine-issued capability.
	token := req.Token
	req.Token = ""
	caller, err := h.authenticate(token)
	if err != nil {
		return Response{Status: "error", Message: "authentication failed: " + err.Error()}
	}
	admin := caller.hasPermission("workflow-admin")
	callerID := caller.PrincipalID

	for field, value := range map[string]string{
		"workflow": req.Workflow, "run_id": req.RunID,
		"job": req.Job, "step": req.Step,
	} {
		if value != "" && !safeID.MatchString(value) {
			return Response{Status: "error", Message: fmt.Sprintf("%s %q contains invalid characters", field, value)}
		}
	}

	if msg := h.authorize(callerID, admin, req); msg != "" {
		return Response{Status: "error", Message: msg}
	}

	switch req.Action {
	// Workflow CRUD
	case "workflow_add":
		return h.handleWorkflowAdd(req, token, callerID, admin)
	case "workflow_get":
		return h.handleWorkflowGet(req)
	case "workflow_list":
		return h.handleWorkflowList(req, callerID, admin)
	case "workflow_rm":
		return h.handleWorkflowRm(req, token)
	case "workflow_inputs":
		return h.handleWorkflowInputs(req)
	// Run management
	case "run":
		return h.handleRun(req, token, callerID)
	case "cancel":
		return h.handleCancel(req)
	case "rerun":
		return h.handleRerun(req, token, callerID)
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

// authenticate asks the Engine to validate the Dex bearer and return its immutable
// Principal and effective authorization. The workflow process never decodes claims as
// an authority and never calls an Engine-local login endpoint.
func (h *TaskHandler) authenticate(token string) (callerPrincipal, error) {
	if token == "" {
		return callerPrincipal{}, fmt.Errorf("Dex access token required")
	}
	req, err := http.NewRequest(http.MethodGet, h.engineURL+"/appmesh/principal/self", nil)
	if err != nil {
		return callerPrincipal{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := h.principalHTTP.Do(req)
	if err != nil {
		return callerPrincipal{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return callerPrincipal{}, fmt.Errorf("Engine rejected Dex bearer with HTTP %d", resp.StatusCode)
	}
	var principal callerPrincipal
	if err := json.NewDecoder(resp.Body).Decode(&principal); err != nil {
		return callerPrincipal{}, fmt.Errorf("decode Engine Principal response: %w", err)
	}
	if principal.PrincipalID == "" {
		return callerPrincipal{}, fmt.Errorf("Engine Principal response omitted principal_id")
	}
	return principal, nil
}

func (p callerPrincipal) hasPermission(permission string) bool {
	for _, granted := range p.Permissions {
		if granted == permission {
			return true
		}
	}
	return false
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
	case "workflow_rm":
		if !h.workflowExists(req.Workflow) {
			return "" // unknown workflow; the handler reports not-found
		}
		if !canAccess(caller, admin, h.ownerOf(req.Workflow)) {
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

// workflowExists reports whether the workflow definition is present on disk —
// the same source of truth handleWorkflowGet reads for its not-found answer.
func (h *TaskHandler) workflowExists(wfName string) bool {
	if wfName == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(h.wdir.BaseDir(), wfName, "workflow.yaml"))
	return err == nil
}

// --- Workflow CRUD ---

func (h *TaskHandler) handleWorkflowAdd(req Request, callerToken, caller string, admin bool) Response {
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
	// An automatic trigger has no user bearer and therefore executes under an
	// Engine-issued run capability bound to this owner. Only workflow administrators
	// may authorize that delegation by registering such a definition.
	if wf.On != nil && (wf.On.AppEvent != nil || len(wf.On.Schedule) != 0) && !admin {
		return Response{Status: "error", Message: "workflow-admin permission is required to register automatic triggers"}
	}

	// Register the daemon App FIRST. If it succeeds, we then write the YAML.
	// This order avoids orphan YAML on crash between write and AddApp.
	yamlPath := filepath.Join(h.wdir.BaseDir(), wf.Name, "workflow.yaml")
	appName := workflowAppPrefix + req.Workflow
	trueCmd := "true"
	// The daemon derives owner_principal_id from this caller-authenticated request.
	// Workflow also keeps the same immutable Principal ID in metadata so its narrow
	// registry and per-workflow authorization do not depend on a client-supplied App
	// ownership field.
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
		Status:   false, // disabled
		Metadata: &metadata,
	}
	if wf.Permission != 0 {
		app.Permission = &wf.Permission
	}
	callerClient, err := h.newCallerClient(callerToken)
	if err != nil {
		return Response{Status: "error", Message: "failed to create caller Engine client: " + err.Error()}
	}
	defer callerClient.CloseConnection()
	if _, err := callerClient.AddApp(app); err != nil {
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
		callerClient.DeleteApp(appName)
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
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	apps, err := h.client.ListWorkflowRegistryContext(ctx)
	if err != nil {
		return Response{Status: "error", Message: "failed to list workflow registry: " + err.Error()}
	}

	type WfInfo struct {
		Name             string `json:"name"`
		Owner            string `json:"owner"`
		OwnerDisplayName string `json:"owner_display_name,omitempty"`
		LastRunStatus    string `json:"last_run_status,omitempty"`
		LastRunAt        string `json:"last_run_at,omitempty"`
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
		ownerDisplayName := ""
		// The label is valid only for the same immutable owner recorded in
		// Workflow metadata. A mismatched/stale registration falls back to the ID.
		if app.OwnerPrincipalID != nil && *app.OwnerPrincipalID == owner && app.OwnerDisplayName != nil {
			ownerDisplayName = *app.OwnerDisplayName
		}
		info := WfInfo{Name: wfName, Owner: owner, OwnerDisplayName: ownerDisplayName}
		if runs := h.wdir.ListRuns(wfName); len(runs) > 0 {
			info.LastRunStatus = runs[0].Status
			info.LastRunAt = runs[0].StartedAt
		}
		workflows = append(workflows, info)
	}
	return Response{Status: "ok", Data: workflows}
}

func (h *TaskHandler) handleWorkflowRm(req Request, callerToken string) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	if !h.workflowExists(req.Workflow) {
		return Response{Status: "error", Message: "workflow not found"}
	}
	h.svc.CancelByWorkflow(req.Workflow)
	h.svc.Registry().Remove(req.Workflow)
	appName := workflowAppPrefix + req.Workflow
	callerClient, err := h.newCallerClient(callerToken)
	if err != nil {
		return Response{Status: "error", Message: "failed to create caller Engine client: " + err.Error()}
	}
	defer callerClient.CloseConnection()
	if _, err := callerClient.DeleteApp(appName); err != nil {
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

// newCallerClient keeps workflow-definition mutations under the authenticated
// human Principal. The Workflow control capability cannot register or delete
// definitions and is never upgraded to a general system identity.
func (h *TaskHandler) newCallerClient(token string) (*appmesh.AppMeshClientTCP, error) {
	if token == "" {
		return nil, fmt.Errorf("caller Dex bearer is required")
	}
	option := h.engineOption
	option.JwtToken = token
	return appmesh.NewTCPClient(option)
}

// Close closes the server-side TCP connection used for fetch_task / send_task_result.
func (h *TaskHandler) Close() {
	h.server.CloseConnection()
}
