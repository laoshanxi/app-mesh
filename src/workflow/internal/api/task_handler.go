// Package api implements a Task API RPC handler for all workflow operations.
// The workflow engine process runs a task_fetch/task_return loop
// to receive requests from CLI/GUI via daemon's RunTask API.
//
// Protocol: client sends JSON payload via run_task("workflow", payload).
// Handler parses action, dispatches, and returns JSON response via task_return.
//
// 12 actions covering workflow CRUD + run management + observability:
//
//	workflow_add, workflow_get, workflow_list, workflow_rm,
//	workflow_inputs, run, cancel, rerun,
//	runs, run_detail, log, step_log
package api

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
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
}

// Response is the JSON returned via task_return.
type Response struct {
	Status  string      `json:"status"` // "ok" or "error"
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// TaskHandler runs the task_fetch/task_return loop.
type TaskHandler struct {
	svc    *trigger.Service
	wdir   *workdir.Manager
	client *appmesh.AppMeshClient // daemon client for CRUD operations (uses JWT)
	server *appmesh.AppMeshServerTcpContext
}

// NewTaskHandler creates a Task RPC handler.
func NewTaskHandler(svc *trigger.Service, wdir *workdir.Manager, client *appmesh.AppMeshClient, opts appmesh.Option) (*TaskHandler, error) {
	server, err := appmesh.NewTCPContext(opts)
	if err != nil {
		return nil, fmt.Errorf("create task context: %w", err)
	}
	return &TaskHandler{svc: svc, wdir: wdir, client: client, server: server}, nil
}

// Run starts the task_fetch/task_return loop. Blocks forever.
func (h *TaskHandler) Run() {
	logger.Info("TASK handler started — accepting RPC via run_task")
	for {
		payload, err := h.server.TaskFetch()
		if err != nil {
			logger.Error("task_fetch error: " + err.Error())
			continue
		}

		resp := h.dispatch(payload)

		data, err := json.Marshal(resp)
		if err != nil {
			logger.Error("response marshal error: " + err.Error())
			data = []byte(`{"status":"error","message":"internal marshal error"}`)
		}
		if err := h.server.TaskReturn(string(data)); err != nil {
			logger.Error("task_return error: " + err.Error())
		}
	}
}

func (h *TaskHandler) dispatch(payload string) Response {
	var req Request
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		return Response{Status: "error", Message: "invalid JSON: " + err.Error()}
	}

	for field, value := range map[string]string{
		"workflow": req.Workflow, "run_id": req.RunID,
		"job": req.Job, "step": req.Step,
	} {
		if value != "" && !safeID.MatchString(value) {
			return Response{Status: "error", Message: fmt.Sprintf("%s %q contains invalid characters", field, value)}
		}
	}

	switch req.Action {
	// Workflow CRUD
	case "workflow_add":
		return h.handleWorkflowAdd(req)
	case "workflow_get":
		return h.handleWorkflowGet(req)
	case "workflow_list":
		return h.handleWorkflowList(req)
	case "workflow_rm":
		return h.handleWorkflowRm(req)
	case "workflow_inputs":
		return h.handleWorkflowInputs(req)
	// Run management
	case "run":
		return h.handleRun(req)
	case "cancel":
		return h.handleCancel(req)
	case "rerun":
		return h.handleRerun(req)
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

// --- Workflow CRUD ---

func (h *TaskHandler) handleWorkflowAdd(req Request) Response {
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

	// Register the daemon App FIRST. If it succeeds, we then write the YAML.
	// This order avoids orphan YAML on crash between write and AddApp.
	yamlPath := filepath.Join(h.wdir.BaseDir(), wf.Name, "workflow.yaml")
	appName := workflowAppPrefix + req.Workflow
	trueCmd := "true"
	metaBytes, err := json.Marshal(map[string]string{"type": "workflow", "yaml_path": yamlPath})
	if err != nil {
		return Response{Status: "error", Message: "failed to marshal metadata: " + err.Error()}
	}
	metadata := json.RawMessage(metaBytes)
	app := appmesh.Application{
		Name:     appName,
		Command:  &trueCmd,
		Status:   0, // disabled
		Metadata: &metadata,
	}
	if wf.Owner != "" {
		app.Owner = &wf.Owner
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
		h.client.RemoveApp(appName)
		return Response{Status: "error", Message: err.Error()}
	}

	h.wdir.EnsureWorkflowDir(req.Workflow)
	h.svc.Registry().Update(req.Workflow, wf)
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

func (h *TaskHandler) handleWorkflowList(req Request) Response {
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
		owner := ""
		if app.Owner != nil {
			owner = *app.Owner
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
	if _, err := h.client.RemoveApp(appName); err != nil {
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

func (h *TaskHandler) handleRun(req Request) Response {
	if req.Workflow == "" {
		return Response{Status: "error", Message: "workflow name required"}
	}
	runID, runStatus, err := h.svc.TriggerManual(req.Workflow, req.Inputs)
	if err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	return Response{Status: "ok", Message: runStatus, Data: map[string]string{"run_id": runID}}
}

func (h *TaskHandler) handleCancel(req Request) Response {
	if req.RunID == "" {
		return Response{Status: "error", Message: "run_id required"}
	}
	if err := h.svc.CancelByRunID(req.RunID); err != nil {
		return Response{Status: "error", Message: err.Error()}
	}
	return Response{Status: "ok", Message: "cancelled"}
}

func (h *TaskHandler) handleRerun(req Request) Response {
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
	runID, runStatus, err := h.svc.TriggerManual(req.Workflow, inputs)
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

// Close closes the server-side TCP connection used for task_fetch / task_return.
func (h *TaskHandler) Close() {
	h.server.CloseConnection()
}
