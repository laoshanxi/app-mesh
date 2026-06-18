// Package api implements the model-env App's Task RPC handler.
//
// The model-env process runs a task_fetch/task_return loop (same shape as the
// workflow engine) to serve agent sessions. The same handler runs in two
// admin-provisioned Apps (model-env registers nothing itself):
//
//   - the shared per-tenant App: serves Scenario A (DAG/batch, non-streaming)
//     sessions in-process.
//   - a worker App (workerSessionID set, started with --session-worker): serves
//     exactly one Scenario B session, streams tokens to its own (clean,
//     per-session) stdout, and exits on close / idle / max-lifetime. Register it
//     with behavior exit=remove so the daemon removes it on any exit.
//
// Authorization mirrors the workflow engine (ADR 0006): L1 is the daemon's
// app-run-task gate; L2 is enforced here (session owner == caller || admin); L3
// is the caller's own token running tool Apps. model-env holds no daemon
// credentials: the task RPC uses APP_MESH_PROCESS_KEY; everything else uses the
// caller's token from the request payload.
//
// Actions: session_open, session_send, session_close.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/agent"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/budget"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/session"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/tools"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// Request is the JSON payload sent via run_task.
type Request struct {
	Action    string `json:"action"`
	Token     string `json:"token,omitempty"`      // caller JWT (authn + tool execution)
	SessionID string `json:"session_id,omitempty"` // target session (send/close)
	Input     string `json:"input,omitempty"`      // user message (send)
	Stream    bool   `json:"stream,omitempty"`     // stream tokens to stdout (worker only)
	// Per-turn limit requests; may only lower the operator ceiling.
	MaxIterations int `json:"max_iterations,omitempty"`
	MaxTokens     int `json:"max_tokens,omitempty"`
}

// Response is the JSON returned via task_return.
type Response struct {
	Status  string      `json:"status"` // "ok" or "error"
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// TaskHandler runs the task_fetch/task_return loop and dispatches session actions.
type TaskHandler struct {
	server      *appmesh.AppMeshServerTcpContext
	store       *session.Store
	ledger      budget.TenantLedger
	ceiling     budget.TurnLimits
	backend     llm.Backend
	serverURI   string
	tenant      string
	toolTimeout int // RunTask timeout (seconds) for tool invocations
	admins      map[string]bool

	// Worker role (zero on the shared App): when workerSessionID is set this
	// handler serves exactly that one session and exits on close / reap.
	workerSessionID string
	idleTTL         time.Duration
	maxLifetime     time.Duration

	// workspace is the root for per-session tool scratch dirs (sessionWorkdir).
	workspace string

	// Worker lifecycle state.
	mu         sync.Mutex
	lastActive time.Time
	createdAt  time.Time
	inflight   int  // turns currently running; the reaper never exits while > 0
	exit       bool // set after an explicit close; Run() returns after acking it

	// Seams (injected by NewTaskHandler with real defaults; overridden in tests).
	// authFn validates a caller token and returns the verified username.
	authFn func(token string) (string, error)
	// toolsFn builds a caller-scoped, session-scoped tool provider plus a cleanup func.
	toolsFn func(token, sessionID string) (agent.ToolProvider, func(), error)
}

// Config configures a TaskHandler.
type Config struct {
	Store       *session.Store
	Ledger      budget.TenantLedger
	Ceiling     budget.TurnLimits
	Backend     llm.Backend
	ServerURI   string
	Tenant      string
	ToolTimeout int            // RunTask timeout (seconds) for tools; <=0 → 300
	Opts        appmesh.Option // for the server-side task context

	// Workspace is the root for per-session tool scratch dirs.
	Workspace string

	// Worker role (set only when running as a session worker).
	WorkerSessionID string
	IdleTTL         time.Duration
	MaxLifetime     time.Duration
}

// NewTaskHandler creates a session Task RPC handler.
func NewTaskHandler(cfg Config) (*TaskHandler, error) {
	server, err := appmesh.NewTCPContext(cfg.Opts)
	if err != nil {
		return nil, fmt.Errorf("create task context: %w", err)
	}
	now := time.Now()
	h := &TaskHandler{
		server:          server,
		store:           cfg.Store,
		ledger:          cfg.Ledger,
		ceiling:         cfg.Ceiling,
		backend:         cfg.Backend,
		serverURI:       cfg.ServerURI,
		tenant:          cfg.Tenant,
		toolTimeout:     cfg.ToolTimeout,
		admins:          parseAdmins(),
		workspace:       cfg.Workspace,
		workerSessionID: cfg.WorkerSessionID,
		idleTTL:         cfg.IdleTTL,
		maxLifetime:     cfg.MaxLifetime,
		lastActive:      now,
		createdAt:       now,
	}
	h.authFn = h.authenticate
	h.toolsFn = h.defaultTools
	return h, nil
}

// sanitizeName reduces a string to [A-Za-z0-9_-] so it is safe as a path component.
func sanitizeName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// callerClient builds a daemon client carrying the caller's token. model-env holds
// no credentials of its own — every daemon operation (token validation, tools,
// worker registration) runs under the caller's identity. cleanup closes it.
func (h *TaskHandler) callerClient(token string) (*appmesh.AppMeshClient, func(), error) {
	noVerify := ""
	c, err := appmesh.NewTCPClient(appmesh.Option{
		AppMeshUri:   h.serverURI,
		JwtToken:     token,
		SslTrustedCA: &noVerify,
	})
	if err != nil {
		return nil, func() {}, err
	}
	c.EnableConcurrency()
	return c.AppMeshClient, func() { c.CloseConnection() }, nil
}

// defaultTools builds a caller- and session-scoped tool catalog so tools execute
// under the caller's identity (L3) and can scope per-session side effects.
func (h *TaskHandler) defaultTools(token, sessionID string) (agent.ToolProvider, func(), error) {
	c, cleanup, err := h.callerClient(token)
	if err != nil {
		return nil, func() {}, err
	}
	return tools.NewCatalog(c, h.toolTimeout, sessionID, h.sessionWorkdir(sessionID)), cleanup, nil
}

// sessionWorkdir returns an absolute per-session scratch dir injected into tool
// calls so a file-writing tool can isolate its output (tools are separate Apps, so
// this is the only way to scope their files). Best-effort: "" if unavailable.
func (h *TaskHandler) sessionWorkdir(sessionID string) string {
	if h.workspace == "" {
		return ""
	}
	dir := filepath.Join(h.workspace, sanitizeName(h.tenant), sanitizeName(sessionID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		log.Printf("session workdir %q: %v (tools run without an injected workdir)", dir, err)
		return ""
	}
	return dir
}

// Close releases the task context.
func (h *TaskHandler) Close() { /* server context has no explicit close today */ }

// StartReaper (worker only) exits the process once the session has been idle
// longer than idleTTL or has outlived maxLifetime. Exiting triggers the App's
// behavior exit=remove, so the daemon removes the worker registration. No-op on
// the shared App or when both limits are disabled.
func (h *TaskHandler) StartReaper(ctx context.Context) {
	if h.workerSessionID == "" || (h.idleTTL <= 0 && h.maxLifetime <= 0) {
		return
	}
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				h.mu.Lock()
				// Never reap mid-turn: an in-flight turn must finish (and ack the
				// client) before the process exits.
				busy := h.inflight > 0
				idle := !busy && h.idleTTL > 0 && time.Since(h.lastActive) > h.idleTTL
				old := !busy && h.maxLifetime > 0 && time.Since(h.createdAt) > h.maxLifetime
				h.mu.Unlock()
				if idle || old {
					reason := "idle"
					if old {
						reason = "max-lifetime"
					}
					// Drop the session's on-disk history before exiting (close does the same).
					h.cleanupSession()
					log.Printf("session worker %s reaping (%s) — exiting; daemon removes the App", h.workerSessionID, reason)
					os.Exit(0)
				}
			}
		}
	}()
}

// Run starts the task_fetch/task_return loop. Blocks until a worker is asked to
// exit (explicit session_close); the shared App loops forever.
func (h *TaskHandler) Run() {
	if h.workerSessionID != "" {
		log.Printf("model-env session worker started — serving session %s", h.workerSessionID)
	} else {
		log.Println("model-env shared App started — accepting sessions via run_task")
	}
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		payload, err := h.server.TaskFetch()
		if err != nil {
			log.Printf("task_fetch error: %v", err)
			time.Sleep(backoff)
			if backoff *= 2; backoff > maxBackoff {
				backoff = maxBackoff
			}
			continue
		}
		backoff = time.Second

		// Mark the whole request in-flight (not just the agent turn) so the reaper
		// won't exit while a request is being serviced, and stamp the idle clock.
		// (A sub-microsecond window between fetch and this call remains; an idle
		// reaper firing exactly there is harmless — the client retries.)
		h.beginTurn()
		resp := h.dispatch(payload)
		data, err := json.Marshal(resp)
		if err != nil {
			data = []byte(`{"status":"error","message":"internal marshal error"}`)
		}
		if err := h.server.TaskReturn(string(data)); err != nil {
			log.Printf("task_return error: %v", err)
		}
		h.endTurn()

		// A worker that has acked an explicit close exits here; the daemon then
		// removes the App (behavior exit=remove).
		h.mu.Lock()
		exit := h.exit
		h.mu.Unlock()
		if exit {
			log.Printf("session worker %s closed — exiting", h.workerSessionID)
			return
		}
	}
}

func errResp(msg string) Response { return Response{Status: "error", Message: msg} }
func okResp(data interface{}) Response {
	return Response{Status: "ok", Data: data}
}

func (h *TaskHandler) dispatch(payload string) Response {
	var req Request
	if err := json.Unmarshal([]byte(payload), &req); err != nil {
		return errResp("invalid request JSON: " + err.Error())
	}

	caller, err := h.authFn(req.Token)
	if err != nil {
		return errResp("authentication failed: " + err.Error())
	}
	token := req.Token
	req.Token = "" // strip immediately; never persist/log the token

	switch req.Action {
	case "session_open":
		return h.handleOpen(caller)
	case "session_send":
		return h.handleSend(req, caller, token)
	case "session_close":
		return h.handleClose(req, caller)
	default:
		return errResp("unknown action: " + req.Action)
	}
}

func (h *TaskHandler) handleOpen(caller string) Response {
	if h.workerSessionID != "" {
		return errResp("session worker serves its single pre-assigned session; send to it directly")
	}
	// Scenario A: in-process session on the shared model-env App. (Scenario B uses an
	// admin-provisioned worker App and is addressed directly, not opened here.)
	sess, err := h.store.Open(caller, h.tenant)
	if err != nil {
		return errResp("open session: " + err.Error())
	}
	return okResp(map[string]string{"session_id": sess.ID})
}

func (h *TaskHandler) handleClose(req Request, caller string) Response {
	if req.SessionID == "" {
		return errResp("session_id required")
	}
	if err := h.store.Close(req.SessionID, caller, h.isAdmin(caller)); err != nil {
		return mapStoreErr(err)
	}
	// A worker closing its only session exits after acking (Run() handles it).
	if h.workerSessionID != "" {
		h.mu.Lock()
		h.exit = true
		h.mu.Unlock()
	}
	return okResp(nil)
}

func (h *TaskHandler) handleSend(req Request, caller, token string) Response {
	if req.SessionID == "" {
		return errResp("session_id required")
	}
	if h.workerSessionID != "" {
		if req.SessionID != h.workerSessionID {
			return errResp("session not found")
		}
	} else if req.Stream {
		// Streaming is a worker-only feature; the shared App has no clean per-session
		// stdout. Fail loud rather than silently return a non-streamed result.
		return errResp("streaming is only available on a session worker App (an admin-provisioned model-env --session-worker); the shared App does not stream")
	}
	sess, err := h.store.Get(req.SessionID, caller, h.isAdmin(caller))
	if err != nil {
		return mapStoreErr(err)
	}

	// Per-tenant hard quota (checked before spending more).
	if err := h.ledger.CheckTenant(h.tenant); err != nil {
		return Response{Status: "error", Message: "budget_exceeded",
			Data: map[string]int{"tenant_used": h.ledger.Used(h.tenant)}}
	}

	// Build a caller-scoped, session-scoped tool provider so tools run under the
	// caller's identity (L3) and can isolate per-session side effects.
	catalog, cleanup, err := h.toolsFn(token, sess.ID)
	if err != nil {
		return errResp("caller client: " + err.Error())
	}
	defer cleanup()

	limits := h.ceiling.Clamp(budget.TurnLimits{MaxIterations: req.MaxIterations, MaxTokens: req.MaxTokens})

	// Worker only: tokens go to the worker's own stdout, a clean per-session stream.
	var stream llm.StreamFunc
	if req.Stream && h.workerSessionID != "" {
		stream = func(chunk string) { fmt.Print(chunk) }
	}

	ctx := agent.WithInput(context.Background(), req.Input)

	sess.Lock()
	res, runErr := agent.RunTurn(ctx, h.backend, sess, catalog, limits, stream)
	// Persist regardless of outcome: partial history must survive (design contract).
	_ = h.store.Persist(sess)
	sess.Unlock()

	if res != nil {
		h.ledger.Add(h.tenant, res.TurnTokens)
	}

	if runErr != nil {
		if errors.Is(runErr, budget.ErrBudgetExceeded) && res != nil {
			return Response{Status: "error", Message: "budget_exceeded", Data: map[string]interface{}{
				"iterations":  res.Iterations,
				"turn_tokens": res.TurnTokens,
				"max_tokens":  limits.MaxTokens,
				"max_rounds":  limits.MaxIterations,
			}}
		}
		return errResp(runErr.Error())
	}

	return okResp(map[string]interface{}{
		"answer":      res.Answer,
		"iterations":  res.Iterations,
		"turn_tokens": res.TurnTokens,
		"cost_tokens": sess.CostTokens,
	})
}

// beginTurn marks a request in-flight (so the reaper won't exit between fetch and
// ack) and stamps activity; endTurn clears it and re-stamps on completion.
func (h *TaskHandler) beginTurn() {
	h.mu.Lock()
	h.inflight++
	h.lastActive = time.Now()
	h.mu.Unlock()
}

func (h *TaskHandler) endTurn() {
	h.mu.Lock()
	h.inflight--
	h.lastActive = time.Now()
	h.mu.Unlock()
}

// cleanupSession removes the worker's session and its on-disk history (admin
// bypass: the worker acting on its own session during reap).
func (h *TaskHandler) cleanupSession() {
	if h.workerSessionID != "" {
		_ = h.store.Close(h.workerSessionID, "", true)
	}
}

// --- authz (mirrors workflow engine ADR 0006) ---

func (h *TaskHandler) authenticate(token string) (string, error) {
	if token == "" {
		return "", fmt.Errorf("token required")
	}
	// Validate by using the token: a self lookup succeeds only for an authentic,
	// unexpired token (the daemon verifies the signature). model-env keeps no
	// credentials of its own to validate with.
	c, cleanup, err := h.callerClient(token)
	if err != nil {
		return "", err
	}
	defer cleanup()
	if _, err := c.GetCurrentUser(); err != nil {
		return "", fmt.Errorf("invalid or expired token: %w", err)
	}
	user := usernameFromJWT(token) // trustworthy now that the token is verified
	if user == "" {
		return "", fmt.Errorf("token has no subject")
	}
	return user, nil
}

func (h *TaskHandler) isAdmin(caller string) bool { return h.admins[caller] }

func mapStoreErr(err error) Response {
	switch {
	case errors.Is(err, session.ErrNotFound):
		return errResp("session not found")
	case errors.Is(err, session.ErrForbidden):
		return errResp("permission denied: not the session owner")
	default:
		return errResp(err.Error())
	}
}

// parseAdmins reads the admin username set from APPMESH_WORKFLOW_ADMINS
// (comma-separated; default {"admin"}), reusing the workflow engine's env var so
// operators configure admins once.
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

// usernameFromJWT extracts the username from a JWT (already validated in
// authenticate). It mirrors the daemon's claim priority — preferred_username,
// then username, then sub — so the identity matches across security backends:
// for Keycloak/OAuth2 `sub` is an opaque id, not the username.
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
		PreferredUsername string `json:"preferred_username"`
		Username          string `json:"username"`
		Sub               string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return ""
	}
	switch {
	case claims.PreferredUsername != "":
		return claims.PreferredUsername
	case claims.Username != "":
		return claims.Username
	default:
		return claims.Sub
	}
}
