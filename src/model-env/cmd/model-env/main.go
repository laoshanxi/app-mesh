// model-env is the App Mesh LLM model-environment App.
//
// It runs in one of two roles, both built from this same binary and each
// provisioned by an admin as an ordinary App (model-env registers nothing itself):
//
//   - default (one per tenant): serves Scenario A (DAG/batch, non-streaming)
//     sessions in-process via the Task API.
//   - --session-worker (one per interactive session): serves exactly one Scenario B
//     session, streams tokens to its own stdout, and exits on close / idle /
//     max-lifetime (register it with behavior exit=remove so the daemon removes it).
//
// model-env holds NO daemon credentials: the task RPC authenticates with the
// daemon-injected APP_MESH_PROCESS_KEY, and every other daemon call (token
// validation, tools) runs under the CALLER's token from the request payload —
// which also decides identity (the workflow engine forwards the invoker's token in
// Scenario A; a client sends its own in Scenario B). See LLMAgentWorkflowDesign.md.
//
// Configuration (env):
//
//	APPMESH_TENANT             — tenant namespace for this App (default: "default")
//	APPMESH_SESSION_OWNER      — (worker only) session owner
//	APPMESH_WORKFLOW_ADMINS    — comma-separated admins (may access any session; default: "admin")
//	MODELENV_BACKEND           — LLM backend name (default: "stub")
//	MODELENV_SESSION_DIR       — session persistence dir (default: "./sessions")
//	MODELENV_LEDGER_DIR        — shared per-tenant token ledger dir (default: MODELENV_SESSION_DIR)
//	MODELENV_SESSION_TTL_HOURS — Scenario A session TTL hours, 0 = no reap (default: 168)
//	MODELENV_WORKSPACE_DIR     — root for per-session tool scratch dirs (default: "./model-env-workspace")
//	MODELENV_SESSION_IDLE_MINUTES — worker idle reap minutes, 0 = disabled (default: 30)
//	MODELENV_SESSION_MAX_HOURS    — worker absolute lifetime cap, 0 = disabled (default: 8)
//	MODELENV_MAX_ITERATIONS    — per-turn tool-call ceiling (default: 8)
//	MODELENV_MAX_TOKENS        — per-turn token ceiling, 0 = unlimited (default: 0)
//	MODELENV_MAX_OUTPUT_TOKENS — provider API output cap per call (default: 8192)
//	MODELENV_TOOL_TIMEOUT      — per tool-call RunTask timeout seconds (default: 300)
//	MODELENV_TENANT_QUOTA      — per-tenant token quota, 0 = unlimited (default: 0)
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/api"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/budget"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	"github.com/laoshanxi/app-mesh/src/model-env/internal/session"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// buildTag is stamped at link time via -ldflags "-X main.buildTag=...".
var buildTag string

func main() {
	var server, sessionID string
	var sessionWorker, version bool
	flag.StringVar(&server, "server", "127.0.0.1:6059", "App Mesh TCP server address (host:port)")
	flag.BoolVar(&sessionWorker, "session-worker", false, "run as a single-session interactive worker (Scenario B)")
	flag.StringVar(&sessionID, "session-id", "", "worker: the session id this worker serves")
	flag.BoolVar(&version, "version", false, "print build tag and exit")
	flag.Parse()

	if version {
		fmt.Println("model-env", buildTag)
		return
	}
	fmt.Fprintf(os.Stderr, "model-env starting (build %s)\n", buildTag)

	tenant := envOr("APPMESH_TENANT", "default")

	backend, err := llm.NewBackend(os.Getenv("MODELENV_BACKEND"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Backend init failed: %v\n", err)
		os.Exit(1)
	}

	quota := map[string]int{}
	if q := envInt("MODELENV_TENANT_QUOTA", 0); q > 0 {
		quota[tenant] = q
	}
	// Absolute, so the shared App and all workers pointed here share one per-tenant
	// counter regardless of cwd.
	ledgerDir, err := filepath.Abs(envOr("MODELENV_LEDGER_DIR", envOr("MODELENV_SESSION_DIR", "./sessions")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot resolve ledger dir: %v\n", err)
		os.Exit(1)
	}
	ledger, err := budget.NewFileLedger(ledgerDir, quota)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ledger init failed: %v\n", err)
		os.Exit(1)
	}

	ceiling := budget.TurnLimits{
		MaxIterations: envInt("MODELENV_MAX_ITERATIONS", 8),
		MaxTokens:     envInt("MODELENV_MAX_TOKENS", 0),
	}

	// model-env holds no credentials: the task RPC authenticates via the
	// daemon-injected APP_MESH_PROCESS_KEY, and every other daemon call runs under
	// the caller's token from the request payload. So no login here.
	noVerify := ""
	opts := appmesh.Option{
		AppMeshUri:   server,
		SslTrustedCA: &noVerify,
	}

	if sessionWorker {
		runWorker(server, sessionID, tenant, backend, ledger, ceiling, opts)
		return
	}
	runSharedApp(server, tenant, backend, ledger, ceiling, opts)
}

// workspaceDir resolves the per-session tool scratch root to an absolute path so a
// tool App (a separate process) and model-env agree on it.
func workspaceDir() string {
	dir, err := filepath.Abs(envOr("MODELENV_WORKSPACE_DIR", "./model-env-workspace"))
	if err != nil {
		return envOr("MODELENV_WORKSPACE_DIR", "./model-env-workspace")
	}
	return dir
}

// runSharedApp is the per-tenant App serving Scenario A (in-process) sessions.
// (Scenario B uses admin-provisioned worker Apps, addressed directly.)
func runSharedApp(server, tenant string, backend llm.Backend, ledger budget.TenantLedger, ceiling budget.TurnLimits, opts appmesh.Option) {
	ttl := time.Duration(envInt("MODELENV_SESSION_TTL_HOURS", 168)) * time.Hour
	store, err := session.NewStore(envOr("MODELENV_SESSION_DIR", "./sessions"), ttl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Session store init failed: %v\n", err)
		os.Exit(1)
	}

	handler, err := api.NewTaskHandler(api.Config{
		Store:       store,
		Ledger:      ledger,
		Ceiling:     ceiling,
		Backend:     backend,
		ServerURI:   server,
		Tenant:      tenant,
		ToolTimeout: envInt("MODELENV_TOOL_TIMEOUT", 300),
		Workspace:   workspaceDir(),
		Opts:        opts,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Task handler init failed: %v\n", err)
		os.Exit(1)
	}
	defer handler.Close()
	go handler.Run()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if ttl > 0 {
		go reapLoop(ctx, store)
	}

	waitForSignal()
}

// runWorker serves one interactive session (Scenario B), then exits when the
// session is closed or reaped. The worker App is provisioned by an admin.
func runWorker(server, sessionID, tenant string, backend llm.Backend, ledger budget.TenantLedger, ceiling budget.TurnLimits, opts appmesh.Option) {
	if sessionID == "" {
		fmt.Fprintln(os.Stderr, "Worker mode requires --session-id")
		os.Exit(1)
	}
	owner := os.Getenv("APPMESH_SESSION_OWNER")
	if owner == "" {
		fmt.Fprintln(os.Stderr, "Worker mode requires APPMESH_SESSION_OWNER (the session owner)")
		os.Exit(1)
	}

	// Idle TTL + absolute lifetime are disabled with 0 (handler reaper no-ops).
	idle := time.Duration(envInt("MODELENV_SESSION_IDLE_MINUTES", 30)) * time.Minute
	maxLife := time.Duration(envInt("MODELENV_SESSION_MAX_HOURS", 8)) * time.Hour

	// TTL=0: the worker's lifetime is the session's, governed by the reaper below.
	store, err := session.NewStore(envOr("MODELENV_SESSION_DIR", "./sessions"), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Session store init failed: %v\n", err)
		os.Exit(1)
	}
	// Materialize (or recover) the single session this worker owns.
	if _, err := store.Create(sessionID, owner, tenant); err != nil {
		fmt.Fprintf(os.Stderr, "Session create failed: %v\n", err)
		os.Exit(1)
	}

	handler, err := api.NewTaskHandler(api.Config{
		Store:           store,
		Ledger:          ledger,
		Ceiling:         ceiling,
		Backend:         backend,
		ServerURI:       server,
		Tenant:          tenant,
		ToolTimeout:     envInt("MODELENV_TOOL_TIMEOUT", 300),
		Workspace:       workspaceDir(),
		Opts:            opts,
		WorkerSessionID: sessionID,
		IdleTTL:         idle,
		MaxLifetime:     maxLife,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "Task handler init failed: %v\n", err)
		os.Exit(1)
	}
	defer handler.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handler.StartReaper(ctx)

	// Run blocks until the session is closed; then the process exits and the
	// daemon removes the worker App.
	handler.Run()
}

func waitForSignal() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh
}

func reapLoop(ctx context.Context, store *session.Store) {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			store.Reap()
		}
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
