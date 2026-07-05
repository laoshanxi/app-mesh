// wf-engine is the App Mesh Workflow Engine.
// It runs as a long-lived daemon App and handles all workflow operations
// via the App Mesh Task API (run_task).
//
// Authentication via sec_env (set on the workflow App definition):
//
//	APPMESH_USER     — login username (default: admin)
//	APPMESH_PASSWORD — login password
//	APPMESH_EXEC_IDENTITIES — optional JSON map {"user":"password", ...} of
//	                  execution identities a workflow may run as (ADR 0004).
//
// The daemon decrypts sec_env at rest and passes plain env vars to this process.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/api"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/trigger"
)

func main() {
	var (
		server       string
		clusterNodes string
	)
	flag.StringVar(&server, "server", "127.0.0.1:6059", "App Mesh TCP server address (host:port)")
	flag.StringVar(&clusterNodes, "cluster-nodes", "", "Comma-separated cluster node addresses")
	flag.Parse()

	user := os.Getenv("APPMESH_USER")
	if user == "" {
		user = "admin"
	}
	password := os.Getenv("APPMESH_PASSWORD")
	token := os.Getenv("APPMESH_JWT_TOKEN")

	if password == "" && token == "" {
		fmt.Fprintln(os.Stderr, "Authentication required."+
			"\n  Set APPMESH_PASSWORD via App sec_env (recommended):"+
			"\n    appm add -a workflow -z APPMESH_PASSWORD=<password>"+
			"\n  Or set APPMESH_JWT_TOKEN env var (fallback).")
		os.Exit(1)
	}

	tcpClient, err := newTCPClient(server, token)
	if err != nil {
		fmt.Fprintf(os.Stderr, "TCP client error: %v\n", err)
		os.Exit(1)
	}
	defer tcpClient.CloseConnection()

	// This single connection is shared by the scan loop, the task dispatch loop
	// (CRUD + auth checks), and step cleanup. Enable the demuxer so those goroutines
	// can't cross-wire each other's responses on the shared socket. (Previously this
	// happened only incidentally, once a step's WaitForAsyncRun subscribed.)
	tcpClient.EnableConcurrency()

	if password != "" {
		if _, err := tcpClient.Login(user, password, "", 86400, ""); err != nil {
			fmt.Fprintf(os.Stderr, "Login failed: %v\n", err)
			os.Exit(1)
		}
	}

	workflowDir, err := filepath.Abs(filepath.Join("..", "workflow"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to resolve workflow directory: %v\n", err)
		os.Exit(1)
	}
	os.MkdirAll(workflowDir, 0755)
	if err := os.Chdir(workflowDir); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to enter workflow directory %s: %v\n", workflowDir, err)
		os.Exit(1)
	}
	svc := trigger.NewService(tcpClient.AppMeshClient, server, parseCSV(clusterNodes), workflowDir)

	if creds, err := parseExecIdentities(os.Getenv("APPMESH_EXEC_IDENTITIES")); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid APPMESH_EXEC_IDENTITIES: %v\n", err)
		os.Exit(1)
	} else if len(creds) > 0 {
		svc.SetExecIdentities(creds)
		logger.Info(fmt.Sprintf("Loaded %d execution identities for execution_identity workflows", len(creds)))
	}

	if password != "" {
		svc.SetReAuth(func() error {
			_, err := tcpClient.Login(user, password, "", 86400, "")
			return err
		})
	}

	taskHandler, taskErr := api.NewTaskHandler(svc, svc.Wdir(), tcpClient.AppMeshClient, appmesh.Option{
		AppMeshUri:         server,
		JwtToken:           tcpClient.GetToken(),
		InsecureSkipVerify: true,
	})
	if taskErr != nil {
		logger.Error("Task handler init failed: " + taskErr.Error())
	} else {
		defer taskHandler.Close()
		go taskHandler.Run()
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sigCh
		cancel()
	}()

	svc.Run(ctx)
}

func newTCPClient(server, token string) (*appmesh.AppMeshClientTCP, error) {
	return appmesh.NewTCPClient(appmesh.Option{
		AppMeshUri:         server,
		JwtToken:           token,
		InsecureSkipVerify: true,
		// Auto-refresh keeps the long-lived engine session valid. It is safe because the
		// shared connection enables the demuxer (see EnableConcurrency in main): the renew
		// reply is correlated by UUID and the new token is installed correctly, so the
		// prior cross-wiring that left a revoked token in place (-> 401) cannot occur.
		AutoRefreshToken: true,
	})
}

// parseExecIdentities parses the APPMESH_EXEC_IDENTITIES secured env var: a JSON
// object mapping execution-identity usernames to passwords. Empty/unset yields a
// nil map (no identities configured). Credentials are never logged.
func parseExecIdentities(s string) (map[string]string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var creds map[string]string
	if err := json.Unmarshal([]byte(s), &creds); err != nil {
		return nil, fmt.Errorf("expected a JSON object {\"user\":\"password\"}: %w", err)
	}
	for user, pwd := range creds {
		if user == "" || pwd == "" {
			return nil, fmt.Errorf("execution identity entries must have a non-empty user and password")
		}
	}
	return creds, nil
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
