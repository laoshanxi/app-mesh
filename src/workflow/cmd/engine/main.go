// wf-engine is the App Mesh Workflow Engine. Every run — human-initiated,
// Engine-initiated, or recovered — executes under a short-lived, run-bound
// capability issued by the local Engine after proving the current managed
// process, renewed for the run's lifetime. A human caller's Dex bearer only
// authenticates the trigger and (forward_token) message-step payloads, and is
// kept in memory only; wf-engine is not an OAuth client.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/api"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/tlsconf"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/trigger"
)

var controlOperations = []string{"app-view-all", "app-subscribe"}

func main() {
	var server, clusterNodes string
	flag.StringVar(&server, "server", "127.0.0.1:6059", "App Mesh TCP server address (host:port)")
	flag.StringVar(&clusterNodes, "cluster-nodes", "", "Comma-separated cluster node addresses")
	flag.Parse()

	appmesh.SetLogger(func(format string, args ...any) {
		logger.Error("SDK " + fmt.Sprintf(format, args...))
	})

	engineOption := newEngineOption(server, "")
	tcpClient, err := appmesh.NewTCPClient(engineOption)
	if err != nil {
		fmt.Fprintln(os.Stderr, "TCP client error:", err)
		os.Exit(1)
	}
	defer tcpClient.CloseConnection()
	tcpClient.EnableConcurrency()

	cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), trigger.CapabilityRequestTimeout)
	removedOrphans, err := tcpClient.CleanupWorkflowOrphansContext(cleanupCtx)
	cleanupCancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Engine workflow orphan cleanup failed:", err)
		os.Exit(1)
	}
	if removedOrphans > 0 {
		logger.Info(fmt.Sprintf("removed %d temporary App(s) left by a prior Workflow process", removedOrphans))
	}

	controlCtx, controlCancel := context.WithTimeout(context.Background(), trigger.CapabilityRequestTimeout)
	controlCapability, err := requestCapability(controlCtx, tcpClient.AppMeshClient,
		appmesh.WorkflowControlCapabilityAudience, "", "", controlOperations)
	controlCancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Engine workflow control capability failed:", err)
		os.Exit(1)
	}
	tcpClient.SetToken(controlCapability.Capability)
	engineOption.JwtToken = controlCapability.Capability

	workflowDir, err := filepath.Abs(filepath.Join("..", "workflow"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "Failed to resolve workflow directory:", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(workflowDir, 0755); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to create workflow directory:", err)
		os.Exit(1)
	}
	if err := os.Chdir(workflowDir); err != nil {
		fmt.Fprintln(os.Stderr, "Failed to enter workflow directory:", err)
		os.Exit(1)
	}

	svc := trigger.NewService(tcpClient.AppMeshClient, server, parseCSV(clusterNodes), workflowDir)
	svc.SetProcessUUID(controlCapability.ProcessUUID)
	svc.SetCapabilityIssuer(func(ctx context.Context, workflowID, runID string, operations []string) (appmesh.WorkflowCapability, error) {
		return requestCapability(ctx, tcpClient.AppMeshClient,
			appmesh.WorkflowRunCapabilityAudience, workflowID, runID, operations)
	})
	// Shared control-capability refresh for the renewal loop and the reactive path.
	controlRefresh := func(ctx context.Context) error {
		refreshed, err := requestCapability(ctx, tcpClient.AppMeshClient,
			appmesh.WorkflowControlCapabilityAudience, "", "", controlOperations)
		if err != nil {
			return err
		}
		if refreshed.ProcessUUID != controlCapability.ProcessUUID {
			return fmt.Errorf("Engine returned a workflow control capability for a different process")
		}
		tcpClient.SetToken(refreshed.Capability)
		return nil
	}
	svc.SetControlRefresh(controlRefresh)

	taskHandler, taskErr := api.NewTaskHandler(svc, svc.Wdir(), tcpClient.AppMeshClient, engineOption)
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

	// Renew the control capability before its TTL; a failed attempt retries next tick.
	go func() {
		ticker := time.NewTicker(trigger.CapabilityLifetime - trigger.CapabilityRefreshMargin)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(ctx, trigger.CapabilityRequestTimeout)
				err := controlRefresh(renewCtx)
				renewCancel()
				if err != nil {
					logger.Error("workflow control capability renewal failed (retrying next tick): " + err.Error())
				}
			}
		}
	}()

	svc.Run(ctx)
}

func requestCapability(ctx context.Context, client *appmesh.AppMeshClient, audience, workflowID, runID string, operations []string) (appmesh.WorkflowCapability, error) {
	return client.RequestWorkflowCapabilityContext(ctx, appmesh.WorkflowCapabilityRequest{
		Audience:   audience,
		Workflow:   workflowID,
		RunID:      runID,
		Operations: operations,
		ExpiresIn:  int(trigger.CapabilityLifetime / time.Second),
	})
}

func newEngineOption(server, token string) appmesh.Option {
	option := appmesh.Option{
		AppMeshUri: server,
		JwtToken:   token,
	}
	tlsconf.Apply(&option)
	return option
}

func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}
