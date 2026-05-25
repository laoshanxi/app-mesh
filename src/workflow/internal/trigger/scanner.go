package trigger

import (
	"encoding/json"
	"os"
	"strings"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/parser"
)

const WorkflowAppPrefix = "workflow-"

// ScanWorkflows discovers workflow definitions registered as special Apps.
func ScanWorkflows(client *appmesh.AppMeshClient, registry *Registry) error {
	apps, err := client.ListApps()
	if err != nil {
		logger.Error("failed to list apps: " + err.Error())
		return err
	}

	found := make(map[string]bool)
	for _, app := range apps {
		if !strings.HasPrefix(app.Name, WorkflowAppPrefix) {
			continue
		}

		meta := parseMetadata(app.Metadata)
		if meta["type"] != "workflow" {
			continue
		}

		wfName := strings.TrimPrefix(app.Name, WorkflowAppPrefix)
		found[wfName] = true

		yamlPath, _ := meta["yaml_path"]
		if yamlPath == "" || !fileExists(yamlPath) {
			continue
		}

		wf, err := parser.LoadWorkflow(yamlPath)
		if err != nil {
			logger.Error("failed to load workflow '" + wfName + "': " + err.Error())
			continue
		}
		registry.Update(wfName, wf)
	}

	for name := range registry.All() {
		if !found[name] {
			registry.Remove(name)
		}
	}
	return nil
}

func parseMetadata(raw *json.RawMessage) map[string]string {
	if raw == nil {
		return nil
	}
	var m map[string]string
	if err := json.Unmarshal(*raw, &m); err != nil {
		return nil
	}
	return m
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
