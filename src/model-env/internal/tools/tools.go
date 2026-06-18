// Package tools exposes registered App Mesh Apps as agent tools.
//
// A tool is a registered App carrying metadata.tool (the same pattern the
// workflow engine uses to store workflows as Apps). The catalog lists Apps the
// caller's token may see — so the advertised tool set is automatically scoped to
// what the tenant could already run (no separate whitelist). Tool invocation is
// RunTask against the App (structured JSON in, structured JSON out).
package tools

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// toolMeta is the metadata.tool block on a tool App.
type toolMeta struct {
	Tool *struct {
		Description string          `json:"description"`
		Parameters  json.RawMessage `json:"parameters"`
	} `json:"tool"`
}

// Catalog builds tool specs from registered Apps and invokes them.
//
// The tool name equals the App name, so Invoke needs no resolution table: it
// RunTasks the App named by the call. The client carries the caller's token, so
// listing and invocation are both naturally RBAC-scoped (design L3).
type Catalog struct {
	client  *appmesh.AppMeshClient
	timeout int               // RunTask timeout (seconds)
	inject  map[string]string // fields added to tool args (session_id, workdir)
}

// NewCatalog creates a catalog bound to a caller-scoped client. sessionID and
// workdir (either may be empty) are injected into each tool call so a tool App can
// scope its side effects (notably files) to the calling session.
func NewCatalog(client *appmesh.AppMeshClient, timeout int, sessionID, workdir string) *Catalog {
	if timeout <= 0 {
		timeout = 300
	}
	inject := map[string]string{}
	if sessionID != "" {
		inject["session_id"] = sessionID
	}
	if workdir != "" {
		inject["workdir"] = workdir
	}
	return &Catalog{client: client, timeout: timeout, inject: inject}
}

// Specs lists Apps with metadata.tool and returns their function schemas. Apps
// the caller cannot see are absent from ListApps, so they never become tools.
func (c *Catalog) Specs(ctx context.Context) ([]llm.ToolSpec, error) {
	apps, err := c.client.ListApps()
	if err != nil {
		return nil, fmt.Errorf("list apps: %w", err)
	}
	var specs []llm.ToolSpec
	for _, app := range apps {
		if app.Metadata == nil {
			continue
		}
		var m toolMeta
		if err := json.Unmarshal(*app.Metadata, &m); err != nil || m.Tool == nil {
			continue
		}
		desc := m.Tool.Description
		if desc == "" && app.Description != nil {
			desc = *app.Description
		}
		params := m.Tool.Parameters
		if len(params) == 0 {
			params = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		specs = append(specs, llm.ToolSpec{
			Name:        app.Name,
			Description: desc,
			Parameters:  params,
		})
	}
	return specs, nil
}

// Invoke RunTasks the App named by the call (its JSON args as payload), with the
// catalog's inject fields merged in, and returns the App's response body.
func (c *Catalog) Invoke(ctx context.Context, call llm.ToolCall) (string, error) {
	args := withInjected(call.Arguments, c.inject)
	resp, err := c.client.RunTask(call.Name, args, c.timeout)
	if err != nil {
		return "", fmt.Errorf("tool %q failed: %w", call.Name, err)
	}
	return resp, nil
}

// withInjected adds each inject key to the args JSON when raw is an object lacking
// it (the model's explicit value wins). Non-object payloads pass through unchanged.
func withInjected(raw json.RawMessage, inject map[string]string) string {
	s := string(raw)
	if s == "" {
		s = "{}"
	}
	if len(inject) == 0 {
		return s
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal([]byte(s), &obj); err != nil || obj == nil {
		return s // not a JSON object — leave it alone
	}
	changed := false
	for k, v := range inject {
		if v == "" {
			continue
		}
		if _, exists := obj[k]; exists {
			continue // caller/model set it explicitly; do not override
		}
		vJSON, err := json.Marshal(v) // proper JSON-string encoding, not concat
		if err != nil {
			continue
		}
		obj[k] = vJSON
		changed = true
	}
	if !changed {
		return s
	}
	merged, err := json.Marshal(obj)
	if err != nil {
		return s
	}
	return string(merged)
}
