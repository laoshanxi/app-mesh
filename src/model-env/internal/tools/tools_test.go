package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// TestWithInjected verifies session_id + workdir are injected into object
// payloads, never override explicit keys, and leave non-object payloads untouched.
func TestWithInjected(t *testing.T) {
	inj := map[string]string{"session_id": "s1", "workdir": "/w/s1"}

	// Empty args become an object carrying both injected fields.
	got := withInjected(nil, inj)
	if !jsonHas(t, got, "session_id", "s1") || !jsonHas(t, got, "workdir", "/w/s1") {
		t.Errorf("empty args: %s", got)
	}
	// Existing fields are preserved alongside the injected ones.
	got = withInjected(json.RawMessage(`{"city":"Paris"}`), inj)
	if !jsonHas(t, got, "session_id", "s1") || !jsonHas(t, got, "workdir", "/w/s1") || !jsonHas(t, got, "city", "Paris") {
		t.Errorf("merge: %s", got)
	}
	// An explicit value from the model is not overridden.
	if got := withInjected(json.RawMessage(`{"session_id":"caller"}`), inj); !jsonHas(t, got, "session_id", "caller") {
		t.Errorf("override guard: %s", got)
	}
	// Empty inject map is a no-op.
	if got := withInjected(json.RawMessage(`{"a":1}`), nil); got != `{"a":1}` {
		t.Errorf("no-op: %s", got)
	}
	// A non-object payload is passed through unchanged.
	if got := withInjected(json.RawMessage(`[1,2]`), inj); got != `[1,2]` {
		t.Errorf("non-object: %s", got)
	}
}

func jsonHas(t *testing.T, raw, key, want string) bool {
	t.Helper()
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("unmarshal %s: %v", raw, err)
	}
	return m[key] == want
}

// TestSpecsFiltersToolApps verifies the catalog advertises only Apps carrying
// metadata.tool, mapping name + schema, and ignoring plain Apps.
func TestSpecsFiltersToolApps(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/appmesh/applications" {
			t.Errorf("path = %s", r.URL.Path)
		}
		w.Write([]byte(`[
			{"name":"weather","metadata":{"tool":{"description":"Get weather","parameters":{"type":"object","properties":{"city":{"type":"string"}}}}}},
			{"name":"plain-app"},
			{"name":"described","description":"fallback desc","metadata":{"tool":{}}}
		]`))
	}))
	defer srv.Close()

	noVerify := ""
	client, err := appmesh.NewHTTPClient(appmesh.Option{AppMeshUri: srv.URL, SslTrustedCA: &noVerify})
	if err != nil {
		t.Fatal(err)
	}
	cat := NewCatalog(client, 30, "", "")
	specs, err := cat.Specs(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	byName := map[string]string{}
	for _, s := range specs {
		byName[s.Name] = s.Description
	}
	if _, ok := byName["plain-app"]; ok {
		t.Error("plain App without metadata.tool must not be a tool")
	}
	if byName["weather"] != "Get weather" {
		t.Errorf("weather desc = %q", byName["weather"])
	}
	// metadata.tool present but no description → falls back to App description.
	if byName["described"] != "fallback desc" {
		t.Errorf("described desc = %q, want fallback", byName["described"])
	}
	if len(specs) != 2 {
		t.Errorf("got %d specs, want 2", len(specs))
	}
}
