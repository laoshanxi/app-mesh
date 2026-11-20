package agent

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"

	"github.com/docker/docker/client"

	"github.com/laoshanxi/app-mesh/src/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
)

// fakeEngine answers the subset of the Docker Engine API the container
// service uses, with enough state (images, containers, execs) for the
// handlers' decisions to be observable.
type fakeEngine struct {
	mu         sync.Mutex
	images     map[string]bool
	containers map[string]*fakeContainer // by id and by name
	nextID     int
	logsByID   map[string][]byte
	execExit   int
	pullBody   string
}

type fakeContainer struct {
	id      string
	name    string
	running bool
	pid     int
	labels  map[string]string
}

func newFakeEngine() *fakeEngine {
	return &fakeEngine{
		images:     map[string]bool{},
		containers: map[string]*fakeContainer{},
		logsByID:   map[string][]byte{},
		nextID:     100,
	}
}

func (f *fakeEngine) containerByRef(ref string) *fakeContainer {
	if c, ok := f.containers[ref]; ok {
		return c
	}
	for _, c := range f.containers {
		if c.name == ref {
			return c
		}
	}
	return nil
}

func (f *fakeEngine) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Strip the negotiated version prefix (/v1.xx/...).
	path := r.URL.Path
	if strings.HasPrefix(path, "/v1.") {
		if cut := strings.IndexByte(path[1:], '/'); cut > 0 {
			path = path[1+cut:]
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case path == "/_ping":
		w.Header().Set("API-Version", "1.47")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))

	case path == "/images/create":
		for _, line := range strings.Split(f.pullBody, "\n") {
			if line != "" {
				_, _ = w.Write([]byte(line + "\n"))
			}
		}
		ref := r.URL.Query().Get("fromImage")
		if tag := r.URL.Query().Get("tag"); tag != "" && tag != "latest" {
			ref += ":" + tag
		}
		if !strings.Contains(f.pullBody, `"error"`) {
			f.images[ref] = true
		}

	case strings.HasPrefix(path, "/images/") && strings.HasSuffix(path, "/json"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/images/"), "/json")
		if f.images[ref] {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"Id":"sha256:img"}`))
		} else {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"no such image"}`))
		}

	case path == "/containers/create":
		name := r.URL.Query().Get("name")
		var body struct {
			Labels map[string]string
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.nextID++
		prefix := "cid"
		if strings.Contains(name, "boom") { // sabotage hook for the cleanup test
			prefix = "boom-cid"
		}
		c := &fakeContainer{
			id:      fmt.Sprintf("%s%d", prefix, f.nextID),
			name:    name,
			running: true,
			pid:     4242,
			labels:  body.Labels,
		}
		f.containers[c.id] = c
		f.containers[name] = c
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": c.id})

	case strings.Contains(path, "/containers/") && strings.HasSuffix(path, "/start"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/start")
		if strings.Contains(ref, "boom") { // sabotage hook for the cleanup test
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if c := f.containerByRef(ref); c != nil {
			c.running = true
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case strings.Contains(path, "/containers/") && strings.HasSuffix(path, "/stop"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/stop")
		if c := f.containerByRef(ref); c != nil {
			c.running = false
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case strings.Contains(path, "/containers/") && strings.HasSuffix(path, "/kill"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/kill")
		if c := f.containerByRef(ref); c != nil {
			c.running = false
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}

	case strings.Contains(path, "/containers/") && strings.HasSuffix(path, "/logs"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/logs")
		c := f.containerByRef(ref)
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		payload := f.logsByID[c.id]
		if c.labels != nil && c.labels["tty"] == "true" {
			_, _ = w.Write(payload) // TTY: plain stream
			return
		}
		_, _ = w.Write(frame(payload))

	case strings.Contains(path, "/containers/") && strings.HasSuffix(path, "/exec"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/exec")
		if f.containerByRef(ref) == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"Id": "exec1"})

	case path == "/exec/exec1/start":
		w.WriteHeader(http.StatusOK)

	case path == "/exec/exec1/json":
		_ = json.NewEncoder(w).Encode(map[string]any{"ID": "exec1", "Running": false, "ExitCode": f.execExit})

	case path == "/containers/json":
		list := []map[string]any{}
		for key, c := range f.containers {
			if key != c.id { // skip name aliases pointing at the same container
				continue
			}
			if c.labels[labelManaged] == "true" {
				list = append(list, map[string]any{
					"Id":     c.id,
					"Names":  []string{"/" + c.name},
					"Labels": c.labels,
					"State":  "running",
				})
			}
		}
		_ = json.NewEncoder(w).Encode(list)

	case strings.HasPrefix(path, "/containers/") && strings.HasSuffix(path, "/json"):
		ref := strings.TrimSuffix(strings.TrimPrefix(path, "/containers/"), "/json")
		c := f.containerByRef(ref)
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"No such container"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id":    c.id,
			"Name":  "/" + c.name,
			"State": map[string]any{"Running": c.running, "Pid": c.pid, "ExitCode": 3, "Health": map[string]any{"Status": "healthy"}},
			"Config": map[string]any{
				"Labels": c.labels,
				"Tty":    c.labels != nil && c.labels["tty"] == "true",
			},
		})

	case strings.HasPrefix(path, "/containers/"):
		ref := strings.TrimPrefix(path, "/containers/")
		c := f.containerByRef(ref)
		if c == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		delete(f.containers, c.id)
		delete(f.containers, c.name)
		w.WriteHeader(http.StatusNoContent)

	default:
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"message":"unhandled ` + path + `"}`))
	}
}

// frame wraps a payload in one docker stdout stream frame.
func frame(payload []byte) []byte {
	f := make([]byte, 8+len(payload))
	f[0] = 1
	binary.BigEndian.PutUint32(f[4:8], uint32(len(payload)))
	copy(f[8:], payload)
	return f
}

// newTestService mounts the container service against a fake engine and
// returns a caller that signs requests with the boot PSK.
func newTestService(t *testing.T, engine *fakeEngine) func(method, path, body string) (*http.Response, string) {
	t.Helper()
	// The endpoint gate must see a Docker endpoint before registration.
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	engineSrv := httptest.NewServer(engine)
	t.Cleanup(engineSrv.Close)

	origClient := dockerClient
	cli, err := client.NewClientWithOpts(client.WithHost("tcp://" + engineSrv.Listener.Addr().String()))
	if err != nil {
		t.Fatal(err)
	}
	dockerClient = cli
	t.Cleanup(func() { dockerClient = origClient })

	router := mux.NewRouter()
	if err := RegisterContainerRoutes(router); err != nil {
		t.Fatal(err)
	}
	svc := httptest.NewServer(router)
	t.Cleanup(svc.Close)

	origPSK := cloud.AgentToCPPHMAC
	cloud.AgentToCPPHMAC = cloud.NewHMACVerify("unit-test-psk")
	t.Cleanup(func() { cloud.AgentToCPPHMAC = origPSK })

	return func(method, path, body string) (*http.Response, string) {
		req, err := http.NewRequest(method, svc.URL+ContainerPathPrefix+path, strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("req-%s", path)
		req.Header.Set(requestIDHeader, id)
		req.Header.Set(cloud.HeaderHMAC, cloud.AgentToCPPHMAC.GenerateHMAC(id))
		resp, err := svc.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		text, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp, string(text)
	}
}

func TestPSKProofRequired(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	orig := cloud.AgentToCPPHMAC
	cloud.AgentToCPPHMAC = cloud.NewHMACVerify("psk")
	t.Cleanup(func() { cloud.AgentToCPPHMAC = orig })

	router := mux.NewRouter()
	if err := RegisterContainerRoutes(router); err != nil {
		t.Fatal(err)
	}
	svc := httptest.NewServer(router)
	t.Cleanup(svc.Close)

	cases := map[string]map[string]string{
		"no headers":  {},
		"wrong mac":   {requestIDHeader: "id", cloud.HeaderHMAC: "bad"},
		"missing id":  {cloud.HeaderHMAC: "bad"},
		"foreign key": {requestIDHeader: "id", cloud.HeaderHMAC: cloud.NewHMACVerify("other").GenerateHMAC("id")},
	}
	for name, headers := range cases {
		req, _ := http.NewRequest(http.MethodGet, svc.URL+ContainerPathPrefix+"/ping", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		resp, err := svc.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusProxyAuthRequired {
			t.Fatalf("%s: expected 407, got %d", name, resp.StatusCode)
		}
	}
}

func TestPing(t *testing.T) {
	call := newTestService(t, newFakeEngine())
	resp, body := call(http.MethodGet, "/ping", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"apiVersion"`) {
		t.Fatalf("ping: %d %s", resp.StatusCode, body)
	}
}

func TestImageGet(t *testing.T) {
	engine := newFakeEngine()
	engine.images["alpine:3.19"] = true
	call := newTestService(t, engine)

	resp, _ := call(http.MethodGet, "/image?ref=alpine:3.19", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("present image expected 200, got %d", resp.StatusCode)
	}
	resp, _ = call(http.MethodGet, "/image?ref=missing:latest", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing image expected 404, got %d", resp.StatusCode)
	}
}

func TestEnsureImagePull(t *testing.T) {
	engine := newFakeEngine()
	engine.pullBody = strings.Join([]string{
		`{"status":"Pulling from library/alpine"}`,
		`{"id":"abc","status":"Downloading","progress":"[===>] 10kB/20kB"}`,
		`{"id":"abc","status":"Downloading","progress":"[===>] 10kB/20kB"}`, // duplicate collapses
		`{"status":"Status: Downloaded newer image"}`,
	}, "\n")
	call := newTestService(t, engine)

	resp, body := call(http.MethodPost, "/image/ensure",
		`{"ref":"alpine:3.19","timeoutSeconds":5,"auth":{"server":"reg.example.com","username":"u","password":"p"}}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"ok":true`) {
		t.Fatalf("ensure: %d %s", resp.StatusCode, body)
	}
	if strings.Count(body, `Downloading`) != 1 {
		t.Fatalf("duplicate progress lines did not collapse: %s", body)
	}
	// The SDK normalizes the reference (docker.io/library/alpine), so match loosely.
	pulled := false
	for ref := range engine.images {
		if strings.HasSuffix(ref, "alpine:3.19") {
			pulled = true
		}
	}
	if !pulled {
		t.Fatalf("fake engine did not record the pulled image: %v", engine.images)
	}

	// A failed pull reports the engine's error text.
	engine.pullBody = `{"error":"manifest unknown"}`
	resp, body = call(http.MethodPost, "/image/ensure", `{"ref":"bad:1","timeoutSeconds":5}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "manifest unknown") {
		t.Fatalf("failed pull: %d %s", resp.StatusCode, body)
	}
}

func TestEnsureImageAlreadyPresent(t *testing.T) {
	engine := newFakeEngine()
	engine.images["present:1"] = true
	engine.pullBody = `{"error":"must not pull"}`
	call := newTestService(t, engine)

	resp, body := call(http.MethodPost, "/image/ensure", `{"ref":"present:1","timeoutSeconds":5}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"alreadyPresent":true`) {
		t.Fatalf("already present: %d %s", resp.StatusCode, body)
	}
}

func TestContainerRun(t *testing.T) {
	engine := newFakeEngine()
	call := newTestService(t, engine)

	// A leftover labeled for this app is replaced and its logs are returned.
	leftover := &fakeContainer{id: "old1", name: "appmesh-demo", running: false, labels: map[string]string{labelManaged: "true", labelApp: "demo"}}
	engine.containers["old1"] = leftover
	engine.containers["appmesh-demo"] = leftover
	engine.logsByID["old1"] = []byte("leftover line\n")

	resp, body := call(http.MethodPost, "/run",
		`{"name":"appmesh-demo","app":"demo","legacyName":"demo","graceSeconds":10,"createBody":{"Image":"alpine:3.19","Cmd":["sleep","10"]}}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"pid":4242`) {
		t.Fatalf("run: %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(body, "leftover line") {
		t.Fatalf("replaced container logs missing: %s", body)
	}
	created := engine.containerByRef("appmesh-demo")
	if created == nil || created.labels[labelApp] != "demo" || created.labels[labelManaged] != "true" {
		t.Fatalf("ownership labels not stamped: %+v", created)
	}

	// A foreign occupant of the name blocks the run with 409.
	foreign := &fakeContainer{id: "fx1", name: "appmesh-other", running: true, labels: map[string]string{labelManaged: "true", labelApp: "other"}}
	engine.containers["fx1"] = foreign
	engine.containers["appmesh-other"] = foreign
	resp, body = call(http.MethodPost, "/run",
		`{"name":"appmesh-other","app":"mine","legacyName":"mine","createBody":{"Image":"alpine"}}`)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "owned by application <other>") {
		t.Fatalf("foreign occupant: %d %s", resp.StatusCode, body)
	}

	// An unlabeled occupant is never deleted.
	unlabeled := &fakeContainer{id: "un1", name: "appmesh-plain", running: true}
	engine.containers["un1"] = unlabeled
	engine.containers["appmesh-plain"] = unlabeled
	resp, body = call(http.MethodPost, "/run",
		`{"name":"appmesh-plain","app":"plain","legacyName":"plain","createBody":{"Image":"alpine"}}`)
	if resp.StatusCode != http.StatusConflict || !strings.Contains(body, "unlabeled") {
		t.Fatalf("unlabeled occupant: %d %s", resp.StatusCode, body)
	}
	if engine.containerByRef("appmesh-plain") == nil {
		t.Fatal("unlabeled occupant must survive")
	}
}

func TestRunCleanupAfterFailedStart(t *testing.T) {
	engine := newFakeEngine()
	call := newTestService(t, engine)

	// The fake engine fails start for names containing "boom"; the created
	// container must not survive the failed run.
	resp, _ := call(http.MethodPost, "/run", `{"name":"boom","app":"boom","createBody":{"Image":"alpine"}}`)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("sabotaged start expected 404, got %d", resp.StatusCode)
	}
	engine.mu.Lock()
	defer engine.mu.Unlock()
	for ref, c := range engine.containers {
		if c.name == "boom" || strings.HasPrefix(ref, "cid") {
			t.Fatalf("created container survived a failed start: %s %+v", ref, c)
		}
	}
}

func TestContainerLogs(t *testing.T) {
	engine := newFakeEngine()
	c := &fakeContainer{id: "lg1", name: "appmesh-logs", running: true, labels: map[string]string{}}
	engine.containers["lg1"] = c
	engine.containers["appmesh-logs"] = c
	engine.logsByID["lg1"] = []byte("2026-11-21T10:00:00.123456789Z first\n2026-11-21T10:00:01.000000000Z second\n")
	call := newTestService(t, engine)

	resp, body := call(http.MethodGet, "/lg1/logs?sinceNs=0&tail=all", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("logs: %d %s", resp.StatusCode, body)
	}
	var parsed struct {
		Lines []struct {
			Ns   int64  `json:"ns"`
			Text string `json:"text"`
		} `json:"lines"`
	}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatal(err)
	}
	if len(parsed.Lines) != 2 || parsed.Lines[0].Text != "first" || parsed.Lines[1].Text != "second" {
		t.Fatalf("log lines: %+v", parsed.Lines)
	}
	if parsed.Lines[0].Ns <= 0 || parsed.Lines[1].Ns <= parsed.Lines[0].Ns {
		t.Fatalf("timestamps not resolved: %+v", parsed.Lines)
	}
}

func TestContainerInspectStopKillDelete(t *testing.T) {
	engine := newFakeEngine()
	c := &fakeContainer{id: "op1", name: "appmesh-ops", running: true, pid: 99, labels: map[string]string{}}
	engine.containers["op1"] = c
	engine.containers["appmesh-ops"] = c
	call := newTestService(t, engine)

	resp, body := call(http.MethodGet, "/op1", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"health":"healthy"`) || !strings.Contains(body, `"pid":99`) {
		t.Fatalf("inspect: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(http.MethodGet, "/no-such", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("missing inspect expected 404, got %d", resp.StatusCode)
	}

	if resp, _ := call(http.MethodPost, "/op1/stop", `{"graceSeconds":7}`); resp.StatusCode != http.StatusOK {
		t.Fatalf("stop failed: %d", resp.StatusCode)
	}
	if c.running {
		t.Fatal("stop did not stop")
	}
	if resp, _ := call(http.MethodPost, "/op1/kill", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("kill failed: %d", resp.StatusCode)
	}
	if resp, _ := call(http.MethodDelete, "/op1?force=1", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("delete failed: %d", resp.StatusCode)
	}
	if engine.containerByRef("op1") != nil {
		t.Fatal("delete did not remove")
	}
	if resp, _ := call(http.MethodDelete, "/op1?force=1", ""); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("second delete expected 404, got %d", resp.StatusCode)
	}
}

func TestContainerExec(t *testing.T) {
	engine := newFakeEngine()
	engine.execExit = 5
	c := &fakeContainer{id: "ex1", name: "appmesh-exec", running: true, labels: map[string]string{}}
	engine.containers["ex1"] = c
	engine.containers["appmesh-exec"] = c
	call := newTestService(t, engine)

	resp, body := call(http.MethodPost, "/ex1/exec", `{"cmd":["/bin/sh","-c","exit 5"]}`)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"exitCode":5`) {
		t.Fatalf("exec: %d %s", resp.StatusCode, body)
	}
}

func TestContainerList(t *testing.T) {
	engine := newFakeEngine()
	c := &fakeContainer{id: "ls1", name: "appmesh-listed", running: true, labels: map[string]string{labelManaged: "true", labelApp: "listed"}}
	engine.containers["ls1"] = c
	engine.containers["appmesh-listed"] = c
	stranger := &fakeContainer{id: "st1", name: "stranger", running: true}
	engine.containers["st1"] = stranger
	call := newTestService(t, engine)

	resp, body := call(http.MethodGet, "/list", "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "appmesh-listed") || strings.Contains(body, "stranger") {
		t.Fatalf("list: %d %s", resp.StatusCode, body)
	}
}

func TestLocalPeerGate(t *testing.T) {
	cases := []struct {
		remote    string
		listenIPs []net.IP
		want      bool
	}{
		{"127.0.0.1:5000", nil, true},
		{"127.9.9.9:80", nil, true},                                      // the whole 127/8 block
		{"[::1]:443", nil, true},                                         // ::1
		{"[::ffff:127.0.0.1]:80", nil, true},                             // v4-mapped loopback spelling
		{"192.168.1.5:5000", nil, false},                                 // foreign host
		{"192.168.1.5:5000", []net.IP{net.ParseIP("192.168.1.5")}, true}, // the agent's own listen address
		{"192.168.1.6:5000", []net.IP{net.ParseIP("192.168.1.5")}, false},
		{"no-address", nil, false},
	}
	for _, tc := range cases {
		if got := isLocalDaemonPeer(tc.remote, tc.listenIPs); got != tc.want {
			t.Errorf("isLocalDaemonPeer(%q) = %v, want %v", tc.remote, got, tc.want)
		}
	}
}

// A non-loopback peer is refused before the PSK check, even with a valid proof.
func TestForeignPeerRejected(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	origPSK := cloud.AgentToCPPHMAC
	cloud.AgentToCPPHMAC = cloud.NewHMACVerify("psk")
	t.Cleanup(func() { cloud.AgentToCPPHMAC = origPSK })

	router := mux.NewRouter()
	if err := RegisterContainerRoutes(router); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, ContainerPathPrefix+"/ping", nil)
	req.RemoteAddr = "10.1.2.3:55555"
	req.Header.Set(requestIDHeader, "id")
	req.Header.Set(cloud.HeaderHMAC, cloud.AgentToCPPHMAC.GenerateHMAC("id"))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("foreign peer: expected 403, got %d (%s)", rec.Code, rec.Body.String())
	}

	// The same request from loopback passes the transport gate (and fails on
	// the unreachable engine instead, proving the gate is the only blocker).
	req = httptest.NewRequest(http.MethodGet, ContainerPathPrefix+"/ping", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	req.Header.Set(requestIDHeader, "id")
	req.Header.Set(cloud.HeaderHMAC, cloud.AgentToCPPHMAC.GenerateHMAC("id"))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code == http.StatusForbidden {
		t.Fatalf("loopback peer: unexpectedly 403 (%s)", rec.Body.String())
	}
}

// The Docker.Enable switch keeps the whole service off the router.
func TestDockerEnableSwitchDisablesRoutes(t *testing.T) {
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:1")
	orig := config.ConfigData.Docker.Enable
	config.ConfigData.Docker.Enable = false
	t.Cleanup(func() { config.ConfigData.Docker.Enable = orig })

	router := mux.NewRouter()
	if err := RegisterContainerRoutes(router); err == nil {
		t.Fatal("expected the disabled switch to keep the routes off")
	} else if !strings.Contains(err.Error(), "Docker.Enable") {
		t.Fatalf("unexpected disable reason: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, ContainerPathPrefix+"/ping", nil)
	req.RemoteAddr = "127.0.0.1:55555"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("disabled service: expected 404 for an unmounted route, got %d", rec.Code)
	}
}
