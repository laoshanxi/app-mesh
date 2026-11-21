package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/registry"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/stdcopy"

	"github.com/laoshanxi/app-mesh/src/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

var (
	DockerSocketFilePath = "/var/run/docker.sock"
)

const (
	// ContainerPathPrefix is the daemon-to-agent container lifecycle API; the
	// agent drives Docker itself and the daemon never speaks raw Engine API.
	ContainerPathPrefix = "/appmesh/container"
	requestIDHeader     = "X-Request-ID"

	// requestTimeout bounds every engine call except a pull, which carries its
	// own bounded window from the daemon.
	requestTimeout = 30 * time.Second
	// pullProgressMaxBytes bounds the pull progress dump; the tail carries the outcome.
	pullProgressMaxBytes = 64 * 1024
	defaultPullTimeout   = 300 * time.Second
	// Ownership labels: cleanup deletes only containers it owns.
	labelManaged = "appmesh.managed"
	labelApp     = "appmesh.app"
)

// One shared engine client for the whole agent; the SDK negotiates the API version.
var (
	dockerClientMu sync.Mutex
	dockerClient   *client.Client
)

func engineClient() (*client.Client, error) {
	dockerClientMu.Lock()
	defer dockerClientMu.Unlock()
	if dockerClient == nil {
		// FromEnv honors DOCKER_HOST (podman socket, remote engine); default is the local socket.
		cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
		if err != nil {
			return nil, err
		}
		dockerClient = cli
	}
	return dockerClient, nil
}

// dockerGateError reports why the container lifecycle service cannot run on
// this node; nil when it may. The single DOCKER_HOST/socket endpoint check.
func dockerGateError() error {
	if !config.ConfigData.Docker.Enable {
		return fmt.Errorf("disabled by configuration (Docker.Enable: false)")
	}
	if os.Getenv("DOCKER_HOST") == "" && !appmesh.IsFileExist(DockerSocketFilePath) {
		return fmt.Errorf("docker endpoint not found: %s (set DOCKER_HOST to override)", DockerSocketFilePath)
	}
	return nil
}

// RegisterContainerRoutes mounts the container lifecycle service; the routes
// exist only when Docker is enabled and an endpoint is configured.
func RegisterContainerRoutes(router *mux.Router) error {
	if err := dockerGateError(); err != nil {
		return err
	}
	if _, err := engineClient(); err != nil {
		return fmt.Errorf("docker client: %w", err)
	}

	listenIPs := localListenIPs()
	s := router.PathPrefix(ContainerPathPrefix).Subrouter()
	s.Use(func(next http.Handler) http.Handler {
		return requirePSK(listenIPs, func(w http.ResponseWriter, r *http.Request) {
			ctx, cancel := context.WithTimeout(r.Context(), requestTimeout)
			defer cancel()
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	})

	s.HandleFunc("/ping", handleContainerPing).Methods(http.MethodGet)
	s.HandleFunc("/image", handleImageGet).Methods(http.MethodGet)
	s.HandleFunc("/image/ensure", handleImageEnsure).Methods(http.MethodPost)
	s.HandleFunc("/run", handleContainerRun).Methods(http.MethodPost)
	s.HandleFunc("/list", handleContainerList).Methods(http.MethodGet)
	// Registered after the fixed paths so "/image" never matches "{id}".
	s.HandleFunc("/{id}", handleContainerInspect).Methods(http.MethodGet)
	s.HandleFunc("/{id}", handleContainerDelete).Methods(http.MethodDelete)
	s.HandleFunc("/{id}/logs", handleContainerLogs).Methods(http.MethodGet)
	s.HandleFunc("/{id}/stop", handleContainerStop).Methods(http.MethodPost)
	s.HandleFunc("/{id}/kill", handleContainerKill).Methods(http.MethodPost)
	s.HandleFunc("/{id}/exec", handleContainerExec).Methods(http.MethodPost)
	return nil
}

// localListenIPs resolves the REST listen address once at mount time; the
// daemon dials this agent through it. Any-interface binds dial over loopback.
func localListenIPs() []net.IP {
	listen := config.ConfigData.REST.RESTListenAddress
	switch listen {
	case "", "0.0.0.0", "::":
		return nil
	}
	if ip := net.ParseIP(listen); ip != nil {
		return []net.IP{ip}
	}
	ips, err := net.LookupIP(listen)
	if err != nil {
		return nil
	}
	return ips
}

// isLocalDaemonPeer mirrors the daemon's HttpRequest::isLoopbackPeer: the
// 127/8 block, ::1, the v4-mapped spelling, or this agent's own listen address.
func isLocalDaemonPeer(remoteAddr string, listenIPs []net.IP) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	for _, listenIP := range listenIPs {
		if ip.Equal(listenIP) {
			return true
		}
	}
	return false
}

// requirePSK accepts only the local daemon: a non-local peer answers 403
// before the proof check, a bad PSK proof answers 407.
func requirePSK(listenIPs []net.IP, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLocalDaemonPeer(r.RemoteAddr, listenIPs) {
			http.Error(w, "the container service is restricted to the local daemon", http.StatusForbidden)
			return
		}
		id := r.Header.Get(requestIDHeader)
		mac := r.Header.Get(cloud.HeaderHMAC)
		if cloud.AgentToCPPHMAC == nil || !cloud.AgentToCPPHMAC.VerifyHMAC(id, mac) {
			http.Error(w, "PSK authentication failed", http.StatusProxyAuthRequired)
			return
		}
		r.Header.Del(requestIDHeader)
		r.Header.Del(cloud.HeaderHMAC)
		next(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// engineError maps a Docker client error onto the HTTP statuses the daemon's
// thin client already distinguishes (404 missing, 409 name conflict).
func engineError(w http.ResponseWriter, err error) {
	switch {
	case errdefs.IsNotFound(err):
		http.Error(w, err.Error(), http.StatusNotFound)
	case errdefs.IsConflict(err):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		http.Error(w, err.Error(), http.StatusBadGateway)
	}
}

func handleContainerPing(w http.ResponseWriter, r *http.Request) {
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ping, err := cli.Ping(r.Context())
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "apiVersion": ping.APIVersion})
}

func handleImageGet(w http.ResponseWriter, r *http.Request) {
	ref := r.URL.Query().Get("ref")
	if ref == "" {
		http.Error(w, "missing ref", http.StatusBadRequest)
		return
	}
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if _, err := cli.ImageInspect(r.Context(), ref); err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"present": true})
}

// Registry credentials ride the request body, never logs.
type registryAuth struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a registryAuth) pullOptions() (image.PullOptions, error) {
	opts := image.PullOptions{}
	if a.Username == "" {
		return opts, nil
	}
	// The engine wants URL-safe base64; the standard alphabet fails on '+' or '/'.
	payload, err := json.Marshal(registry.AuthConfig{
		Username:      a.Username,
		Password:      a.Password,
		ServerAddress: a.Server,
	})
	if err != nil {
		return opts, err
	}
	opts.RegistryAuth = base64.URLEncoding.EncodeToString(payload)
	return opts, nil
}

// One pull per reference; later callers share the owner's outcome.
type ensureCall struct {
	done   chan struct{}
	result ensureResult
}

type ensureResult struct {
	OK             bool   `json:"ok"`
	AlreadyPresent bool   `json:"alreadyPresent,omitempty"`
	Error          string `json:"error,omitempty"`
	Progress       string `json:"progress,omitempty"`
}

var (
	ensureMu    sync.Mutex
	ensureCalls = map[string]*ensureCall{}
)

func ensureImage(ctx context.Context, ref string, auth registryAuth) ensureResult {
	ensureMu.Lock()
	if call, ok := ensureCalls[ref]; ok {
		ensureMu.Unlock()
		select {
		case <-call.done:
			return call.result
		case <-ctx.Done():
			return ensureResult{Error: fmt.Sprintf("timed out waiting for a concurrent pull of %s", ref)}
		}
	}
	call := &ensureCall{done: make(chan struct{})}
	ensureCalls[ref] = call
	ensureMu.Unlock()

	result := runImagePull(ctx, ref, auth)

	ensureMu.Lock()
	delete(ensureCalls, ref)
	ensureMu.Unlock()
	call.result = result
	close(call.done)
	return result
}

func runImagePull(ctx context.Context, ref string, auth registryAuth) ensureResult {
	cli, err := engineClient()
	if err != nil {
		return ensureResult{Error: err.Error()}
	}
	if _, err := cli.ImageInspect(ctx, ref); err == nil {
		return ensureResult{OK: true, AlreadyPresent: true}
	} else if !errdefs.IsNotFound(err) {
		return ensureResult{Error: err.Error()}
	}

	opts, err := auth.pullOptions()
	if err != nil {
		return ensureResult{Error: err.Error()}
	}
	reader, err := cli.ImagePull(ctx, ref, opts)
	if err != nil {
		return ensureResult{Error: err.Error()}
	}
	defer reader.Close()

	// NDJSON progress: consecutive duplicate lines collapse, the tail is bounded.
	var pullErr error
	var progress strings.Builder
	var previous string
	dec := json.NewDecoder(reader)
	for {
		var msg jsonmessage.JSONMessage
		if err := dec.Decode(&msg); err != nil {
			if !errors.Is(err, io.EOF) && pullErr == nil {
				pullErr = err
			}
			break
		}
		if msg.Error != nil {
			pullErr = errors.New(msg.Error.Message)
			break
		}
		// The engine reports terminal failures as a plain "error" string.
		if msg.ErrorMessage != "" {
			pullErr = errors.New(msg.ErrorMessage)
			break
		}
		line := msg.Status
		if msg.ProgressMessage != "" {
			line += " " + msg.ProgressMessage
		}
		if msg.ID != "" {
			line = msg.ID + ": " + line
		}
		if line != previous {
			progress.WriteString(line)
			progress.WriteByte('\n')
			previous = line
		}
	}
	dump := progress.String()
	if len(dump) > pullProgressMaxBytes {
		dump = "...\n" + dump[len(dump)-pullProgressMaxBytes:]
	}
	if pullErr != nil {
		return ensureResult{Error: "image pull failed: " + pullErr.Error(), Progress: dump}
	}
	return ensureResult{OK: true, Progress: dump}
}

func handleImageEnsure(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ref            string       `json:"ref"`
		Auth           registryAuth `json:"auth"`
		TimeoutSeconds int          `json:"timeoutSeconds"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || body.Ref == "" {
		http.Error(w, "body must carry a ref", http.StatusBadRequest)
		return
	}
	timeout := defaultPullTimeout
	if body.TimeoutSeconds > 0 {
		timeout = time.Duration(body.TimeoutSeconds) * time.Second
	}
	// The pull runs under its own window, outside the route's requestTimeout.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), timeout)
	defer cancel()
	writeJSON(w, http.StatusOK, ensureImage(ctx, body.Ref, body.Auth))
}

// inspectState is the projection the daemon's run-state machine consumes.
type inspectState struct {
	ID       string            `json:"id"`
	Pid      int               `json:"pid"`
	Running  bool              `json:"running"`
	ExitCode int               `json:"exitCode"`
	Health   string            `json:"health,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

func projectInspect(insp container.InspectResponse) inspectState {
	state := inspectState{ID: insp.ID}
	if insp.State != nil {
		state.Pid = insp.State.Pid
		state.Running = insp.State.Running
		state.ExitCode = insp.State.ExitCode
		if insp.State.Health != nil {
			state.Health = string(insp.State.Health.Status)
		}
	}
	if insp.Config != nil {
		state.Labels = insp.Config.Labels
	}
	return state
}

func inspectContainer(ctx context.Context, cli *client.Client, idOrName string) (container.InspectResponse, error) {
	return cli.ContainerInspect(ctx, idOrName)
}

func handleContainerInspect(w http.ResponseWriter, r *http.Request) {
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	insp, err := inspectContainer(r.Context(), cli, mux.Vars(r)["id"])
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, projectInspect(insp))
}

func handleContainerStop(w http.ResponseWriter, r *http.Request) {
	var body struct {
		GraceSeconds int `json:"graceSeconds"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body)
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	timeout := body.GraceSeconds
	// SIGTERM first, grace is only the upper bound; already stopped is success.
	err = cli.ContainerStop(r.Context(), mux.Vars(r)["id"], container.StopOptions{Timeout: &timeout})
	if err != nil && !errdefs.IsNotModified(err) {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleContainerKill(w http.ResponseWriter, r *http.Request) {
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	if err := cli.ContainerKill(r.Context(), mux.Vars(r)["id"], "SIGKILL"); err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleContainerDelete(w http.ResponseWriter, r *http.Request) {
	force := r.URL.Query().Get("force") == "1" || r.URL.Query().Get("force") == "true"
	removeVolumes := r.URL.Query().Get("volumes") == "1" || r.URL.Query().Get("volumes") == "true"
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	err = cli.ContainerRemove(r.Context(), mux.Vars(r)["id"], container.RemoveOptions{Force: force, RemoveVolumes: removeVolumes})
	if err != nil {
		engineError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func handleContainerExec(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Cmd []string `json:"cmd"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&body); err != nil || len(body.Cmd) == 0 {
		http.Error(w, "body must carry a cmd array", http.StatusBadRequest)
		return
	}
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx := r.Context()
	created, err := cli.ContainerExecCreate(ctx, mux.Vars(r)["id"], container.ExecOptions{
		Cmd:          body.Cmd,
		AttachStdout: true,
		AttachStderr: true,
	})
	if err != nil {
		engineError(w, err)
		return
	}
	if err := cli.ContainerExecStart(ctx, created.ID, container.ExecStartOptions{}); err != nil {
		engineError(w, err)
		return
	}
	// Bounded wait: the start call can return before the verdict is recorded.
	for i := 0; i < 100; i++ {
		insp, err := cli.ContainerExecInspect(ctx, created.ID)
		if err != nil {
			engineError(w, err)
			return
		}
		if !insp.Running {
			writeJSON(w, http.StatusOK, map[string]any{"exitCode": insp.ExitCode})
			return
		}
		select {
		case <-ctx.Done():
			http.Error(w, "exec did not finish in time", http.StatusGatewayTimeout)
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
	http.Error(w, "exec did not finish in time", http.StatusGatewayTimeout)
}

func handleContainerList(w http.ResponseWriter, r *http.Request) {
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	filter := filters.NewArgs(filters.Arg("label", labelManaged+"=true"))
	summaries, err := cli.ContainerList(r.Context(), container.ListOptions{All: true, Filters: filter})
	if err != nil {
		engineError(w, err)
		return
	}
	type entry struct {
		ID      string            `json:"id"`
		Name    string            `json:"name,omitempty"`
		Running bool              `json:"running"`
		Labels  map[string]string `json:"labels,omitempty"`
	}
	list := make([]entry, 0, len(summaries))
	for _, s := range summaries {
		e := entry{ID: s.ID, Labels: s.Labels, Running: string(s.State) == "running"}
		if len(s.Names) > 0 {
			e.Name = strings.TrimPrefix(s.Names[0], "/")
		}
		list = append(list, e)
	}
	writeJSON(w, http.StatusOK, list)
}

// One log line with its RFC3339 timestamp resolved to epoch nanoseconds; ns
// stays negative when the prefix is not a stamp and the line is kept verbatim.
type logLine struct {
	Ns   int64  `json:"ns"`
	Text string `json:"text"`
}

func handleContainerLogs(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sinceNs, _ := strconv.ParseInt(r.URL.Query().Get("sinceNs"), 10, 64)
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "all"
	}
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	ctx := r.Context()
	insp, err := inspectContainer(ctx, cli, id)
	if err != nil {
		engineError(w, err)
		return
	}
	// docker's `since` is inclusive: advance past the caller's stored cursor.
	since := "0"
	if sinceNs > 0 {
		advanced := sinceNs + int64(time.Millisecond)
		since = fmt.Sprintf("%d.%09d", advanced/1e9, advanced%1e9)
	}
	reader, err := cli.ContainerLogs(ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: true,
		Since:      since,
		Tail:       tail,
	})
	if err != nil {
		engineError(w, err)
		return
	}
	defer reader.Close()

	text, err := readLogStream(insp, reader)
	if err != nil {
		engineError(w, err)
		return
	}

	lines := make([]logLine, 0, 64)
	for _, line := range strings.Split(text, "\n") {
		if line == "" {
			continue
		}
		ns := int64(-1)
		if space := strings.IndexByte(line, ' '); space > 0 {
			if stamp, err := time.Parse(time.RFC3339Nano, line[:space]); err == nil {
				ns = stamp.UnixNano()
				line = line[space+1:]
			}
		}
		lines = append(lines, logLine{Ns: ns, Text: line})
	}
	writeJSON(w, http.StatusOK, map[string]any{"lines": lines})
}

// deleteOwnedContainer removes a name occupant only when App Mesh owns it
// (ownership labels), returning its tail logs for the daemon's archive; a
// foreign occupant blocks with 409.
func deleteOwnedContainer(ctx context.Context, cli *client.Client, name, app string, graceSeconds int) (string, error) {
	insp, err := inspectContainer(ctx, cli, name)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	labels := map[string]string{}
	if insp.Config != nil {
		labels = insp.Config.Labels
	}
	labeledApp := labels[labelApp]
	if labeledApp == "" {
		return "", errdefs.Conflict(fmt.Errorf("container name <%s> is occupied by an unlabeled container; remove it manually", name))
	}
	if labeledApp != app {
		return "", errdefs.Conflict(fmt.Errorf("container name <%s> is owned by application <%s>", name, labeledApp))
	}

	// Leftovers get the SIGTERM grace and log archive, not the force shortcut.
	timeout := graceSeconds
	if err := cli.ContainerStop(ctx, name, container.StopOptions{Timeout: &timeout}); err != nil && !errdefs.IsNotModified(err) {
		return "", err
	}
	archived := ""
	if logs, err := fetchLogText(ctx, cli, insp.ID, "2000"); err == nil {
		archived = logs
	}
	if err := cli.ContainerRemove(ctx, insp.ID, container.RemoveOptions{Force: true, RemoveVolumes: true}); err != nil && !errdefs.IsNotFound(err) {
		return "", err
	}
	return archived, nil
}

// fetchLogText returns the container's demultiplexed, timestamp-stripped log
// text (the archive tail), best effort.
func fetchLogText(ctx context.Context, cli *client.Client, id, tail string) (string, error) {
	insp, err := inspectContainer(ctx, cli, id)
	if err != nil {
		return "", err
	}
	reader, err := cli.ContainerLogs(ctx, id, container.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
		Timestamps: true,
		Tail:       tail,
	})
	if err != nil {
		return "", err
	}
	defer reader.Close()
	return readLogStream(insp, reader)
}

// readLogStream drains a container log stream: a TTY container returns one
// plain byte stream; a non-TTY container multiplexes stdout/stderr in 8-byte
// framed chunks that stdcopy demultiplexes.
func readLogStream(insp container.InspectResponse, reader io.ReadCloser) (string, error) {
	if insp.Config != nil && insp.Config.Tty {
		raw, err := io.ReadAll(reader)
		return string(raw), err
	}
	var buf strings.Builder
	_, err := stdcopy.StdCopy(&buf, &buf, reader)
	return buf.String(), err
}

func handleContainerRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name         string          `json:"name"`
		App          string          `json:"app"`
		LegacyName   string          `json:"legacyName"`
		GraceSeconds int             `json:"graceSeconds"`
		CreateBody   json.RawMessage `json:"createBody"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&body); err != nil ||
		body.Name == "" || body.App == "" || len(body.CreateBody) == 0 {
		http.Error(w, "body must carry name, app and createBody", http.StatusBadRequest)
		return
	}
	cli, err := engineClient()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}

	// The daemon compiles the create-body; ownership labels are stamped here.
	var cfg struct {
		container.Config
		HostConfig *container.HostConfig `json:"HostConfig,omitempty"`
	}
	if err := json.Unmarshal(body.CreateBody, &cfg); err != nil {
		http.Error(w, "createBody: "+err.Error(), http.StatusBadRequest)
		return
	}
	if cfg.Labels == nil {
		cfg.Labels = map[string]string{}
	}
	cfg.Labels[labelManaged] = "true"
	cfg.Labels[labelApp] = body.App
	hostConfig := cfg.HostConfig
	if hostConfig == nil {
		hostConfig = &container.HostConfig{}
	}

	ctx := r.Context()
	var replacedLogs strings.Builder
	for _, name := range []string{body.Name, body.LegacyName} {
		if name == "" {
			continue
		}
		logs, err := deleteOwnedContainer(ctx, cli, name, body.App, body.GraceSeconds)
		if err != nil {
			engineError(w, err)
			return
		}
		replacedLogs.WriteString(logs)
	}

	created, err := cli.ContainerCreate(ctx, &cfg.Config, hostConfig, nil, nil, body.Name)
	if err != nil {
		engineError(w, fmt.Errorf("create failed: %w", err))
		return
	}
	// A failed start must not leave a created-not-running container behind.
	if err := cli.ContainerStart(ctx, created.ID, container.StartOptions{}); err != nil {
		if rmErr := cli.ContainerRemove(context.WithoutCancel(ctx), created.ID, container.RemoveOptions{Force: true}); rmErr != nil {
			logger.Errorf("container run: cleanup after failed start of <%s> failed: %v", created.ID, rmErr)
		}
		engineError(w, fmt.Errorf("start failed: %w", err))
		return
	}
	insp, err := inspectContainer(ctx, cli, created.ID)
	if err != nil {
		engineError(w, fmt.Errorf("inspect failed: %w", err))
		return
	}
	state := projectInspect(insp)
	state.Labels = nil // the daemon knows the labels it asked for
	writeJSON(w, http.StatusOK, map[string]any{
		"id":           state.ID,
		"pid":          state.Pid,
		"running":      state.Running,
		"exitCode":     state.ExitCode,
		"replacedLogs": replacedLogs.String(),
	})
}
