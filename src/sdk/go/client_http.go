// client_http.go
package appmesh

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"go.uber.org/atomic"
)

// AppMeshClient interacts with App Mesh REST APIs.
type AppMeshClient struct {
	req              Requester
	sslClientCert    string // Client SSL certificate file.
	sslClientCertKey string // Client SSL certificate key file.
	sslCAFile        string // Trusted CA file/dir.
}

// Option for NewHttpClient
type Option struct {
	AppMeshUri string // URI of the App Mesh server; use "https://127.0.0.1:6060" for HTTP or "127.0.0.1:6059" for TCP.
	ForwardTo  string // The target host to which all requests will be forwarded; with this set, AppMeshUri will act as a proxy to forward requests.

	SslClientCertificateFile    string // Path to the client certificate file (PEM format), leave empty to disable client authentication.
	SslClientCertificateKeyFile string // Path to the client certificate private key (PEM format), leave empty to disable client authentication.

	// SslTrustedCA controls server certificate verification:
	//   - nil: default App Mesh CA (/opt/appmesh/ssl/ca.pem) if present, else the system trust store
	//   - File path: custom CA file or directory; a missing/unreadable path is a hard error
	//   - Empty string (""): disables verification (legacy form of InsecureSkipVerify)
	// When a CA file/dir is used, system CAs are not included; combine bundles if needed.
	SslTrustedCA *string

	// InsecureSkipVerify disables server certificate verification (testing only; same as SslTrustedCA = "").
	InsecureSkipVerify bool

	JwtToken string // Dex access token set directly without a network call.

	// HTTPTimeout is the overall timeout for http.Client requests; honored when non-zero.
	HTTPTimeout time.Duration
}

// NewHTTPClient builds an HTTP-backed client for App Mesh REST APIs.
// It does not authenticate; obtain a Dex access token separately and call SetToken.
func NewHTTPClient(options Option) (*AppMeshClient, error) {
	return newHTTPClientWithRequester(options, nil)
}
func newHTTPClientWithRequester(options Option, r Requester) (*AppMeshClient, error) {
	clientCertFile := options.SslClientCertificateFile
	clientCertKeyFile := options.SslClientCertificateKeyFile
	caFile := DefaultCAFile
	if options.InsecureSkipVerify {
		// Explicit insecure mode: an empty CA path signals skip-verify to the transports.
		caFile = ""
	} else if options.SslTrustedCA != nil {
		// Legacy form: an explicit empty CA path ("") also disables verification.
		caFile = *options.SslTrustedCA
	} else if !IsFileExist(DefaultCAFile) {
		// No local App Mesh install: fall back to the system trust store.
		// An explicitly configured CA path that is missing remains a hard error.
		caFile = caSystemTrust
	}

	baseURL := options.AppMeshUri
	if baseURL == "" {
		baseURL = DefaultHTTPURI
	}
	parsed, err := ParseURL(baseURL)
	if err != nil {
		return nil, err
	}

	var req Requester
	if r != nil {
		req = r
	} else {
		httpClient, err := newHTTPConnection(clientCertFile, clientCertKeyFile, caFile)
		if err != nil {
			return nil, err
		}
		if options.HTTPTimeout > 0 {
			httpClient.Timeout = options.HTTPTimeout
		}

		req = &HTTPRequester{
			baseURL:        *parsed,
			httpClient:     httpClient,
			forwardingHost: atomic.NewString(options.ForwardTo),
		}
	}

	c := &AppMeshClient{
		req:              req,
		sslClientCert:    clientCertFile,
		sslClientCertKey: clientCertKeyFile,
		sslCAFile:        caFile,
	}

	if options.JwtToken != "" {
		c.SetToken(options.JwtToken)
	}

	return c, nil
}

// SetToken attaches a caller-owned Dex access token in memory. Engine validates it
// when an API request is made; the SDK never sends credentials or refresh tokens.
func (r *AppMeshClient) SetToken(token string) {
	r.req.setToken(strings.TrimSpace(token))
}

// ClearToken removes the locally attached bearer without contacting Engine or Dex.
func (r *AppMeshClient) ClearToken() {
	r.req.setToken("")
}

// GetToken returns the current in-memory Dex access token.
func (r *AppMeshClient) GetToken() string {
	return r.req.getAccessToken()
}

// GetAuthConfig returns the public Dex/OIDC configuration advertised by Engine.
func (r *AppMeshClient) GetAuthConfig() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/auth/config", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("get auth config request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("get auth config", code, string(raw))
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth config: %w", err)
	}
	return result, nil
}

// GetCurrentPrincipal returns the verified Dex principal represented by the bearer.
func (r *AppMeshClient) GetCurrentPrincipal() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/principal/self", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("get current principal request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("get current principal", code, string(raw))
	}
	result := map[string]interface{}{}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("failed to unmarshal current principal: %w", err)
	}
	return result, nil
}

// ListLabels retrieves all available labels from the server.
func (r *AppMeshClient) ListLabels() (Labels, error) {
	code, raw, _, err := r.get("/appmesh/labels", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view labels request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("list labels", code, string(raw))
	}
	labels := Labels{}
	if err := json.Unmarshal(raw, &labels); err != nil {
		return nil, fmt.Errorf("failed to unmarshal labels: %w", err)
	}
	return labels, nil
}

// GetHostResources retrieves system resource information (CPU, memory, disk)
// as the daemon's raw JSON document (schema is daemon-owned).
func (r *AppMeshClient) GetHostResources() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/resources", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view host resources request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("view host resources", code, string(raw))
	}
	res := map[string]interface{}{}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal host resources: %w", err)
	}
	return res, nil
}

// ListApps returns all applications visible to the current user.
func (r *AppMeshClient) ListApps() ([]Application, error) {
	return r.ListAppsContext(context.Background())
}

// ListAppsContext is ListApps bounded by ctx. Prefer it on a single-threaded control
// loop: over TCP a dropped reply otherwise blocks until the connection breaks.
func (r *AppMeshClient) ListAppsContext(ctx context.Context) ([]Application, error) {
	code, raw, _, err := r.req.SendContext(ctx, http.MethodGet, "/appmesh/applications", nil, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view all apps request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("list apps", code, string(raw))
	}
	apps := []Application{}
	if err := json.Unmarshal(raw, &apps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal applications: %w", err)
	}
	return apps, nil
}

// GetApp returns detailed information about a specific application.
func (r *AppMeshClient) GetApp(appName string) (*Application, error) {
	if appName == "" {
		return nil, fmt.Errorf("application name is required")
	}

	path := fmt.Sprintf("/appmesh/app/%s", appName)
	code, raw, _, err := r.get(path, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view app request failed: %w", err)
	}
	if code == http.StatusOK {
		var app Application
		if err := json.Unmarshal(raw, &app); err != nil {
			return nil, fmt.Errorf("failed to unmarshal application: %w", err)
		}
		return &app, nil
	}
	return nil, newAPIError("view app", code, string(raw))
}

// CheckAppHealth checks the health status of an application.
// It returns true when the application is healthy (daemon health value "0").
func (r *AppMeshClient) CheckAppHealth(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, raw, _, err := r.get(fmt.Sprintf("/appmesh/app/%s/health", appName), nil, nil)
	if err != nil {
		return false, fmt.Errorf("check app health request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("check app health", code, string(raw))
	}
	return strings.TrimSpace(string(raw)) == "0", nil
}

// GetAppOutput fetches incremental stdout/stderr from a running or completed application.
// OutputPosition is the next cursor to read from, and ExitCode is populated once the process
// has finished. timeout controls how long the server may long-poll for new output.
// AppOutput.Error is non-nil on transport failure or any non-200 HTTP status.
func (r *AppMeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string, timeout int) AppOutput {
	return r.GetAppOutputContext(context.Background(), appName, stdoutPosition, stdoutIndex, stdoutMaxsize, processUuid, timeout)
}

// GetAppOutputContext is GetAppOutput with a caller-supplied context controlling cancellation.
func (r *AppMeshClient) GetAppOutputContext(ctx context.Context, appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string, timeout int) AppOutput {
	return r.getAppOutput(ctx, appName, stdoutPosition, stdoutIndex, stdoutMaxsize, processUuid, timeout, nil)
}

// getAppOutput implements the output fetch; extraHeaders allows per-request
// X-Target-Host overrides without mutating shared client state.
func (r *AppMeshClient) getAppOutput(ctx context.Context, appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string, timeout int, extraHeaders Headers) AppOutput {
	if appName == "" {
		return AppOutput{
			Error:       fmt.Errorf("application name is required"),
			HttpSuccess: false,
		}
	}

	q := url.Values{}
	q.Set("stdout_position", strconv.FormatInt(stdoutPosition, 10))
	q.Set("stdout_index", strconv.Itoa(stdoutIndex))
	q.Set("stdout_maxsize", strconv.Itoa(stdoutMaxsize))
	q.Set("process_uuid", processUuid)
	q.Set("timeout", strconv.Itoa(timeout))

	code, body, hdr, err := r.req.SendContext(ctx, http.MethodGet, fmt.Sprintf("/appmesh/app/%s/output", appName), q, extraHeaders, nil)
	if err == nil && code != http.StatusOK {
		err = newAPIError("get app output", code, string(body))
	}
	resp := AppOutput{
		Error:       err,
		HttpSuccess: code == http.StatusOK,
		HttpBody:    string(body),
	}

	if exitStr := hdr.Get("X-Exit-Code"); exitStr != "" {
		if ec, err := strconv.Atoi(exitStr); err == nil {
			resp.ExitCode = &ec
		}
	}
	if posStr := hdr.Get("X-Output-Position"); posStr != "" {
		if pos, err := strconv.ParseInt(posStr, 10, 64); err == nil {
			resp.OutputPosition = &pos
		}
	}
	return resp
}

// EnableApp starts or enables the specified application.
func (r *AppMeshClient) EnableApp(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/enable", appName), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("enable app request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("enable app", code, string(raw))
	}
	return true, nil
}

// DisableApp stops or disables the specified application.
func (r *AppMeshClient) DisableApp(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/disable", appName), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("disable app request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("disable app", code, string(raw))
	}
	return true, nil
}

// DeleteApp deletes an application from the system.
// A 404 (app does not exist) is not an error: it returns (false, nil) so callers can
// distinguish "removed now" from "was already absent". Any other non-2xx status is an error.
func (r *AppMeshClient) DeleteApp(appName string) (bool, error) {
	return r.deleteApp(context.Background(), appName, nil)
}

// DeleteAppContext is DeleteApp bounded by ctx.
func (r *AppMeshClient) DeleteAppContext(ctx context.Context, appName string) (bool, error) {
	return r.deleteApp(ctx, appName, nil)
}

// deleteApp implements DeleteApp; extraHeaders allows per-request
// X-Target-Host overrides without mutating shared client state.
func (r *AppMeshClient) deleteApp(ctx context.Context, appName string, extraHeaders Headers) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, _, _, err := r.req.SendContext(ctx, http.MethodDelete, fmt.Sprintf("/appmesh/app/%s", appName), nil, extraHeaders, nil)
	if err != nil {
		return false, fmt.Errorf("remove app request failed: %w", err)
	}

	switch code {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, newAPIErrorText("delete app", code, "", fmt.Sprintf("unexpected status %d when deleting app %q", code, appName))
	}
}

// AddApp registers a new application or updates an existing one.
// Optional subscribeEvents specifies event types to subscribe atomically with registration,
// ensuring no events are missed. Pass event names like "START", "EXIT", "STDOUT",
// or "ALL" for all events. Requires TCP or WSS connection; ignored over HTTP.
// When subscribeEvents is set, the returned Application.SubscriptionID will be non-empty.
func (r *AppMeshClient) AddApp(app Application, subscribeEvents ...string) (*Application, error) {
	if app.Name == "" {
		return nil, fmt.Errorf("application name is required")
	}

	body, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal application %q: %w", app.Name, err)
	}

	var params url.Values
	if len(subscribeEvents) > 0 {
		// START may be pushed before the add-app response. Give the demuxer
		// ownership of the persistent connection before sending the atomic request.
		if sub, ok := r.req.(subscribableRequester); ok {
			sub.enableDemuxer()
		}
		params = url.Values{}
		params.Set("subscribe_events", strings.Join(subscribeEvents, ","))
	}

	code, raw, err := r.put(fmt.Sprintf("/appmesh/app/%s", app.Name), params, nil, body)
	if err != nil {
		return nil, fmt.Errorf("add app request failed: %w", err)
	}
	if code == http.StatusOK {
		var outApp Application
		if err := json.Unmarshal(raw, &outApp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal application response: %w", err)
		}
		return &outApp, nil
	}
	return nil, newAPIError("add app", code, string(raw))
}

// RunTask sends a payload to a running application instance and waits for its response.
// A non-positive timeout falls back to 300 seconds.
func (r *AppMeshClient) RunTask(appName string, payload string, timeout int) (string, error) {
	return r.RunTaskContext(context.Background(), appName, payload, timeout)
}

// RunTaskContext is RunTask with a caller-supplied context controlling cancellation.
func (r *AppMeshClient) RunTaskContext(ctx context.Context, appName string, payload string, timeout int) (string, error) {
	if appName == "" {
		return "", fmt.Errorf("application name is required")
	}

	if timeout <= 0 {
		timeout = 300
	}
	q := url.Values{}
	q.Set("timeout", strconv.Itoa(timeout))
	code, raw, _, err := r.req.SendContext(ctx, http.MethodPost, fmt.Sprintf("/appmesh/app/%s/task", appName), q, nil, bytes.NewBufferString(payload))
	if err != nil {
		return "", fmt.Errorf("run task request failed: %w", err)
	}
	if code == http.StatusOK {
		return string(raw), nil
	}
	return "", newAPIError("run task", code, string(raw))
}

// CancelTask cancels a running task for the specified application.
func (r *AppMeshClient) CancelTask(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, raw, err := r.delete(fmt.Sprintf("/appmesh/app/%s/task", appName))
	if err != nil {
		return false, fmt.Errorf("cancel task request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("cancel task", code, string(raw))
	}
	return true, nil
}

// RunAppAsync starts an application asynchronously and returns a handle for monitoring.
// The returned AppRun captures the current forward target so Wait can keep polling the same
// cluster node even if the client forwarding setting changes later.
func (r *AppMeshClient) RunAppAsync(app Application, maxTime int, lifecycle int) (*AppRun, error) {
	if app.Name == "" {
		return nil, fmt.Errorf("application name is required")
	}

	appJson, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal application: %w", err)
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", maxTime))
	q.Set("lifecycle", fmt.Sprintf("%d", lifecycle))
	code, raw, _, err := r.post("/appmesh/app/run", q, nil, appJson)
	if err != nil {
		return nil, fmt.Errorf("run app async request failed: %w", err)
	}
	if code == http.StatusOK {
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, fmt.Errorf("failed to unmarshal async run response: %w", err)
		}
		name, _ := resp["name"].(string)
		proc, _ := resp["process_uuid"].(string)
		return &AppRun{AppName: name, ProcUid: proc, ForwardTo: r.getForwardTo()}, nil
	}
	return nil, newAPIError("run async", code, string(raw))
}

// Wait polls output for an asynchronous application run until it finishes or times out
// (timeoutSeconds <= 0 waits forever). On success it best-effort removes the temporary run
// app and returns the process exit code. On timeout/cancellation it returns 0 with an
// error wrapping ErrWaitTimeout; the exit code is only meaningful when err is nil.
// Safe for concurrent use: it polls the node captured at RunAppAsync via a per-request
// forwarding override. Works on any transport; for TCP/WSS streaming see WaitForAsyncRun.
func (r *AppMeshClient) Wait(asyncRun *AppRun, stdoutHandler OutputHandler, timeoutSeconds int) (int, error) {
	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	}
	return r.WaitContext(ctx, asyncRun, stdoutHandler)
}

// WaitContext is Wait with a caller-supplied context controlling timeout/cancellation.
func (r *AppMeshClient) WaitContext(ctx context.Context, asyncRun *AppRun, stdoutHandler OutputHandler) (int, error) {
	if asyncRun == nil || asyncRun.ProcUid == "" {
		return 0, fmt.Errorf("invalid async run object")
	}

	// Poll the node the run was started on (captured at RunAppAsync) via a per-request
	// X-Target-Host override; an empty ForwardTo explicitly disables forwarding for
	// these requests regardless of the client-wide setting.
	forwardHeaders := Headers{headerTargetHost: asyncRun.ForwardTo}

	lastPos := int64(0)
	interval := 1 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("%w: %v", ErrWaitTimeout, ctx.Err())
		case <-ticker.C:
			out := r.getAppOutput(ctx, asyncRun.AppName, lastPos, 0, 10240, asyncRun.ProcUid, int(interval.Seconds()), forwardHeaders)
			if out.HttpBody != "" && stdoutHandler != nil {
				stdoutHandler(out.HttpBody, lastPos)
			}
			if out.OutputPosition != nil {
				lastPos = *out.OutputPosition
			}
			if out.ExitCode != nil {
				// best-effort cleanup on the same node
				_, _ = r.deleteApp(context.Background(), asyncRun.AppName, forwardHeaders)
				return *out.ExitCode, nil
			}
			if !out.HttpSuccess {
				return 0, fmt.Errorf("failed to get app output: %v", out.Error)
			}
		}
	}
}

// RunAppSync runs an application synchronously and returns the exit code plus collected stdout.
// The exit code is derived from the X-Exit-Code response header when present.
func (r *AppMeshClient) RunAppSync(app Application, maxTime int, lifecycle int) (int, string, error) {
	appJson, err := json.Marshal(app)
	if err != nil {
		return 0, "", fmt.Errorf("failed to marshal application: %w", err)
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", maxTime))
	q.Set("lifecycle", fmt.Sprintf("%d", lifecycle))
	code, raw, hdr, err := r.post("/appmesh/app/syncrun", q, nil, appJson)
	if err != nil {
		return 0, "", fmt.Errorf("run app sync request failed: %w", err)
	}
	exit := 0
	if ec := hdr.Get("X-Exit-Code"); ec != "" {
		if v, err2 := strconv.Atoi(ec); err2 == nil {
			exit = v
		}
	}
	out := string(raw)
	if code == http.StatusOK {
		return exit, out, nil
	}
	return exit, out, newAPIError("sync run", code, out)
}

// UploadFile uploads a local file to the remote server.
// When applyFileAttributes is true, local POSIX mode/owner/group metadata is sent in headers
// so the server can recreate permissions when supported.
func (r *AppMeshClient) UploadFile(localFile, remoteFile string, applyFileAttributes bool) error {
	// Default the remote filename to the local file's base name when omitted.
	if remoteFile == "" {
		remoteFile = filepath.Base(localFile)
	}
	if localFile == "" {
		return fmt.Errorf("local file path is required")
	}

	f, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer f.Close()

	// Stream the multipart body through a pipe so the file is never buffered in memory.
	// The small "filename" form field is written before the streamed file part (matching
	// the Python SDK); the server locates the "file" part by name, so order is tolerated.
	pr, pw := io.Pipe()
	defer pr.Close() // unblocks the writer goroutine if the request fails early
	writer := multipart.NewWriter(pw)
	go func() {
		if err := writer.WriteField("filename", filepath.Base(remoteFile)); err != nil {
			pw.CloseWithError(fmt.Errorf("failed to write filename field: %w", err))
			return
		}
		part, err := writer.CreateFormFile("file", filepath.Base(localFile))
		if err != nil {
			pw.CloseWithError(fmt.Errorf("failed to create form file: %w", err))
			return
		}
		if _, err := io.Copy(part, f); err != nil {
			pw.CloseWithError(fmt.Errorf("failed to copy file data: %w", err))
			return
		}
		pw.CloseWithError(writer.Close())
	}()

	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"X-File-Path":  url.QueryEscape(remoteFile),
	}
	// Include POSIX metadata headers (X-File-Mode/X-File-User/X-File-Group) so the
	// server recreates the file's permissions and ownership (see openapi.yaml).
	if applyFileAttributes {
		attrs, err := fileAttributes(localFile)
		if err != nil {
			return fmt.Errorf("failed to read file attributes of %q: %w", localFile, err)
		}
		for key, value := range attrs {
			headers[key] = value
		}
	}

	code, raw, _, err := r.req.Send(http.MethodPost, "/appmesh/file/upload", nil, headers, pr)
	if err != nil {
		return fmt.Errorf("upload file request failed: %w", err)
	}
	if code != http.StatusOK {
		return newAPIError("upload", code, string(raw))
	}
	return nil
}

// DownloadFile downloads a remote file to local path.
// When applyFileAttributes is true, POSIX mode/owner/group metadata from response headers is
// applied locally on a best-effort basis.
func (r *AppMeshClient) DownloadFile(remoteFile, localFile string, applyFileAttributes bool) error {
	// Default the local filename to the remote file's base name when omitted.
	if localFile == "" {
		localFile = filepath.Base(remoteFile)
	}
	if remoteFile == "" {
		return fmt.Errorf("remote file path is required")
	}

	headers := map[string]string{"X-File-Path": url.QueryEscape(remoteFile)}
	code, body, respHdr, err := r.getStream("/appmesh/file/download", nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	defer body.Close()
	if code != http.StatusOK {
		raw, _ := io.ReadAll(body) // error responses are small
		return newAPIError("download", code, string(raw))
	}
	out, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer out.Close()
	if _, err := io.Copy(out, body); err != nil {
		return fmt.Errorf("failed to write file data: %w", err)
	}

	if applyFileAttributes {
		_ = ApplyFileAttributes(localFile, respHdr)
	}

	return nil
}

// GetConfig retrieves the current App Mesh configuration as the daemon's raw
// JSON document (schema is daemon-owned).
func (r *AppMeshClient) GetConfig() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/config", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view config request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("view config", code, string(raw))
	}
	cfg := map[string]interface{}{}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return cfg, nil
}

// SetConfig updates the App Mesh configuration and returns the new configuration.
// Input and return value are the daemon's raw JSON config document (see GetConfig).
func (r *AppMeshClient) SetConfig(config map[string]interface{}) (map[string]interface{}, error) {
	if config == nil {
		return nil, fmt.Errorf("config JSON is required")
	}

	body, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal config: %w", err)
	}
	code, raw, _, err := r.post("/appmesh/config", nil, nil, body)
	if err != nil {
		return nil, fmt.Errorf("set config request failed: %w", err)
	}
	if code == http.StatusOK {
		out := map[string]interface{}{}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, fmt.Errorf("failed to unmarshal config response: %w", err)
		}
		return out, nil
	}
	return nil, newAPIError("set config", code, string(raw))
}

// SetLogLevel updates the application log level and returns the new level.
func (r *AppMeshClient) SetLogLevel(level string) (string, error) {
	if level == "" {
		return "", fmt.Errorf("log level is required")
	}

	cfg := map[string]interface{}{
		"BaseConfig": map[string]interface{}{
			"LogLevel": level,
		},
	}
	body, err := json.Marshal(cfg)
	if err != nil {
		return "", fmt.Errorf("failed to marshal log level config: %w", err)
	}
	code, raw, _, err := r.post("/appmesh/config", nil, nil, body)
	if err != nil {
		return "", fmt.Errorf("set log level request failed: %w", err)
	}
	if code == http.StatusOK {
		resp := map[string]interface{}{}
		if err := json.Unmarshal(raw, &resp); err == nil {
			if baseCfg, ok := resp["BaseConfig"].(map[string]interface{}); ok {
				if ll, ok := baseCfg["LogLevel"].(string); ok {
					return ll, nil
				}
			}
		}
	}
	return "", newAPIError("set log level", code, string(raw))
}

// GetMetrics retrieves Prometheus metrics text from the server.
func (r *AppMeshClient) GetMetrics() (string, error) {
	code, raw, _, err := r.get("/appmesh/metrics", nil, nil)
	if err != nil {
		return "", fmt.Errorf("get metrics request failed: %w", err)
	}
	if code == http.StatusOK {
		return string(raw), nil
	}
	return "", newAPIError("get metrics", code, string(raw))
}

// ListPrincipals returns App Mesh authorization overlays keyed by immutable Dex principal ID.
func (r *AppMeshClient) ListPrincipals() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/principals", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("list principals request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("list principals", code, string(raw))
	}
	principals := map[string]interface{}{}
	if err := json.Unmarshal(raw, &principals); err != nil {
		return nil, fmt.Errorf("failed to unmarshal principals: %w", err)
	}
	return principals, nil
}

// UpdatePrincipal creates or replaces an App Mesh authorization overlay. It does
// not create or modify an identity-provider account.
func (r *AppMeshClient) UpdatePrincipal(principalID string, policy map[string]interface{}) (bool, error) {
	if strings.TrimSpace(principalID) == "" || policy == nil {
		return false, fmt.Errorf("principal ID and policy are required")
	}
	body, err := json.Marshal(policy)
	if err != nil {
		return false, fmt.Errorf("failed to marshal principal policy: %w", err)
	}
	code, raw, _, err := r.post("/appmesh/principal/"+url.PathEscape(principalID), nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("update principal request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("update principal", code, string(raw))
	}
	return true, nil
}

// DeletePrincipal removes only the Engine authorization overlay.
func (r *AppMeshClient) DeletePrincipal(principalID string) (bool, error) {
	if strings.TrimSpace(principalID) == "" {
		return false, fmt.Errorf("principal ID is required")
	}
	code, raw, _, err := r.req.Send(http.MethodDelete, "/appmesh/principal/"+url.PathEscape(principalID), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("delete principal request failed: %w", err)
	}
	if code != http.StatusNoContent && code != http.StatusOK {
		return false, newAPIError("delete principal", code, string(raw))
	}
	return true, nil
}

// GetPrincipalPermissions returns effective permissions for the current principal.
func (r *AppMeshClient) GetPrincipalPermissions() ([]string, error) {
	code, raw, _, err := r.get("/appmesh/principal/self/permissions", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("get principal permissions request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("get principal permissions", code, string(raw))
	}
	var permissions []string
	if err := json.Unmarshal(raw, &permissions); err != nil {
		return nil, fmt.Errorf("failed to unmarshal principal permissions: %w", err)
	}
	return permissions, nil
}

// GetCurrentUser is a source-compatibility alias for GetCurrentPrincipal. It does
// not query or mutate an identity-provider user account.
func (r *AppMeshClient) GetCurrentUser() (map[string]interface{}, error) {
	return r.GetCurrentPrincipal()
}

// GetUserPermissions is a source-compatibility alias for GetPrincipalPermissions.
func (r *AppMeshClient) GetUserPermissions() ([]string, error) {
	return r.GetPrincipalPermissions()
}

// ListPermissions retrieves all available permissions in the system.
func (r *AppMeshClient) ListPermissions() ([]string, error) {
	code, raw, _, err := r.get("/appmesh/permissions", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view permissions request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("view permissions", code, string(raw))
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
	}
	return perms, nil
}

// ListRoles retrieves all roles with their permission definitions.
// The returned map has role names as keys and slices of permission strings as values.
func (r *AppMeshClient) ListRoles() (map[string][]string, error) {
	code, raw, _, err := r.get("/appmesh/roles", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view roles request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, newAPIError("list roles", code, string(raw))
	}
	roles := map[string][]string{}
	if err := json.Unmarshal(raw, &roles); err != nil {
		return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
	}
	return roles, nil
}

// UpdateRole creates or updates a role with specified permissions.
func (r *AppMeshClient) UpdateRole(roleName string, rolePerm []string) (bool, error) {
	if roleName == "" {
		return false, fmt.Errorf("role name is required")
	}

	body, err := json.Marshal(rolePerm)
	if err != nil {
		return false, fmt.Errorf("failed to marshal role permissions: %w", err)
	}
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/role/%s", roleName), nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("update role request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIErrorText("update role", code, "", fmt.Sprintf("update role failed with status %d", code))
	}
	return true, nil
}

// DeleteRole removes a role from the system.
func (r *AppMeshClient) DeleteRole(roleName string) (bool, error) {
	if roleName == "" {
		return false, fmt.Errorf("role name is required")
	}

	code, _, err := r.delete(fmt.Sprintf("/appmesh/role/%s", roleName))
	if err != nil {
		return false, fmt.Errorf("delete role request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIErrorText("delete role", code, "", fmt.Sprintf("delete role failed with status %d", code))
	}
	return true, nil
}

// AddLabel creates or updates a label with the specified name and value.
func (r *AppMeshClient) AddLabel(labelName string, labelValue string) (bool, error) {
	if labelName == "" {
		return false, fmt.Errorf("label name is required")
	}

	q := url.Values{}
	q.Set("value", labelValue)
	code, raw, err := r.put(fmt.Sprintf("/appmesh/label/%s", url.PathEscape(labelName)), q, nil, nil)
	if err != nil {
		return false, fmt.Errorf("add label request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("add label", code, string(raw))
	}
	return true, nil
}

// DeleteLabel removes a label from the system.
func (r *AppMeshClient) DeleteLabel(labelName string) (bool, error) {
	if labelName == "" {
		return false, fmt.Errorf("label name is required")
	}

	code, raw, err := r.delete(fmt.Sprintf("/appmesh/label/%s", url.PathEscape(labelName)))
	if err != nil {
		return false, fmt.Errorf("delete label request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, newAPIError("delete label", code, string(raw))
	}
	return true, nil
}

// Close the client and release resources.
func (r *AppMeshClient) Close() {
	r.req.Close()
}

// getForwardTo returns the current forward target host in a thread-safe manner.
func (r *AppMeshClient) getForwardTo() string {
	return r.req.getForwardTo()
}

// updateForwardTo sets the forward target host in a thread-safe manner.
func (r *AppMeshClient) updateForwardTo(host string) {
	r.req.setForwardTo(host)
}

func (r *AppMeshClient) get(path string, params url.Values, headers map[string]string) (int, []byte, http.Header, error) {
	return r.req.Send(http.MethodGet, path, params, headers, nil)
}

// streamingRequester is implemented by transports that can stream a response body (HTTP).
type streamingRequester interface {
	getStream(apiPath string, queries url.Values, headers map[string]string) (int, io.ReadCloser, http.Header, error)
}

// getStream performs a GET request returning the response body as a stream when the
// transport supports it (HTTP); other transports fall back to the buffered response.
// The caller must close the returned body.
func (r *AppMeshClient) getStream(path string, params url.Values, headers map[string]string) (int, io.ReadCloser, http.Header, error) {
	if s, ok := r.req.(streamingRequester); ok {
		return s.getStream(path, params, headers)
	}
	code, raw, hdr, err := r.req.Send(http.MethodGet, path, params, headers, nil)
	if err != nil {
		return code, nil, hdr, err
	}
	return code, io.NopCloser(bytes.NewReader(raw)), hdr, nil
}

func (r *AppMeshClient) put(path string, params url.Values, headers map[string]string, body []byte) (int, []byte, error) {
	code, raw, _, err := r.req.Send(http.MethodPut, path, params, headers, bytes.NewBuffer(body))
	return code, raw, err
}

func (r *AppMeshClient) post(path string, params url.Values, headers map[string]string, body []byte) (int, []byte, http.Header, error) {
	return r.req.Send(http.MethodPost, path, params, headers, bytes.NewBuffer(body))
}

func (r *AppMeshClient) delete(path string) (int, []byte, error) {
	code, raw, _, err := r.req.Send(http.MethodDelete, path, nil, nil, nil)
	return code, raw, err
}
