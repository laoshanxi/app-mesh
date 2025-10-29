// client_http.go
package appmesh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/pquerna/otp"
	"go.uber.org/atomic"
)

// AppMeshClient interacts with App Mesh REST APIs.
type AppMeshClient struct {
	req              Requester
	forwardTo        string // Forward target host
	cookieFile       string
	sslClientCert    string // Client SSL certificate file.
	sslClientCertKey string // Client SSL certificate key file.
	sslCAFile        string // Trusted CA file/dir.

}

// Option for NewHttpClient
type Option struct {
	AppMeshUri string // URI of the App Mesh server; use "https://127.0.0.1:6060" for HTTP or "127.0.0.1:6059" for TCP.
	CookieFile string // Cookie file path for persistence
	ForwardTo  string // The target host to which all requests will be forwarded; with this set, AppMeshUri will act as a proxy to forward requests.

	SslClientCertificateFile    string // Path to the client certificate file (PEM format), leave empty to disable client authentication.
	SslClientCertificateKeyFile string // Path to the client certificate private key (PEM format), leave empty to disable client authentication.

	// SslTrustedCA controls server certificate verification:
	//   - Empty string (""): disables server certificate verification
	//   - nil: uses default App Mesh CA at /opt/appmesh/ssl/ca.pem
	//   - File path: uses custom CA file or directory
	// Note: System CAs are not included by default. Create a combined CA bundle if needed.
	SslTrustedCA *string

	HttpTimeoutMinutes *time.Duration // Timeout for http.Client requests in minutes.
	tcpOnly            *bool          // Indicates if the client is for TCP connections only, skip create http.Client.
}

// NewHTTPClient builds a new client instance for interacting with App Mesh REST APIs.
func NewHTTPClient(options Option) (*AppMeshClient, error) {
	return newHTTPClientWithRequester(options, nil)
}
func newHTTPClientWithRequester(options Option, r Requester) (*AppMeshClient, error) {
	clientCertFile := options.SslClientCertificateFile
	clientCertKeyFile := options.SslClientCertificateKeyFile
	caFile := DEFAULT_CA_FILE
	if options.SslTrustedCA != nil {
		caFile = *options.SslTrustedCA
	}

	baseURL := options.AppMeshUri
	if baseURL == "" {
		baseURL = DEFAULT_HTTP_URI
	}
	parsed, err := ParseURL(baseURL)
	if err != nil {
		return nil, err
	}

	var req Requester
	if r != nil {
		req = r
	} else {
		var httpClient *HTTPConnection

		if options.tcpOnly == nil || !*options.tcpOnly {
			httpClient = newHTTPConnection(clientCertFile, clientCertKeyFile, caFile, options.CookieFile)
			if options.HttpTimeoutMinutes != nil {
				httpClient.Timeout = *options.HttpTimeoutMinutes
			}
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

	return c, nil
}

// Login authenticates the user with username/password and optional TOTP code.
func (r *AppMeshClient) Login(user string, password string, totpCode string, timeoutSeconds int, audience string) (string, error) {
	if user == "" || password == "" {
		return "", fmt.Errorf("username and password are required")
	}

	headers := map[string]string{
		"Authorization":            "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
		"X-Expire-Seconds":         fmt.Sprintf("%d", timeoutSeconds),
		HTTP_HEADER_JWT_SET_COOKIE: strconv.FormatBool(true),
	}
	if audience != "" && audience != DEFAULT_JWT_AUDIENCE {
		headers["X-Audience"] = audience
	}
	if totpCode != "" {
		headers["X-Totp-Code"] = totpCode
	}

	code, raw, _, err := r.post("/appmesh/login", nil, headers, nil)
	if err != nil {
		return "", fmt.Errorf("login request failed: %w", err)
	}
	switch code {
	case http.StatusOK:
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return "", fmt.Errorf("failed to decode JWT response: %w", err)
		}
		r.req.handleTokenUpdate(result.AccessToken)
		return "", nil

	case http.StatusPreconditionRequired:
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err == nil {
			if challenge, ok := resp["totp_challenge"].(string); ok {
				if totpCode == "" {
					return challenge, nil
				}
				r.ValidateTotp(user, challenge, totpCode, timeoutSeconds)
				return "", nil
			}
		}
		return "", fmt.Errorf("TOTP challenge required or server error: %s", string(raw))

	default:
		return "", fmt.Errorf("login failed with status %d: %s", code, string(raw))
	}
}

// ValidateTotp validates TOTP challenge.
func (r *AppMeshClient) ValidateTotp(username string, challenge string, totpCode string, timeoutSeconds int) error {
	if username == "" || challenge == "" || totpCode == "" {
		return fmt.Errorf("username, challenge, and TOTP code are required")
	}

	type TotpReq struct {
		UserName      string `json:"user_name"`
		TotpCode      string `json:"totp_code"`
		TotpChallenge string `json:"totp_challenge"`
		ExpireSeconds int    `json:"expire_seconds"`
	}
	req := TotpReq{
		UserName:      username,
		TotpCode:      totpCode,
		TotpChallenge: challenge,
		ExpireSeconds: timeoutSeconds,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal TOTP request: %w", err)
	}
	code, raw, _, err := r.post("/appmesh/totp/validate", nil, nil, body)
	if err != nil {
		return fmt.Errorf("TOTP validation request failed: %w", err)
	}
	if code == http.StatusOK {
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return fmt.Errorf("failed to decode JWT response: %w", err)
		}
		r.req.handleTokenUpdate(result.AccessToken)
		return nil
	}
	return fmt.Errorf("TOTP validation failed with status %d: %s", code, string(raw))
}

// Logout logs out the current session and invalidates the token.
func (r *AppMeshClient) Logout() (bool, error) {
	code, _, _, err := r.post("/appmesh/self/logoff", nil, nil, nil)
	r.req.handleTokenUpdate("")
	return code == http.StatusOK, err
}

// Authenticate checks token validity and optional permission against the server.
func (r *AppMeshClient) Authenticate(jwtToken string, permission string, audience string, apply bool) (bool, error) {
	if jwtToken == "" {
		return false, fmt.Errorf("JWT token is required")
	}

	headers := Headers{}
	if permission != "" {
		headers["X-Permission"] = permission
	}
	if audience != "" && audience != DEFAULT_JWT_AUDIENCE {
		headers["X-Audience"] = audience
	}
	if apply {
		headers[HTTP_HEADER_JWT_SET_COOKIE] = strconv.FormatBool(true)
	}

	code, _, _, err := r.post("/appmesh/auth", nil, headers, nil)
	if err != nil {
		return false, fmt.Errorf("authentication request failed: %w", err)
	}

	if apply && code == http.StatusOK {
		r.req.handleTokenUpdate(jwtToken)
	}
	return code == http.StatusOK, nil
}

// RenewToken renews the current JWT token before expiration.
func (r *AppMeshClient) RenewToken() (bool, error) {
	code, raw, _, err := r.post("/appmesh/token/renew", nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("token renewal request failed: %w", err)
	}
	if code == http.StatusOK {
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return false, fmt.Errorf("failed to decode JWT response: %w", err)
		}
		r.req.handleTokenUpdate(result.AccessToken)
		return true, nil
	}
	return false, fmt.Errorf("token renewal failed with status %d: %s", code, string(raw))
}

// GetTotpSecret retrieves the TOTP secret for setting up 2FA authentication.
func (r *AppMeshClient) GetTotpSecret() (string, error) {
	code, raw, _, err := r.post("/appmesh/totp/secret", nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get TOTP secret: %w", err)
	}
	if code == http.StatusOK {
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return "", fmt.Errorf("failed to unmarshal TOTP secret response: %w", err)
		}
		if mfa, ok := resp["mfa_uri"].(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(mfa)
			if err != nil {
				return "", fmt.Errorf("failed to decode MFA URI: %w", err)
			}
			key, err := otp.NewKeyFromURL(string(decoded))
			if err != nil {
				return "", fmt.Errorf("failed to parse OTP key from URL: %w", err)
			}
			return key.Secret(), nil
		}
	}
	return "", fmt.Errorf("failed to get TOTP secret with status %d: %s", code, string(raw))
}

// EnableTotp configures TOTP 2FA for the current user and returns a new token.
func (r *AppMeshClient) EnableTotp(totpCode string) (string, error) {
	if totpCode == "" {
		return "", fmt.Errorf("TOTP code is required")
	}

	headers := map[string]string{"X-Totp-Code": totpCode}
	code, raw, _, err := r.post("/appmesh/totp/setup", nil, headers, nil)
	if err != nil {
		return "", fmt.Errorf("TOTP setup request failed: %w", err)
	}
	if code == http.StatusOK {
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return "", fmt.Errorf("failed to decode JWT response: %w", err)
		}
		r.req.handleTokenUpdate(result.AccessToken)
		return result.AccessToken, nil
	}
	return "", fmt.Errorf("TOTP setup failed with status %d: %s", code, string(raw))
}

// DisableTotp disables TOTP 2FA for the specified user (or "self" if empty).
func (r *AppMeshClient) DisableTotp(user string) (bool, error) {
	if user == "" {
		user = "self"
	}
	path := fmt.Sprintf("/appmesh/totp/%s/disable", user)
	code, _, _, err := r.post(path, nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("disable TOTP request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// GetTags retrieves all available labels/tags from the server.
func (r *AppMeshClient) GetTags() (Labels, error) {
	code, raw, _, err := r.get("/appmesh/labels", nil, nil)
	labels := Labels{}
	if err != nil {
		return labels, fmt.Errorf("view tags request failed: %w", err)
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &labels); err != nil {
			return labels, fmt.Errorf("failed to unmarshal tags: %w", err)
		}
	}
	return labels, nil
}

// GetHostResources retrieves system resource information (CPU, memory, disk).
func (r *AppMeshClient) GetHostResources() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/resources", nil, nil)
	res := map[string]interface{}{}
	if err != nil {
		return res, fmt.Errorf("view host resources request failed: %w", err)
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &res); err != nil {
			return res, fmt.Errorf("failed to unmarshal host resources: %w", err)
		}
	}
	return res, nil
}

// ListApps returns all applications visible to the current user.
func (r *AppMeshClient) ListApps() ([]Application, error) {
	code, raw, _, err := r.get("/appmesh/applications", nil, nil)
	apps := []Application{}
	if err != nil {
		return apps, fmt.Errorf("view all apps request failed: %w", err)
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &apps); err != nil {
			return apps, fmt.Errorf("failed to unmarshal applications: %w", err)
		}
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
	return nil, fmt.Errorf("view app failed with status %d: %s", code, string(raw))
}

// GetAppOutput fetches stdout/stderr output from a running or completed application.
func (r *AppMeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string, timeout int) AppOutput {
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

	code, body, hdr, err := r.get(fmt.Sprintf("/appmesh/app/%s/output", appName), q, nil)
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

	code, _, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/enable", appName), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("enable app request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// DisableApp stops or disables the specified application.
func (r *AppMeshClient) DisableApp(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, _, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/disable", appName), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("disable app request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// RemoveApp deletes an application from the system.
func (r *AppMeshClient) RemoveApp(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, _, err := r.delete(fmt.Sprintf("/appmesh/app/%s", appName))
	if err != nil {
		return false, fmt.Errorf("remove app request failed: %w", err)
	}

	switch code {
	case http.StatusOK, http.StatusNoContent:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	default:
		return false, fmt.Errorf("unexpected status %d when deleting app %q", code, appName)
	}
}

// AddApp registers a new application or updates an existing one.
func (r *AppMeshClient) AddApp(app Application) (*Application, error) {
	if app.Name == "" {
		return nil, fmt.Errorf("application name is required")
	}

	body, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal application %q: %w", app.Name, err)
	}
	code, raw, err := r.put(fmt.Sprintf("/appmesh/app/%s", app.Name), nil, nil, body)
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
	return nil, fmt.Errorf("add app failed with status %d: %s", code, string(raw))
}

// RunTask sends a message to a running application and waits for response.
func (r *AppMeshClient) RunTask(appName string, payload string, timeout int) (string, error) {
	if appName == "" {
		return "", fmt.Errorf("application name is required")
	}

	if timeout <= 0 {
		timeout = 300
	}
	q := url.Values{}
	q.Set("timeout", strconv.Itoa(timeout))
	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/task", appName), q, nil, []byte(payload))
	if err != nil {
		return "", fmt.Errorf("run task request failed: %w", err)
	}
	if code == http.StatusOK {
		return string(raw), nil
	}
	return "", fmt.Errorf("run task failed with status %d: %s", code, string(raw))
}

// CancelTask cancels a running task for the specified application.
func (r *AppMeshClient) CancelTask(appName string) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, _, err := r.delete(fmt.Sprintf("/appmesh/app/%s/task", appName))
	if err != nil {
		return false, fmt.Errorf("cancel task request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// RunAppAsync starts an application asynchronously and returns a handle for monitoring.
func (r *AppMeshClient) RunAppAsync(app Application, maxTimeSeconds int, lifeCycleSeconds int) (*AppRun, error) {
	if app.Name == "" {
		return nil, fmt.Errorf("application name is required")
	}

	appJson, err := json.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal application: %w", err)
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", maxTimeSeconds))
	q.Set("lifecycle", fmt.Sprintf("%d", lifeCycleSeconds))
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
	return nil, fmt.Errorf("run async failed with status %d: %s", code, string(raw))
}

// Wait waits for an asynchronous application run to complete and optionally prints output.
func (r *AppMeshClient) Wait(asyncRun *AppRun, stdoutPrint bool, timeoutSeconds int) (int, error) {
	if asyncRun == nil || asyncRun.ProcUid == "" {
		return 0, fmt.Errorf("invalid async run object")
	}

	ctx := context.Background()
	var cancel context.CancelFunc
	if timeoutSeconds > 0 {
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
		defer cancel()
	}

	lastPos := int64(0)
	interval := 1 * time.Second
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("wait timed out: %w", ctx.Err())
		case <-ticker.C:
			out := r.GetAppOutput(asyncRun.AppName, lastPos, 0, 10240, asyncRun.ProcUid, int(interval.Seconds()))
			if out.HttpBody != "" && stdoutPrint {
				fmt.Print(out.HttpBody)
			}
			if out.OutputPosition != nil {
				lastPos = *out.OutputPosition
			}
			if out.ExitCode != nil {
				// best-effort cleanup
				_, _ = r.RemoveApp(asyncRun.AppName)
				return *out.ExitCode, nil
			}
			if !out.HttpSuccess {
				return 0, fmt.Errorf("failed to get app output: %v", out.Error)
			}
		}
	}
}

// RunAppSync runs an application synchronously and returns exit code and output.
func (r *AppMeshClient) RunAppSync(app Application, stdoutPrint bool, maxTimeSeconds int, lifeCycleSeconds int) (int, string, error) {
	if app.Name == "" {
		return 0, "", fmt.Errorf("application name is required")
	}

	appJson, err := json.Marshal(app)
	if err != nil {
		return 0, "", fmt.Errorf("failed to marshal application: %w", err)
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", maxTimeSeconds))
	q.Set("lifecycle", fmt.Sprintf("%d", lifeCycleSeconds))
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
	if stdoutPrint {
		fmt.Print(out)
	}
	if code == http.StatusOK {
		return exit, out, nil
	}
	return exit, out, fmt.Errorf("sync run failed with status %d: %s", code, out)
}

// UploadFile uploads a local file to the remote server with optional file attributes.
func (r *AppMeshClient) UploadFile(localFile, remoteFile string, applyFileAttributes bool) error {
	if localFile == "" || remoteFile == "" {
		return fmt.Errorf("local file and remote file paths are required")
	}

	f, err := os.Open(localFile)
	if err != nil {
		return fmt.Errorf("failed to open local file: %w", err)
	}
	defer f.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(localFile))
	if err != nil {
		return fmt.Errorf("failed to create form file: %w", err)
	}
	if _, err := io.Copy(part, f); err != nil {
		return fmt.Errorf("failed to copy file data: %w", err)
	}
	// set filename form field too if server expects it
	if err := writer.WriteField("filename", filepath.Base(remoteFile)); err != nil {
		return fmt.Errorf("failed to write filename field: %w", err)
	}

	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close multipart writer: %w", err)
	}
	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"X-File-Path":  url.QueryEscape(remoteFile),
	}
	// Optionally include attributes (placeholder — server must support)
	if applyFileAttributes && runtime.GOOS != "windows" {
		if fi, err := os.Stat(localFile); err == nil {
			mode := fi.Mode().Perm()
			headers["X-File-Mode"] = fmt.Sprintf("%d", mode)
		}
	}

	code, raw, _, err := r.post("/appmesh/file/upload", nil, headers, body.Bytes())
	if err != nil {
		return fmt.Errorf("upload file request failed: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("upload failed with status %d: %s", code, string(raw))
	}
	return nil
}

// DownloadFile downloads a remote file to local path with optional file attributes.
func (r *AppMeshClient) DownloadFile(remoteFile, localFile string, applyFileAttributes bool) error {
	if remoteFile == "" || localFile == "" {
		return fmt.Errorf("remote file and local file paths are required")
	}

	headers := map[string]string{"X-File-Path": url.QueryEscape(remoteFile)}
	code, raw, respHdr, err := r.get("/appmesh/file/download", nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("download failed with status %d: %s", code, string(raw))
	}
	out, err := os.Create(localFile)
	if err != nil {
		return fmt.Errorf("failed to create local file: %w", err)
	}
	defer out.Close()
	if _, err := out.Write(raw); err != nil {
		return fmt.Errorf("failed to write file data: %w", err)
	}
	// apply attributes if requested (placeholder)
	if applyFileAttributes && runtime.GOOS != "windows" {
		if modeStr := respHdr.Get("X-File-Mode"); modeStr != "" {
			if m, err := strconv.ParseInt(modeStr, 10, 32); err == nil {
				if err := os.Chmod(localFile, os.FileMode(m)); err != nil {
					// Log but don't fail the entire operation
					fmt.Printf("Warning: failed to set file permissions: %v\n", err)
				}
			}
		}
	}
	return nil
}

// GetConfig retrieves the current App Mesh configuration.
func (r *AppMeshClient) GetConfig() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/config", nil, nil)
	cfg := map[string]interface{}{}
	if err != nil {
		return cfg, fmt.Errorf("view config request failed: %w", err)
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, fmt.Errorf("failed to unmarshal config: %w", err)
		}
	}
	return cfg, nil
}

// SetConfig updates the App Mesh configuration and returns the new configuration.
func (r *AppMeshClient) SetConfig(configJson map[string]interface{}) (map[string]interface{}, error) {
	if configJson == nil {
		return nil, fmt.Errorf("config JSON is required")
	}

	body, err := json.Marshal(configJson)
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
	return nil, fmt.Errorf("set config failed with status %d: %s", code, string(raw))
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
	return "", fmt.Errorf("set log level failed with status %d: %s", code, string(raw))
}

// UpdatePassword changes the password for a user (default is "self").
func (r *AppMeshClient) UpdatePassword(oldPassword, newPassword, userName string) (bool, error) {
	if oldPassword == "" || newPassword == "" {
		return false, fmt.Errorf("old password and new password are required")
	}

	if userName == "" {
		userName = "self"
	}
	payload := map[string]string{
		"old_password": base64.StdEncoding.EncodeToString([]byte(oldPassword)),
		"new_password": base64.StdEncoding.EncodeToString([]byte(newPassword)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal password update payload: %w", err)
	}
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/passwd", userName), nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("update password request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("update password failed with status %d", code)
	}
	return true, nil
}

// AddUser creates a new user with the specified configuration.
func (r *AppMeshClient) AddUser(userName string, userJson map[string]interface{}) (bool, error) {
	if userName == "" {
		return false, fmt.Errorf("username is required")
	}
	if userJson == nil {
		return false, fmt.Errorf("user JSON is required")
	}

	body, err := json.Marshal(userJson)
	if err != nil {
		return false, fmt.Errorf("failed to marshal user JSON: %w", err)
	}
	code, _, err := r.put(fmt.Sprintf("/appmesh/user/%s", userName), nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("add user request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// DeleteUser removes a user from the system.
func (r *AppMeshClient) DeleteUser(userName string) (bool, error) {
	if userName == "" {
		return false, fmt.Errorf("username is required")
	}

	code, _, err := r.delete(fmt.Sprintf("/appmesh/user/%s", userName))
	if err != nil {
		return false, fmt.Errorf("delete user request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// LockUser disables login for the specified user.
func (r *AppMeshClient) LockUser(userName string) (bool, error) {
	if userName == "" {
		return false, fmt.Errorf("username is required")
	}

	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/lock", userName), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("lock user request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("lock user failed with status %d", code)
	}
	return true, nil
}

// UnlockUser re-enables login for the specified user.
func (r *AppMeshClient) UnlockUser(userName string) (bool, error) {
	if userName == "" {
		return false, fmt.Errorf("username is required")
	}

	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/unlock", userName), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("unlock user request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("unlock user failed with status %d", code)
	}
	return true, nil
}

// ListUsers retrieves information about all users visible to the current user.
func (r *AppMeshClient) ListUsers() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/users", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view users request failed: %w", err)
	}
	users := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &users); err != nil {
			return nil, fmt.Errorf("failed to unmarshal users: %w", err)
		}
	}
	return users, nil
}

// GetCurrentUser retrieves information about the current authenticated user.
func (r *AppMeshClient) GetCurrentUser() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/self", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view self request failed: %w", err)
	}
	user := map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &user); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user data: %w", err)
		}
		return user, nil
	}
	return nil, fmt.Errorf("view self failed with status %d", code)
}

// ListGroups retrieves information about all user groups.
func (r *AppMeshClient) ListGroups() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/groups", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view groups request failed: %w", err)
	}
	groups := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, fmt.Errorf("failed to unmarshal groups: %w", err)
		}
	}
	return groups, nil
}

// ViewPermissions retrieves all available permissions in the system.
func (r *AppMeshClient) ViewPermissions() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/permissions", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view permissions request failed: %w", err)
	}
	perms := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &perms); err != nil {
			return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
		}
	}
	return perms, nil
}

// GetUserPermissions retrieves permissions assigned to the current user.
func (r *AppMeshClient) GetUserPermissions() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/permissions", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view user permissions request failed: %w", err)
	}
	perms := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &perms); err != nil {
			return nil, fmt.Errorf("failed to unmarshal user permissions: %w", err)
		}
	}
	return perms, nil
}

// ListRoles retrieves all roles with their permission definitions.
func (r *AppMeshClient) ListRoles() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/roles", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view roles request failed: %w", err)
	}
	roles := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &roles); err != nil {
			return nil, fmt.Errorf("failed to unmarshal roles: %w", err)
		}
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
		return false, fmt.Errorf("update role failed with status %d", code)
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
		return false, fmt.Errorf("delete role failed with status %d", code)
	}
	return true, nil
}

// AddTag creates a new label with the specified name and value.
func (r *AppMeshClient) AddTag(tagName string, tagValue string) (bool, error) {
	if tagName == "" {
		return false, fmt.Errorf("tag name is required")
	}

	body, err := json.Marshal(map[string]string{tagName: tagValue})
	if err != nil {
		return false, fmt.Errorf("failed to marshal tag: %w", err)
	}
	code, _, _, err := r.post("/appmesh/label", nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("add tag request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// DeleteTag removes a label/tag from the system.
func (r *AppMeshClient) DeleteTag(tagName string) (bool, error) {
	if tagName == "" {
		return false, fmt.Errorf("tag name is required")
	}

	code, _, err := r.delete(fmt.Sprintf("/appmesh/label/%s", tagName))
	if err != nil {
		return false, fmt.Errorf("delete tag request failed: %w", err)
	}
	return code == http.StatusOK, nil
}

// Close releases all resources and stops background timers.
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
