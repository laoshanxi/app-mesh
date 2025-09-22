// client_http.go
package appmesh

import (
	"bytes"
	"encoding/base64"
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
	"sync"
	"time"

	"github.com/pquerna/otp"
)

// AppMeshClient interacts with App Mesh REST APIs.
type AppMeshClient struct {
	Proxy            ClientRequester
	forwardTo        string // Forward target host
	jwtToken         string
	sslClientCert    string // Client SSL certificate file.
	sslClientCertKey string // Client SSL certificate key file.
	sslCAFile        string // Trusted CA file/dir.

	autoRefreshToken  bool
	tokenRefreshTimer *time.Timer

	mutex sync.Mutex
}

// Option for NewHttpClient
type Option struct {
	AppMeshUri string // URI of the App Mesh server; use "https://127.0.0.1:6060" for HTTP or "127.0.0.1:6059" for TCP.
	Token      string // JWT authentication token for API requests.
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
	AutoRefreshToken   bool           // Enable automatic token refresh before expiration.
}

// NewHttpClient builds a new client instance for interacting with App Mesh REST APIs.
func NewHttpClient(options Option) *AppMeshClient {
	clientCertFile := options.SslClientCertificateFile
	clientCertKeyFile := options.SslClientCertificateKeyFile
	caFile := DEFAULT_CA_FILE
	if options.SslTrustedCA != nil {
		caFile = *options.SslTrustedCA
	}

	var httpClient *http.Client
	if options.tcpOnly == nil || !*options.tcpOnly {
		httpClient = newHttpClient(clientCertFile, clientCertKeyFile, caFile)
		if options.HttpTimeoutMinutes != nil {
			httpClient.Timeout = *options.HttpTimeoutMinutes
		}
	}

	baseURL := options.AppMeshUri
	if baseURL == "" {
		baseURL = DEFAULT_HTTP_URI
	}

	httpRequester := &ClientRequesterRest{
		baseURL:    baseURL,
		httpClient: httpClient,
	}

	c := &AppMeshClient{
		Proxy:             httpRequester,
		sslClientCert:     clientCertFile,
		sslClientCertKey:  clientCertKeyFile,
		sslCAFile:         caFile,
		autoRefreshToken:  options.AutoRefreshToken,
		tokenRefreshTimer: nil,
	}

	c.updateForwardTo(options.ForwardTo)
	c.updateToken(options.Token)

	return c
}

// Login authenticates the user with username/password and optional TOTP code.
func (r *AppMeshClient) Login(user string, password string, totpCode string, timeoutSeconds int, audience string) (string, error) {
	r.updateToken("") // reset token
	headers := map[string]string{
		"Authorization":    "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
		"X-Expire-Seconds": fmt.Sprintf("%d", timeoutSeconds),
	}
	if audience != "" && audience != DEFAULT_JWT_AUDIENCE {
		headers["X-Audience"] = audience
	}

	code, raw, _, err := r.post("/appmesh/login", nil, headers, nil)
	if err != nil {
		return "", err
	}
	switch code {
	case http.StatusOK:
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return "", err
		}
		r.updateToken(result.AccessToken)
		return result.AccessToken, nil

	case http.StatusPreconditionRequired:
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err == nil {
			if challenge, ok := resp["totp_challenge"].(string); ok && totpCode != "" {
				return r.ValidateTotp(user, challenge, totpCode, timeoutSeconds)
			}
		}
		return "", fmt.Errorf("TOTP challenge required or server error: %s", string(raw))

	default:
		return "", fmt.Errorf("unexpected status code: %d, body: %s", code, string(raw))
	}
}

// ValidateTotp validates TOTP challenge and returns a new JWT token.
func (r *AppMeshClient) ValidateTotp(username string, challenge string, totpCode string, timeoutSeconds int) (string, error) {
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
	body, _ := json.Marshal(req)
	code, raw, _, err := r.post("/appmesh/totp/validate", nil, nil, body)
	if err != nil {
		return "", err
	}
	if code == http.StatusOK {
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return "", err
		}
		r.updateToken(result.AccessToken)
		return result.AccessToken, nil
	}
	return "", fmt.Errorf("TOTP validate failed status %d: %s", code, string(raw))
}

// Logoff logs out the current session and invalidates the token.
func (r *AppMeshClient) Logoff() (bool, error) {
	token := r.getToken()
	if token != "" {
		code, _, _, err := r.post("/appmesh/self/logoff", nil, nil, nil)
		r.updateToken("")
		if err != nil {
			return false, err
		}
		return code == http.StatusOK, nil
	}
	return true, nil
}

// Authenticate checks token validity and optional permission against the server.
func (r *AppMeshClient) Authenticate(jwtToken string, permission string, audience string) (bool, error) {
	old := r.getToken()
	r.updateToken(jwtToken)
	defer r.updateToken(old)

	headers := Headers{}
	if permission != "" {
		headers["X-Permission"] = permission
	}
	if audience != "" && audience != DEFAULT_JWT_AUDIENCE {
		headers["X-Audience"] = audience
	}

	code, _, _, err := r.post("/appmesh/auth", nil, headers, nil)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// RenewToken renews the current JWT token before expiration.
func (r *AppMeshClient) RenewToken() (bool, error) {
	if r.getToken() == "" {
		return false, fmt.Errorf("no token to renew")
	}
	code, raw, _, err := r.post("/appmesh/token/renew", nil, nil, nil)
	if err != nil {
		return false, err
	}
	if code == http.StatusOK {
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return false, err
		}
		r.updateToken(result.AccessToken)
		return true, nil
	}
	return false, fmt.Errorf("renew failed status %d: %s", code, string(raw))
}

// GetTotpSecret retrieves the TOTP secret for setting up 2FA authentication.
func (r *AppMeshClient) GetTotpSecret() (string, error) {
	code, raw, _, err := r.post("/appmesh/totp/secret", nil, nil, nil)
	if err != nil {
		return "", err
	}
	if code == http.StatusOK {
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return "", err
		}
		if mfa, ok := resp["mfa_uri"].(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(mfa)
			if err != nil {
				return "", err
			}
			key, err := otp.NewKeyFromURL(string(decoded))
			if err != nil {
				return "", err
			}
			return key.Secret(), nil
		}
	}
	return "", fmt.Errorf("failed to get totp secret status %d: %s", code, string(raw))
}

// SetupTotp configures TOTP 2FA for the current user and returns a new token.
func (r *AppMeshClient) SetupTotp(totpCode string) (string, error) {
	headers := map[string]string{"X-Totp-Code": totpCode}
	code, raw, _, err := r.post("/appmesh/totp/setup", nil, headers, nil)
	if err != nil {
		return "", err
	}
	if code == http.StatusOK {
		result := JWTResponse{}
		if err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result); err != nil {
			return "", err
		}
		r.updateToken(result.AccessToken)
		return result.AccessToken, nil
	}
	return "", fmt.Errorf("setup totp failed status %d: %s", code, string(raw))
}

// DisableTotp disables TOTP 2FA for the specified user (or "self" if empty).
func (r *AppMeshClient) DisableTotp(user string) (bool, error) {
	if user == "" {
		user = "self"
	}
	path := fmt.Sprintf("/appmesh/totp/%s/disable", user)
	code, _, _, err := r.post(path, nil, nil, nil)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// ViewTags retrieves all available labels/tags from the server.
func (r *AppMeshClient) ViewTags() (Labels, error) {
	code, raw, _, err := r.get("/appmesh/labels", nil, nil)
	labels := Labels{}
	if err != nil {
		return labels, err
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &labels); err != nil {
			return labels, err
		}
	}
	return labels, nil
}

// ViewHostResources retrieves system resource information (CPU, memory, disk).
func (r *AppMeshClient) ViewHostResources() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/resources", nil, nil)
	res := map[string]interface{}{}
	if err != nil {
		return res, err
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// ViewAllApps returns all applications visible to the current user.
func (r *AppMeshClient) ViewAllApps() ([]Application, error) {
	code, raw, _, err := r.get("/appmesh/applications", nil, nil)
	apps := []Application{}
	if err != nil {
		return apps, err
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &apps); err != nil {
			return apps, err
		}
	}
	return apps, nil
}

// ViewApp returns detailed information about a specific application.
func (r *AppMeshClient) ViewApp(appName string) (*Application, error) {
	path := fmt.Sprintf("/appmesh/app/%s", appName)
	code, raw, _, err := r.get(path, nil, nil)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		var app Application
		if err := json.Unmarshal(raw, &app); err != nil {
			return nil, err
		}
		return &app, nil
	}
	return nil, fmt.Errorf("view app failed status %d: %s", code, string(raw))
}

// GetAppOutput fetches stdout/stderr output from a running or completed application.
func (r *AppMeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string, timeout int) AppOutput {
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
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/enable", appName), nil, nil, nil)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// DisableApp stops or disables the specified application.
func (r *AppMeshClient) DisableApp(appName string) (bool, error) {
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/disable", appName), nil, nil, nil)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// RemoveApp deletes an application from the system.
func (r *AppMeshClient) RemoveApp(appName string) (bool, error) {
	code, _, err := r.delete(fmt.Sprintf("/appmesh/app/%s", appName))
	if err != nil {
		return false, err
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
	body, err := json.Marshal(app)
	if err != nil {
		return nil, err
	}
	code, raw, err := r.put(fmt.Sprintf("/appmesh/app/%s", app.Name), nil, nil, body)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		var outApp Application
		if err := json.Unmarshal(raw, &outApp); err != nil {
			return nil, err
		}
		return &outApp, nil
	}
	return nil, fmt.Errorf("add app failed status %d: %s", code, string(raw))
}

// RunTask sends a message to a running application and waits for response.
func (r *AppMeshClient) RunTask(appName string, payload string, timeout int) (string, error) {
	if timeout <= 0 {
		timeout = 300
	}
	q := url.Values{}
	q.Set("timeout", strconv.Itoa(timeout))
	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/task", appName), q, nil, []byte(payload))
	if err != nil {
		return "", err
	}
	if code == http.StatusOK {
		return string(raw), nil
	}
	return "", fmt.Errorf("run task failed status %d: %s", code, string(raw))
}

// CancelTask cancels a running task for the specified application.
func (r *AppMeshClient) CancelTask(appName string) (bool, error) {
	code, _, err := r.delete(fmt.Sprintf("/appmesh/app/%s/task", appName))
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// RunAppAsync starts an application asynchronously and returns a handle for monitoring.
func (r *AppMeshClient) RunAppAsync(app Application, maxTimeSeconds int, lifeCycleSeconds int) (*AppRun, error) {
	appJson, err := json.Marshal(app)
	if err != nil {
		return nil, err
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", maxTimeSeconds))
	q.Set("lifecycle", fmt.Sprintf("%d", lifeCycleSeconds))
	code, raw, _, err := r.post("/appmesh/app/run", q, nil, appJson)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		name, _ := resp["name"].(string)
		proc, _ := resp["process_uuid"].(string)
		return &AppRun{AppName: name, ProcUid: proc, ForwardTo: r.forwardTo}, nil
	}
	return nil, fmt.Errorf("run async failed status %d: %s", code, string(raw))
}

// Wait waits for an asynchronous application run to complete and optionally prints output.
func (r *AppMeshClient) Wait(asyncRun *AppRun, stdoutPrint bool, timeoutSeconds int) (int, error) {
	if asyncRun == nil || asyncRun.ProcUid == "" {
		return 0, fmt.Errorf("invalid async run object")
	}
	lastPos := int64(0)
	start := time.Now()
	interval := 1 * time.Second
	for asyncRun.ProcUid != "" {
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
			break
		}
		if timeoutSeconds > 0 && time.Since(start) > time.Duration(timeoutSeconds)*time.Second {
			break
		}
		time.Sleep(interval)
	}
	return 0, fmt.Errorf("wait timed out or process failed")
}

// RunAppSync runs an application synchronously and returns exit code and output.
func (r *AppMeshClient) RunAppSync(app Application, stdoutPrint bool, maxTimeSeconds int, lifeCycleSeconds int) (int, string, error) {
	appJson, err := json.Marshal(app)
	if err != nil {
		return 0, "", err
	}
	q := url.Values{}
	q.Set("timeout", fmt.Sprintf("%d", maxTimeSeconds))
	q.Set("lifecycle", fmt.Sprintf("%d", lifeCycleSeconds))
	code, raw, hdr, err := r.post("/appmesh/app/syncrun", q, nil, appJson)
	if err != nil {
		return 0, "", err
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
	return exit, out, fmt.Errorf("sync run failed status %d: %s", code, out)
}

// UploadFile uploads a local file to the remote server with optional file attributes.
func (r *AppMeshClient) UploadFile(localFile, remoteFile string, applyFileAttributes bool) error {
	f, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer f.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("file", filepath.Base(localFile))
	if err != nil {
		return err
	}
	if _, err := io.Copy(part, f); err != nil {
		return err
	}
	// set filename form field too if server expects it
	_ = writer.WriteField("filename", filepath.Base(remoteFile))

	if err := writer.Close(); err != nil {
		return err
	}
	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"X-File-Path":  url.QueryEscape(remoteFile),
	}
	// Optionally include attributes (placeholder — server must support)
	if applyFileAttributes {
		if fi, err := os.Stat(localFile); err == nil {
			mode := fi.Mode().Perm()
			headers["X-File-Mode"] = fmt.Sprintf("%d", mode)
		}
	}

	code, raw, _, err := r.post("/appmesh/file/upload", nil, headers, body.Bytes())
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("upload failed status %d: %s", code, string(raw))
	}
	return nil
}

// DownloadFile downloads a remote file to local path with optional file attributes.
func (r *AppMeshClient) DownloadFile(remoteFile, localFile string, applyFileAttributes bool) error {
	headers := map[string]string{"X-File-Path": url.QueryEscape(remoteFile)}
	code, raw, respHdr, err := r.get("/appmesh/file/download", nil, headers)
	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("download failed status %d: %s", code, string(raw))
	}
	out, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err := out.Write(raw); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	// apply attributes if requested (placeholder)
	if applyFileAttributes {
		if modeStr := respHdr.Get("X-File-Mode"); modeStr != "" {
			if m, err := strconv.ParseInt(modeStr, 10, 32); err == nil {
				os.Chmod(localFile, os.FileMode(m))
			}
		}
	}
	return nil
}

// ViewConfig retrieves the current App Mesh configuration.
func (r *AppMeshClient) ViewConfig() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/config", nil, nil)
	cfg := map[string]interface{}{}
	if err != nil {
		return cfg, err
	}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return cfg, err
		}
	}
	return cfg, nil
}

// SetConfig updates the App Mesh configuration and returns the new configuration.
func (r *AppMeshClient) SetConfig(configJson map[string]interface{}) (map[string]interface{}, error) {
	body, err := json.Marshal(configJson)
	if err != nil {
		return nil, err
	}
	code, raw, _, err := r.post("/appmesh/config", nil, nil, body)
	if err != nil {
		return nil, err
	}
	if code == http.StatusOK {
		out := map[string]interface{}{}
		if err := json.Unmarshal(raw, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
	return nil, fmt.Errorf("set config failed status %d: %s", code, string(raw))
}

// SetLogLevel updates the application log level and returns the new level.
func (r *AppMeshClient) SetLogLevel(level string) (string, error) {
	cfg := map[string]interface{}{
		"BaseConfig": map[string]interface{}{
			"LogLevel": level,
		},
	}
	body, _ := json.Marshal(cfg)
	code, raw, _, err := r.post("/appmesh/config", nil, nil, body)
	if err != nil {
		return "", err
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
	return "", fmt.Errorf("set log level failed status %d: %s", code, string(raw))
}

// UpdateUserPassword changes the password for a user (default is "self").
func (r *AppMeshClient) UpdateUserPassword(oldPassword, newPassword, userName string) (bool, error) {
	if userName == "" {
		userName = "self"
	}
	payload := map[string]string{
		"old_password": base64.StdEncoding.EncodeToString([]byte(oldPassword)),
		"new_password": base64.StdEncoding.EncodeToString([]byte(newPassword)),
	}
	body, _ := json.Marshal(payload)
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/passwd", userName), nil, nil, body)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("update password failed status %d", code)
	}
	return true, nil
}

// AddUser creates a new user with the specified configuration.
func (r *AppMeshClient) AddUser(userName string, userJson map[string]interface{}) (bool, error) {
	body, _ := json.Marshal(userJson)
	code, _, err := r.put(fmt.Sprintf("/appmesh/user/%s", userName), nil, nil, body)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// DeleteUser removes a user from the system.
func (r *AppMeshClient) DeleteUser(userName string) (bool, error) {
	code, _, err := r.delete(fmt.Sprintf("/appmesh/user/%s", userName))
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// LockUser disables login for the specified user.
func (r *AppMeshClient) LockUser(userName string) (bool, error) {
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/lock", userName), nil, nil, nil)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("lock user failed %d", code)
	}
	return true, nil
}

// UnlockUser re-enables login for the specified user.
func (r *AppMeshClient) UnlockUser(userName string) (bool, error) {
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/unlock", userName), nil, nil, nil)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("unlock user failed %d", code)
	}
	return true, nil
}

// ViewUsers retrieves information about all users visible to the current user.
func (r *AppMeshClient) ViewUsers() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/users", nil, nil)
	if err != nil {
		return nil, err
	}
	users := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &users); err != nil {
			return nil, err
		}
	}
	return users, nil
}

// ViewSelf retrieves information about the current authenticated user.
func (r *AppMeshClient) ViewSelf() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/self", nil, nil)
	if err != nil {
		return nil, err
	}
	user := map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &user); err != nil {
			return nil, err
		}
		return user, nil
	}
	return nil, fmt.Errorf("view self failed status %d", code)
}

// ViewGroups retrieves information about all user groups.
func (r *AppMeshClient) ViewGroups() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/groups", nil, nil)
	if err != nil {
		return nil, err
	}
	groups := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &groups); err != nil {
			return nil, err
		}
	}
	return groups, nil
}

// ViewPermissions retrieves all available permissions in the system.
func (r *AppMeshClient) ViewPermissions() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/permissions", nil, nil)
	if err != nil {
		return nil, err
	}
	perms := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &perms); err != nil {
			return nil, err
		}
	}
	return perms, nil
}

// ViewUserPermissions retrieves permissions assigned to the current user.
func (r *AppMeshClient) ViewUserPermissions() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/permissions", nil, nil)
	if err != nil {
		return nil, err
	}
	perms := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &perms); err != nil {
			return nil, err
		}
	}
	return perms, nil
}

// ViewRoles retrieves all roles with their permission definitions.
func (r *AppMeshClient) ViewRoles() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/roles", nil, nil)
	if err != nil {
		return nil, err
	}
	roles := []map[string]interface{}{}
	if code == http.StatusOK {
		if err := json.Unmarshal(raw, &roles); err != nil {
			return nil, err
		}
	}
	return roles, nil
}

// UpdateRole creates or updates a role with specified permissions.
func (r *AppMeshClient) UpdateRole(roleName string, rolePerm []string) (bool, error) {
	body, _ := json.Marshal(rolePerm)
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/role/%s", roleName), nil, nil, body)
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("update role failed %d", code)
	}
	return true, nil
}

// DeleteRole removes a role from the system.
func (r *AppMeshClient) DeleteRole(roleName string) (bool, error) {
	code, _, err := r.delete(fmt.Sprintf("/appmesh/role/%s", roleName))
	if err != nil {
		return false, err
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("delete role failed %d", code)
	}
	return true, nil
}

// AddTag creates a new label with the specified name and value.
func (r *AppMeshClient) AddTag(tagName string, tagValue string) (bool, error) {
	body, _ := json.Marshal(map[string]string{tagName: tagValue})
	code, _, _, err := r.post("/appmesh/label", nil, nil, body)
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// DeleteTag removes a label/tag from the system.
func (r *AppMeshClient) DeleteTag(tagName string) (bool, error) {
	code, _, err := r.delete(fmt.Sprintf("/appmesh/label/%s", tagName))
	if err != nil {
		return false, err
	}
	return code == http.StatusOK, nil
}

// Close releases all resources and stops background timers.
func (r *AppMeshClient) Close() {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	if r.tokenRefreshTimer != nil {
		r.tokenRefreshTimer.Stop()
		r.tokenRefreshTimer = nil
	}
	// nothing else to close for http.Client (CloseIdleConnections if needed)
}

// getForwardTo returns the current forward target host in a thread-safe manner.
func (r *AppMeshClient) getForwardTo() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.forwardTo
}

// updateForwardTo sets the forward target host in a thread-safe manner.
func (r *AppMeshClient) updateForwardTo(host string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.forwardTo = host
}

// getToken returns the current JWT token in a thread-safe manner.
func (r *AppMeshClient) getToken() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.jwtToken
}

// updateToken sets the JWT token and manages auto-refresh scheduling in a thread-safe manner.
func (r *AppMeshClient) updateToken(token string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	old := r.jwtToken
	r.jwtToken = token
	if token != "" && r.autoRefreshToken {
		r.scheduleTokenRefresh()
	} else if old != "" && r.tokenRefreshTimer != nil {
		r.tokenRefreshTimer.Stop()
		r.tokenRefreshTimer = nil
	}
}

// scheduleTokenRefresh calculates and schedules the next token refresh check.
func (r *AppMeshClient) scheduleTokenRefresh() {
	// Note: mutex should already be held by caller (updateToken)
	if r.tokenRefreshTimer != nil {
		r.tokenRefreshTimer.Stop()
		r.tokenRefreshTimer = nil
	}

	timeToExpiry := r.getSecondsToExpiry()
	checkInterval := time.Duration(TOKEN_REFRESH_INTERVAL_SECONDS) * time.Second

	if timeToExpiry > 0 {
		if timeToExpiry <= TOKEN_REFRESH_OFFSET_SECONDS {
			checkInterval = 1 * time.Second
		} else {
			checkInterval = time.Duration(timeToExpiry-TOKEN_REFRESH_OFFSET_SECONDS) * time.Second
		}
	}

	r.tokenRefreshTimer = time.AfterFunc(checkInterval, func() {
		r.checkAndRefreshToken()
	})
}

// getSecondsToExpiry extracts the expiration time from the JWT token payload.
func (r *AppMeshClient) getSecondsToExpiry() int64 {
	token := r.getToken()
	if token == "" {
		return 0
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return 0
	}
	payload := parts[1]
	// base64 URL decode (raw variant)
	payloadBytes, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		// sometimes padding is required
		payloadBytes2, err2 := base64.URLEncoding.DecodeString(payload)
		if err2 != nil {
			return 0
		}
		payloadBytes = payloadBytes2
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return 0
	}
	return claims.Exp - time.Now().Unix()
}

// checkAndRefreshToken attempts to refresh the token if it's near expiration.
func (r *AppMeshClient) checkAndRefreshToken() {
	needsRefresh := true
	timeToExpiry := r.getSecondsToExpiry()
	if timeToExpiry > TOKEN_REFRESH_OFFSET_SECONDS {
		needsRefresh = false
	}
	if needsRefresh {
		if _, err := r.RenewToken(); err != nil {
			fmt.Printf("Token refresh failed: %v\n", err)
		} else {
			fmt.Println("Token successfully refreshed")
		}
	}
	if r.autoRefreshToken && r.getToken() != "" {
		r.scheduleTokenRefresh()
	}
}
