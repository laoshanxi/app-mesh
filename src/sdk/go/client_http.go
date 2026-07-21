// client_http.go
package appmesh

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

	// Token auto-refresh
	autoRefreshToken bool
	refreshStop      chan struct{} // closed to signal the goroutine to exit
	refreshMu        sync.Mutex    // protects refreshStop

	// OAuth2 (Keycloak) refresh token, captured from login/renew response bodies.
	// Stays empty in local-JWT mode, so renew/logout send no X-Refresh-Token header there.
	// Guarded by atomic.String (the SDK's token-state convention) because the auto-refresh
	// goroutine and user calls may read/write it concurrently.
	refreshToken atomic.String
}

// Option for NewHttpClient
type Option struct {
	AppMeshUri string // URI of the App Mesh server; use "https://127.0.0.1:6060" for HTTP or "127.0.0.1:6059" for TCP.
	CookieFile string // Cookie file path for persistence
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

	JwtToken string // JWT token set directly without server verification (no network call).

	// HTTPTimeout is the overall timeout for http.Client requests; honored when non-zero.
	HTTPTimeout time.Duration

	AutoRefreshToken bool // Enable automatic token refresh before expiration.
}

// NewHTTPClient builds an HTTP-backed client for App Mesh REST APIs.
// It applies the configured URL, TLS, cookie persistence, and optional initial JWT token,
// but does not perform any authentication request by itself.
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
		httpClient, err := newHTTPConnection(clientCertFile, clientCertKeyFile, caFile, options.CookieFile)
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
		cookieFile:       options.CookieFile,
		sslClientCert:    clientCertFile,
		sslClientCertKey: clientCertKeyFile,
		sslCAFile:        caFile,
		autoRefreshToken: options.AutoRefreshToken,
	}

	if options.JwtToken != "" {
		c.SetToken(options.JwtToken)
	}

	return c, nil
}

// captureRefreshToken stores the OAuth2 refresh token from a login/renew response body when present.
// Only the Keycloak (OAuth2) daemon returns refresh_token; local-JWT mode omits it, so the stored
// refresh token stays empty and renew/logout send no X-Refresh-Token header. Keycloak rotates the
// refresh token on every renew, so a present value replaces the stored one; an absent value keeps it.
func (r *AppMeshClient) captureRefreshToken(raw []byte) {
	var result JWTResponse
	if err := json.Unmarshal(raw, &result); err == nil && result.RefreshToken != "" {
		r.refreshToken.Store(result.RefreshToken)
	}
}

// Login authenticates with username/password and updates this client session on success.
// It returns a TOTP challenge string when the server responds with HTTP 428 and no code was
// provided; otherwise it returns an empty string. An empty challenge with a nil error means
// the client is fully authenticated. When auto refresh is enabled, a successful login also
// starts the background token refresh loop.
// On a non-empty challenge, either retry Login with the TOTP code or pass the
// challenge to ValidateTotp.
func (r *AppMeshClient) Login(username string, password string, totpCode string, tokenExpire int, audience string) (string, error) {
	if username == "" || password == "" {
		return "", fmt.Errorf("username and password are required")
	}

	headers := map[string]string{
		"Authorization":    "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password)),
		"X-Expire-Seconds": fmt.Sprintf("%d", tokenExpire),
		headerJWTSetCookie: strconv.FormatBool(true),
	}
	if audience != "" && audience != DefaultJWTAudience {
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
		// Capture the OAuth2 refresh token when the daemon (Keycloak mode) issues one, so
		// RenewToken/Logout can present it via X-Refresh-Token. Local-JWT mode: no-op.
		r.captureRefreshToken(raw)
		r.StartTokenRefresh()
		return "", nil

	case 428: // HTTP 428 Precondition Required (TOTP challenge)
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err == nil {
			if challenge, ok := resp["totp_challenge"].(string); ok {
				if totpCode == "" {
					return challenge, nil
				}
				if err := r.ValidateTotp(username, challenge, totpCode, tokenExpire); err != nil {
					return "", fmt.Errorf("TOTP validation failed: %w", err)
				}
				return "", nil
			}
		}
		return "", fmt.Errorf("TOTP challenge required or server error: %s", string(raw))

	default:
		return "", fmt.Errorf("login failed with status %d: %s", code, string(raw))
	}
}

// ValidateTotp completes a TOTP challenge flow and stores the issued JWT in this client.
func (r *AppMeshClient) ValidateTotp(username string, challenge string, totpCode string, tokenExpire int) error {
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
		ExpireSeconds: tokenExpire,
	}
	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal TOTP request: %w", err)
	}
	headers := map[string]string{headerJWTSetCookie: "true"}
	code, raw, _, err := r.post("/appmesh/totp/validate", nil, headers, body)
	if err != nil {
		return fmt.Errorf("TOTP validation request failed: %w", err)
	}
	if code == http.StatusOK {
		return nil
	}
	return fmt.Errorf("TOTP validation failed with status %d: %s", code, string(raw))
}

// Logout invalidates the current session on the server and clears the locally stored token.
func (r *AppMeshClient) Logout() (bool, error) {
	// OAuth2 (Keycloak) proxy mode: present the refresh token so the daemon can revoke the
	// Keycloak session server-side. Local-JWT mode leaves the refresh token empty and omits it.
	var headers map[string]string
	if rt := r.refreshToken.Load(); rt != "" {
		headers = map[string]string{headerJWTRefreshToken: rt}
	}
	code, raw, _, err := r.post("/appmesh/self/logoff", nil, headers, nil)
	r.StopTokenRefresh()
	if err != nil {
		return false, fmt.Errorf("logout request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("logout failed with status %d: %s", code, string(raw))
	}
	r.refreshToken.Store("")
	return true, nil
}

// SetToken sets a JWT token directly without server-side verification.
// Use when the token is already known to be valid.
// For server-side verification, use Authenticate() instead.
func (r *AppMeshClient) SetToken(token string) {
	r.req.setToken(token)
	r.StartTokenRefresh()
}

// GetToken returns the current JWT access token, or empty if not authenticated.
func (r *AppMeshClient) GetToken() string {
	return r.req.getAccessToken()
}

// Authenticate validates the provided JWT token with the server.
// When updateSession is true, the verified token is applied to the current client session and local auth
// state is updated on success.
// When updateSession is false, the token is only verified and the current client session remains unchanged.
func (r *AppMeshClient) Authenticate(jwtToken string, permission string, audience string, updateSession bool) (bool, error) {
	if jwtToken == "" {
		return false, fmt.Errorf("JWT token is required")
	}

	headers := Headers{"Authorization": "Bearer " + jwtToken}
	if permission != "" {
		headers["X-Permission"] = permission
	}
	if audience != "" && audience != DefaultJWTAudience {
		headers["X-Audience"] = audience
	}
	if updateSession {
		headers[headerJWTSetCookie] = "true"
	}

	code, raw, _, err := r.post("/appmesh/auth", nil, headers, nil)
	if err != nil {
		return false, fmt.Errorf("authentication request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("authentication failed with status %d: %s", code, string(raw))
	}
	return true, nil
}

// RenewToken renews the current JWT token already attached to this client session.
func (r *AppMeshClient) RenewToken() (bool, error) {
	// OAuth2 (Keycloak) proxy mode renews via the refresh token; the daemon requires it in
	// X-Refresh-Token. Local-JWT mode leaves the refresh token empty and omits the header.
	var headers map[string]string
	if rt := r.refreshToken.Load(); rt != "" {
		headers = map[string]string{headerJWTRefreshToken: rt}
	}
	code, raw, _, err := r.post("/appmesh/token/renew", nil, headers, nil)
	if err != nil {
		return false, fmt.Errorf("token renewal request failed: %w", err)
	}
	if code == http.StatusOK {
		// Keycloak rotates the refresh token on renew — store the new one for the next cycle.
		r.captureRefreshToken(raw)
		return true, nil
	}
	return false, fmt.Errorf("token renewal failed with status %d: %s", code, string(raw))
}

// GetTotpUri retrieves the TOTP provisioning URI (otpauth://...) for setting up 2FA
// authentication, e.g. for rendering a QR code in an authenticator app.
func (r *AppMeshClient) GetTotpUri() (string, error) {
	code, raw, _, err := r.post("/appmesh/totp/secret", nil, nil, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get TOTP URI: %w", err)
	}
	if code == http.StatusOK {
		var resp map[string]interface{}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return "", fmt.Errorf("failed to unmarshal TOTP URI response: %w", err)
		}
		if mfa, ok := resp["mfa_uri"].(string); ok {
			decoded, err := base64.StdEncoding.DecodeString(mfa)
			if err != nil {
				return "", fmt.Errorf("failed to decode MFA URI: %w", err)
			}
			return string(decoded), nil
		}
	}
	return "", fmt.Errorf("failed to get TOTP URI with status %d: %s", code, string(raw))
}

// GetTotpSecret retrieves the TOTP provisioning URI and extracts only the raw secret component.
// Use GetTotpUri for the full otpauth:// provisioning URI.
func (r *AppMeshClient) GetTotpSecret() (string, error) {
	uri, err := r.GetTotpUri()
	if err != nil {
		return "", err
	}
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return "", fmt.Errorf("failed to parse OTP key from URL: %w", err)
	}
	return key.Secret(), nil
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
	code, raw, _, err := r.post(path, nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("disable TOTP request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("disable TOTP failed with status %d: %s", code, string(raw))
	}
	return true, nil
}

// ListLabels retrieves all available labels from the server.
func (r *AppMeshClient) ListLabels() (Labels, error) {
	code, raw, _, err := r.get("/appmesh/labels", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view labels request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list labels failed with status %d: %s", code, string(raw))
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
		return nil, fmt.Errorf("view host resources failed with status %d: %s", code, string(raw))
	}
	res := map[string]interface{}{}
	if err := json.Unmarshal(raw, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal host resources: %w", err)
	}
	return res, nil
}

// ListApps returns all applications visible to the current user.
func (r *AppMeshClient) ListApps() ([]Application, error) {
	code, raw, _, err := r.get("/appmesh/applications", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view all apps request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list apps failed with status %d: %s", code, string(raw))
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
	return nil, fmt.Errorf("view app failed with status %d: %s", code, string(raw))
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
		err = fmt.Errorf("get app output failed with status %d: %s", code, string(body))
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
		return false, fmt.Errorf("enable app failed with status %d: %s", code, string(raw))
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
		return false, fmt.Errorf("disable app failed with status %d: %s", code, string(raw))
	}
	return true, nil
}

// DeleteApp deletes an application from the system.
// A 404 (app does not exist) is not an error: it returns (false, nil) so callers can
// distinguish "removed now" from "was already absent". Any other non-2xx status is an error.
func (r *AppMeshClient) DeleteApp(appName string) (bool, error) {
	return r.deleteApp(appName, nil)
}

// deleteApp implements DeleteApp; extraHeaders allows per-request
// X-Target-Host overrides without mutating shared client state.
func (r *AppMeshClient) deleteApp(appName string, extraHeaders Headers) (bool, error) {
	if appName == "" {
		return false, fmt.Errorf("application name is required")
	}

	code, _, _, err := r.req.Send(http.MethodDelete, fmt.Sprintf("/appmesh/app/%s", appName), nil, extraHeaders, nil)
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
	return nil, fmt.Errorf("add app failed with status %d: %s", code, string(raw))
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
	return "", fmt.Errorf("run task failed with status %d: %s", code, string(raw))
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
		return false, fmt.Errorf("cancel task failed with status %d: %s", code, string(raw))
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
	return nil, fmt.Errorf("run async failed with status %d: %s", code, string(raw))
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
				_, _ = r.deleteApp(asyncRun.AppName, forwardHeaders)
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
	return exit, out, fmt.Errorf("sync run failed with status %d: %s", code, out)
}

// UploadFile uploads a local file to the remote server.
// When applyFileAttributes is true, local POSIX mode/owner/group metadata is sent in headers
// so the server can recreate permissions when supported.
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
	if applyFileAttributes {
		attrs, err := fileAttributes(localFile)
		if err != nil {
			return fmt.Errorf("failed to read file attributes of %q: %w", localFile, err)
		}
		for key, value := range attrs {
			headers[key] = value
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

// DownloadFile downloads a remote file to local path.
// When applyFileAttributes is true, POSIX mode/owner/group metadata from response headers is
// applied locally on a best-effort basis.
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
		return nil, fmt.Errorf("view config failed with status %d: %s", code, string(raw))
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

// GetMetrics retrieves Prometheus metrics text from the server.
func (r *AppMeshClient) GetMetrics() (string, error) {
	code, raw, _, err := r.get("/appmesh/metrics", nil, nil)
	if err != nil {
		return "", fmt.Errorf("get metrics request failed: %w", err)
	}
	if code == http.StatusOK {
		return string(raw), nil
	}
	return "", fmt.Errorf("get metrics failed with status %d: %s", code, string(raw))
}

// UpdatePassword changes the password for a user (default is "self").
func (r *AppMeshClient) UpdatePassword(oldPassword, newPassword, username string) (bool, error) {
	if oldPassword == "" || newPassword == "" {
		return false, fmt.Errorf("old password and new password are required")
	}

	if username == "" {
		username = "self"
	}
	payload := map[string]string{
		"old_password": base64.StdEncoding.EncodeToString([]byte(oldPassword)),
		"new_password": base64.StdEncoding.EncodeToString([]byte(newPassword)),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal password update payload: %w", err)
	}
	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/passwd", username), nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("update password request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("update password failed with status %d", code)
	}
	return true, nil
}

// AddUser creates a new user with the specified configuration.
func (r *AppMeshClient) AddUser(username string, user map[string]interface{}) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required")
	}
	if user == nil {
		return false, fmt.Errorf("user JSON is required")
	}

	body, err := json.Marshal(user)
	if err != nil {
		return false, fmt.Errorf("failed to marshal user JSON: %w", err)
	}
	code, raw, err := r.put(fmt.Sprintf("/appmesh/user/%s", username), nil, nil, body)
	if err != nil {
		return false, fmt.Errorf("add user request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("add user failed with status %d: %s", code, string(raw))
	}
	return true, nil
}

// DeleteUser removes a user from the system.
func (r *AppMeshClient) DeleteUser(username string) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required")
	}

	code, raw, err := r.delete(fmt.Sprintf("/appmesh/user/%s", username))
	if err != nil {
		return false, fmt.Errorf("delete user request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("delete user failed with status %d: %s", code, string(raw))
	}
	return true, nil
}

// LockUser disables login for the specified user.
func (r *AppMeshClient) LockUser(username string) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required")
	}

	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/lock", username), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("lock user request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("lock user failed with status %d", code)
	}
	return true, nil
}

// UnlockUser re-enables login for the specified user.
func (r *AppMeshClient) UnlockUser(username string) (bool, error) {
	if username == "" {
		return false, fmt.Errorf("username is required")
	}

	code, _, _, err := r.post(fmt.Sprintf("/appmesh/user/%s/unlock", username), nil, nil, nil)
	if err != nil {
		return false, fmt.Errorf("unlock user request failed: %w", err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("unlock user failed with status %d", code)
	}
	return true, nil
}

// ListUsers retrieves all users visible to the current user as the daemon's raw
// JSON document keyed by user name (schema is daemon-owned).
func (r *AppMeshClient) ListUsers() (map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/users", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view users request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list users failed with status %d: %s", code, string(raw))
	}
	users := map[string]interface{}{}
	if err := json.Unmarshal(raw, &users); err != nil {
		return nil, fmt.Errorf("failed to unmarshal users: %w", err)
	}
	return users, nil
}

// GetCurrentUser retrieves the current authenticated user as the daemon's raw
// JSON document (schema is daemon-owned).
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

// ListGroups retrieves all user groups; each element is the daemon's raw JSON
// group document (schema is daemon-owned).
func (r *AppMeshClient) ListGroups() ([]map[string]interface{}, error) {
	code, raw, _, err := r.get("/appmesh/user/groups", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view groups request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("list groups failed with status %d: %s", code, string(raw))
	}
	groups := []map[string]interface{}{}
	if err := json.Unmarshal(raw, &groups); err != nil {
		return nil, fmt.Errorf("failed to unmarshal groups: %w", err)
	}
	return groups, nil
}

// ListPermissions retrieves all available permissions in the system.
func (r *AppMeshClient) ListPermissions() ([]string, error) {
	code, raw, _, err := r.get("/appmesh/permissions", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view permissions request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("view permissions failed with status %d: %s", code, string(raw))
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, fmt.Errorf("failed to unmarshal permissions: %w", err)
	}
	return perms, nil
}

// GetUserPermissions retrieves permissions assigned to the current user.
func (r *AppMeshClient) GetUserPermissions() ([]string, error) {
	code, raw, _, err := r.get("/appmesh/user/permissions", nil, nil)
	if err != nil {
		return nil, fmt.Errorf("view user permissions request failed: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("view user permissions failed with status %d: %s", code, string(raw))
	}
	var perms []string
	if err := json.Unmarshal(raw, &perms); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user permissions: %w", err)
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
		return nil, fmt.Errorf("list roles failed with status %d: %s", code, string(raw))
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
		return false, fmt.Errorf("add label failed with status %d: %s", code, string(raw))
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
		return false, fmt.Errorf("delete label failed with status %d: %s", code, string(raw))
	}
	return true, nil
}

// Close the client and release resources.
func (r *AppMeshClient) Close() {
	r.StopTokenRefresh()
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

// decodeJwtExp extracts the "exp" claim from a JWT token without verifying the signature.
func decodeJwtExp(token string) (int64, error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) < 2 {
		return 0, fmt.Errorf("invalid JWT token format")
	}
	// Base64url decode the payload (2nd part)
	payload := parts[1]
	// Add padding if needed
	switch len(payload) % 4 {
	case 2:
		payload += "=="
	case 3:
		payload += "="
	}
	decoded, err := base64.URLEncoding.DecodeString(payload)
	if err != nil {
		return 0, fmt.Errorf("failed to decode JWT payload: %w", err)
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(decoded, &claims); err != nil {
		return 0, fmt.Errorf("failed to parse JWT claims: %w", err)
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, fmt.Errorf("JWT token missing exp claim")
	}
	return int64(exp), nil
}

// computeRefreshDelay calculates how long to wait before the next token refresh.
func (r *AppMeshClient) computeRefreshDelay() time.Duration {
	token := r.req.getAccessToken()
	if token != "" {
		if exp, err := decodeJwtExp(token); err == nil {
			remaining := time.Until(time.Unix(exp, 0))
			if remaining <= tokenRefreshOffsetSeconds*time.Second {
				return 1 * time.Second // Expiring soon, refresh immediately
			}
			delay := remaining - tokenRefreshOffsetSeconds*time.Second
			if delay > tokenRefreshIntervalSeconds*time.Second {
				delay = tokenRefreshIntervalSeconds * time.Second
			}
			return delay
		}
	}
	return tokenRefreshIntervalSeconds * time.Second
}

// StartTokenRefresh starts background token auto-refresh when AutoRefreshToken is enabled.
// The refresh loop decodes the JWT exp claim and renews shortly before expiration.
// Concurrent calls atomically stop any existing refresh goroutine before starting a new one.
func (r *AppMeshClient) StartTokenRefresh() {
	if !r.autoRefreshToken {
		return
	}
	r.refreshMu.Lock()
	if r.refreshStop != nil {
		close(r.refreshStop)
	}
	stop := make(chan struct{})
	r.refreshStop = stop
	r.refreshMu.Unlock()

	go func() {
		for {
			delay := r.computeRefreshDelay()
			select {
			case <-stop:
				return
			case <-time.After(delay):
			}
			if _, err := r.RenewToken(); err != nil {
				log.Printf("Auto-refresh: token renewal failed: %v", err)
			}
		}
	}()
}

// StopTokenRefresh stops the background token auto-refresh goroutine if one is running.
func (r *AppMeshClient) StopTokenRefresh() {
	r.refreshMu.Lock()
	defer r.refreshMu.Unlock()
	if r.refreshStop != nil {
		close(r.refreshStop)
		r.refreshStop = nil
	}
}
