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
	"sync"
	"time"

	"github.com/pquerna/otp"
)

// AppMeshClient interacts with the REST server using REST API requests.
type AppMeshClient struct {
	Proxy     ClientRequester
	forwardTo string // The target host to which all requests will be forwarded.
	jwtToken  string // JWT authentication token for API requests.

	sslClientCert    string // Client SSL certificate file.
	sslClientCertKey string // Client SSL certificate key file.
	sslCAFile        string // Trusted CA file/dir.

	mutex sync.Mutex
}

// Option represents the configuration options for the AppMeshClient.
type Option struct {
	AppMeshUri string // URI of the App Mesh server; use "https://localhost:6060" for HTTP or "localhost:6059" for TCP.
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
}

// NewHttpClient creates a new AppMeshClient instance for interacting with a REST server.
func NewHttpClient(options Option) *AppMeshClient {
	// Apply the provided options.
	clientCertFile := options.SslClientCertificateFile
	clientCertKeyFile := options.SslClientCertificateKeyFile
	caFile := DEFAULT_CA_FILE
	if options.SslTrustedCA != nil {
		caFile = *options.SslTrustedCA
	}

	httpRequester := &ClientRequesterRest{
		baseURL: func() string {
			if options.AppMeshUri != "" {
				return options.AppMeshUri
			}
			return DEFAULT_HTTP_URI
		}(),
		httpClient: func() *http.Client {
			// Conditional httpClient creation based on options.tcpOnly.
			if options.tcpOnly == nil || !*options.tcpOnly {
				return newHttpClient(clientCertFile, clientCertKeyFile, caFile)
			}
			return nil
		}(),
	}

	c := &AppMeshClient{
		Proxy: httpRequester,

		sslClientCert:    clientCertFile,
		sslClientCertKey: clientCertKeyFile,
		sslCAFile:        caFile,
	}

	if options.HttpTimeoutMinutes != nil {
		httpRequester.httpClient.Timeout = (*options.HttpTimeoutMinutes)
	}
	c.updateForwardTo(options.ForwardTo)
	c.updateToken(options.Token)

	return c
}

// Login authenticates the user with username and password.
func (r *AppMeshClient) Login(user string, password string, totpCode string, timeoutSeconds int, audience string) (bool, string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS
	}
	headers := map[string]string{
		"Authorization":    "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
		"X-Expire-Seconds": strconv.Itoa(timeoutSeconds),
	}
	if audience != "" {
		headers["X-Audience"] = audience
	}
	code, raw, _, err := r.post("appmesh/login", nil, headers, nil)
	if code == http.StatusOK {
		result := JWTResponse{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result)
		if err == nil {
			r.updateToken(result.AccessToken)
			return true, r.getToken(), err
		}
	} else if code == http.StatusPreconditionRequired && len(totpCode) > 0 {
		m := make(map[string]interface{})
		decoder := json.NewDecoder(bytes.NewReader(raw))
		_ = decoder.Decode(&m)
		if challenge, ok := m["totp_challenge"].(string); ok {
			token, err := r.ValidateTotp(user, challenge, totpCode, timeoutSeconds)
			if err == nil && token != "" {
				return true, token, nil
			}
			return false, "", err
		}
	}
	return false, "", err
}

// ValidateTotp validates the TOTP code and returns a new JWT token.
func (r *AppMeshClient) ValidateTotp(username string, challenge string, totpCode string, timeoutSeconds int) (string, error) {
	type TotpRequest struct {
		UserName      string `json:"user_name"`
		TotpCode      string `json:"totp_code"`
		TotpChallenge string `json:"totp_challenge"`
		ExpireSeconds int    `json:"expire_seconds"`
	}
	request := TotpRequest{
		UserName:      username,
		TotpCode:      totpCode,
		TotpChallenge: challenge,
		ExpireSeconds: timeoutSeconds,
	}
	body, _ := json.Marshal(request)
	code, raw, _, err := r.post("appmesh/totp/validate", nil, nil, body)
	if code == http.StatusOK {
		result := JWTResponse{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result)
		if err == nil {
			r.updateToken(result.AccessToken)
			return r.getToken(), nil
		}
	}
	return "", err
}

// Logoff logs the user off from the server.
func (r *AppMeshClient) Logoff() (bool, error) {
	if r.getToken() != "" {
		code, _, _, err := r.post("appmesh/self/logoff", nil, nil, nil)
		r.updateToken("")
		return code == http.StatusOK, err
	}
	return true, nil
}

// Authenticate authenticates the user with an existing JWT token and optional permission check.
func (r *AppMeshClient) Authenticate(jwtToken string, permission string, audience string) (bool, error) {
	headers := Headers{}
	if permission != "" {
		headers["X-Permission"] = permission
	}
	if audience != "" {
		headers["X-Audience"] = audience
	}
	code, _, _, err := r.post("appmesh/auth", nil, headers, nil)
	if code == http.StatusOK {
		r.updateToken(jwtToken)
		return true, nil
	}
	return false, err
}

// RenewToken renews the JWT token.
func (r *AppMeshClient) RenewToken() (bool, error) {
	code, raw, _, err := r.post("appmesh/token/renew", nil, nil, nil)
	if code == http.StatusOK {
		result := JWTResponse{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result)
		if err == nil {
			r.updateToken(result.AccessToken)
			return true, err
		}
	}
	return false, err
}

// GetTotpSecret retrieves the TOTP secret for the user.
func (r *AppMeshClient) GetTotpSecret() (string, error) {
	code, raw, _, err := r.post("appmesh/totp/secret", nil, nil, nil)
	if code == http.StatusOK {
		m := make(map[string]interface{})
		decoder := json.NewDecoder(bytes.NewReader(raw))
		_ = decoder.Decode(&m)
		totpUri, _ := base64.StdEncoding.DecodeString(m["mfa_uri"].(string))
		k, err := otp.NewKeyFromURL(string(totpUri))
		if err != nil {
			return "", err
		}
		return k.Secret(), nil
	}
	return "", err
}

// SetupTotp sets up TOTP for the user.
func (r *AppMeshClient) SetupTotp(totpCode string) (bool, error) {
	headers := map[string]string{"X-Totp-Code": totpCode}
	code, raw, _, err := r.post("appmesh/totp/setup", nil, headers, nil)
	if code == http.StatusOK {
		result := JWTResponse{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result)
		if err == nil {
			r.updateToken(result.AccessToken)
			return true, err
		}
	}
	return false, err
}

// DisableTotp disables TOTP for the user.
func (r *AppMeshClient) DisableTotp() (bool, error) {
	code, _, _, err := r.post("appmesh/totp/self/disable", nil, nil, nil)
	return code == http.StatusOK, err
}

// ViewTags retrieves all labels.
func (r *AppMeshClient) ViewTags() (Labels, error) {
	code, raw, _, err := r.get("appmesh/labels", nil, nil)
	label := Labels{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &label)
	}
	return label, err
}

// ViewHostResources retrieves resources.
func (r *AppMeshClient) ViewHostResources() ([]byte, error) {
	_, raw, _, err := r.get("appmesh/resources", nil, nil)
	return raw, err
}

// ViewAllApps retrieves all applications.
func (r *AppMeshClient) ViewAllApps() ([]Application, error) {
	code, raw, _, err := r.get("appmesh/applications", nil, nil)
	apps := []Application{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &apps)
	}
	return apps, err
}

// ViewApp retrieves a specific application by name.
func (r *AppMeshClient) ViewApp(appName string) (*Application, error) {
	code, raw, _, err := r.get(fmt.Sprintf("/appmesh/app/%s", appName), nil, nil)
	if code == http.StatusOK {
		app := Application{}
		err = json.Unmarshal(raw, &app)
		return &app, err
	}
	return nil, err
}

// GetAppOutput retrieves the stdout of an application.
func (r *AppMeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string) AppOutput {
	query := url.Values{}
	query.Set("stdout_position", strconv.FormatInt(stdoutPosition, 10))
	query.Set("stdout_index", strconv.Itoa(stdoutIndex))
	query.Set("stdout_maxsize", strconv.Itoa(stdoutMaxsize))
	query.Set("process_uuid", processUuid)

	code, body, header, err := r.get(fmt.Sprintf("/appmesh/app/%s/output", appName), query, nil)
	resp := AppOutput{Error: err, HttpSuccess: code == http.StatusOK, HttpBody: string(body)}

	// Extract and parse headers.
	if exitCodeStr := header.Get("X-Exit-Code"); exitCodeStr != "" {
		if exitCode, err := strconv.Atoi(exitCodeStr); err == nil {
			resp.ExitCode = &exitCode
		}
	}

	if outputPositionStr := header.Get("X-Output-Position"); outputPositionStr != "" {
		if outputPosition, err := strconv.ParseInt(outputPositionStr, 10, 64); err == nil {
			resp.OutputPosition = &outputPosition
		}
	}

	return resp
}

// EnableApp enables an application.
func (r *AppMeshClient) EnableApp(appName string) error {
	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/enable", appName), nil, nil, nil)
	if code == http.StatusOK {
		return nil
	} else {
		if err != nil {
			return err
		}
		return fmt.Errorf("HTTP error: %s", string(raw))
	}
}

// DisableApp disables an application.
func (r *AppMeshClient) DisableApp(appName string) error {
	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/disable", appName), nil, nil, nil)
	if code == http.StatusOK {
		return nil
	} else {
		if err != nil {
			return err
		}
		return fmt.Errorf("HTTP error: %s", string(raw))
	}
}

// RemoveApp removes an application.
func (r *AppMeshClient) RemoveApp(appName string) error {
	code, raw, err := r.delete(fmt.Sprintf("/appmesh/app/%s", appName))
	if code == http.StatusOK {
		return nil
	} else {
		if err != nil {
			return err
		}
		return fmt.Errorf("HTTP error: %s", string(raw))
	}
}

// AddApp adds an application.
func (r *AppMeshClient) AddApp(app Application) (*Application, error) {
	appJson, err := json.Marshal(app)
	if err == nil {
		code, raw, err := r.put(fmt.Sprintf("/appmesh/app/%s", app.Name), nil, nil, appJson)
		if code == http.StatusOK {
			resultApp := Application{}
			json.Unmarshal(raw, &resultApp)
			return &resultApp, err
		} else {
			if err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("HTTP error: %s", string(raw))
		}
	}
	return nil, err
}

// RunTask runs a task.
func (r *AppMeshClient) RunTask(appName string, payload string) (string, error) {
	code, raw, _, err := r.post(fmt.Sprintf("/appmesh/app/%s/task", appName), nil, nil, nil)
	if code != http.StatusOK {
		return "", err
	}
	return string(raw), nil
}

// RunAppSync runs an application synchronously.
func (r *AppMeshClient) RunAppSync(app Application, maxTimeoutSeconds int) (*int, string, error) {
	appJson, err := json.Marshal(app)
	var exitCode *int
	var respose string
	if err == nil {
		path := "/appmesh/app/syncrun"
		query := url.Values{}
		query.Add("timeout", strconv.Itoa(maxTimeoutSeconds))

		code, raw, headers, err := r.post(path, query, nil, appJson)
		if headers.Get("X-Exit-Code") != "" {
			value, _ := strconv.Atoi(headers.Get("X-Exit-Code"))
			exitCode = new(int)
			*exitCode = value
		}
		if code == http.StatusOK {
			respose = string(raw)
		}
		return exitCode, respose, err
	}
	return exitCode, respose, err
}

// RunAppAsync runs an application asynchronously.
func (r *AppMeshClient) RunAppAsync(app Application, maxTimeoutSeconds int) (int, error) {
	appJson, err := json.Marshal(app)
	exitCode := 0
	if err == nil {
		path := "/appmesh/app/run"
		query := url.Values{}
		query.Add("timeout", strconv.Itoa(maxTimeoutSeconds))

		code, raw, _, _ := r.post(path, query, nil, appJson)
		if code == http.StatusOK {
			resultApp := Application{}
			json.Unmarshal(raw, &resultApp)
			uuid := resultApp.Uuid
			if uuid != nil && *uuid != "" {
				var outputPosition int64 = 0
				for {
					query = url.Values{}
					query.Add("process_uuid", *uuid)
					query.Add("stdout_position", strconv.FormatInt(outputPosition, 10))
					query.Add("stdout_timeout", strconv.FormatInt(1, 10))

					resp := r.GetAppOutput(resultApp.Name, outputPosition, 0, 10240, *uuid)
					if len(resp.HttpBody) > 0 {
						fmt.Print(resp.HttpBody)
					}
					if resp.OutputPosition != nil {
						outputPosition = *resp.OutputPosition
					}
					if resp.ExitCode != nil {
						exitCode = *resp.ExitCode
						break
					}
					if !resp.HttpSuccess {
						break
					}
				}
				r.RemoveApp(resultApp.Name)
			}
		}
	}
	return exitCode, err
}

// UploadFile uploads a file to the server.
func (r *AppMeshClient) UploadFile(localFile, remoteFile string, applyFileAttributes bool) error {
	file, err := os.Open(localFile)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(localFile))
	if err != nil {
		return err
	}
	_, err = io.Copy(part, file)
	if err != nil {
		return err
	}

	err = writer.Close()
	if err != nil {
		return err
	}

	headers := map[string]string{
		"Content-Type": writer.FormDataContentType(),
		"X-File-Path":  url.QueryEscape(remoteFile),
	}

	// Get the file attributes.
	if applyFileAttributes {
		attrs, err := GetFileAttributes(localFile)
		MergeStringMaps(headers, attrs)
		if err != nil {
			return err
		}
	}

	code, raw, _, err := r.post("/appmesh/file/upload", nil, headers, body.Bytes())
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("upload failed with status: %s", raw)
	}

	return nil
}

// DownloadFile downloads a file from the server.
func (r *AppMeshClient) DownloadFile(remoteFile, localFile string, applyFileAttributes bool) error {
	headers := map[string]string{"X-File-Path": url.QueryEscape(remoteFile)}
	code, raw, respHeaders, err := r.get("/appmesh/file/download", nil, headers)

	if err != nil {
		return fmt.Errorf("download request failed: %w", err)
	}

	if code != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", raw)
	}

	out, err := os.Create(localFile)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = out.Write(raw)
	if err != nil {
		return fmt.Errorf("failed to write to file %s: %w", localFile, err)
	}

	if applyFileAttributes {
		SetFileAttributes(localFile, respHeaders)
	}

	return nil
}

// getForwardTo retrieves the forwarding host thread-safely.
func (r *AppMeshClient) getForwardTo() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.forwardTo
}

// updateForwardTo updates the forwarding host thread-safely.
func (r *AppMeshClient) updateForwardTo(host string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.forwardTo = host
}

// getToken retrieves the JWT token thread-safely.
func (r *AppMeshClient) getToken() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.jwtToken
}

// updateToken updates the JWT token thread-safely.
func (r *AppMeshClient) updateToken(token string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.jwtToken = token
}
