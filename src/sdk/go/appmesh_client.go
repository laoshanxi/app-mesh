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
	"syscall"
	"time"

	"github.com/pquerna/otp"
)

// AppMeshClient uses REST API for interacting with REST server.
type AppMeshClient struct {
	baseURL      string
	delegateHost string
	jwtToken     string
	httpClient   *http.Client

	mutex sync.Mutex
}

type Option struct {
	AppMeshUri                  string
	Token                       string
	DelegateHost                string
	SslClientCertificateFile    *string
	SslClientCertificateKeyFile *string
	SslTrustedCA                *string
	HttpTimeoutMinutes          *time.Duration
}

// NewClient initializes client for interacting with an instance of REST server;
func NewClient(options Option) *AppMeshClient {

	// set default value
	clientCertFile := DefaultClientCertFile       // set to empty to disable client SSL verification
	clientCertKeyFile := DefaultClientCertKeyFile // set to empty to disable client SSL verification
	caFile := DefaultCAFile                       // set to empty to disable server SSL verification

	// Apply the provided options
	if options.SslClientCertificateFile != nil {
		clientCertFile = *options.SslClientCertificateFile
	}

	if options.SslClientCertificateKeyFile != nil {
		clientCertKeyFile = *options.SslClientCertificateKeyFile
	}

	if options.SslTrustedCA != nil {
		caFile = *options.SslTrustedCA
	}

	c := &AppMeshClient{
		baseURL:    DefaultServerUri,
		httpClient: NewHttpClient(clientCertFile, clientCertKeyFile, caFile),
	}

	if options.AppMeshUri != "" {
		c.baseURL = options.AppMeshUri
	}

	if options.HttpTimeoutMinutes != nil {
		c.httpClient.Timeout = (*options.HttpTimeoutMinutes)
	}

	c.updateDelegateHost(options.DelegateHost)
	c.updateToken(options.Token)

	return c
}

// login with username and password
func (r *AppMeshClient) Login(user string, password string, totpCode string, timeoutSeconds int) (bool, string, error) {
	if timeoutSeconds <= 0 {
		timeoutSeconds = DEFAULT_TOKEN_EXPIRE_SECONDS
	}
	headers := map[string]string{
		"Authorization":  "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password)),
		"Expire-Seconds": strconv.Itoa(timeoutSeconds),
	}
	code, raw, _, err := r.post("appmesh/login", nil, headers, nil)
	if code == http.StatusOK {
		result := JWTResponse{}
		err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result)
		if err == nil {
			r.updateToken(result.AccessToken)
			return true, r.getToken(), err
		}
	} else if code == http.StatusUnauthorized && len(totpCode) > 0 {
		m := make(map[string]interface{})
		decoder := json.NewDecoder(bytes.NewReader(raw))
		_ = decoder.Decode(&m)
		if challenge, ok := m["Totp-Challenge"].(string); ok {
			headers = map[string]string{
				"Username":       base64.StdEncoding.EncodeToString([]byte(user)),
				"Totp":           totpCode,
				"Totp-Challenge": base64.StdEncoding.EncodeToString([]byte(challenge)),
				"Expire-Seconds": strconv.Itoa(timeoutSeconds),
			}
			code, raw, _, err = r.post("appmesh/totp/validate", nil, headers, nil)
			if code == http.StatusOK {
				result := JWTResponse{}
				err = json.NewDecoder(bytes.NewReader(raw)).Decode(&result)
				if err == nil {
					r.updateToken(result.AccessToken)
					return true, r.getToken(), err
				}
			}
		}
	}
	return false, "", err
}

func (r *AppMeshClient) Logoff() (bool, error) {
	code, _, _, err := r.post("appmesh/self/logoff", nil, nil, nil)
	r.updateToken("")
	return code == http.StatusOK, err
}

// login with existing JWT token, permission is option parameter to check
func (r *AppMeshClient) Authentication(jwtToken string, permission string) (bool, error) {
	headers := Headers{}
	if permission != "" {
		headers["Auth-Permission"] = permission
	}
	code, _, _, err := r.post("appmesh/auth", nil, headers, nil)
	if code == http.StatusOK {
		r.updateToken(jwtToken)
		return true, nil
	}
	return false, err
}

func (r *AppMeshClient) Renew() (bool, error) {
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

func (r *AppMeshClient) TotpSecret() (string, error) {
	code, raw, _, err := r.post("appmesh/totp/secret", nil, nil, nil)
	if code == http.StatusOK {
		m := make(map[string]interface{})
		decoder := json.NewDecoder(bytes.NewReader(raw))
		_ = decoder.Decode(&m)
		totpUri, _ := base64.StdEncoding.DecodeString(m["Mfa-Uri"].(string))
		k, err := otp.NewKeyFromURL(string(totpUri))
		if err != nil {
			return "", err
		}
		return k.Secret(), nil
	}
	return "", err
}

func (r *AppMeshClient) TotpSetup(totpCode string) (bool, error) {
	headers := map[string]string{"Totp": totpCode}
	code, _, _, err := r.post("appmesh/totp/setup", nil, headers, nil)
	return code == http.StatusOK, err
}

func (r *AppMeshClient) TotpDisable() (bool, error) {
	code, _, _, err := r.post("appmesh/totp/self/disable", nil, nil, nil)
	return code == http.StatusOK, err
}

// GetTags gets all lables.
func (r *AppMeshClient) GetTags() (Labels, error) {
	code, raw, _, err := r.get("appmesh/labels", nil, nil)
	label := Labels{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &label)
	}
	return label, err
}

// Get all applications
func (r *AppMeshClient) GetApps() ([]Application, error) {
	code, raw, _, err := r.get("appmesh/applications", nil, nil)
	apps := []Application{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &apps)
	}
	return apps, err
}

// Get one application
func (r *AppMeshClient) GetApp(appName string) (*Application, error) {
	code, raw, _, err := r.get(fmt.Sprintf("/appmesh/app/%s", appName), nil, nil)
	if code == http.StatusOK {
		app := Application{}
		err = json.Unmarshal(raw, &app)
		return &app, err
	}
	return nil, err
}

// Get application stdout
func (r *AppMeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string) AppOutput {
	query := url.Values{}
	query.Set("stdout_position", strconv.FormatInt(stdoutPosition, 10))
	query.Set("stdout_index", strconv.Itoa(stdoutIndex))
	query.Set("stdout_maxsize", strconv.Itoa(stdoutMaxsize))
	query.Set("process_uuid", processUuid)

	code, body, header, err := r.get(fmt.Sprintf("/appmesh/app/%s/output", appName), query, nil)
	resp := AppOutput{Error: err, HttpSuccess: code == http.StatusOK, HttpBody: string(body)}

	// Extract and parse headers
	if exitCodeStr := header.Get("Exit-Code"); exitCodeStr != "" {
		if exitCode, err := strconv.Atoi(exitCodeStr); err == nil {
			resp.ExitCode = &exitCode
		}
	}

	if outputPositionStr := header.Get("Output-Position"); outputPositionStr != "" {
		if outputPosition, err := strconv.ParseInt(outputPositionStr, 10, 64); err == nil {
			resp.OutputPosition = &outputPosition
		}
	}

	return resp
}

// Enable an application
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

// Disable an application
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

// Remove an application
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

// Add a application
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

// Remote run application
func (r *AppMeshClient) RunSync(app Application, maxTimeoutSeconds int) (*int, string, error) {
	appJson, err := json.Marshal(app)
	var exitCode *int
	var respose string
	if err == nil {
		path := "/appmesh/app/syncrun"
		query := url.Values{}
		query.Add("timeout", strconv.Itoa(maxTimeoutSeconds))

		code, raw, headers, err := r.post(path, query, nil, appJson)
		if headers.Get("Exit-Code") != "" {
			value, _ := strconv.Atoi(headers.Get("Exit-Code"))
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

// Remote run application
func (r *AppMeshClient) RunAsync(app Application, maxTimeoutSeconds int) (int, error) {
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

// FileUpload uploads a file to the server
func (r *AppMeshClient) FileUpload(filePath string, remotePath string) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
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
		"File-Path":    remotePath,
	}

	// Get the file attributes
	fileInfo, _ := os.Stat(filePath)
	stat, _ := fileInfo.Sys().(*syscall.Stat_t)

	headers["File-Mode"] = strconv.Itoa(int(fileInfo.Mode().Perm()))
	headers["File-User"] = strconv.Itoa(int(stat.Uid))
	headers["File-Group"] = strconv.Itoa(int(stat.Gid))

	code, raw, _, err := r.post("/appmesh/file/upload", nil, headers, body.Bytes())
	if err != nil {
		return err
	}

	if code != http.StatusOK {
		return fmt.Errorf("upload failed with status: %s", raw)
	}

	return nil
}

// FileDownload downloads a file from the server
func (r *AppMeshClient) FileDownload(remotePath string, localPath string) error {

	headers := map[string]string{"File-Path": remotePath}
	code, raw, respHeaders, _ := r.get("/appmesh/file/download", nil, headers)

	if code != http.StatusOK {
		return fmt.Errorf("download failed with status: %s", raw)
	}

	out, err := os.Create(localPath)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = out.Write(raw)

	// Apply file mode if provided
	if respHeaders.Get("File-Mode") != "" {
		mode, err := strconv.ParseUint(respHeaders.Get("File-Mode"), 10, 32)
		if err != nil {
			fmt.Println("Invalid file mode:", err)
		} else {
			err := os.Chmod(localPath, os.FileMode(uint32(mode)))
			if err != nil {
				fmt.Println("Failed to change file mode:", err)
			}
		}
	}

	// Apply file ownership (UID, GID) if provided
	if respHeaders.Get("File-User") != "" {
		if respHeaders.Get("File-Group") != "" {
			uid, err := strconv.Atoi(respHeaders.Get("File-User"))
			if err != nil {
				fmt.Println("Invalid UID:", err)
			}
			gid, err := strconv.Atoi(respHeaders.Get("File-Group"))
			if err != nil {
				fmt.Println("Invalid GID:", err)
			}
			err = os.Chown(localPath, uid, gid)
			if err != nil {
				fmt.Println("Failed to change file ownership:", err)
			}
		}
	}

	return err
}

// delegate request to target host
func (r *AppMeshClient) getDelegateHost() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.delegateHost
}

// delegate request to target host
func (r *AppMeshClient) updateDelegateHost(host string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.delegateHost = host
}

func (r *AppMeshClient) getToken() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.jwtToken
}

func (r *AppMeshClient) updateToken(token string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.jwtToken = token
}
