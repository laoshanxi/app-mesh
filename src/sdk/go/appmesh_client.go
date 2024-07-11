package appmesh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"sync"

	"github.com/pquerna/otp"
)

var DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24) // default 7 day(s)

// AppmeshClient uses REST API for interacting with REST server.
type AppmeshClient struct {
	baseURL string
	token   string
	client  *http.Client

	mutex sync.Mutex
}

type AppOutputResponse struct {
	HttpSuccess    bool
	HttpBody       string
	OutputPosition *int64
	ExitCode       *int
	Error          error
}

func (r *AppmeshClient) getToken() string {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	return r.token
}

func (r *AppmeshClient) updateToken(token string) {
	r.mutex.Lock()
	defer r.mutex.Unlock()
	r.token = token
}

// NewClient initializes client for interacting with an instance of REST server;
func NewClient(appmeshUri string) *AppmeshClient {
	return &AppmeshClient{baseURL: appmeshUri, client: getRestClient()}
}

func NewClientWithAuth(appmeshUri string, authenKey string) *AppmeshClient {
	return &AppmeshClient{baseURL: appmeshUri, token: authenKey, client: getRestClient()}
}

// login with username and password
func (r *AppmeshClient) Login(user string, password string, totpCode string, timeoutSeconds int) (bool, string, error) {
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

func (r *AppmeshClient) Logoff() (bool, error) {
	code, _, _, err := r.post("appmesh/self/logoff", nil, nil, nil)
	r.updateToken("")
	return code == http.StatusOK, err
}

// login with existing JWT token, permission is option parameter to check
func (r *AppmeshClient) Authentication(jwtToken string, permission string) (bool, error) {
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

func (r *AppmeshClient) Renew() (bool, error) {
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

func (r *AppmeshClient) TotpSecret() (string, error) {
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

func (r *AppmeshClient) TotpSetup(totpCode string) (bool, error) {
	headers := map[string]string{"Totp": totpCode}
	code, _, _, err := r.post("appmesh/totp/setup", nil, headers, nil)
	return code == http.StatusOK, err
}

func (r *AppmeshClient) TotpDisable() (bool, error) {
	code, _, _, err := r.post("appmesh/totp/self/disable", nil, nil, nil)
	return code == http.StatusOK, err
}

// GetTags gets all lables.
func (r *AppmeshClient) GetTags() (Labels, error) {
	code, raw, _, err := r.get("appmesh/labels", nil)
	label := Labels{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &label)
	}
	return label, err
}

// Get all applications
func (r *AppmeshClient) GetApps() ([]Application, error) {
	code, raw, _, err := r.get("appmesh/applications", nil)
	apps := []Application{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &apps)
	}
	return apps, err
}

// Get one application
func (r *AppmeshClient) GetApp(appName string) (*Application, error) {
	code, raw, _, err := r.get(fmt.Sprintf("/appmesh/app/%s", appName), nil)
	if code == http.StatusOK {
		app := Application{}
		err = json.Unmarshal(raw, &app)
		return &app, err
	}
	return nil, err
}

// Get application stdout
func (r *AppmeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string) AppOutputResponse {
	query := url.Values{}
	query.Set("stdout_position", strconv.FormatInt(stdoutPosition, 10))
	query.Set("stdout_index", strconv.Itoa(stdoutIndex))
	query.Set("stdout_maxsize", strconv.Itoa(stdoutMaxsize))
	query.Set("process_uuid", processUuid)

	code, body, header, err := r.get(fmt.Sprintf("/appmesh/app/%s/output", appName), query)
	resp := AppOutputResponse{Error: err, HttpSuccess: code == http.StatusOK, HttpBody: string(body)}

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
func (r *AppmeshClient) EnableApp(appName string) error {
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
func (r *AppmeshClient) DisableApp(appName string) error {
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
func (r *AppmeshClient) RemoveApp(appName string) error {
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
func (r *AppmeshClient) AddApp(app Application) (*Application, error) {
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
func (r *AppmeshClient) RunSync(app Application, maxTimeoutSeconds int) (int, error) {
	appJson, err := json.Marshal(app)
	exitCode := 0
	if err == nil {
		path := "/appmesh/app/syncrun"
		query := url.Values{}
		query.Add("timeout", strconv.Itoa(maxTimeoutSeconds))

		code, raw, headers, err := r.post(path, query, nil, appJson)
		if headers.Get("Exit-Code") != "" {
			exitCode, err = strconv.Atoi(headers.Get("Exit-Code"))
		}
		if code == http.StatusOK {
			fmt.Print(string(raw))
		}
		return exitCode, err
	}
	return exitCode, err
}

// Remote run application
func (r *AppmeshClient) RunAsync(app Application, maxTimeoutSeconds int) (int, error) {
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
