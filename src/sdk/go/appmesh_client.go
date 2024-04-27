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
	"time"

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
		"Username":       base64.StdEncoding.EncodeToString([]byte(user)),
		"Password":       base64.StdEncoding.EncodeToString([]byte(password)),
		"Expire-Seconds": strconv.Itoa(timeoutSeconds),
	}
	raw, code, err := r.post("appmesh/login", nil, headers, nil)
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
		if challenge, ok := m["totp_challenge"].(string); ok {
			headers = map[string]string{
				"Username":       base64.StdEncoding.EncodeToString([]byte(user)),
				"Totp":           base64.StdEncoding.EncodeToString([]byte(totpCode)),
				"Totp-Challenge": base64.StdEncoding.EncodeToString([]byte(challenge)),
				"Expire-Seconds": strconv.Itoa(timeoutSeconds),
			}
			raw, code, err = r.post("appmesh/totp/validate", nil, headers, nil)
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
	_, code, err := r.post("appmesh/self/logoff", nil, nil, nil)
	r.updateToken("")
	return code == http.StatusOK, err
}

// login with existing JWT token, permission is option parameter to check
func (r *AppmeshClient) Authentication(jwtToken string, permission string) (bool, error) {
	headers := Headers{}
	if permission != "" {
		headers["Auth-Permission"] = permission
	}
	_, code, err := r.post("appmesh/auth", nil, headers, nil)
	if code == http.StatusOK {
		r.updateToken(jwtToken)
		return true, nil
	}
	return false, err
}

func (r *AppmeshClient) Renew() (bool, error) {
	raw, code, err := r.post("appmesh/token/renew", nil, nil, nil)
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
	raw, code, err := r.post("appmesh/totp/secret", nil, nil, nil)
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
	headers := map[string]string{"Totp": base64.StdEncoding.EncodeToString([]byte(totpCode))}
	_, code, err := r.post("appmesh/totp/setup", nil, headers, nil)
	return code == http.StatusOK, err
}

func (r *AppmeshClient) TotpDisable() (bool, error) {
	_, code, err := r.post("appmesh/totp/self/disable", nil, nil, nil)
	return code == http.StatusOK, err
}

// GetTags gets all lables.
func (r *AppmeshClient) GetTags() (Labels, error) {
	raw, code, _, err := r.get("appmesh/labels", nil)
	label := Labels{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &label)
	}
	return label, err
}

// Get all applications
func (r *AppmeshClient) GetApps() ([]Application, error) {
	raw, code, _, err := r.get("appmesh/applications", nil)
	apps := []Application{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &apps)
	}
	return apps, err
}

// Get one application
func (r *AppmeshClient) GetApp(appName string) (*Application, error) {
	raw, code, _, err := r.get(fmt.Sprintf("/appmesh/app/%s", appName), nil)
	if code == http.StatusOK {
		app := Application{}
		err = json.Unmarshal(raw, &app)
		return &app, err
	}
	return nil, err
}

// Get application stdout
func (r *AppmeshClient) GetAppOutput(appName string, stdoutPosition int64, stdoutIndex int, stdoutMaxsize int, processUuid string) (bool, string, http.Header, error) {
	query := url.Values{}
	query.Add("stdout_position", strconv.FormatInt(int64(stdoutPosition), 10))
	query.Add("stdout_index", strconv.Itoa(stdoutIndex))
	query.Add("stdout_maxsize", strconv.Itoa(stdoutMaxsize))
	query.Add("process_uuid", processUuid)
	raw, code, header, err := r.get(fmt.Sprintf("/appmesh/app/%s/output", appName), query)
	if code == http.StatusOK {
		return true, string(raw), header, err
	} else {
		if err != nil {
			return false, string(raw), header, err
		}
		return false, string(raw), header, fmt.Errorf("HTTP error: %s", string(raw))
	}
}

// Enable an application
func (r *AppmeshClient) EnableApp(appName string) error {
	raw, code, err := r.post(fmt.Sprintf("/appmesh/app/%s/enable", appName), nil, nil, nil)
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
	raw, code, err := r.post(fmt.Sprintf("/appmesh/app/%s/disable", appName), nil, nil, nil)
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
	raw, code, err := r.delete(fmt.Sprintf("/appmesh/app/%s", appName))
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
		raw, code, err := r.put(fmt.Sprintf("/appmesh/app/%s", app.Name), nil, nil, appJson)
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
func (r *AppmeshClient) Run(app Application, syncrize bool, maxExectimeSeconds int) (int, error) {
	appJson, err := json.Marshal(app)
	exitCode := 0
	if err == nil {
		path := ""
		if syncrize {
			path = "/appmesh/app/syncrun"
		} else {
			path = "/appmesh/app/run"
		}
		query := url.Values{}
		query.Add("timeout", strconv.Itoa(maxExectimeSeconds))

		raw, code, _ := r.post(path, query, nil, appJson)
		if code == http.StatusOK {
			if syncrize {
				fmt.Print(string(raw))
				return exitCode, nil
			} else {
				resultApp := Application{}
				json.Unmarshal(raw, &resultApp)
				uuid := resultApp.Uuid
				if uuid != nil && *uuid != "" {
					var outputPosition int64 = 0
					for {
						query = url.Values{}
						query.Add("process_uuid", *uuid)
						query.Add("stdout_position", strconv.FormatInt(outputPosition, 10))

						success, output, header, _ := r.GetAppOutput(resultApp.Name, outputPosition, 0, 10240, *uuid)
						if len(output) > 0 {
							fmt.Print(string(output))
						}
						if header.Get("Output-Position") != "" {
							outputPosition, err = strconv.ParseInt(header.Get("Output-Position"), 10, 64)
						}
						if header.Get("Exit-Code") != "" {
							exitCode, err = strconv.Atoi(header.Get("Exit-Code"))
							break
						}
						if !success {
							break
						}
						time.Sleep(time.Microsecond * 500)
					}
					r.RemoveApp(resultApp.Name)
				}
			}
		}
	}
	return exitCode, err
}
