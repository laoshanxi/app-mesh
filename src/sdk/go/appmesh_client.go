package appmesh

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// defaultHTTPClient initialized AppMesh with appropriate conditions.
// skip https ssl certification.
var defaultHTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
var DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24) // default 7 days
// Client uses REST API for interacting with REST server.
type Client struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewClient initializes client for interacting with an instance of REST server;
func NewClient(apiURL string) (*Client, error) {
	if strings.HasPrefix(apiURL, "https://") {
		return &Client{baseURL: apiURL, client: defaultHTTPClient}, nil
	} else if strings.HasPrefix(apiURL, "http://") {
		return &Client{baseURL: apiURL, client: http.DefaultClient}, nil
	} else {
		return nil, fmt.Errorf("invalid API URL <%s>", apiURL)
	}
}

// REST GET
func (r *Client) get(path string, params url.Values) ([]byte, int, http.Header, error) {
	return r.doRequest("GET", path, params, nil, nil)
}

// REST PUT
func (r *Client) put(path string, params url.Values, headers map[string]string, body []byte) ([]byte, int, error) {
	raw, code, _, err := r.doRequest("PUT", path, params, headers, bytes.NewBuffer(body))
	return raw, code, err
}

// REST POST
func (r *Client) post(path string, params url.Values, headers map[string]string, body []byte) ([]byte, int, error) {
	raw, code, _, err := r.doRequest("POST", path, params, headers, bytes.NewBuffer(body))
	return raw, code, err
}

// REST DELETE
func (r *Client) delete(path string) ([]byte, int, error) {
	raw, code, _, err := r.doRequest("DELETE", path, nil, nil, nil)
	return raw, code, err
}

// REST request
func (r *Client) doRequest(method string, apiPath string, params url.Values, headers map[string]string, buf io.Reader) ([]byte, int, http.Header, error) {
	u, _ := url.Parse(r.baseURL)
	u.Path = path.Join(u.Path, apiPath)
	if params != nil {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, 0, nil, err
	}

	// headers
	if r.token != "" {
		req.Header.Set("Authorization", "Bearer "+r.token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "autograf")
	for k, v := range headers {
		req.Header.Add(k, v)
	}

	resp, err := r.client.Do(req)

	if err != nil {
		fmt.Println(err.Error())
		return nil, 0, nil, err
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(string(data))
	}
	// https://www.cnblogs.com/wangjiale1024/p/10979993.html
	return data, resp.StatusCode, resp.Header, err
}

// login with username and password
func (r *Client) Login(user string, password string, timeoutSeconds int) (bool, string, error) {
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
			r.token = result.AccessToken
			return true, r.token, err
		} else {
			return false, "", err
		}
	} else {
		return (code == http.StatusOK), "", err
	}
}

// login with existing JWT token, permission is option parameter to check
func (r *Client) Authentication(jwtToken string, permission string) (bool, error) {
	r.token = jwtToken
	headers := Headers{}
	if permission != "" {
		headers["Auth-Permission"] = permission
	}
	_, code, err := r.post("appmesh/auth", nil, headers, nil)
	return (code == http.StatusOK), err
}

// GetTags gets all lables.
func (r *Client) GetTags() (Labels, error) {
	raw, code, _, err := r.get("appmesh/labels", nil)
	label := Labels{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &label)
	}
	return label, err
}

// Get all applications
func (r *Client) GetApps() ([]Application, error) {
	raw, code, _, err := r.get("appmesh/applications", nil)
	apps := []Application{}
	if code == http.StatusOK {
		err = json.Unmarshal(raw, &apps)
	}
	return apps, err
}

// Get one application
func (r *Client) GetApp(appName string) (*Application, error) {
	raw, code, _, err := r.get(fmt.Sprintf("/appmesh/app/%s", appName), nil)
	if code == http.StatusOK {
		app := Application{}
		err = json.Unmarshal(raw, &app)
		return &app, err
	}
	return nil, err
}

// Get application stdout
func (r *Client) GetAppOutput(appName string, keepHistory bool, stdoutIndex int) (string, error) {
	query := url.Values{}
	keep := 0
	if keepHistory {
		keep = 1
	}
	query.Add("keep_history", strconv.Itoa(keep))
	query.Add("stdout_index", strconv.Itoa(stdoutIndex))
	raw, code, _, err := r.get(fmt.Sprintf("/appmesh/app/%s/output", appName), query)
	if code == http.StatusOK {
		return string(raw), err
	} else {
		if err != nil {
			return string(raw), err
		}
		return string(raw), fmt.Errorf("HTTP error: %s", string(raw))
	}
}

// Enable an application
func (r *Client) EnableApp(appName string) error {
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
func (r *Client) DisableApp(appName string) error {
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
func (r *Client) RemoveApp(appName string) error {
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
func (r *Client) AddApp(app Application) (*Application, error) {
	appJson, err := json.Marshal(app)
	if err == nil {
		raw, code, err := r.put(fmt.Sprintf("/appmesh/app/%s", *app.Name), nil, nil, appJson)
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
func (r *Client) Run(app Application, syncrize bool, maxExectimeSeconds int, asyncRetentionSeconds int) error {
	appJson, err := json.Marshal(app)
	if err == nil {
		path := ""
		if syncrize {
			path = "/appmesh/app/syncrun"
		} else {
			path = "/appmesh/app/run"
		}
		query := url.Values{}
		query.Add("timeout", strconv.Itoa(maxExectimeSeconds))
		query.Add("retention", strconv.Itoa(asyncRetentionSeconds))

		raw, code, _ := r.post(path, query, nil, appJson)
		if code == http.StatusOK {
			if syncrize {
				fmt.Print(string(raw))
				return nil
			} else {
				resultApp := Application{}
				json.Unmarshal(raw, &resultApp)
				uuid := resultApp.Uuid
				if uuid != nil && *uuid != "" {
					query = url.Values{}
					query.Add("process_uuid", *uuid)
					for {
						path = fmt.Sprintf("/appmesh/app/%s/run/output", *resultApp.Name)
						output, returnCode, header, _ := r.get(path, query)
						if len(output) > 0 {
							fmt.Print(string(output))
						}
						if header.Get("exit_code") != "" {
							break
						}
						if returnCode != http.StatusOK {
							break
						}
						time.Sleep(time.Microsecond * 500)
					}
				}
			}
		}
	}
	return nil
}

//////////////////////////////////////////////////////////////////////////
// Entity definition
//////////////////////////////////////////////////////////////////////////

// Application json
type Application struct {
	// main definition
	Name           *string `json:"name"`
	Command        *string `json:"command"`
	InitCommand    *string `json:"init_command"`
	FiniCommand    *string `json:"fini_command"`
	HealthCheckCMD *string `json:"health_check_cmd"`
	WorkingDir     *string `json:"working_dir"`
	Status         *int    `json:"status"`
	StartTime      *string `json:"start_time"`
	EndTime        *string `json:"end_time"`

	// short running definition
	StartIntervalSeconds *string `json:"start_interval_seconds"`
	StartIntervalTimeout *string `json:"start_interval_timeout"`
	Cron                 *bool   `json:"cron"`
	KeepRunning          *bool   `json:"keep_running"`

	// runtime attributes
	Pid           *int    `json:"pid"`
	Return        *int    `json:"return"`
	Health        *int    `json:"health"`
	Fd            *int    `json:"fd"`
	ContainerID   *string `json:"container_id"`
	LastStartTime *string `json:"last_start_time"`
	NextStartTime *string `json:"next_start_time"`
	RegisterTime  *string `json:"register_time"`
	CPU           *int    `json:"cpu"`
	Memory        *int    `json:"memory"`
	Uuid          *string `json:"process_uuid"` // for run application

	Owner      *string `json:"owner"`
	Permission *int    `json:"permission"`
	ShellMode  *bool   `json:"shell_mode"`

	StdoutCacheNum *int    `json:"stdout_cache_num"`
	Metadata       *string `json:"metadata"`
	Version        *string `json:"version"`
	LastError      *string `json:"last_error"`

	PosixTimeZone *string `json:"posix_timezone"`
	DockerImage   *string `json:"docker_image"`

	DailyLimit    *DailyLimitation    `json:"daily_limitation"`
	ResourceLimit *ResourceLimitation `json:"resource_limit"`
	Env           *Environments       `json:"env"`
	SecEnv        *Environments       `json:"sec_env"`
}

type DailyLimitation struct {
	DailyStart string `json:"daily_start"`
	DailyEnd   string `json:"daily_end"`
}

type ResourceLimitation struct {
	MemoryMb        int `json:"memory_mb"`
	MemoryVirtualMb int `json:"memory_virt_mb"`
	CpuShares       int `json:"cpu_shares"`
}

// https://mholt.github.io/json-to-go/
type JWTResponse struct {
	AccessToken   string `json:"Access-Token"`
	ExpireSeconds int    `json:"expire_seconds"`
	ExpireTime    int    `json:"expire_time"`
	Profile       struct {
		AuthTime int    `json:"auth_time"`
		Name     string `json:"name"`
	} `json:"profile"`
	TokenType string `json:"token_type"`
}

// Env json
type Environments = map[string]string

// Label json
type Labels = map[string]string

// REST Headers
type Headers = map[string]string
