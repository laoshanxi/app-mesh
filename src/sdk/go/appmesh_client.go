package main

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
	"unsafe"
)

// defaultHTTPClient initialized AppMesh with appropriate conditions.
// It allows you globally redefine HTTP client.
// skip https ssl certification.
var defaultHTTPClient = &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
var DEFAULT_TOKEN_EXPIRE_SECONDS = 7 * (60 * 60 * 24) // default 7 days
// Client uses REST API for interacting with REST server.
type Client struct {
	baseURL string
	token   string
	client  *http.Client
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
		err = json.NewDecoder(strings.NewReader(*raw)).Decode(&result)
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

// login with existing JWT token
func (r *Client) LoginWithToken(jwtToken string) (bool, error) {
	r.token = jwtToken
	_, code, err := r.post("appmesh/auth", nil, nil, nil)
	return (code == http.StatusOK), err
}

func (r *Client) get(path string, params url.Values) (*string, int, error) {
	return r.doRequest("GET", path, params, nil, nil)
}

func (r *Client) patch(path string, params url.Values, headers map[string]string, body []byte) (*string, int, error) {
	return r.doRequest("PATCH", path, params, headers, bytes.NewBuffer(body))
}

func (r *Client) put(path string, params url.Values, headers map[string]string, body []byte) (*string, int, error) {
	return r.doRequest("PUT", path, params, headers, bytes.NewBuffer(body))
}

func (r *Client) post(path string, params url.Values, headers map[string]string, body []byte) (*string, int, error) {
	return r.doRequest("POST", path, params, headers, bytes.NewBuffer(body))
}

func (r *Client) delete(path string) (*string, int, error) {
	return r.doRequest("DELETE", path, nil, nil, nil)
}

func (r *Client) doRequest(method string, apiPath string, params url.Values, headers map[string]string, buf io.Reader) (*string, int, error) {
	u, _ := url.Parse(r.baseURL)
	u.Path = path.Join(u.Path, apiPath)
	if params != nil {
		u.RawQuery = params.Encode()
	}
	req, err := http.NewRequest(method, u.String(), buf)
	if err != nil {
		return nil, 0, err
	}

	// headers
	if len(r.token) > 0 {
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
		return nil, 0, err
	}
	data, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Println(string(data))
	}
	// https://www.cnblogs.com/wangjiale1024/p/10979993.html
	return (*string)(unsafe.Pointer(&data)), resp.StatusCode, err
}

// GetTags gets all lables.
// Reflects GET /appmesh/labels API call.
func (r *Client) GetTags() (*string, int, error) {
	return r.get("appmesh/labels", nil)
}

func main() {

	fmt.Println("main")
	client, _ := NewClient("https://localhost:6060")

	_, token, _ := client.Login("admin", "Admin123", DEFAULT_TOKEN_EXPIRE_SECONDS)
	client.LoginWithToken(token)
	raw, code, err := client.GetTags()
	if err != nil {
		fmt.Printf("HTTP error %d: returns %s", code, *raw)
	} else {
		fmt.Printf("HTTP success %d: returns %s", code, *raw)
	}
	fmt.Println("end")
}
