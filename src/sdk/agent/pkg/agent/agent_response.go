package agent

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// Response represents the message received over TCP
type Response struct {
	appmesh.Response
	TempDownloadFilePath string
	TempUploadFilePath   string
}

type ResponseMessage struct {
	Message string `json:"message"`
}

// ReadAppMeshResponse reads and parses a new response from the connection
func ReadAppMeshResponse(conn *Connection) (*Response, error) {
	data, err := conn.ReadMessage()
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, errors.New("empty message received")
	}

	r := new(Response)
	err = r.Deserialize(data)
	if err != nil {
		return nil, err
	}

	// Handle TCP file download
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Recv_File_Socket]; exists && r.HttpStatus == http.StatusOK {
		r.TempDownloadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.Uuid)

		bytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			logger.Warnf("Failed to decode base64 string for download: %v", err)
			return nil, err
		}

		file := string(bytes)
		logger.Infof("Downloading remote file <%s> to local file <%s>", file, r.TempDownloadFilePath)

		if err := r.ReadFileData(conn, r.TempDownloadFilePath); err != nil {
			return nil, err
		}
	}

	// Handle TCP file upload
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Send_File_Socket]; exists && r.HttpStatus == http.StatusOK {
		r.TempUploadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.Uuid)

		bytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			logger.Warnf("Failed to decode base64 string for upload: %v", err)
			return nil, err
		}

		file := string(bytes)
		logger.Debugf("Preparing to upload local file <%s> to remote file <%s>", r.TempUploadFilePath, file)
	}

	return r, err
}

// ReadFileData reads file data from the connection and writes it to the target file path
func (r *Response) ReadFileData(conn *Connection, targetFilePath string) error {
	// No need lock here, as ReadAppMeshResponse() is a single thread
	f, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		logger.Warnf("Failed to create file: %v", err)
		return err
	}
	defer f.Close()

	for {
		bodyBuf, err := conn.ReadMessage()
		if err != nil {
			logger.Warnf("Error reading TCP file header: %v", err)
			return err
		}

		if bodyBuf == nil {
			logger.Debugf("Completed reading TCP file to: <%s>", targetFilePath)
			break
		}

		if _, err = f.Write(bodyBuf); err != nil {
			logger.Warnf("Failed to write to file: %v", err)
			return err
		}
	}

	return nil
}

// ApplyResponse applies the response to the HTTP response writer
func (r *Response) ApplyResponse(w http.ResponseWriter, req *http.Request, request *appmesh.Request) {
	// Set headers
	for k, v := range r.Headers {
		w.Header().Set(k, v)
	}

	// Set cookies
	r.setCookie(w, req, request)

	// Handle the response body based on the path
	if r.RequestUri == REST_PATH_DOWNLOAD || r.RequestUri == REST_PATH_UPLOAD {
		if err := HandleRESTFile(w, req, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		logger.Debugf("File REST call Finished %s", r.Uuid)
	} else {
		// Set content type
		if len(r.BodyMsgType) > 0 {
			w.Header().Set("Content-Type", r.BodyMsgType)
		}

		// Set status code
		w.WriteHeader(r.HttpStatus)

		if len(r.Body) > 0 {
			if _, err := w.Write([]byte(r.Body)); err != nil {
				logger.Warnf("Error writing response body for %s: %v", r.Uuid, err)
			}
		}
		logger.Debugf("REST call Finished %s", r.Uuid)
	}
}

// setCookie manages authentication cookies based on the HTTP request and response
// It handles three scenarios:
// 1. Setting cookies on successful login
// 2. Refreshing cookies on token renewal
// 3. Removing cookies on logout
func (r *Response) setCookie(w http.ResponseWriter, req *http.Request, request *appmesh.Request) {
	// Check if authentication failed
	if r.HttpStatus == http.StatusUnauthorized {
		// Clear cookie on unauthorized response
		if _, err := req.Cookie(COOKIE_TOKEN); err == nil {
			r.clearAuthCookie(w, req)
		}
		return
	}

	// Only proceed for successful responses
	if r.HttpStatus != http.StatusOK {
		return
	}

	switch r.RequestUri {
	case REST_PATH_LOGIN, REST_PATH_TOTP_VALIDATE:
		// Set cookie if explicitly requested via header and value is true
		if setCookieVal, ok := request.Headers[HTTP_HEADER_KEY_X_SET_COOKIE]; ok {
			if requestSetCookie, err := strconv.ParseBool(setCookieVal); err == nil && requestSetCookie {
				r.createAuthCookie(w, req)
			} else {
				logger.Debugf("Set-Cookie header value invalid or false for %s", r.Uuid)
			}
		}

	case REST_PATH_TOKEN_RENEW, REST_PATH_TOTP_SETUP:
		// Verify cookie exists and has valid value
		if cookie, err := req.Cookie(COOKIE_TOKEN); err != nil {
			logger.Debugf("No cookie present for %s", r.Uuid)
			return
		} else if cookie.Value == "" {
			logger.Debugf("Empty cookie value for %s", r.Uuid)
			return
		}
		r.createAuthCookie(w, req)

	case REST_PATH_LOGOFF:
		// Clear existing cookie if present
		if _, err := req.Cookie(COOKIE_TOKEN); err == nil {
			r.clearAuthCookie(w, req)
		}
	}
}

// createAuthCookie extracts JWT token from response body and creates an auth cookie
func (r *Response) createAuthCookie(w http.ResponseWriter, req *http.Request) {
	logger.Infof("Creating authentication cookie for %s", r.Uuid)
	// Parse JWT from response body
	var jwtResponse struct {
		AccessToken   string  `json:"access_token"`
		ExpireSeconds float64 `json:"expire_seconds"`
	}

	if err := json.Unmarshal([]byte(r.Body), &jwtResponse); err != nil {
		logger.Warnf("Failed to unmarshal JWT response body for %s: %v", r.Uuid, err)
		return
	}

	// Validate token presence
	if jwtResponse.AccessToken == "" {
		logger.Warnf("Missing access_token in response body for %s", r.Uuid)
		return
	}

	// Create cookie with standard security settings
	cookie := &http.Cookie{
		Name:     COOKIE_TOKEN,
		Value:    strings.TrimPrefix(jwtResponse.AccessToken, "Bearer "),
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteStrictMode,
	}

	// Set expiration if available
	if jwtResponse.ExpireSeconds > 0 {
		cookie.MaxAge = int(jwtResponse.ExpireSeconds)
	}

	http.SetCookie(w, cookie)

	// Create CSRF token cookie (generate HMAC token from access token)
	r.createCSRFToken(w, req, cookie.MaxAge, jwtResponse.AccessToken)
}

// clearAuthCookie invalidates the authentication cookie
func (r *Response) clearAuthCookie(w http.ResponseWriter, req *http.Request) {
	logger.Debugf(" Clearing authentication cookie for %s", r.Uuid)
	http.SetCookie(w, &http.Cookie{
		Name:     COOKIE_TOKEN,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Expire immediately
	})

	r.clearCSRFToken(w, req)
}

// clearCSRFToken invalidates the CSRF token cookie
func (r *Response) clearCSRFToken(w http.ResponseWriter, req *http.Request) {
	logger.Debugf("Clearing CSRF token for %s", r.Uuid)
	http.SetCookie(w, &http.Cookie{
		Name:     COOKIE_TOKEN,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1, // Expire immediately
	})
}

// createCSRFToken generates a CSRF token and sets it in the response header
func (r *Response) createCSRFToken(w http.ResponseWriter, req *http.Request, maxAge int, hmacMessage string) {
	logger.Debugf("Creating CSRF token for %s", r.Uuid)

	token := cloud.HMAC.GenerateHMAC(hmacMessage)

	cookie := &http.Cookie{
		Name:     COOKIE_CSRF_TOKEN,
		Value:    token, // Set the CSRF token as the cookie value
		Path:     "/",
		HttpOnly: false, // CSRF token should be accessible via JavaScript
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}

	http.SetCookie(w, cookie)
}
