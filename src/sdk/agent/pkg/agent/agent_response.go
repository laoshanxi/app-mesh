// agent_response.go
package agent

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/cloud"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/utils"
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

// ReceiveAppMeshResponse reads and parses a new response from the connection
func ReceiveAppMeshResponse(conn *Connection) (*Response, error) {
	data, err := conn.ReadMessage()
	if err != nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	if data == nil {
		return nil, errors.New("empty message received")
	}

	r := new(Response)
	if err := r.Deserialize(data); err != nil {
		return nil, fmt.Errorf("deserialize response: %w", err)
	}

	// Handle TCP file download
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Recv_File_Socket]; exists && r.HttpStatus == http.StatusOK {
		if err := r.handleFileDownload(conn, value); err != nil {
			return nil, fmt.Errorf("handle file download for UUID %s: %w", r.UUID, err)
		}
	}

	// Handle TCP file upload
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Send_File_Socket]; exists && r.HttpStatus == http.StatusOK {
		if err := r.handleFileUpload(value); err != nil {
			return nil, fmt.Errorf("prepare file upload for UUID %s: %w", r.UUID, err)
		}
	}

	return r, nil
}

// handleFileDownload processes file download from the connection
func (r *Response) handleFileDownload(conn *Connection, encodedPath string) error {
	bytes, err := base64.StdEncoding.DecodeString(encodedPath)
	if err != nil {
		return fmt.Errorf("decode base64 path: %w", err)
	}

	r.TempDownloadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.UUID)
	remoteFile := string(bytes)

	logger.Infof("Downloading remote file <%s> to local file <%s>", remoteFile, r.TempDownloadFilePath)

	if err := r.ReadFileData(conn, r.TempDownloadFilePath); err != nil {
		// Clean up partial file on error
		os.Remove(r.TempDownloadFilePath)
		return fmt.Errorf("read file data from %s: %w", remoteFile, err)
	}

	return nil
}

// handleFileUpload sets up for file upload
func (r *Response) handleFileUpload(encodedPath string) error {
	bytes, err := base64.StdEncoding.DecodeString(encodedPath)
	if err != nil {
		return fmt.Errorf("decode base64 path: %w", err)
	}

	r.TempUploadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.UUID)
	remoteFile := string(bytes)

	logger.Debugf("Preparing to upload local file <%s> to remote file <%s>", r.TempUploadFilePath, remoteFile)
	return nil
}

// ReadFileData reads file data from the connection and writes it to the target file path
func (r *Response) ReadFileData(conn *Connection, targetFilePath string) error {
	// No need lock here, as ReadAppMeshResponse() is a single thread
	f, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create file: %w", err)
	}
	defer f.Close()

	// Use larger buffer for better performance
	bufWriter := bufio.NewWriterSize(f, 128*1024) // 128KB buffer
	defer bufWriter.Flush()

	for {
		bodyBuf, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read TCP file chunk: %w", err)
		}

		// EOF marker
		if len(bodyBuf) == 0 {
			break
		}

		if _, err = bufWriter.Write(bodyBuf); err != nil {
			return fmt.Errorf("write to file: %w", err)
		}
	}

	return bufWriter.Flush()
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
			utils.HttpError(w, err.Error(), http.StatusInternalServerError)
		}
		logger.Debugf("File REST call finished %s", r.UUID)
	} else {
		// Set content type
		if len(r.BodyMsgType) > 0 {
			w.Header().Set("Content-Type", r.BodyMsgType)
		}

		// Set status code
		w.WriteHeader(r.HttpStatus)

		if len(r.Body) > 0 {
			if _, err := w.Write(r.Body); err != nil {
				logger.Warnf("Error writing response body for %s: %v", r.UUID, err)
			}
		}
		logger.Debugf("REST call finished %s", r.UUID)
	}
}

// setCookie manages authentication cookies based on the HTTP request and response
// It handles three scenarios:
// 1. Setting cookies on successful login
// 2. Refreshing cookies on token renewal
// 3. Removing cookies on logout
func (r *Response) setCookie(w http.ResponseWriter, req *http.Request, request *appmesh.Request) {
	// Only proceed for successful responses
	if r.HttpStatus != http.StatusOK {
		return
	}

	switch r.RequestUri {
	case REST_PATH_LOGIN, REST_PATH_TOTP_VALIDATE, REST_PATH_AUTH:
		r.setSecureHeaders(w)
		// Set cookie if explicitly requested via header and value is true
		if setCookieVal, ok := request.Headers[HTTP_HEADER_KEY_X_SET_COOKIE]; ok {
			if requestSetCookie, _ := strconv.ParseBool(setCookieVal); requestSetCookie {
				r.createAuthCookie(w, req)
			}
		}

	case REST_PATH_TOKEN_RENEW, REST_PATH_TOTP_SETUP:
		r.setSecureHeaders(w)
		// Verify cookie exists and has valid value
		cookie, err := req.Cookie(COOKIE_TOKEN)
		if err != nil {
			logger.Debugf("No cookie present for %s", r.UUID)
			return
		}
		if cookie.Value == "" {
			logger.Debugf("Empty cookie value for %s", r.UUID)
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
	logger.Infof("Creating authentication cookie for %s", r.UUID)

	// Parse JWT from response body
	var jwtResponse struct {
		AccessToken   string  `json:"access_token"`
		ExpireSeconds float64 `json:"expire_seconds"`
	}

	if err := json.Unmarshal(r.Body, &jwtResponse); err != nil {
		logger.Warnf("Failed to unmarshal JWT response body for %s: %v", r.UUID, err)
		return
	}

	// Validate token presence
	if jwtResponse.AccessToken == "" {
		logger.Warnf("Missing access_token in response body for %s", r.UUID)
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
	logger.Debugf("Clearing authentication cookie for %s", r.UUID)
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
	logger.Debugf("Clearing CSRF token for %s", r.UUID)
	http.SetCookie(w, &http.Cookie{
		Name:     COOKIE_CSRF_TOKEN,
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
	logger.Debugf("Creating CSRF token for %s", r.UUID)

	token := cloud.HMAC_SDKToAgent.GenerateHMAC(hmacMessage)

	cookie := &http.Cookie{
		Name:     COOKIE_CSRF_TOKEN,
		Value:    token,
		Path:     "/",
		HttpOnly: false, // CSRF token should be accessible via JavaScript
		Secure:   req.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	}

	http.SetCookie(w, cookie)
}

// setSecureHeaders sets security headers for sensitive responses
func (r *Response) setSecureHeaders(w http.ResponseWriter) {
	// Prevent sensitive responses (like JWTs) from being cached by browsers or proxies.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}
