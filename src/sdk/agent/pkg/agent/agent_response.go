// agent_response.go
package agent

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path"

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

// readResponseFromConn reads and parses a new response from the connection
func readResponseFromConn(conn *Connection) (*Response, error) {
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
		if err := r.downloadFileFromConn(conn, value); err != nil {
			return nil, fmt.Errorf("handle file download for UUID %s: %w", r.UUID, err)
		}
	}

	// Handle TCP file upload
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Send_File_Socket]; exists && r.HttpStatus == http.StatusOK {
		if err := r.prepareFileUpload(value); err != nil {
			return nil, fmt.Errorf("prepare file upload for UUID %s: %w", r.UUID, err)
		}
	}

	return r, nil
}

// downloadFileFromConn processes file download from the connection
func (r *Response) downloadFileFromConn(conn *Connection, encodedPath string) error {
	bytes, err := base64.StdEncoding.DecodeString(encodedPath)
	if err != nil {
		return fmt.Errorf("decode base64 path: %w", err)
	}

	r.TempDownloadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.UUID)
	remoteFile := string(bytes)

	logger.Infof("Downloading remote file <%s> to local file <%s>", remoteFile, r.TempDownloadFilePath)

	if err := r.readFileFromConn(conn, r.TempDownloadFilePath); err != nil {
		// Clean up partial file on error
		os.Remove(r.TempDownloadFilePath)
		return fmt.Errorf("read file data from %s: %w", remoteFile, err)
	}

	return nil
}

// prepareFileUpload sets up for file upload
func (r *Response) prepareFileUpload(encodedPath string) error {
	bytes, err := base64.StdEncoding.DecodeString(encodedPath)
	if err != nil {
		return fmt.Errorf("decode base64 path: %w", err)
	}

	r.TempUploadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.UUID)
	remoteFile := string(bytes)

	logger.Debugf("Preparing to upload local file <%s> to remote file <%s>", r.TempUploadFilePath, remoteFile)
	return nil
}

// readFileFromConn reads file data from the connection and writes it to the target file path
func (r *Response) readFileFromConn(conn *Connection, targetFilePath string) error {
	// No need lock here, as ReadAppMeshResponse() is a single thread
	f, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
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

// writeToHTTPResponse applies the response to the HTTP response writer
func (r *Response) writeToHTTPResponse(w http.ResponseWriter, req *http.Request) {
	// Set headers
	for k, v := range r.Headers {
		w.Header().Set(k, v)
	}

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
