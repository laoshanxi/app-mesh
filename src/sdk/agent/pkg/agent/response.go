package agent

import (
	"encoding/base64"
	"encoding/binary"
	"log"
	"net"
	"net/http"
	"os"
	"path"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/valyala/fasthttp"
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

func ReadNewResponse(conn net.Conn) (*Response, error) {
	headerBuf, err := readTcpData(conn, TCP_MESSAGE_HEADER_LENGTH)
	if err != nil {
		return nil, err
	}

	bodyBuf, err := readTcpData(conn, binary.BigEndian.Uint32(headerBuf))
	if err != nil {
		return nil, err
	}

	r := new(Response)
	err = r.Deserialize(bodyBuf)
	if err != nil {
		return nil, err
	}

	// Handle TCP file download
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Recv_File_Socket]; exists && r.HttpStatus == fasthttp.StatusOK {
		r.TempDownloadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.Uuid)

		bytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			log.Printf("Failed to decode base64 string for download: %v", err)
			return nil, err
		}

		file := string(bytes)
		log.Printf("Downloading remote file <%s> to local file <%s>", file, r.TempDownloadFilePath)

		if err := r.readDownloadFileData(conn, r.TempDownloadFilePath); err != nil {
			return nil, err
		}
	}

	// Handle TCP file upload
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Send_File_Socket]; exists && r.HttpStatus == fasthttp.StatusOK {
		r.TempUploadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.Uuid)

		bytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			log.Printf("Failed to decode base64 string for upload: %v", err)
			return nil, err
		}

		file := string(bytes)
		log.Printf("Preparing to upload local file <%s> to remote file <%s>", r.TempUploadFilePath, file)
	}

	return r, err
}

func (r *Response) readDownloadFileData(conn net.Conn, targetFilePath string) error {
	f, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("Failed to create file: %v", err)
		return err
	}
	defer f.Close()

	for {
		headerBuf, err := readTcpData(conn, TCP_MESSAGE_HEADER_LENGTH)
		if err != nil {
			log.Printf("Error reading TCP file header: %v", err)
			return err
		}

		chunkSize := binary.BigEndian.Uint32(headerBuf)
		if chunkSize == 0 {
			log.Printf("Completed reading TCP file to: <%s>", targetFilePath)
			break
		}

		buf, err := readTcpData(conn, chunkSize)
		if err != nil {
			log.Printf("Error reading TCP file: %v", err)
			return err
		}

		if _, err = f.Write(buf); err != nil {
			log.Printf("Failed to write to file: %v", err)
			return err
		}
	}

	return nil
}

func (r *Response) applyResponse(w http.ResponseWriter, req *http.Request) {

	// Handle the response body based on the path
	if r.RequestUri == REST_PATH_DOWNLOAD || r.RequestUri == REST_PATH_UPLOAD {
		if err := handleRestFile(w, req, r); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		log.Printf("File REST call Finished %s", r.Uuid)
	} else {
		// Set headers
		for k, v := range r.Headers {
			w.Header().Set(k, v)
		}
		// Set content type
		if len(r.BodyMsgType) > 0 {
			w.Header().Set("Content-Type", r.BodyMsgType)
		}

		// Set status code
		w.WriteHeader(r.HttpStatus)

		if len(r.Body) > 0 {
			if _, err := w.Write([]byte(r.Body)); err != nil {
				log.Printf("Error writing response body for %s: %v", r.Uuid, err)
			}
		}
		log.Printf("REST call Finished %s", r.Uuid)
	}
}
