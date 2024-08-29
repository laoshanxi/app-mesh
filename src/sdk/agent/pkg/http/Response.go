package http

import (
	"encoding/base64"
	"encoding/binary"
	"log"
	"net"
	"os"
	"path"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/valyala/fasthttp"
	"github.com/vmihailenco/msgpack/v5"
)

type Response struct {
	Uuid                 string            `msg:"uuid" msgpack:"uuid"`
	RequestUri           string            `msg:"request_uri" msgpack:"request_uri"`
	HttpStatus           int               `msg:"http_status" msgpack:"http_status"`
	BodyMsgType          string            `msg:"body_msg_type" msgpack:"body_msg_type"`
	Body                 string            `msg:"body" msgpack:"body"`
	Headers              map[string]string `msg:"headers" msgpack:"headers"`
	TempDownloadFilePath string
	TempUploadFilePath   string
}

func ReadNewResponse(conn net.Conn) (*Response, error) {
	// read header 4 bytes (int)
	headerBuf, err := readTcpData(conn, PROTOBUF_HEADER_LENGTH)
	if err != nil {
		return nil, err
	}
	// read body
	bodyBuf, err := readTcpData(conn, binary.BigEndian.Uint32(headerBuf))
	if err != nil {
		return nil, err
	}

	r := new(Response)
	err = msgpack.Unmarshal(bodyBuf, r)
	if err != nil {
		return nil, err
	}

	// handle TCP file download
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Recv_File_Socket]; exists && r.HttpStatus == fasthttp.StatusOK {
		r.TempDownloadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.Uuid)

		bytes, _ := base64.StdEncoding.DecodeString(value)
		file := string(bytes)
		log.Printf("will download remote file <%s> to local file <%s>", file, r.TempDownloadFilePath)

		err = r.readDownloadFileData(conn, r.TempDownloadFilePath)
	}

	// handle TCP file upload
	if value, exists := r.Headers[HTTP_HEADER_KEY_X_Send_File_Socket]; exists && r.HttpStatus == fasthttp.StatusOK {
		r.TempUploadFilePath = path.Join(config.GetAppMeshHomeDir(), "work", "tmp", r.Uuid)

		bytes, _ := base64.StdEncoding.DecodeString(value)
		file := string(bytes)
		log.Printf("will upload local file <%s> to remote file <%s>", r.TempUploadFilePath, file)
	}
	return r, err
}

func (r *Response) readDownloadFileData(conn net.Conn, targetFilePath string) error {
	f, err := os.OpenFile(targetFilePath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		log.Printf("Failed create file: %v", err)
		return err
	}
	defer f.Close()
	for {
		headerBuf, err := readTcpData(conn, PROTOBUF_HEADER_LENGTH)
		if err == nil {
			chunkSize := binary.BigEndian.Uint32(headerBuf)
			if chunkSize > 0 {
				buf, err := readTcpData(conn, chunkSize)
				if err == nil {
					if _, err = f.Write(buf); err != nil {
						log.Printf("Failed write to file: %v", err)
					}
				} else {
					log.Printf("Error read TCP file: %v", err)
					break
				}
			} else {
				log.Printf("Read TCP file to: <%s> finished", targetFilePath)
				break
			}
		} else {
			log.Printf("Error read TCP file: %v", err)
			break
		}
	}
	return nil
}

func (r *Response) applyResponse(ctx *fasthttp.RequestCtx) {
	// headers
	for k, v := range r.Headers {
		ctx.Response.Header.Set(k, v)
	}
	// user agent
	ctx.Response.Header.Set(HTTP_USER_AGENT_HEADER_NAME, USER_AGENT_APPMESH_SDK)
	// status code
	ctx.Response.SetStatusCode(int(r.HttpStatus))
	// body
	if (REST_PATH_DOWNLOAD == string(ctx.Request.URI().Path()) || REST_PATH_UPLOAD == string(ctx.Request.URI().Path())) &&
		handleRestFile(ctx, r) {
		ctx.Logger().Printf("File REST call Finished %s", r.Uuid)
	} else {
		ctx.Response.SetBodyRaw([]byte(r.Body))
		ctx.SetContentType(r.BodyMsgType)
		ctx.Logger().Printf("REST call Finished  %s", r.Uuid)
	}
}
