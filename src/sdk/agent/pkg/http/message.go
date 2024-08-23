package http

import (
	"bufio"
	"encoding/base64"
	"encoding/binary"
	"html"
	"io"
	"log"
	"net"
	"os"
	"path"

	"github.com/laoshanxi/app-mesh/src/sdk/agent/pkg/config"
	"github.com/rs/xid"
	"github.com/valyala/fasthttp"
	"github.com/vmihailenco/msgpack/v5"
)

const (
	TCP_CHUNK_READ_BLOCK_SIZE          = 8192
	PROTOBUF_HEADER_LENGTH             = 4
	HTTP_HEADER_KEY_X_TARGET_HOST      = "X-Target-Host"
	HTTP_HEADER_KEY_X_Send_File_Socket = "X-Send-File-Socket"
	HTTP_HEADER_KEY_X_Recv_File_Socket = "X-Recv-File-Socket"
)

type ResponseMessage struct {
	Message string `json:"message"`
}

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

type Request struct {
	Uuid          string            `msg:"uuid" msgpack:"uuid"`
	RequestUri    string            `msg:"request_uri" msgpack:"request_uri"`
	HttpMethod    string            `msg:"http_method" msgpack:"http_method"`
	ClientAddress string            `msg:"client_addr" msgpack:"client_addr"`
	Body          string            `msg:"body" msgpack:"body"`
	Headers       map[string]string `msg:"headers" msgpack:"headers"`
	Querys        map[string]string `msg:"querys" msgpack:"querys"`
}

func readTcpData(conn net.Conn, msgLength uint32) ([]byte, error) {
	// read body buffer
	var chunkSize uint32 = TCP_CHUNK_READ_BLOCK_SIZE
	if msgLength < chunkSize {
		chunkSize = msgLength
	}
	// make 0 length data bytes (since we'll be appending)
	bodyBuf := make([]byte, 0)
	var totalReadSize uint32 = 0
	for totalReadSize < msgLength {
		// https://stackoverflow.com/questions/24339660/read-whole-data-with-golang-net-conn-read
		oneTimeRead := msgLength - totalReadSize
		if oneTimeRead > chunkSize {
			oneTimeRead = chunkSize
		}
		data := make([]byte, oneTimeRead) //TODO: use global buffer avoid garbage
		n, err := conn.Read(data)
		if n > 0 {
			bodyBuf = append(bodyBuf, data[:n]...)
			totalReadSize += uint32(n)
			//log.Printf("expect: %d, read: %d, left: %d", oneTimeRead, n, msgLength-totalReadSize)
			continue
		} else if err != nil {
			return nil, err
		}
	}

	return bodyBuf, nil
}

func sendTcpData(conn net.Conn, buf []byte) error {
	var totalSentSize int = 0
	var err error = nil
	for totalSentSize < len(buf) {
		byteSent := 0

		if byteSent, err = conn.Write(buf[totalSentSize:]); err != nil {
			return err
		}
		totalSentSize += byteSent
		//log.Printf("total send size %d bytes", totalSentSize)
	}
	return err
}

func (r *Response) readResponse(conn net.Conn) error {

	// read header 4 bytes (int)
	headerBuf, err := readTcpData(conn, PROTOBUF_HEADER_LENGTH)
	if err != nil {
		return err
	}
	// read body
	bodyBuf, err := readTcpData(conn, binary.BigEndian.Uint32(headerBuf))
	if err != nil {
		return err
	}
	err = msgpack.Unmarshal(bodyBuf, r)
	if err != nil {
		return err
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
	return err
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

func (r *Request) serialize() ([]byte, error) {
	return msgpack.Marshal(*r)
}

func convertHttpRequest(ctx *fasthttp.RequestCtx) *Request {
	req := &ctx.Request
	// do not proxy "Connection" header.
	req.Header.Del("Connection")

	data := new(Request)
	data.Uuid = xid.New().String()
	data.HttpMethod = string(req.Header.Method())
	data.RequestUri = string(req.URI().Path())
	data.ClientAddress = ctx.RemoteAddr().String()
	data.Headers = make(map[string]string)
	req.Header.VisitAll(func(key, value []byte) {
		data.Headers[string(key)] = string(value)
	})
	data.Querys = make(map[string]string)
	req.URI().QueryArgs().VisitAll(func(key, value []byte) {
		data.Querys[string(key)] = string(value)
	})

	// do not read body for file upload
	if !(req.Header.IsPost() && string(req.URI().Path()) == REST_PATH_UPLOAD) {
		data.Body = html.UnescapeString(string(req.Body()))
	}
	return data
}

func applyHttpResponse(ctx *fasthttp.RequestCtx, data *Response) {
	// headers
	for k, v := range data.Headers {
		ctx.Response.Header.Set(k, v)
	}
	// user agent
	ctx.Response.Header.Set(HTTP_USER_AGENT_HEADER_NAME, USER_AGENT_APPMESH_SDK)
	// status code
	ctx.Response.SetStatusCode(int(data.HttpStatus))
	// body
	if (REST_PATH_DOWNLOAD == string(ctx.Request.URI().Path()) || REST_PATH_UPLOAD == string(ctx.Request.URI().Path())) &&
		handleRestFile(ctx, data) {
		ctx.Logger().Printf("File REST call Finished %s", data.Uuid)
	} else {
		ctx.Response.SetBodyRaw([]byte(data.Body))
		ctx.SetContentType(data.BodyMsgType)
		ctx.Logger().Printf("REST call Finished  %s", data.Uuid)
	}
}

func sendUploadFileData(localFile string, targetConnection *safeConn) error {
	var err error
	var file *os.File
	if file, err = os.Open(localFile); err == nil {
		defer os.Remove(localFile)
		defer file.Close()
		// Create a buffered reader for the file
		reader := bufio.NewReader(file)
		chunkSize := 1024 * 8 // 8 KB chunks
		// Create a buffer to store chunks
		bodyData := make([]byte, chunkSize)

		// header buffer
		headerData := make([]byte, PROTOBUF_HEADER_LENGTH)

		targetConnection.mu.Lock()
		defer targetConnection.mu.Unlock()
		// Read the file in chunks and send each chunk over the TCP connection
		for {
			// Read a chunk from the file
			n, err := reader.Read(bodyData)

			if err != nil && err != io.EOF {
				log.Printf("Error reading file: %v", err)
				break
			}

			// If we've reached the end of the file, break out of the loop
			if n == 0 {
				break
			}

			binary.BigEndian.PutUint32(headerData, uint32(n))
			if err = sendTcpData(targetConnection.conn, headerData); err == nil {
				err = sendTcpData(targetConnection.conn, bodyData[:n])
			}

			if err != nil {
				break
			}
		}

		binary.BigEndian.PutUint32(headerData, uint32(0))
		err = sendTcpData(targetConnection.conn, headerData)

		log.Printf("upload socket file %s finished", localFile)
	} else {
		log.Printf("Error opening file: %v", err)
	}
	return err
}
