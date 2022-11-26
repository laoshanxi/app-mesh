package http

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/vmihailenco/msgpack/v5"
)

const (
	TCP_CHUNK_READ_BLOCK_SIZE = 2048
	PROTOBUF_HEADER_LENGTH    = 4
)

type ResponseMessage struct {
	Message string `json:"message"`
}

type Response struct {
	Uuid        string            `msg:"uuid" msgpack:"uuid"`
	RequestUri  string            `msg:"request_uri" msgpack:"request_uri"`
	HttpStatus  int               `msg:"http_status" msgpack:"http_status"`
	BodyMsgType string            `msg:"body_msg_type" msgpack:"body_msg_type"`
	Body        string            `msg:"body" msgpack:"body"`
	Headers     map[string]string `msg:"headers" msgpack:"headers"`
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

func blockRead(conn net.Conn, msgLength uint32) ([]byte, error) {
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
			log.Printf("expect: %d, read: %d, left: %d", oneTimeRead, n, msgLength-totalReadSize)
			continue
		} else if err != nil {
			return nil, err
		}
	}

	return bodyBuf, nil
}

func blockSend(conn net.Conn, buf []byte) error {
	var totalSentSize int = 0
	var err error = nil
	for totalSentSize < len(buf) {
		byteSent := 0

		if byteSent, err = tcpConnect.Write(buf[totalSentSize:]); err != nil {
			return err
		}
		totalSentSize += byteSent
		log.Printf("total send size %d bytes", totalSentSize)
	}
	return err
}

func (r *Response) readResponse(conn net.Conn) error {

	// read header 4 bytes (int)
	headerBuf, err := blockRead(conn, PROTOBUF_HEADER_LENGTH)
	if err != nil {
		return err
	}
	// read body
	bodyBuf, err := blockRead(conn, binary.BigEndian.Uint32(headerBuf))
	if err != nil {
		return err
	}
	return msgpack.Unmarshal(bodyBuf, r)
}

func (r *Request) serialize() ([]byte, error) {
	return msgpack.Marshal(*r)
}
