package main

import (
	"encoding/binary"
	"log"
	"net"

	"github.com/vmihailenco/msgpack/v5"
)

const TCP_CHUNK_READ_BLOCK_SIZE = 2048
const PROTOBUF_HEADER_LENGTH = 4

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

func (r *Response) readResponse(conn net.Conn) error {
	// read header 4 bytes (int)
	headerBuf := make([]byte, PROTOBUF_HEADER_LENGTH)
	_, err := conn.Read(headerBuf) //TODO: check read size
	if err != nil {
		return err
	}
	bodyLength := binary.BigEndian.Uint32(headerBuf)
	log.Printf("read body length: %d", bodyLength)
	// read body buffer
	var chunkSize uint32 = TCP_CHUNK_READ_BLOCK_SIZE
	if bodyLength < chunkSize {
		chunkSize = bodyLength
	}
	// make 0 length data bytes (since we'll be appending)
	bodyBuf := make([]byte, 0)
	var alreadyReadSize uint32 = 0
	for {
		// https://stackoverflow.com/questions/24339660/read-whole-data-with-golang-net-conn-read
		oneTimeRead := bodyLength - alreadyReadSize
		if oneTimeRead > chunkSize {
			oneTimeRead = chunkSize
		}
		data := make([]byte, oneTimeRead) //TODO: use global buffer avoid garbage
		n, err := conn.Read(data)
		if n > 0 {
			bodyBuf = append(bodyBuf, data[:n]...)
			alreadyReadSize += uint32(n)
			log.Printf("expect: %d, read: %d, left: %d", oneTimeRead, n, bodyLength-alreadyReadSize)
			if alreadyReadSize >= bodyLength {
				break
			}
			continue
		}
		if err != nil {
			return err
		}
	}
	return msgpack.Unmarshal(bodyBuf, r)
}

func (r *Request) serialize() ([]byte, error) {
	return msgpack.Marshal(*r)
}
