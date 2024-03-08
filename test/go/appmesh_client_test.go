package main

// go get github.com/laoshanxi/app-mesh/src/sdk/go

import (
	"fmt"
	"os"
	"testing"

	"github.com/rs/xid"
	"github.com/vmihailenco/msgpack/v5"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

func TestAppmeshLogin(t *testing.T) {

	fmt.Println("main")
	client := appmesh.NewClient("https://localhost:6060")

	_, token, _ := client.Login("admin", "admin123", appmesh.DEFAULT_TOKEN_EXPIRE_SECONDS)
	client.Authentication(token, "")
	labels, err := client.GetTags()
	fmt.Printf("HTTP error %v, returns %v\n", err, labels)
	apps, err1 := client.GetApps()
	fmt.Printf("Applications:%v\n %v\n", err1, apps)

	app, err2 := client.GetApp("test")
	fmt.Printf("Application:%v\n %v\n", err2, app)

	runApp := appmesh.Application{}
	cmd := "ping www.baidu.com -w 5"
	runApp.Command = &cmd
	client.Run(runApp, false, 5)
	fmt.Println("end")
}

func TestMessagePack(t *testing.T) {
	type Response struct {
		Uuid        string            `msg:"uuid" msgpack:"uuid"`
		RequestUri  string            `msg:"request_uri" msgpack:"request_uri"`
		HttpStatus  int               `msg:"http_status" msgpack:"http_status"`
		BodyMsgType string            `msg:"body_msg_type" msgpack:"body_msg_type"`
		Body        string            `msg:"body" msgpack:"body"`
		Headers     map[string]string `msg:"headers" msgpack:"headers"`
	}

	data := new(Response)
	data.Uuid = xid.New().String()
	data.RequestUri = "123"
	data.HttpStatus = 1
	content, _ := os.ReadFile("/root/app-mesh/1.log")
	data.Body = string(content)
	data.Headers = make(map[string]string)
	data.Headers[string("key")] = string("value")

	buf, err := msgpack.Marshal(*data)
	if err != nil {
		t.Errorf("msgpack.Marshal: %v", err)
	}
	t.Log(len(buf))
	protocResponse := new(Response)
	if err = msgpack.Unmarshal(buf, protocResponse); err != nil {
		t.Errorf("msgpack.Unmarshal: %v", err)
	}
	if data.Body != protocResponse.Body {
		t.Errorf("not same as expected")
	}
	t.Log("same as expected")
}
