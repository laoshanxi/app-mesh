package main

// go get github.com/laoshanxi/app-mesh/src/sdk/go

import (
	"fmt"
	"testing"

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
