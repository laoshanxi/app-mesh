package appmesh

import (
	"os"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

func TestAppmeshLogin(t *testing.T) {

	emptyStr := ""
	client := NewHttpClient(Option{SslTrustedCA: &emptyStr})

	_, token, _ := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS)
	res, _ := client.GetResource()
	t.Log(res)
	ret, err := client.Authentication(token, "")
	require.Equal(t, ret, true)
	require.Nil(t, err)
	labels, _ := client.GetTags()
	t.Log(labels)
	apps, _ := client.GetApps()
	t.Log(apps)

	app, _ := client.GetApp("test")
	t.Log(app)

	runApp := Application{}
	cmd := "ping github.com -w 3"
	runApp.Command = &cmd
	client.RunSync(runApp, 5)
	client.RunAsync(runApp, 5)
}

func TestAppmeshFile(t *testing.T) {

	client := NewHttpClient(Option{})
	client.updateForwardingHost("localhost:6059")

	success, _, _ := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS)
	require.True(t, success)

	os.Remove("appsvc")
	os.Remove("/tmp/appsvc")

	require.Nil(t, client.FileDownload("/opt/appmesh/bin/appsvc", "appsvc", true))
	require.Nil(t, client.FileUpload("appsvc", "/tmp/appsvc", true))
	os.Remove("appsvc")
}

func TestAppmeshTotp(t *testing.T) {

	client := NewHttpClient(Option{})

	success, token, err := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS)
	require.True(t, success, "Login failed")
	require.NoError(t, err, "Login failed")

	success, err = client.Authentication(token, "")
	require.True(t, success, "Authentication failed")
	require.NoError(t, err, "Authentication failed")

	/*
		secret, err := client.TotpSecret()
		require.NoError(t, err, "TotpSecret failed")

		code, _ := totp.GenerateCode(secret, time.Now().UTC())
		success, err = client.TotpSetup(code)
		require.True(t, success, "TotpSetup failed")
		require.NoError(t, err, "TotpSetup failed")

		code, _ = totp.GenerateCode(secret, time.Now().UTC())
		success, _, err = client.Login("admin", "admin123", code, DEFAULT_TOKEN_EXPIRE_SECONDS)
		require.True(t, success, "Login with TOTP code failed")
		require.NoError(t, err, "Login with TOTP code failed")

		success, err = client.TotpDisable()
		require.True(t, success, "TotpDisable failed")
		require.NoError(t, err, "TotpDisable failed")
	*/
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
	require.NoError(t, err, "msgpack Marshal failed")

	t.Log(len(buf))
	protocResponse := new(Response)
	err = msgpack.Unmarshal(buf, protocResponse)
	require.NoError(t, err, "msgpack Unmarshal failed")

	require.Equal(t, data.Body, protocResponse.Body)
}
