package appmesh

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/rs/xid"
	"github.com/stretchr/testify/require"
	"github.com/vmihailenco/msgpack/v5"
)

func TestAppmeshLogin(t *testing.T) {

	emptyStr := ""
	client, _ := NewHTTPClient(Option{SslTrustedCA: &emptyStr})

	client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	res, _ := client.GetHostResources()
	t.Log(res)
	labels, _ := client.GetLabels()
	t.Log(labels)
	apps, _ := client.ListApps()
	t.Log(apps)

	app, _ := client.GetApp("test")
	t.Log(app)

	runApp := Application{}
	cmd := "ping cloudflare.com -w 3"
	runApp.Command = &cmd
	client.RunAppSync(runApp, true, 5, 10)
	client.RunAppAsync(runApp, 5, 10)
}

func TestAppmeshFile(t *testing.T) {
	client, _ := NewHTTPClient(Option{})

	_, err := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, DEFAULT_JWT_AUDIENCE)
	require.NoError(t, err)

	var remotePath, localFile, tempFile string
	if runtime.GOOS == "windows" {
		remotePath = `C:\local\appmesh\bin\appsvc.exe`
		localFile = "appsvc.exe"
		tempFile = filepath.Join(os.TempDir(), fmt.Sprintf("appsvc_%d.exe", os.Getpid()))
	} else {
		remotePath = "/opt/appmesh/bin/appsvc"
		localFile = "appsvc"
		tempFile = fmt.Sprintf("/tmp/appsvc_%d", os.Getpid())
	}

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
	require.Nil(t, client.DownloadFile(remotePath, localFile, true))
	require.Nil(t, client.UploadFile(localFile, tempFile, true))
	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
	client.updateForwardTo("localhost:6059")
	require.Nil(t, client.DownloadFile(remotePath, localFile, true))
	// require.Nil(t, client.UploadFile(localFile, tempFile, true))

	_ = os.Remove(localFile)
	_ = os.Remove(tempFile)
}

func TestAppmeshTotp(t *testing.T) {

	client, _ := NewHTTPClient(Option{})

	_, err := client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, DEFAULT_JWT_AUDIENCE)
	require.NoError(t, err, "Login failed")

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

func TestAppmeshAppManagement(t *testing.T) {
	noVerify := ""
	client, err := NewHTTPClient(Option{SslTrustedCA: &noVerify})
	require.NoError(t, err)

	_, err = client.Login("admin", "admin123", "", DEFAULT_TOKEN_EXPIRE_SECONDS, "")
	require.NoError(t, err, "Login failed")

	// --- AddApp ---
	appName := "go-test-app"
	cmd := "echo hello"
	shellMode := true
	app := Application{
		Name:      appName,
		Command:   &cmd,
		ShellMode: &shellMode,
	}
	added, err := client.AddApp(app)
	require.NoError(t, err, "AddApp failed")
	require.NotNil(t, added, "AddApp returned nil")
	require.Equal(t, appName, added.Name)
	t.Logf("AddApp: %s (status=%d)", added.Name, added.Status)

	// Ensure cleanup regardless of test outcome.
	defer func() {
		ok, err := client.RemoveApp(appName)
		require.NoError(t, err, "RemoveApp (cleanup) failed")
		require.True(t, ok, "RemoveApp (cleanup) returned false")
		t.Logf("RemoveApp: %s removed", appName)
	}()

	// --- EnableApp ---
	ok, err := client.EnableApp(appName)
	require.NoError(t, err, "EnableApp failed")
	require.True(t, ok, "EnableApp returned false")
	t.Logf("EnableApp: %s enabled", appName)

	// --- DisableApp ---
	ok, err = client.DisableApp(appName)
	require.NoError(t, err, "DisableApp failed")
	require.True(t, ok, "DisableApp returned false")
	t.Logf("DisableApp: %s disabled", appName)

	// --- GetAppOutput ---
	out := client.GetAppOutput(appName, 0, 0, 4096, "", 3)
	// Output may be empty for a disabled/stopped app; check no transport error.
	require.NoError(t, out.Error, "GetAppOutput returned error")
	t.Logf("GetAppOutput: success=%v body=%q", out.HttpSuccess, out.HttpBody)

	// --- GetConfig / SetConfig ---
	cfg, err := client.GetConfig()
	require.NoError(t, err, "GetConfig failed")
	require.NotEmpty(t, cfg, "GetConfig returned empty config")
	t.Logf("GetConfig: keys=%d", len(cfg))

	// Set a description field inside BaseConfig to verify round-trip.
	// We only mutate a safe, low-risk field (Description) and restore it.
	baseCfg, _ := cfg["BaseConfig"].(map[string]interface{})
	var origDescription interface{}
	if baseCfg != nil {
		origDescription = baseCfg["Description"]
	}

	patchCfg := map[string]interface{}{
		"BaseConfig": map[string]interface{}{
			"Description": "go-sdk-test",
		},
	}
	updatedCfg, err := client.SetConfig(patchCfg)
	require.NoError(t, err, "SetConfig failed")
	require.NotEmpty(t, updatedCfg, "SetConfig returned empty config")
	t.Logf("SetConfig: keys=%d", len(updatedCfg))

	// Restore original description.
	restoreVal := ""
	if origDescription != nil {
		if s, ok := origDescription.(string); ok {
			restoreVal = s
		}
	}
	restoreCfg := map[string]interface{}{
		"BaseConfig": map[string]interface{}{
			"Description": restoreVal,
		},
	}
	_, err = client.SetConfig(restoreCfg)
	require.NoError(t, err, "SetConfig restore failed")

	// --- AddLabel / DeleteLabel ---
	tagName := "go-sdk-test-tag"
	tagValue := "test-value-123"
	ok, err = client.AddLabel(tagName, tagValue)
	require.NoError(t, err, "AddLabel failed")
	require.True(t, ok, "AddLabel returned false")
	t.Logf("AddLabel: %s=%s", tagName, tagValue)

	tags, err := client.GetLabels()
	require.NoError(t, err, "GetLabels after AddLabel failed")
	require.Equal(t, tagValue, tags[tagName], "label value mismatch after AddLabel")

	ok, err = client.DeleteLabel(tagName)
	require.NoError(t, err, "DeleteLabel failed")
	require.True(t, ok, "DeleteLabel returned false")
	t.Logf("DeleteLabel: %s deleted", tagName)

	tags, err = client.GetLabels()
	require.NoError(t, err, "GetLabels after DeleteLabel failed")
	_, exists := tags[tagName]
	require.False(t, exists, "label should be absent after DeleteLabel")

	// --- ListUsers ---
	users, err := client.ListUsers()
	require.NoError(t, err, "ListUsers failed")
	require.NotEmpty(t, users, "ListUsers returned empty map")
	t.Logf("ListUsers: count=%d", len(users))

	// --- GetCurrentUser ---
	currentUser, err := client.GetCurrentUser()
	require.NoError(t, err, "GetCurrentUser failed")
	require.NotEmpty(t, currentUser, "GetCurrentUser returned empty map")
	t.Logf("GetCurrentUser: %v", currentUser)

	// --- ListRoles ---
	roles, err := client.ListRoles()
	require.NoError(t, err, "ListRoles failed")
	require.NotEmpty(t, roles, "ListRoles returned empty slice")
	t.Logf("ListRoles: count=%d", len(roles))

	// --- ListPermissions (ViewPermissions) ---
	perms, err := client.ViewPermissions()
	require.NoError(t, err, "ViewPermissions failed")
	require.NotEmpty(t, perms, "ViewPermissions returned empty list")
	t.Logf("ViewPermissions: count=%d", len(perms))

	// --- GetUserPermissions ---
	userPerms, err := client.GetUserPermissions()
	require.NoError(t, err, "GetUserPermissions failed")
	require.NotEmpty(t, userPerms, "GetUserPermissions returned empty list")
	t.Logf("GetUserPermissions: count=%d", len(userPerms))
}
