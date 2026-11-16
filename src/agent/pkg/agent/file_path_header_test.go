package agent

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// TestDecodeFilePathHeader pins the X-File-Path contract the agent shares with the
// daemon: the header carries a percent-encoded path, and the daemon decodes and
// authorizes it. The agent forwards the header unchanged and decodes it only for
// the download's display filename — never to open a file. The JS, Java and C++
// SDKs encode the separators ("%2F"); Python, Go and Rust leave them literal and
// must pass unchanged. A resulting '+' must stay literal, because the display
// name must match the file the client asked for.
func TestDecodeFilePathHeader(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"encoded separators decode", "%2Ftmp%2Fappmesh.txt", "/tmp/appmesh.txt"},
		{"literal separators pass through", "/tmp/appmesh.txt", "/tmp/appmesh.txt"},
		{"literal plus is not a space", "/tmp/a+b.txt", "/tmp/a+b.txt"},
		{"encoded space decodes", "/tmp/a%20b.txt", "/tmp/a b.txt"},
		{"invalid escape keeps the raw value", "/tmp/bad%ZZ.txt", "/tmp/bad%ZZ.txt"},
		{"empty stays empty", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := decodeFilePathHeader(tc.value); got != tc.want {
				t.Fatalf("decodeFilePathHeader(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// An upload whose precheck answer carries no armed transfer must fail closed:
// nothing is written anywhere — in particular never at the client-supplied
// path, whose components an attacker can swap between the daemon's check and
// an open (TOCTOU bypass of the daemon's file jail).
func TestHandleRESTFileUploadRequiresArmedTransfer(t *testing.T) {
	dir, err := os.MkdirTemp(".", "upload-failclosed-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	target := filepath.Join(dir, "smuggled.txt")
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, _ := writer.CreateFormFile("file", "smuggled.txt")
	_, _ = part.Write([]byte("payload"))
	_ = writer.Close()

	req := httptest.NewRequest(http.MethodPost, RestPathUpload, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set(HTTPHeaderKeyFilePath, strings.ReplaceAll(target, "/", "%2F"))
	// Precheck OK but no X-Send-File-Socket arm: the daemon never pinned an fd.
	response := &Response{Response: appmesh.Response{RequestURI: RestPathUpload, HTTPStatus: http.StatusOK}}

	err = HandleRESTFile(httptest.NewRecorder(), req, response)
	if !errors.Is(err, errNoArmedTransfer) {
		t.Fatalf("HandleRESTFile error = %v, want errNoArmedTransfer", err)
	}
	if _, statErr := os.Stat(target); statErr == nil {
		t.Fatalf("upload must not write the client-supplied path %q", target)
	}
}

// An armed upload stages the client body into the agent's uuid-named temp file
// (later streamed to the daemon's verified fd); the client-supplied path is
// never opened on this side.
func TestHandleRESTFileUploadStagesArmedTempFile(t *testing.T) {
	dir, err := os.MkdirTemp(".", "upload-staged-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	staged := filepath.Join(dir, "uuid-tmp-file")
	content := []byte("appmesh upload payload")

	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	part, err := writer.CreateFormFile("file", "uploaded.txt")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write form file: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close multipart writer: %v", err)
	}

	// The daemon decoded and authorized this path; the agent must not touch it.
	requested := filepath.Join(dir, "requested-destination.txt")
	req := httptest.NewRequest(http.MethodPost, RestPathUpload, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set(HTTPHeaderKeyFilePath, strings.ReplaceAll(requested, "/", "%2F"))
	response := &Response{Response: appmesh.Response{RequestURI: RestPathUpload, HTTPStatus: http.StatusOK}}
	response.TempUploadFilePath = staged

	if err := HandleRESTFile(httptest.NewRecorder(), req, response); err != nil {
		t.Fatalf("HandleRESTFile: %v", err)
	}

	stored, err := os.ReadFile(staged)
	if err != nil {
		t.Fatalf("upload did not stage into the armed temp file %q: %v", staged, err)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("staged content = %q, want %q", stored, content)
	}
	if _, err := os.Stat(requested); err == nil {
		t.Fatalf("upload must not write the client-supplied path %q", requested)
	}
}

// A download whose precheck answer carries no armed transfer must fail closed
// before anything is served: this side must not re-open the client-supplied
// path, or a component swapped after the daemon's check would exfiltrate a
// file outside the jail.
func TestHandleRESTFileDownloadRequiresArmedTransfer(t *testing.T) {
	dir, err := os.MkdirTemp(".", "download-failclosed-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	secret := filepath.Join(dir, "outside-jail-secret.txt")
	if err := os.WriteFile(secret, []byte("TOP-SECRET"), 0600); err != nil {
		t.Fatalf("write secret: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, RestPathDownload, nil)
	req.Header.Set(HTTPHeaderKeyFilePath, strings.ReplaceAll(secret, "/", "%2F"))
	// Precheck OK but no X-Recv-File-Socket arm: the daemon never streamed
	// from a verified fd.
	response := &Response{Response: appmesh.Response{RequestURI: RestPathDownload, HTTPStatus: http.StatusOK}}

	recorder := httptest.NewRecorder()
	if err := HandleRESTFile(recorder, req, response); !errors.Is(err, errNoArmedTransfer) {
		t.Fatalf("HandleRESTFile error = %v, want errNoArmedTransfer", err)
	}
	if recorder.Body.Len() != 0 {
		t.Fatalf("download must not serve bytes without an armed transfer, got %q", recorder.Body.String())
	}
}
