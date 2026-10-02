package agent

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// TestDecodeFilePathHeader pins the X-File-Path contract the agent shares with the
// daemon: the header carries a percent-encoded path, and the agent must decode it to
// reach the same file the daemon authorized. The JS, Java and C++ SDKs encode the
// separators ("%2F"); Python, Go and Rust leave them literal and must pass unchanged.
// A resulting '+' must stay literal, because chown and friends treat a decoded space
// as a different path than the client asked for.
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

// TestHandleRESTFileUploadDecodesPath asserts an upload lands at the decoded path.
// The daemon authorizes the decoded path while the agent writes the file, so a header
// the agent does not decode makes the two disagree: the file lands under its still
// encoded name in the agent's working directory and the matching download answers
// "file not found".
func TestHandleRESTFileUploadDecodesPath(t *testing.T) {
	dir, err := os.MkdirTemp(".", "upload-path-test-")
	if err != nil {
		t.Fatalf("create temp dir: %v", err)
	}
	defer os.RemoveAll(dir)

	target := dir + "/uploaded.txt"
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

	// What the browser-facing SDKs send: every separator percent-encoded.
	encodedPath := strings.ReplaceAll(target, "/", "%2F")
	// A failing run is exactly when the pre-fix behavior writes this name, so clean it too.
	defer os.Remove(encodedPath)

	req := httptest.NewRequest(http.MethodPost, REST_PATH_UPLOAD, &body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set(HTTP_HEADER_KEY_File_Path, encodedPath)
	response := &Response{Response: appmesh.Response{RequestUri: REST_PATH_UPLOAD, HttpStatus: http.StatusOK}}

	if err := HandleRESTFile(httptest.NewRecorder(), req, response); err != nil {
		t.Fatalf("HandleRESTFile: %v", err)
	}

	stored, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("upload did not reach the decoded path %q: %v", target, err)
	}
	if !bytes.Equal(stored, content) {
		t.Fatalf("stored content = %q, want %q", stored, content)
	}
	if _, err := os.Stat(encodedPath); err == nil {
		t.Fatalf("upload also wrote the still-encoded name %q", encodedPath)
	}
}
