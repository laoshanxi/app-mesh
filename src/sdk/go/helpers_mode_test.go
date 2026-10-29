//go:build !windows
// +build !windows

package appmesh

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

// X-File-Mode is decimal permission bits (493 = 0755), the same convention the
// daemon applies. An out-of-range value such as the octal digits "755" must be
// ignored, not masked: 755 & 0777 = 0363 would silently grant write access to
// group and other.
func TestApplyFileAttributesModeRange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f")

	created := 0o600
	modes := []struct {
		header string
		want   os.FileMode
	}{
		{"755", os.FileMode(created)}, // octal digits as-is: out of range, ignored
		{"493", 0o755},                // decimal 0755: applied
		{"0", 0},                      // decimal 0: applied
	}
	for _, m := range modes {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(created))
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		h := http.Header{}
		h.Set(headerFileMode, m.header)
		if err := ApplyFileAttributes(path, h); err != nil {
			t.Fatalf("mode %q: %v", m.header, err)
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != m.want {
			t.Errorf("mode %q: got %04o, want %04o", m.header, got, m.want)
		}
	}
}
