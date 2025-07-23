package utils

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

func MoveFile(src string, dst string) error {

	buf := make([]byte, 1024)
	fin, err := os.Open(src)
	if err != nil {
		return err
	}

	defer fin.Close()
	fout, err := os.Create(dst)
	if err != nil {
		return err
	}

	defer fout.Close()
	for {
		n, err := fin.Read(buf)
		if err != nil && err != io.EOF {
			return err
		}
		if n == 0 {
			break
		}
		if _, err := fout.Write(buf[:n]); err != nil {
			return err
		}
	}
	return os.Remove(src)
}

func GetCurrentAbPath() string {
	dir := getCurrentAbPathByExecutable()
	if strings.Contains(dir, getTmpDir()) {
		return getCurrentAbPathByCaller()
	}
	return dir
}

func getTmpDir() string {
	dir := os.Getenv("TEMP")
	if dir == "" {
		dir = os.Getenv("TMP")
	}
	res, _ := filepath.EvalSymlinks(dir)
	return res
}

func getCurrentAbPathByExecutable() string {
	exePath, err := os.Executable()
	if err != nil {
		GetLogger().Fatal(err)
	}
	res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
	return res
}

func getCurrentAbPathByCaller() string {
	var abPath string
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		abPath = path.Dir(filename)
	}
	return abPath
}

func substr(s string, pos, length int) string {
	runes := []rune(s)
	l := pos + length
	if l > len(runes) {
		l = len(runes)
	}
	return string(runes[pos:l])
}

func GetParentDir(directory string) string {
	if directory == "" {
		return ""
	}

	// filepath.Dir handles both Windows and Unix path separators correctly
	return filepath.Dir(filepath.Clean(directory))
}

// DecodeURIComponent decodes a URI component string by replacing each escaped sequence
// with its actual character. It's compatible with JavaScript's decodeURIComponent.
func DecodeURIComponent(encoded string) string {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		fmt.Printf("decode URI component failed: %v", err)
		return encoded
	}
	return decoded
}

// EncodeURIComponent encodes a string as a URI component by escaping all characters
// that could interfere with URI syntax. It's compatible with JavaScript's encodeURIComponent.
func EncodeURIComponent(str string) string {
	return url.QueryEscape(str)
}

func IsValidFileName(fileName string) bool {
	// Ensure the resulting file path is safe on the Linux file system
	// Avoid certain unsafe patterns
	unsafePrefixes := []string{"/etc/", "/var/", "/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/proc/", "/sys/", "/boot/"}
	for _, prefix := range unsafePrefixes {
		if strings.HasPrefix(fileName, prefix) {
			return false
		}
	}

	return true
}

func SaveStreamToFile(src io.Reader, filePath string) error {
	dst, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("error creating file: %w", err)
	}
	defer dst.Close()

	_, err = io.Copy(dst, src)
	if err != nil {
		return fmt.Errorf("error copying data to file: %w", err)
	}

	return nil
}

// MaskSecret masks the input secret, keeping `visibleChars` at the beginning and end, replacing the middle with `mask`.
// Defaults: visibleChars = 2, mask = "***".
func MaskSecret(secret string, visibleChars int, mask string) string {
	// Handle invalid input
	if visibleChars < 0 {
		visibleChars = 0
	}

	length := len(secret)

	if length <= visibleChars*2 {
		return "***"
	}

	result := make([]byte, 0, visibleChars*2+len(mask))
	result = append(result, secret[:visibleChars]...)
	result = append(result, mask...)
	result = append(result, secret[length-visibleChars:]...)

	return string(result)
}
