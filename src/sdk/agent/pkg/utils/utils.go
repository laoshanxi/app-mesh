package utils

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func IsFileExist(path string) bool {
	if len(path) > 0 {
		_, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				return false
			}
		}
		return true
	}
	return false
}

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
		log.Fatal(err)
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

func GetParentDir(dirctory string) string {
	return substr(dirctory, 0, strings.LastIndex(dirctory, "/"))
}

func LoadCertificatePair(pem string, key string) tls.Certificate {
	if IsFileExist(pem) && IsFileExist(key) {
		cert, err := tls.LoadX509KeyPair(pem, key)
		if err != nil {
			log.Fatalf("Error in LoadX509KeyPair: %s", err)
			panic(err)
		}
		return cert
	} else {
		log.Println("cert file not defined")
		return tls.Certificate{}
	}
}

// loadCACertificate load CA certificate from a file or directory
func LoadCA(caPath string) (*x509.CertPool, error) {
	if IsFileExist(caPath) {
		info, _ := os.Stat(caPath)
		if !info.IsDir() {
			return LoadCACertificate(caPath)
		}
	}
	return LoadCACertificates(caPath)
}

// loadCACertificate load CA certificate from a file
func LoadCACertificate(certFile string) (*x509.CertPool, error) {
	caCrt, err := os.ReadFile(certFile)
	if err != nil {
		log.Printf("Error loading client certificate: %v", err)
		return nil, err
	} else {
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(caCrt)
		return certPool, nil
	}
}

// loadCACertificates loads CA certificates from a directory
func LoadCACertificates(certDir string) (*x509.CertPool, error) {
	caCertPool := x509.NewCertPool()
	files, err := os.ReadDir(certDir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if !file.IsDir() {
			certPath := filepath.Join(certDir, file.Name())
			certPEM, err := os.ReadFile(certPath)
			if err == nil {
				// Append the certificate to the pool
				if ok := caCertPool.AppendCertsFromPEM(certPEM); !ok {
					log.Printf("failed to append certificate from %s", certPath)
				}
			} else {
				log.Printf("failed to read file %s", certPath)
			}
		}
	}

	return caCertPool, nil
}

func IsValidFileName(fileName string) bool {
	// Use a regular expression to allow alphanumeric characters, underscores, dashes, dots, and slashes
	// Avoid special characters and patterns that might lead to security issues
	regex := regexp.MustCompile(`^[a-zA-Z0-9_\-./]+$`)
	if !regex.MatchString(fileName) {
		return false
	}

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

func ParseURL(input string) (*url.URL, error) {
	// Trim whitespace
	input = strings.TrimSpace(input)

	// Check if the input is empty
	if input == "" {
		return nil, fmt.Errorf("empty input")
	}

	// Regular expression to match IP addresses
	ipRegex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}`)

	// If it's an IP address without a scheme, add https://
	if ipRegex.MatchString(input) && !strings.Contains(input, "://") {
		input = "https://" + input
	}

	// If no scheme is present, add https:// as default
	if !strings.Contains(input, "://") {
		input = "https://" + input
	}

	// Parse the URL
	parsedURL, err := url.Parse(input)
	if err != nil {
		return nil, err
	}

	// Ensure the scheme is lowercase
	parsedURL.Scheme = strings.ToLower(parsedURL.Scheme)

	// If no host is present, assume the path is actually the host
	if parsedURL.Host == "" && parsedURL.Path != "" {
		parsedURL.Host = parsedURL.Path
		parsedURL.Path = ""
	}

	return parsedURL, nil
}
