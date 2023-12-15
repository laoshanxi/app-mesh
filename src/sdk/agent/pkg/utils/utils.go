package utils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log"
	"os"
	"path"
	"path/filepath"
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

func GetAppMeshHomeDir() string {
	return getParentDir(getCurrentAbPath())
}

func GetAppMeshConfig(level1 string, level2 string, level3 string) (error, interface{}) {
	configFile := filepath.Join(GetAppMeshHomeDir(), "config.json")
	data, err := os.ReadFile(configFile)
	if err != nil {
		log.Printf("Error reading file: %v", err)
		return err, false
	}

	// Use a map[string]interface{} to store the JSON data
	var jsonData map[string]interface{}

	// Unmarshal the JSON data into the map
	err = json.Unmarshal(data, &jsonData)
	if err != nil {
		log.Printf("Error unmarshalling JSON: %v", err)
		return err, false
	}

	// Access data from the map
	// Read level 3 value in one line
	if value, ok := jsonData[level1].(map[string]interface{})[level2].(map[string]interface{})[level3]; ok {
		log.Printf("Value of %s = %v", level3, value)
		return nil, value
	} else {
		log.Printf("failed to retrieve json value for: %s", level3)
		return errors.New("failed to retrieve json value"), false
	}

}

func getCurrentAbPath() string {
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

func getParentDir(dirctory string) string {
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
