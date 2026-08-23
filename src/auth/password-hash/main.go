// appmesh-password-hash is the repo-native helper used by appmesh-auth to
// seed the authentication service's initial administrator password hash. It reads the password from stdin
// (never from argv or the environment) and writes only the bcrypt hash.
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	password, err := io.ReadAll(io.LimitReader(os.Stdin, 4097))
	if err != nil {
		fmt.Fprintln(os.Stderr, "password input is unreadable")
		os.Exit(1)
	}
	password = bytes.TrimSuffix(password, []byte{'\n'})
	password = bytes.TrimSuffix(password, []byte{'\r'})
	if len(password) == 0 || len(password) > 4096 {
		fmt.Fprintln(os.Stderr, "password input is empty or too long")
		os.Exit(1)
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	for i := range password {
		password[i] = 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to hash password")
		os.Exit(1)
	}
	if _, err := os.Stdout.Write(append(hash, '\n')); err != nil {
		fmt.Fprintln(os.Stderr, "failed to write password hash")
		os.Exit(1)
	}
}
