// dexuser manages Dex password users over the Dex gRPC API. The App Mesh
// launcher (appmesh-auth.sh) calls it to create and delete login identities.
// The Engine stores no user credentials of its own.
//
// The bcrypt password hash arrives on standard input. The plaintext password
// never reaches this process, and no secret is accepted from argv or from the
// environment.
//
// # What this file depends on in Dex
//
// The helper writes the gRPC wire protocol directly, so it needs no gRPC
// library and no generated stubs. Two things come from Dex. Check them when Dex
// changes:
//
//   - Message layout: api/v2/api.proto. Each marshal and parse function below
//     names the field numbers it uses, so a field renumbering is visible here.
//     The messages used are Password, CreatePasswordReq, CreatePasswordResp,
//     DeletePasswordReq, DeletePasswordResp, ListPasswordReq and
//     ListPasswordResp.
//   - OIDC subject: server/tokens/claims.go (GenSubject) and
//     server/internal/types.proto (IDTokenSubject). encodeSubject mirrors it.
//     The test file pins the result against two packaged identities.
//
// The gRPC framing itself is stable and needs no tracking: one HTTP/2 POST per
// call, a five-byte length prefix on the body, and the status in a trailer.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

const (
	// localConnectorID is the built-in password connector. Dex encodes it into
	// the OIDC subject, so it is part of the stable Principal identity.
	localConnectorID = "local"
	// maxHashLen bounds the bcrypt hash read from standard input. A bcrypt hash
	// is 60 bytes.
	maxHashLen = 128
	// requestTimeout bounds one call.
	requestTimeout = 10 * time.Second
	// maxResponseLen bounds the reply body.
	maxResponseLen = 1 << 20
	// createPasswordPath is the gRPC method path: proto package "api", service
	// "Dex". See the service block of api/v2/api.proto.
	createPasswordPath = "/api.Dex/CreatePassword"
	deletePasswordPath = "/api.Dex/DeletePassword"
	listPasswordsPath  = "/api.Dex/ListPasswords"
)

func usage() {
	fmt.Fprintln(os.Stderr, "usage: dexuser create-password --addr host:port --ca file --cert file --key file --email address --username name --user-id id")
	fmt.Fprintln(os.Stderr, "       dexuser delete-password --addr host:port --ca file --cert file --key file --email address")
	fmt.Fprintln(os.Stderr, "create-password reads the bcrypt password hash from standard input.")
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, err.Error())
	os.Exit(1)
}

// --- Dex messages ---------------------------------------------------------
//
// Each function below mirrors one message of api/v2/api.proto. The comment on
// each function is the proto definition it implements.

// CreatePasswordReq { Password password = 1 }
// Password { string email = 1; bytes hash = 2; string username = 3; string user_id = 4 }
func marshalCreatePasswordRequest(email string, hash string, username string, userID string) []byte {
	var password []byte
	password = appendStringField(password, 1, email)
	password = appendBytesField(password, 2, []byte(hash))
	password = appendStringField(password, 3, username)
	password = appendStringField(password, 4, userID)
	return appendBytesField(nil, 1, password)
}

// CreatePasswordResp { bool already_exists = 1 }
func isAlreadyExists(message []byte) bool {
	return boolField(message, 1)
}

// DeletePasswordReq { string email = 1 }
func marshalDeletePasswordRequest(email string) []byte {
	return appendStringField(nil, 1, email)
}

// DeletePasswordResp { bool not_found = 1 }
func isNotFound(message []byte) bool {
	return boolField(message, 1)
}

// ListPasswordReq {}
func marshalListPasswordsRequest() []byte {
	return nil
}

// dexPassword holds the two fields this helper reads from a stored password.
type dexPassword struct {
	Email  string
	UserID string
}

// ListPasswordResp { repeated Password passwords = 1 }
// Password { string email = 1; bytes hash = 2; string username = 3; string user_id = 4 }
func parseListPasswordsResponse(message []byte) ([]dexPassword, error) {
	var passwords []dexPassword
	err := eachField(message, func(number int, wireType protowire.Type, value []byte) error {
		if number == 1 && wireType == protowire.BytesType {
			password, err := parsePassword(value)
			if err != nil {
				return err
			}
			passwords = append(passwords, password)
		}
		return nil
	})
	return passwords, err
}

func parsePassword(message []byte) (dexPassword, error) {
	var password dexPassword
	err := eachField(message, func(number int, wireType protowire.Type, value []byte) error {
		if wireType != protowire.BytesType {
			return nil
		}
		switch number {
		case 1:
			password.Email = string(value)
		case 4:
			password.UserID = string(value)
		}
		return nil
	})
	return password, err
}

// appendStringField appends one length-delimited string field.
func appendStringField(message []byte, number int, value string) []byte {
	message = protowire.AppendTag(message, protowire.Number(number), protowire.BytesType)
	return protowire.AppendString(message, value)
}

// appendBytesField appends one length-delimited bytes field.
func appendBytesField(message []byte, number int, value []byte) []byte {
	message = protowire.AppendTag(message, protowire.Number(number), protowire.BytesType)
	return protowire.AppendBytes(message, value)
}

// boolField reports whether a varint field carries a non-zero value. A proto3
// bool that is false is absent from the wire.
func boolField(message []byte, number int) bool {
	found := false
	_ = eachField(message, func(field int, wireType protowire.Type, value []byte) error {
		if field == number && wireType == protowire.VarintType && len(value) > 0 && value[0] != 0 {
			found = true
		}
		return nil
	})
	return found
}

// eachField walks the fields of a protobuf message. It passes every
// length-delimited field to the callback with its value, and skips the rest.
func eachField(message []byte, visit func(number int, wireType protowire.Type, value []byte) error) error {
	for len(message) > 0 {
		number, wireType, tagLength := protowire.ConsumeTag(message)
		if tagLength < 0 {
			return protowire.ParseError(tagLength)
		}
		message = message[tagLength:]

		var value []byte
		if wireType == protowire.BytesType {
			consumed, length := protowire.ConsumeBytes(message)
			if length < 0 {
				return protowire.ParseError(length)
			}
			value, message = consumed, message[length:]
		} else {
			length := protowire.ConsumeFieldValue(number, wireType, message)
			if length < 0 {
				return protowire.ParseError(length)
			}
			if wireType == protowire.VarintType {
				value = message[:length]
			}
			message = message[length:]
		}
		if err := visit(int(number), wireType, value); err != nil {
			return err
		}
	}
	return nil
}

// --- gRPC over HTTP/2 -----------------------------------------------------
//
// A unary gRPC call is one HTTP/2 POST to /<proto package>.<service>/<method>.
// The body is a compression flag byte, a four-byte big-endian length, then the
// protobuf message. A non-zero result arrives in the grpc-status trailer.

// frame adds the five-byte gRPC message prefix.
func frame(message []byte) []byte {
	framed := make([]byte, 5+len(message))
	binary.BigEndian.PutUint32(framed[1:5], uint32(len(message)))
	copy(framed[5:], message)
	return framed
}

// unframe returns the message of the first frame of a gRPC body.
func unframe(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if len(body) < 5 {
		return nil, errors.New("the reply is shorter than a gRPC frame")
	}
	if body[0] != 0 {
		return nil, errors.New("the reply uses an unsupported compression")
	}
	size := int(binary.BigEndian.Uint32(body[1:5]))
	if len(body) < 5+size {
		return nil, errors.New("the reply frame is truncated")
	}
	return body[5 : 5+size], nil
}

// call sends one request and returns the reply message. Dex reports a refused
// request through a non-zero gRPC status, so that becomes an error here.
func call(ctx context.Context, client *http.Client, addr string, method string, message []byte) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+addr+method, bytes.NewReader(frame(message)))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Content-Type", "application/grpc")
	request.Header.Set("TE", "trailers")

	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = response.Body.Close()
	}()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxResponseLen))
	if err != nil {
		return nil, err
	}
	// A trailers-only reply carries the status in the header block instead.
	status := response.Trailer.Get("Grpc-Status")
	detail := response.Trailer.Get("Grpc-Message")
	if status == "" {
		status = response.Header.Get("Grpc-Status")
		detail = response.Header.Get("Grpc-Message")
	}
	if status != "" && status != "0" {
		return nil, errors.New(decodeStatusMessage(detail, status))
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the authentication service returned HTTP %s", response.Status)
	}
	return unframe(body)
}

// decodeStatusMessage reverses the percent-encoding that gRPC applies to the
// grpc-message trailer, and falls back to the status code.
func decodeStatusMessage(message string, status string) string {
	if message == "" {
		return fmt.Sprintf("the authentication service returned gRPC status %s", status)
	}
	if !strings.Contains(message, "%") {
		return message
	}
	if decoded, err := url.PathUnescape(message); err == nil {
		return decoded
	}
	return message
}

// --- identity -------------------------------------------------------------

// encodeSubject returns the OIDC subject that Dex issues for a local password
// user. It mirrors dexidp/dex tokens.GenSubject:
//
//	base64url_raw(proto(IDTokenSubject{user_id: userID, conn_id: connID}))
//
// IDTokenSubject is declared in Dex server/internal/types.proto. Dex does not
// export that message, so the two fields are written here.
func encodeSubject(userID string, connID string) string {
	var message []byte
	message = appendStringField(message, 1, userID)
	message = appendStringField(message, 2, connID)
	return base64.RawURLEncoding.EncodeToString(message)
}

// readHash reads the bcrypt hash from standard input. One trailing newline or
// one trailing CRLF is not part of the value, which matches the passhash
// helper.
func readHash() (string, error) {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, maxHashLen+1))
	if err != nil {
		return "", fmt.Errorf("cannot read the password hash: %v", err)
	}
	if n := len(raw); n > 0 && raw[n-1] == '\n' {
		raw = raw[:n-1]
	}
	if n := len(raw); n > 0 && raw[n-1] == '\r' {
		raw = raw[:n-1]
	}
	if len(raw) == 0 {
		return "", errors.New("the password hash is empty")
	}
	if len(raw) > maxHashLen {
		return "", errors.New("the password hash is too long")
	}
	return string(raw), nil
}

// --- command --------------------------------------------------------------

// connectionFlags are the options that every subcommand uses.
type connectionFlags struct {
	addr     *string
	caFile   *string
	certFile *string
	keyFile  *string
}

func addConnectionFlags(flags *flag.FlagSet) connectionFlags {
	return connectionFlags{
		addr:     flags.String("addr", "", "Dex gRPC address"),
		caFile:   flags.String("ca", "", "certificate authority file"),
		certFile: flags.String("cert", "", "client certificate file"),
		keyFile:  flags.String("key", "", "client private key file"),
	}
}

type option struct {
	name  string
	value string
}

// requireOptions stops with exit code 2 when an option is empty.
func requireOptions(options ...option) {
	for _, current := range options {
		if current.value == "" {
			fmt.Fprintf(os.Stderr, "the --%s option is required\n", current.name)
			os.Exit(2)
		}
	}
}

// newClient opens a mutual-TLS connection to the Dex gRPC listener. Only the
// packaged certificate authority is trusted, and this process always presents
// a client certificate: the Dex gRPC API has no authentication of its own.
func newClient(caFile string, certFile string, keyFile string) (*http.Client, error) {
	caPEM, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read the certificate authority file: %v", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("the certificate authority file has no certificate: %s", caFile)
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("cannot load the client certificate: %v", err)
	}
	return &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs:      pool,
				Certificates: []tls.Certificate{certificate},
				MinVersion:   tls.VersionTLS12,
			},
			// The gRPC listener speaks HTTP/2 only, and a custom TLS
			// configuration otherwise switches the automatic upgrade off.
			ForceAttemptHTTP2: true,
		},
	}, nil
}

func createPassword(args []string) error {
	flags := flag.NewFlagSet("create-password", flag.ExitOnError)
	connection := addConnectionFlags(flags)
	email := flags.String("email", "", "user email address")
	username := flags.String("username", "", "user name")
	userID := flags.String("user-id", "", "stable user identifier")
	flags.Parse(args)

	requireOptions(
		option{"addr", *connection.addr},
		option{"ca", *connection.caFile},
		option{"cert", *connection.certFile},
		option{"key", *connection.keyFile},
		option{"email", *email},
		option{"username", *username},
		option{"user-id", *userID},
	)

	hash, err := readHash()
	if err != nil {
		return err
	}
	client, err := newClient(*connection.caFile, *connection.certFile, *connection.keyFile)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	reply, err := call(ctx, client, *connection.addr, createPasswordPath,
		marshalCreatePasswordRequest(*email, hash, *username, *userID))
	if err != nil {
		return fmt.Errorf("cannot create the password: %v", err)
	}
	if isAlreadyExists(reply) {
		// The stored user keeps its own user identifier, so no subject is
		// reported here: the caller must not assume the requested one.
		fmt.Println("status=already_exists")
		return nil
	}
	fmt.Println("status=created")
	fmt.Printf("subject=%s\n", encodeSubject(*userID, localConnectorID))
	return nil
}

// deletePassword removes a password user. DeletePassword reports only whether
// the address existed, so the stored password is listed first: the caller needs
// the user identifier to find the Principal that this identity owns.
func deletePassword(args []string) error {
	flags := flag.NewFlagSet("delete-password", flag.ExitOnError)
	connection := addConnectionFlags(flags)
	email := flags.String("email", "", "user email address")
	flags.Parse(args)

	requireOptions(
		option{"addr", *connection.addr},
		option{"ca", *connection.caFile},
		option{"cert", *connection.certFile},
		option{"key", *connection.keyFile},
		option{"email", *email},
	)

	client, err := newClient(*connection.caFile, *connection.certFile, *connection.keyFile)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	reply, err := call(ctx, client, *connection.addr, listPasswordsPath, marshalListPasswordsRequest())
	if err != nil {
		return fmt.Errorf("cannot list the users: %v", err)
	}
	passwords, err := parseListPasswordsResponse(reply)
	if err != nil {
		return err
	}
	password, found := findPassword(passwords, *email)
	if !found {
		return fmt.Errorf("the user %s does not exist", *email)
	}

	// Delete with the stored address rather than the typed one: the storage
	// key is the exact address, while the lookup above is case-insensitive.
	reply, err = call(ctx, client, *connection.addr, deletePasswordPath, marshalDeletePasswordRequest(password.Email))
	if err != nil {
		return fmt.Errorf("cannot delete the password: %v", err)
	}
	if isNotFound(reply) {
		return fmt.Errorf("the user %s does not exist", *email)
	}
	fmt.Println("status=deleted")
	if password.UserID == "" {
		// The service did not report the identifier, so the caller cannot
		// locate the Principal. Report no subject rather than a wrong one.
		return nil
	}
	fmt.Printf("user_id=%s\n", password.UserID)
	fmt.Printf("subject=%s\n", encodeSubject(password.UserID, localConnectorID))
	return nil
}

// findPassword looks up a stored password by address. The match is
// case-insensitive, which mirrors how Dex compares the static emails: an
// operator expects one address to match however it was typed.
func findPassword(passwords []dexPassword, email string) (dexPassword, bool) {
	for _, password := range passwords {
		if strings.EqualFold(password.Email, email) {
			return password, true
		}
	}
	return dexPassword{}, false
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "create-password":
		if err := createPassword(os.Args[2:]); err != nil {
			fail(err)
		}
	case "delete-password":
		if err := deletePassword(os.Args[2:]); err != nil {
			fail(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}
