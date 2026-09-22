package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"
)

// The subjects below are the packaged administrator and guest identities, taken
// from src/daemon/security/authorization.yaml and src/auth/appmesh-auth.sh.
// They pin the encoding that Dex uses. If Dex changes the encoding, these
// fixtures fail instead of the launcher computing a wrong Principal ID.
func TestEncodeSubjectMatchesDex(t *testing.T) {
	tests := []struct {
		name   string
		userID string
		want   string
	}{
		{
			name:   "packaged guest",
			userID: "93ad39b4-eb6f-4945-97a1-3366451867fb",
			want:   "CiQ5M2FkMzliNC1lYjZmLTQ5NDUtOTdhMS0zMzY2NDUxODY3ZmISBWxvY2Fs",
		},
		{
			name:   "packaged administrator",
			userID: "2d1c8c38-3898-4c89-a78b-3caa42f203c1",
			want:   "CiQyZDFjOGMzOC0zODk4LTRjODktYTc4Yi0zY2FhNDJmMjAzYzESBWxvY2Fs",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := encodeSubject(test.userID, localConnectorID); got != test.want {
				t.Errorf("encodeSubject(%q) = %q, want %q", test.userID, got, test.want)
			}
		})
	}
}

// A user identifier longer than 127 bytes needs a multi-byte length prefix. A
// byte splicer that writes a single length byte would corrupt this input.
func TestEncodeSubjectUsesVarintLength(t *testing.T) {
	userID := strings.Repeat("a", 200)
	got := encodeSubject(userID, localConnectorID)

	// Tag 0x0a, then the length as the varint 0xc8 0x01, which encodes to the
	// base64 prefix "CsgB".
	if !strings.HasPrefix(got, "CsgB") {
		t.Errorf("encodeSubject() = %q, want the prefix CsgB for a 200-byte identifier", got)
	}

	raw, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Fatalf("the subject is not raw base64url: %v", err)
	}
	// Two field headers: the first holds a two-byte varint length (0xc8 0x01)
	// plus its tag, the second a one-byte length plus its tag.
	const fieldHeaders = 3 + 2
	if want := fieldHeaders + len(userID) + len(localConnectorID); len(raw) != want {
		t.Errorf("the decoded subject is %d bytes, want %d", len(raw), want)
	}
	if !bytes.HasSuffix(raw, []byte(localConnectorID)) {
		t.Errorf("the decoded subject %q does not end with %q", raw, localConnectorID)
	}
}

func TestReadHash(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "plain value", input: "$2b$10$abcdefghijklmnopqrstuv", want: "$2b$10$abcdefghijklmnopqrstuv"},
		{name: "one trailing newline", input: "hash\n", want: "hash"},
		{name: "trailing CRLF", input: "hash\r\n", want: "hash"},
		{name: "empty input", input: "", wantErr: true},
		{name: "newline only", input: "\n", wantErr: true},
		{name: "too long", input: strings.Repeat("a", maxHashLen+1), wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			restore := replaceStdin(t, test.input)
			defer restore()

			got, err := readHash()
			if test.wantErr {
				if err == nil {
					t.Fatalf("readHash() = %q, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("readHash() returned an unexpected error: %v", err)
			}
			if got != test.want {
				t.Errorf("readHash() = %q, want %q", got, test.want)
			}
		})
	}
}

// replaceStdin points standard input at a temporary file and returns a function
// that restores the original stream.
func replaceStdin(t *testing.T, content string) func() {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatalf("cannot create the temporary file: %v", err)
	}
	if _, err := file.WriteString(content); err != nil {
		t.Fatalf("cannot write the temporary file: %v", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("cannot rewind the temporary file: %v", err)
	}
	original := os.Stdin
	os.Stdin = file
	return func() {
		os.Stdin = original
		file.Close()
	}
}

// The reply parsing is hand-written against the proto, so it is pinned here
// with byte literals rather than with the production encoders.
func TestParseListPasswordsResponse(t *testing.T) {
	// ListPasswordResp { repeated Password passwords = 1 }
	// Password { string email = 1; bytes hash = 2; string username = 3; string user_id = 4 }
	// One entry: field 1 holds a Password with email "a@b" and user_id "id".
	message := []byte{
		0x0a, 0x09, // field 1, length-delimited, 9 bytes
		0x0a, 0x03, 'a', '@', 'b', // email = "a@b"
		0x22, 0x02, 'i', 'd', // user_id = "id"
	}
	passwords, err := parseListPasswordsResponse(message)
	if err != nil {
		t.Fatalf("parseListPasswordsResponse() returned an unexpected error: %v", err)
	}
	if len(passwords) != 1 {
		t.Fatalf("parseListPasswordsResponse() returned %d entries, want 1", len(passwords))
	}
	if passwords[0].Email != "a@b" || passwords[0].UserID != "id" {
		t.Errorf("parseListPasswordsResponse() = %+v, want email a@b and user id", passwords[0])
	}

	// An empty reply is valid and means no stored passwords.
	passwords, err = parseListPasswordsResponse(nil)
	if err != nil {
		t.Fatalf("parseListPasswordsResponse(nil) returned an unexpected error: %v", err)
	}
	if len(passwords) != 0 {
		t.Errorf("parseListPasswordsResponse(nil) = %+v, want no entries", passwords)
	}

	// A truncated entry must be an error, not a silent empty result.
	if _, err := parseListPasswordsResponse([]byte{0x0a, 0x40}); err == nil {
		t.Error("parseListPasswordsResponse() accepted a truncated entry")
	}
}

func TestBoolFields(t *testing.T) {
	// A proto3 bool that is false is absent from the wire.
	if isAlreadyExists(nil) {
		t.Error("isAlreadyExists(nil) = true, want false")
	}
	if !isAlreadyExists([]byte{0x08, 0x01}) {
		t.Error("isAlreadyExists({0x08 0x01}) = false, want true")
	}
	if !isNotFound([]byte{0x08, 0x01}) {
		t.Error("isNotFound({0x08 0x01}) = false, want true")
	}
	// An unknown leading field must not be mistaken for field 1.
	if isAlreadyExists([]byte{0x10, 0x01}) {
		t.Error("isAlreadyExists() read field 2 as field 1")
	}
}

// The outgoing messages must decode to the field numbers the proto declares.
func TestMarshalledRequestShape(t *testing.T) {
	request := marshalCreatePasswordRequest("a@b", "hash", "user", "id")
	seen := map[int]string{}
	err := eachField(request, func(number int, wireType protowire.Type, value []byte) error {
		if wireType != protowire.BytesType {
			return nil
		}
		if number == 1 {
			return eachField(value, func(inner int, innerWire protowire.Type, innerValue []byte) error {
				if innerWire == protowire.BytesType {
					seen[inner] = string(innerValue)
				}
				return nil
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("eachField() returned an unexpected error: %v", err)
	}
	want := map[int]string{1: "a@b", 2: "hash", 3: "user", 4: "id"}
	for number, value := range want {
		if seen[number] != value {
			t.Errorf("field %d = %q, want %q", number, seen[number], value)
		}
	}
}

func TestFrameRoundTrip(t *testing.T) {
	message := []byte{1, 2, 3}
	body, err := unframe(frame(message))
	if err != nil {
		t.Fatalf("unframe(frame()) returned an unexpected error: %v", err)
	}
	if !bytes.Equal(body, message) {
		t.Errorf("unframe(frame()) = %v, want %v", body, message)
	}
	// An empty body is a valid empty message, which is what a successful
	// DeletePassword response looks like.
	body, err = unframe(nil)
	if err != nil || body != nil {
		t.Errorf("unframe(nil) = %v, %v; want nil, nil", body, err)
	}
	if _, err := unframe([]byte{0x01, 0, 0, 0, 0}); err == nil {
		t.Error("unframe() accepted a compressed frame")
	}
}

// The delete flow looks up an address case-insensitively but deletes with the
// stored address, so the match itself is pinned here.
func TestFindPassword(t *testing.T) {
	passwords := []dexPassword{
		{Email: "alice@corp.local", UserID: "id-1"},
		{Email: "bob@corp.local", UserID: "id-2"},
	}
	password, found := findPassword(passwords, "ALICE@corp.local")
	if !found || password.Email != "alice@corp.local" || password.UserID != "id-1" {
		t.Errorf("findPassword() = %+v, %v; want the stored alice entry, true", password, found)
	}
	if _, found := findPassword(passwords, "carol@corp.local"); found {
		t.Error("findPassword() matched an unknown address")
	}
}
