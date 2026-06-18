package executor

import "testing"

func TestInjectToken(t *testing.T) {
	cases := []struct {
		name, payload, token, want string
	}{
		{"object without token gets it", `{"a":1}`, "JWT", `{"a":1,"token":"JWT"}`}, // map marshal sorts keys
		{"author token wins", `{"token":"mine","a":1}`, "JWT", `{"token":"mine","a":1}`},
		{"json array untouched", `[1,2,3]`, "JWT", `[1,2,3]`},
		{"json scalar untouched", `"hi"`, "JWT", `"hi"`},
		{"json null untouched", `null`, "JWT", `null`},
		{"empty payload untouched", ``, "JWT", ``},
		{"invalid json untouched", `{bad`, "JWT", `{bad`},
		{"token is json-escaped", `{}`, `a"b`, `{"token":"a\"b"}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := injectToken(c.payload, c.token); got != c.want {
				t.Errorf("injectToken(%q, %q) = %q, want %q", c.payload, c.token, got, c.want)
			}
		})
	}
}

func TestAppLevelError(t *testing.T) {
	cases := []struct {
		name, resp, wantMsg string
		wantErr             bool
	}{
		{"status error with message", `{"status":"error","message":"token required"}`, "token required", true},
		{"status error no message", `{"status":"error"}`, "app returned status=error", true},
		{"status ok", `{"status":"ok","data":{}}`, "", false},
		{"no status field", `{"answer":"hi"}`, "", false},
		{"plain text", `hello`, "", false},
		{"json array", `[1,2]`, "", false},
		{"empty", ``, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, isErr := appLevelError(c.resp)
			if isErr != c.wantErr || msg != c.wantMsg {
				t.Errorf("appLevelError(%q) = (%q,%v), want (%q,%v)", c.resp, msg, isErr, c.wantMsg, c.wantErr)
			}
		})
	}
}
