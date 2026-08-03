package trigger

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
)

// The engine used to wait for three consecutive scan failures before re-logging in, so an
// expired token cost up to three scan intervals of failed scans — and three ERROR lines —
// before recovery was even attempted. A 401 must now trigger it immediately.
func TestIsAuthError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"401 from the daemon", &appmesh.APIError{StatusCode: http.StatusUnauthorized}, true},
		{"wrapped 401", fmt.Errorf("scan: %w", &appmesh.APIError{StatusCode: http.StatusUnauthorized}), true},
		// 403 means the credential is valid but the user lacks the permission. Re-logging in
		// would replay the same denial every scan, so it must not count as an auth error.
		{"403 permission denied", &appmesh.APIError{StatusCode: http.StatusForbidden}, false},
		{"500 daemon error", &appmesh.APIError{StatusCode: http.StatusInternalServerError}, false},
		{"connection error", errors.New("dial tcp: connection refused"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isAuthError(tc.err); got != tc.want {
				t.Fatalf("isAuthError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// A failed re-auth must still reset the counter, otherwise every subsequent scan would
// immediately retry the login and turn a bad credential into a login storm.
func TestReAuthenticateResetsCounterOnFailure(t *testing.T) {
	calls := 0
	s := &Service{
		scanFails: scanFailsBeforeReAuth,
		reAuth:    func() error { calls++; return errors.New("daemon down") },
	}

	s.reAuthenticate("test")

	if calls != 1 {
		t.Fatalf("expected exactly one re-auth attempt, got %d", calls)
	}
	if s.scanFails != 0 {
		t.Fatalf("expected the failure counter to reset, got %d", s.scanFails)
	}
}

func TestReAuthenticateResetsCounterOnSuccess(t *testing.T) {
	s := &Service{scanFails: 2, reAuth: func() error { return nil }}
	s.reAuthenticate("test")
	if s.scanFails != 0 {
		t.Fatalf("expected the failure counter to reset, got %d", s.scanFails)
	}
	if !s.reAuthCooldown.IsZero() || s.reAuthFails != 0 {
		t.Fatal("a successful re-auth must clear the backoff")
	}
}

// Re-authenticating on the first 401 makes recovery fast, but a credential that will never
// work (wrong password, locked account) must not turn every scan into another login.
func TestReAuthenticateBacksOffAfterRepeatedFailures(t *testing.T) {
	calls := 0
	s := &Service{reAuth: func() error { calls++; return errors.New("bad password") }}

	s.reAuthenticate("first")
	if calls != 1 {
		t.Fatalf("expected the first attempt to run, got %d calls", calls)
	}
	if !s.reAuthCooldown.After(time.Now()) {
		t.Fatal("expected a cooldown to be armed after a failed re-auth")
	}

	// Subsequent scans during the cooldown must not attempt another login.
	for i := 0; i < 5; i++ {
		s.reAuthenticate("during cooldown")
	}
	if calls != 1 {
		t.Fatalf("expected the cooldown to suppress retries, got %d calls", calls)
	}

	// Once it lapses, one more attempt is allowed and the backoff grows.
	s.reAuthCooldown = time.Now().Add(-time.Second)
	s.reAuthenticate("after cooldown")
	if calls != 2 {
		t.Fatalf("expected one attempt after the cooldown lapsed, got %d calls", calls)
	}
	if s.reAuthFails != 2 {
		t.Fatalf("expected the failure count to grow, got %d", s.reAuthFails)
	}
}

// The backoff must be bounded, or a long outage would push the next retry hours out.
func TestReAuthBackoffIsCapped(t *testing.T) {
	s := &Service{reAuth: func() error { return errors.New("still down") }}
	for i := 0; i < 20; i++ {
		s.reAuthCooldown = time.Time{}
		s.reAuthenticate("outage")
	}
	if wait := time.Until(s.reAuthCooldown); wait > reAuthMaxBackoff {
		t.Fatalf("backoff %s exceeded the %s cap", wait, reAuthMaxBackoff)
	}
}

// A cooldown must not restart the three-strike count for non-auth failures: resetting
// scanFails on a suppressed attempt would starve that path entirely.
func TestCooldownDoesNotResetScanFailCounter(t *testing.T) {
	s := &Service{reAuth: func() error { return errors.New("down") }}
	s.reAuthenticate("first") // arms the cooldown

	s.scanFails = 2
	s.reAuthenticate("suppressed by cooldown")
	if s.scanFails != 2 {
		t.Fatalf("a suppressed attempt must leave the counter alone, got %d", s.scanFails)
	}
}
