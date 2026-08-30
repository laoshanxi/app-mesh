package trigger

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	appmesh "github.com/laoshanxi/app-mesh/src/sdk/go"
	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

// The engine used to wait for three consecutive scan failures before refreshing, so an
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
		// 403 means the capability is valid but the owner lacks the permission. Refreshing
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

// A failed refresh must still reset the counter, otherwise every subsequent scan would
// immediately retry and turn an unavailable Engine into a request storm.
func TestControlRefreshResetsCounterOnFailure(t *testing.T) {
	calls := 0
	s := &Service{
		scanFails:      scanFailsBeforeControlRefresh,
		refreshControl: func(context.Context) error { calls++; return errors.New("daemon down") },
	}

	s.refreshControlCapability("test")

	if calls != 1 {
		t.Fatalf("expected exactly one refresh attempt, got %d", calls)
	}
	if s.scanFails != 0 {
		t.Fatalf("expected the failure counter to reset, got %d", s.scanFails)
	}
}

func TestControlRefreshResetsCounterOnSuccess(t *testing.T) {
	s := &Service{scanFails: 2, refreshControl: func(context.Context) error { return nil }}
	s.refreshControlCapability("test")
	if s.scanFails != 0 {
		t.Fatalf("expected the failure counter to reset, got %d", s.scanFails)
	}
	if !s.controlRefreshCooldown.IsZero() || s.controlRefreshFails != 0 {
		t.Fatal("a successful refresh must clear the backoff")
	}
}

// Refreshing on the first 401 makes recovery fast, but a persistently unavailable
// issuer must not turn every scan into another request.
func TestControlRefreshBacksOffAfterRepeatedFailures(t *testing.T) {
	calls := 0
	s := &Service{refreshControl: func(context.Context) error { calls++; return errors.New("Engine unavailable") }}

	s.refreshControlCapability("first")
	if calls != 1 {
		t.Fatalf("expected the first attempt to run, got %d calls", calls)
	}
	if !s.controlRefreshCooldown.After(time.Now()) {
		t.Fatal("expected a cooldown to be armed after a failed re-auth")
	}

	// Subsequent scans during the cooldown must not attempt another login.
	for i := 0; i < 5; i++ {
		s.refreshControlCapability("during cooldown")
	}
	if calls != 1 {
		t.Fatalf("expected the cooldown to suppress retries, got %d calls", calls)
	}

	// Once it lapses, one more attempt is allowed and the backoff grows.
	s.controlRefreshCooldown = time.Now().Add(-time.Second)
	s.refreshControlCapability("after cooldown")
	if calls != 2 {
		t.Fatalf("expected one attempt after the cooldown lapsed, got %d calls", calls)
	}
	if s.controlRefreshFails != 2 {
		t.Fatalf("expected the failure count to grow, got %d", s.controlRefreshFails)
	}
}

// The backoff must be bounded, or a long outage would push the next retry hours out.
func TestControlRefreshBackoffIsCapped(t *testing.T) {
	s := &Service{refreshControl: func(context.Context) error { return errors.New("still down") }}
	for i := 0; i < 20; i++ {
		s.controlRefreshCooldown = time.Time{}
		s.refreshControlCapability("outage")
	}
	if wait := time.Until(s.controlRefreshCooldown); wait > controlRefreshMaxBackoff {
		t.Fatalf("backoff %s exceeded the %s cap", wait, controlRefreshMaxBackoff)
	}
}

// A cooldown must not restart the three-strike count for non-auth failures: resetting
// scanFails on a suppressed attempt would starve that path entirely.
func TestCooldownDoesNotResetScanFailCounter(t *testing.T) {
	s := &Service{refreshControl: func(context.Context) error { return errors.New("down") }}
	s.refreshControlCapability("first") // arms the cooldown

	s.scanFails = 2
	s.refreshControlCapability("suppressed by cooldown")
	if s.scanFails != 2 {
		t.Fatalf("a suppressed attempt must leave the counter alone, got %d", s.scanFails)
	}
}

// --- Run credential resolution ---

func renewalService(t *testing.T, owner string, issuer CapabilityIssuer) *Service {
	t.Helper()
	s := &Service{processUUID: "proc-1", issueCapability: issuer}
	s.registry = NewRegistry()
	s.registry.Update("wf", &models.Workflow{Name: "wf"}, owner)
	return s
}

// A manual run must not execute on the caller's Dex bearer: that bearer dies with the
// access-token TTL and, by ADR 0006/0009, can never be renewed without persisting user
// credentials. Every run — manual included — has to obtain the Engine-issued,
// run-scoped capability instead.
func TestResolveExecCredentialAlwaysUsesCapability(t *testing.T) {
	var gotOperations []string
	s := renewalService(t, "owner-1", func(_ context.Context, workflowID, runID string, operations []string) (appmesh.WorkflowCapability, error) {
		if workflowID != "wf" || runID != "run-1" {
			t.Errorf("issuer got workflow=%q run=%q", workflowID, runID)
		}
		gotOperations = operations
		return appmesh.WorkflowCapability{
			Capability: "cap-1", ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			OwnerPrincipalID: "owner-1", ProcessUUID: "proc-1",
		}, nil
	})

	token, capability, err := s.resolveExecCredential(context.Background(), "wf", "run-1")
	if err != nil {
		t.Fatalf("resolveExecCredential failed: %v", err)
	}
	if token != "cap-1" || capability.Capability != "cap-1" {
		t.Fatalf("execution token must be the run capability, got %q", token)
	}
	// Least privilege: the capability may carry only the run-scoped operations.
	if !slices.Equal(gotOperations, runCapabilityOperations) {
		t.Fatalf("issuer operations = %v, want %v", gotOperations, runCapabilityOperations)
	}
}

// A capability minted for another Principal would silently run steps under foreign
// authority; the run must refuse to start instead.
func TestResolveExecCredentialRejectsOwnerMismatch(t *testing.T) {
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		return appmesh.WorkflowCapability{
			Capability: "cap-1", ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			OwnerPrincipalID: "owner-2", ProcessUUID: "proc-1",
		}, nil
	})
	if _, _, err := s.resolveExecCredential(context.Background(), "wf", "run-1"); err == nil || !strings.Contains(err.Error(), "owner") {
		t.Fatalf("owner mismatch must be rejected, got err=%v", err)
	}
}

// A capability from a different Workflow process instance may belong to a superseded
// engine; accepting it would let two engines drive one run.
func TestResolveExecCredentialRejectsProcessMismatch(t *testing.T) {
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		return appmesh.WorkflowCapability{
			Capability: "cap-1", ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
			OwnerPrincipalID: "owner-1", ProcessUUID: "proc-old",
		}, nil
	})
	if _, _, err := s.resolveExecCredential(context.Background(), "wf", "run-1"); err == nil || !strings.Contains(err.Error(), "process") {
		t.Fatalf("process mismatch must be rejected, got err=%v", err)
	}
}

// Without the local Engine capability channel no run — manual included — may start.
func TestResolveExecCredentialFailsWithoutIssuer(t *testing.T) {
	s := renewalService(t, "owner-1", nil)
	if _, _, err := s.resolveExecCredential(context.Background(), "wf", "run-1"); err == nil {
		t.Fatal("a run must not start without the Engine capability channel")
	}
}

// --- Run capability renewal ---

func newRenewalClient(t *testing.T) *appmesh.AppMeshClient {
	t.Helper()
	// Never connects: renewal only swaps the in-memory token.
	c, err := appmesh.NewHTTPClient(appmesh.Option{AppMeshUri: "https://127.0.0.1:1", JwtToken: "initial"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func waitFor(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

func renewedCapability(token string) appmesh.WorkflowCapability {
	return appmesh.WorkflowCapability{
		Capability: token, ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		OwnerPrincipalID: "owner-1", ProcessUUID: "proc-1",
	}
}

// Long runs survive past CapabilityLifetime only because renewal swaps the token before
// expiry — the exact property whose absence killed manual runs at the Dex TTL.
func TestCapabilityRenewalReplacesTokenBeforeExpiry(t *testing.T) {
	client := newRenewalClient(t)
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		return renewedCapability("cap-renewed"), nil
	})
	expired := make(chan error, 1)
	stop := s.startCapabilityRenewal(context.Background(), client, "wf", "run-1", "owner-1",
		time.Now().Add(capabilityRefreshMargin+time.Second).Unix(), // renewal due in ~1s
		func(err error) { expired <- err })
	defer stop()

	waitFor(t, 5*time.Second, func() bool { return client.GetToken() == "cap-renewed" },
		"capability was not renewed before expiry")
	select {
	case err := <-expired:
		t.Fatalf("a successful renewal must not fail the run: %v", err)
	default:
	}
}

// A transient issuance failure (daemon restart) must retry and recover while the
// current capability is still usable, not abort a healthy run.
func TestCapabilityRenewalRetriesTransientFailure(t *testing.T) {
	client := newRenewalClient(t)
	calls := 0
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		calls++
		if calls == 1 {
			return appmesh.WorkflowCapability{}, errors.New("daemon restarting")
		}
		return renewedCapability("cap-after-retry"), nil
	})
	expired := make(chan error, 1)
	stop := s.startCapabilityRenewal(context.Background(), client, "wf", "run-1", "owner-1",
		time.Now().Add(capabilityRefreshMargin+3*time.Second).Unix(), // slack for one failed attempt
		func(err error) { expired <- err })
	defer stop()

	waitFor(t, 8*time.Second, func() bool { return client.GetToken() == "cap-after-retry" },
		"renewal did not recover after a transient failure")
	select {
	case err := <-expired:
		t.Fatalf("a recoverable failure must not fail the run: %v", err)
	default:
	}
}

// Once the last good capability has expired and renewal still fails, the run must be
// failed explicitly (onExpired, exactly once) instead of retrying forever while every
// step dies with unrelated 401s.
func TestCapabilityRenewalFailsRunWhenExpired(t *testing.T) {
	client := newRenewalClient(t)
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		return appmesh.WorkflowCapability{}, errors.New("owner disabled")
	})
	expired := make(chan error, 1)
	stop := s.startCapabilityRenewal(context.Background(), client, "wf", "run-1", "owner-1",
		time.Now().Add(-time.Second).Unix(), // credential already dead
		func(err error) { expired <- err })
	defer stop()

	select {
	case err := <-expired:
		if err == nil || !strings.Contains(err.Error(), "owner disabled") {
			t.Fatalf("expiry must surface the issuance failure, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run was not failed after its credential expired")
	}
	select {
	case err := <-expired:
		t.Fatalf("onExpired must fire exactly once, got a second callback: %v", err)
	case <-time.After(1500 * time.Millisecond):
	}
}

// A renewal minted for a different owner (workflow re-registered underneath the run)
// must be refused, and once the old capability also expires the run fails explicitly.
func TestCapabilityRenewalRefusesOwnerChange(t *testing.T) {
	client := newRenewalClient(t)
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		capability := renewedCapability("cap-new-owner")
		capability.OwnerPrincipalID = "owner-2"
		return capability, nil
	})
	expired := make(chan error, 1)
	stop := s.startCapabilityRenewal(context.Background(), client, "wf", "run-1", "owner-1",
		time.Now().Add(-time.Second).Unix(),
		func(err error) { expired <- err })
	defer stop()

	select {
	case err := <-expired:
		if err == nil || !strings.Contains(err.Error(), "owner changed") {
			t.Fatalf("owner change must be refused and fail the run, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("owner change was not refused")
	}
	if token := client.GetToken(); token != "initial" {
		t.Fatalf("a refused capability must never be installed, token=%q", token)
	}
}

// stop() must synchronously end the loop before the execution client is closed, so a
// late renewal can never write a token into a dead connection.
func TestCapabilityRenewalStopIsSynchronous(t *testing.T) {
	client := newRenewalClient(t)
	s := renewalService(t, "owner-1", func(context.Context, string, string, []string) (appmesh.WorkflowCapability, error) {
		t.Error("issuer must not be called before the renewal deadline")
		return renewedCapability("cap-late"), nil
	})
	stop := s.startCapabilityRenewal(context.Background(), client, "wf", "run-1", "owner-1",
		time.Now().Add(time.Hour).Unix(), nil)

	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stop() did not return promptly")
	}
	if token := client.GetToken(); token != "initial" {
		t.Fatalf("token must be untouched before the first renewal, got %q", token)
	}
}
