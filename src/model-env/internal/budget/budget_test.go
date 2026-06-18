package budget

import "testing"

func TestClampLowersNeverRaises(t *testing.T) {
	ceiling := TurnLimits{MaxIterations: 8, MaxTokens: 1000}

	// A request may lower the ceiling.
	got := ceiling.Clamp(TurnLimits{MaxIterations: 3, MaxTokens: 500})
	if got.MaxIterations != 3 || got.MaxTokens != 500 {
		t.Errorf("lowered = %+v, want {3 500}", got)
	}
	// A request may NOT raise it.
	got = ceiling.Clamp(TurnLimits{MaxIterations: 100, MaxTokens: 99999})
	if got.MaxIterations != 8 || got.MaxTokens != 1000 {
		t.Errorf("raise attempt = %+v, want ceiling {8 1000}", got)
	}
	// Unset (<=0) inherits the ceiling.
	got = ceiling.Clamp(TurnLimits{})
	if got.MaxIterations != 8 || got.MaxTokens != 1000 {
		t.Errorf("unset = %+v, want ceiling {8 1000}", got)
	}

	// Against an UNLIMITED (0) ceiling, a positive request applies (it is stricter
	// than unlimited) — otherwise per-call max_tokens would be a no-op by default.
	unlimited := TurnLimits{MaxIterations: 0, MaxTokens: 0}
	got = unlimited.Clamp(TurnLimits{MaxIterations: 5, MaxTokens: 4000})
	if got.MaxIterations != 5 || got.MaxTokens != 4000 {
		t.Errorf("under unlimited ceiling = %+v, want {5 4000}", got)
	}
}

func TestLedgerQuota(t *testing.T) {
	l := NewLedger(map[string]int{"acme": 100})

	if err := l.CheckTenant("acme"); err != nil {
		t.Fatalf("under quota CheckTenant: %v", err)
	}
	l.Add("acme", 60)
	if err := l.CheckTenant("acme"); err != nil {
		t.Fatalf("still under quota: %v", err)
	}
	l.Add("acme", 50) // now 110 >= 100
	if err := l.CheckTenant("acme"); err != ErrBudgetExceeded {
		t.Errorf("over quota CheckTenant = %v, want ErrBudgetExceeded", err)
	}
	if l.Used("acme") != 110 {
		t.Errorf("Used = %d, want 110", l.Used("acme"))
	}
}

func TestLedgerUnlimited(t *testing.T) {
	l := NewLedger(nil) // no quota → unlimited
	l.Add("acme", 1_000_000)
	if err := l.CheckTenant("acme"); err != nil {
		t.Errorf("unlimited tenant should never be exceeded: %v", err)
	}
}
