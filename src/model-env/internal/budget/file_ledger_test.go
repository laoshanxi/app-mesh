package budget

import (
	"errors"
	"sync"
	"testing"
)

func TestFileLedgerAddAndCheck(t *testing.T) {
	l, err := NewFileLedger(t.TempDir(), map[string]int{"acme": 100})
	if err != nil {
		t.Fatal(err)
	}

	if err := l.CheckTenant("acme"); err != nil {
		t.Fatalf("fresh tenant under quota should pass: %v", err)
	}
	if got := l.Add("acme", 60); got != 60 {
		t.Errorf("Add = %d, want 60", got)
	}
	if got := l.Used("acme"); got != 60 {
		t.Errorf("Used = %d, want 60", got)
	}
	if err := l.CheckTenant("acme"); err != nil {
		t.Errorf("still under quota should pass: %v", err)
	}
	l.Add("acme", 50) // 110 >= 100
	if err := l.CheckTenant("acme"); !errors.Is(err, ErrBudgetExceeded) {
		t.Errorf("over quota CheckTenant = %v, want ErrBudgetExceeded", err)
	}
	// Unlimited tenant (no quota) never trips.
	if err := l.CheckTenant("other"); err != nil {
		t.Errorf("no-quota tenant should pass: %v", err)
	}
}

// A second FileLedger over the same dir sees the first one's writes — this is the
// cross-process sharing property (separate instances, one on-disk counter).
func TestFileLedgerSharedAcrossInstances(t *testing.T) {
	dir := t.TempDir()
	a, _ := NewFileLedger(dir, map[string]int{"acme": 1000})
	b, _ := NewFileLedger(dir, map[string]int{"acme": 1000})

	a.Add("acme", 300)
	if got := b.Used("acme"); got != 300 {
		t.Errorf("second instance Used = %d, want 300 (shared file)", got)
	}
	b.Add("acme", 200)
	if got := a.Used("acme"); got != 500 {
		t.Errorf("first instance Used = %d, want 500", got)
	}
}

// Concurrent Adds via independent ledger instances (each opens its own fd, so the
// flock genuinely serializes them) must not lose updates.
func TestFileLedgerConcurrentAdd(t *testing.T) {
	dir := t.TempDir()
	const writers, perWriter = 8, 50
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l, _ := NewFileLedger(dir, nil)
			for j := 0; j < perWriter; j++ {
				l.Add("acme", 1)
			}
		}()
	}
	wg.Wait()

	l, _ := NewFileLedger(dir, nil)
	if got := l.Used("acme"); got != writers*perWriter {
		t.Errorf("Used = %d, want %d (lost updates → lock not serializing)", got, writers*perWriter)
	}
}
