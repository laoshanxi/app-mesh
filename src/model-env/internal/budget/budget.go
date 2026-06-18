// Package budget enforces hard ceilings on agent execution.
//
// Two tiers (see design doc): per-turn (max tool-call iterations + max tokens)
// guards a single runaway loop; per-tenant (cumulative token quota + ledger)
// guards one tenant from exhausting the platform. Ceilings are hard: on breach
// the agent loop aborts the turn with ErrBudgetExceeded.
package budget

import (
	"errors"
	"sync"
)

// ErrBudgetExceeded is returned when a hard ceiling is hit.
var ErrBudgetExceeded = errors.New("budget exceeded")

// TenantLedger enforces a per-tenant cumulative token quota. Implemented by Ledger
// (in-memory, single process) and FileLedger (shared on disk across processes).
type TenantLedger interface {
	CheckTenant(tenant string) error // ErrBudgetExceeded if at/over quota
	Add(tenant string, tokens int) int
	Used(tenant string) int
}

// TurnLimits bound a single turn. MaxIterations is the operator-set global
// ceiling on tool-call rounds; callers may lower it but never raise it (enforced
// by Clamp). A non-positive field means "unset" → falls back to the ceiling.
type TurnLimits struct {
	MaxIterations int // tool-call rounds in one turn
	MaxTokens     int // input+output tokens in one turn
}

// Clamp returns a copy of req constrained by the operator ceiling: a request may
// only tighten the limit, never loosen it. A ceiling of 0 means "unlimited" (no
// operator cap), so any positive request applies (it is strictly tighter); against
// a finite ceiling a request applies only if smaller; an unset (<=0) request
// inherits the ceiling.
func (ceiling TurnLimits) Clamp(req TurnLimits) TurnLimits {
	out := ceiling
	if tighter(req.MaxIterations, ceiling.MaxIterations) {
		out.MaxIterations = req.MaxIterations
	}
	if tighter(req.MaxTokens, ceiling.MaxTokens) {
		out.MaxTokens = req.MaxTokens
	}
	return out
}

// tighter reports whether a positive request value is a stricter limit than the
// ceiling (ceiling 0 = unlimited, so any positive request is stricter).
func tighter(req, ceiling int) bool {
	return req > 0 && (ceiling <= 0 || req < ceiling)
}

// Ledger tracks cumulative token spend per tenant and enforces an optional quota.
type Ledger struct {
	mu    sync.Mutex
	quota map[string]int // tenant -> hard token quota (0 = unlimited)
	used  map[string]int // tenant -> tokens spent
}

// NewLedger creates a ledger. quota maps tenant -> token quota (0/absent = unlimited).
func NewLedger(quota map[string]int) *Ledger {
	q := map[string]int{}
	for k, v := range quota {
		q[k] = v
	}
	return &Ledger{quota: q, used: map[string]int{}}
}

// CheckTenant returns ErrBudgetExceeded if the tenant has already met or exceeded
// its quota. Called before starting a turn.
func (l *Ledger) CheckTenant(tenant string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	q := l.quota[tenant]
	if q > 0 && l.used[tenant] >= q {
		return ErrBudgetExceeded
	}
	return nil
}

// Add records token spend for a tenant and returns the new cumulative total.
func (l *Ledger) Add(tenant string, tokens int) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.used[tenant] += tokens
	return l.used[tenant]
}

// Used returns the cumulative tokens spent by a tenant.
func (l *Ledger) Used(tenant string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.used[tenant]
}
