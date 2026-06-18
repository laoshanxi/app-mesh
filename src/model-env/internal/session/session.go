// Package session holds long-lived agent sessions for one tenant's model-env App.
//
// Design contract (see docs/source/workflow/LLMAgentWorkflowDesign.md):
//   - A session is addressed by id, lives across workflow runs, reclaimed by TTL.
//   - State is persisted to disk; after a restart the session is rebuilt from the
//     persisted history. An in-flight turn at crash time is lost (not resumed).
//   - Storage is namespaced per tenant so cross-tenant reads are impossible.
//   - Authorization mirrors the workflow engine L2 PDP: owner == caller || isAdmin.
package session

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
	"github.com/rs/xid"
)

// Errors returned by the store. They are distinct so the API layer can map them
// to stable response messages.
var (
	ErrNotFound  = errors.New("session not found")
	ErrForbidden = errors.New("not authorized for this session")
)

// Session is one conversation/agent state. Each Session serializes its own turns
// via mu — concurrent sends to the same session are not allowed to interleave.
type Session struct {
	ID         string        `json:"id"`
	Owner      string        `json:"owner"`  // username that created it (L2 subject)
	Tenant     string        `json:"tenant"` // isolation namespace
	Messages   []llm.Message `json:"messages"`
	CostTokens int           `json:"cost_tokens"` // cumulative tokens (for ledgers/observability)
	CreatedAt  time.Time     `json:"created_at"`
	UpdatedAt  time.Time     `json:"updated_at"`

	mu sync.Mutex `json:"-"`
}

// Lock/Unlock serialize turns on a single session. The agent loop holds the lock
// for the duration of a turn.
func (s *Session) Lock()   { s.mu.Lock() }
func (s *Session) Unlock() { s.mu.Unlock() }

// Store is the per-tenant-namespaced collection of sessions, backed by disk.
type Store struct {
	mu       sync.RWMutex
	dir      string // base persistence dir; sessions live under {dir}/{tenant}/{id}.json
	ttl      time.Duration
	sessions map[string]*Session
}

// NewStore creates a store rooted at dir with the given TTL, loading any
// previously persisted sessions from disk (restart recovery).
func NewStore(dir string, ttl time.Duration) (*Store, error) {
	s := &Store{dir: dir, ttl: ttl, sessions: map[string]*Session{}}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// Open creates a new session owned by owner within tenant and returns it.
func (s *Store) Open(owner, tenant string) (*Session, error) {
	return s.Create(xid.New().String(), owner, tenant)
}

// Create makes a session with a caller-supplied id (a Scenario B worker
// materializes its pre-assigned --session-id at startup). Returns the existing
// session if the id is already present.
func (s *Store) Create(id, owner, tenant string) (*Session, error) {
	s.mu.Lock()
	if existing, ok := s.sessions[id]; ok {
		s.mu.Unlock()
		return existing, nil
	}
	now := time.Now()
	sess := &Session{
		ID:        id,
		Owner:     owner,
		Tenant:    tenant,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.sessions[id] = sess
	s.mu.Unlock()
	if err := s.persist(sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// Get returns the session if the caller may access it (owner or admin).
func (s *Store) Get(id, caller string, isAdmin bool) (*Session, error) {
	s.mu.RLock()
	sess, ok := s.sessions[id]
	s.mu.RUnlock()
	if !ok {
		return nil, ErrNotFound
	}
	if !isAdmin && sess.Owner != caller {
		return nil, ErrForbidden
	}
	return sess, nil
}

// Persist flushes a session to disk. Callers persist after mutating a session
// under its lock (e.g. at the end of a turn), so history survives a restart.
func (s *Store) Persist(sess *Session) error { return s.persist(sess) }

// Close removes a session (after authorization) from memory and disk.
func (s *Store) Close(id, caller string, isAdmin bool) error {
	sess, err := s.Get(id, caller, isAdmin)
	if err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.sessions, sess.ID)
	s.mu.Unlock()
	return os.Remove(s.path(sess.Tenant, sess.ID))
}

// Reap evicts sessions whose UpdatedAt is older than the TTL. Returns the count
// evicted. A non-positive TTL disables reaping.
func (s *Store) Reap() int {
	if s.ttl <= 0 {
		return 0
	}
	cutoff := time.Now().Add(-s.ttl)
	s.mu.Lock()
	var stale []*Session
	for _, sess := range s.sessions {
		// Read UpdatedAt under the session's own lock to avoid racing a turn that
		// writes it. TryLock failing means the session is mid-turn → busy, not idle.
		if !sess.mu.TryLock() {
			continue
		}
		idle := sess.UpdatedAt.Before(cutoff)
		sess.mu.Unlock()
		if idle {
			stale = append(stale, sess)
		}
	}
	for _, sess := range stale {
		delete(s.sessions, sess.ID)
	}
	s.mu.Unlock()
	for _, sess := range stale {
		_ = os.Remove(s.path(sess.Tenant, sess.ID))
	}
	return len(stale)
}

func (s *Store) path(tenant, id string) string {
	return filepath.Join(s.dir, tenant, id+".json")
}

func (s *Store) persist(sess *Session) error {
	sess.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(sess, "", "  ")
	if err != nil {
		return err
	}
	p := s.path(sess.Tenant, sess.ID)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	// Atomic write: tmp + rename, matching the engine's checkpoint discipline.
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// load rebuilds the in-memory map from disk on startup.
func (s *Store) load() error {
	tenants, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, te := range tenants {
		if !te.IsDir() {
			continue
		}
		files, err := os.ReadDir(filepath.Join(s.dir, te.Name()))
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || filepath.Ext(f.Name()) != ".json" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(s.dir, te.Name(), f.Name()))
			if err != nil {
				continue
			}
			var sess Session
			if err := json.Unmarshal(data, &sess); err != nil {
				continue
			}
			if sess.ID != "" {
				s.sessions[sess.ID] = &sess
			}
		}
	}
	return nil
}
