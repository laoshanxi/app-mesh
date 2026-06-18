package session

import (
	"testing"
	"time"

	"github.com/laoshanxi/app-mesh/src/model-env/internal/llm"
)

func TestOpenGetAuthz(t *testing.T) {
	store, err := NewStore(t.TempDir(), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess, err := store.Open("alice", "acme")
	if err != nil {
		t.Fatal(err)
	}

	// Owner may access.
	if _, err := store.Get(sess.ID, "alice", false); err != nil {
		t.Errorf("owner Get: %v", err)
	}
	// A different non-admin user may not (L2 PDP: tenant isolation matters even when
	// they could guess the id).
	if _, err := store.Get(sess.ID, "bob", false); err != ErrForbidden {
		t.Errorf("non-owner Get = %v, want ErrForbidden", err)
	}
	// Admin may access any session.
	if _, err := store.Get(sess.ID, "bob", true); err != nil {
		t.Errorf("admin Get: %v", err)
	}
	// Unknown id is not-found.
	if _, err := store.Get("nope", "alice", true); err != ErrNotFound {
		t.Errorf("unknown Get = %v, want ErrNotFound", err)
	}
}

func TestPersistAndReload(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	sess, _ := store.Open("alice", "acme")
	sess.Messages = append(sess.Messages, llm.Message{Role: llm.RoleUser, Content: "remember this"})
	if err := store.Persist(sess); err != nil {
		t.Fatal(err)
	}

	// A fresh store over the same dir must rebuild the session from disk — this is
	// the "resume the conversation after restart" contract.
	reloaded, err := NewStore(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, err := reloaded.Get(sess.ID, "alice", false)
	if err != nil {
		t.Fatalf("reload Get: %v", err)
	}
	if len(got.Messages) != 1 || got.Messages[0].Content != "remember this" {
		t.Errorf("history not restored: %+v", got.Messages)
	}
}

func TestCloseRemoves(t *testing.T) {
	dir := t.TempDir()
	store, _ := NewStore(dir, time.Hour)
	sess, _ := store.Open("alice", "acme")

	if err := store.Close(sess.ID, "bob", false); err != ErrForbidden {
		t.Errorf("non-owner close = %v, want ErrForbidden", err)
	}
	if err := store.Close(sess.ID, "alice", false); err != nil {
		t.Fatalf("owner close: %v", err)
	}
	if _, err := store.Get(sess.ID, "alice", true); err != ErrNotFound {
		t.Errorf("after close Get = %v, want ErrNotFound", err)
	}
}

func TestReapTTL(t *testing.T) {
	store, _ := NewStore(t.TempDir(), time.Hour)
	sess, _ := store.Open("alice", "acme")
	// Force the session to look stale.
	sess.UpdatedAt = time.Now().Add(-2 * time.Hour)

	if n := store.Reap(); n != 1 {
		t.Errorf("Reap evicted %d, want 1", n)
	}
	if _, err := store.Get(sess.ID, "alice", true); err != ErrNotFound {
		t.Errorf("reaped session still present: %v", err)
	}
}
