package budget

import (
	"encoding/json"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// FileLedger is a per-tenant token ledger backed by one JSON file per tenant,
// guarded by an advisory whole-file lock (see lock_unix.go). The shared App and all
// per-session workers point at the same directory, so a tenant's quota is enforced
// across processes via a locked read-modify-write (an in-memory counter can't).
type FileLedger struct {
	dir   string
	quota map[string]int // tenant -> hard token quota (0/absent = unlimited)
}

// NewFileLedger creates a file-backed ledger rooted at dir (created if absent).
func NewFileLedger(dir string, quota map[string]int) (*FileLedger, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	q := map[string]int{}
	for k, v := range quota {
		q[k] = v
	}
	return &FileLedger{dir: dir, quota: q}, nil
}

type ledgerFile struct {
	Used int `json:"used"`
}

func (l *FileLedger) path(tenant string) string {
	return filepath.Join(l.dir, sanitizeTenant(tenant)+".ledger.json")
}

// CheckTenant returns ErrBudgetExceeded if the tenant is at/over quota. Fails open
// on I/O error (a transient fault must not brick a tenant; per-turn budget still caps).
func (l *FileLedger) CheckTenant(tenant string) error {
	q := l.quota[tenant]
	if q <= 0 {
		return nil
	}
	var used int
	if err := l.withLock(tenant, func(f *os.File) error {
		used = readUsed(f)
		return nil
	}); err != nil {
		log.Printf("budget: tenant %q ledger read failed, allowing turn: %v", tenant, err)
		return nil
	}
	if used >= q {
		return ErrBudgetExceeded
	}
	return nil
}

// Add records token spend for a tenant and returns the new cumulative total.
func (l *FileLedger) Add(tenant string, tokens int) int {
	var total int
	if err := l.withLock(tenant, func(f *os.File) error {
		total = readUsed(f) + tokens
		return writeUsed(f, total)
	}); err != nil {
		log.Printf("budget: tenant %q ledger write failed: %v", tenant, err)
		return 0
	}
	return total
}

// Used returns the cumulative tokens spent by a tenant (0 on read error).
func (l *FileLedger) Used(tenant string) int {
	var used int
	_ = l.withLock(tenant, func(f *os.File) error {
		used = readUsed(f)
		return nil
	})
	return used
}

// withLock opens the tenant's ledger file, takes an exclusive whole-file lock, and
// runs fn — so concurrent processes serialize their read-modify-write.
func (l *FileLedger) withLock(tenant string, fn func(f *os.File) error) error {
	f, err := os.OpenFile(l.path(tenant), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := lockFile(f); err != nil {
		return err
	}
	defer func() { _ = unlockFile(f) }()
	return fn(f)
}

func readUsed(f *os.File) int {
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return 0
	}
	// Decode the first JSON value and ignore any trailing bytes — writeUsed writes
	// the new value before truncating, so a crash between write and truncate leaves
	// valid leading JSON followed by a stale tail; a plain Unmarshal would reject it.
	var lf ledgerFile
	if err := json.NewDecoder(f).Decode(&lf); err != nil {
		return 0 // empty/corrupt → 0
	}
	return lf.Used
}

func writeUsed(f *os.File, used int) error {
	data, err := json.Marshal(ledgerFile{Used: used})
	if err != nil {
		return err
	}
	// Write the new value FIRST, then truncate to its length. (tmp+rename is not an
	// option: it would replace the inode and break the flock held on this fd.) This
	// avoids the truncate-then-write window where a crash leaves an empty file → 0.
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Truncate(int64(len(data))); err != nil {
		return err
	}
	return f.Sync()
}

// sanitizeTenant reduces a tenant name to a safe filename component.
func sanitizeTenant(tenant string) string {
	var b strings.Builder
	for _, r := range tenant {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "default"
	}
	return b.String()
}
