//go:build !unix

package budget

import "os"

// No-op on non-Unix (model-env deploys alongside the Unix daemon). The shared
// ledger is not serialized under concurrent writers here.
func lockFile(f *os.File) error { return nil }

func unlockFile(f *os.File) error { return nil }
