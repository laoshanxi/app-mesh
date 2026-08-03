package appmesh

import (
	"log"
	"sync/atomic"
)

// Logf is the signature of the SDK's diagnostic sink: printf-style, no level.
type Logf func(format string, args ...any)

// logSink holds the active logger; the default writes to stderr via the standard
// library. Hosts that separate stdout and stderr should install their own sink,
// or SDK diagnostics land in a stream nobody correlates with their symptoms.
var logSink atomic.Value // of Logf

func init() {
	logSink.Store(Logf(log.Printf))
}

// SetLogger routes the SDK's diagnostics to fn. Passing nil restores the
// default standard-library logger. Safe to call at any time.
func SetLogger(fn Logf) {
	if fn == nil {
		fn = Logf(log.Printf)
	}
	logSink.Store(fn)
}

// logf emits an SDK diagnostic through the active sink.
func logf(format string, args ...any) {
	if fn, ok := logSink.Load().(Logf); ok && fn != nil {
		fn(format, args...)
	}
}
