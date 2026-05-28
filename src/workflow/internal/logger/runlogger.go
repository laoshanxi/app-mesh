package logger

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RunLogger writes structured log lines to a file and optionally to stdout.
// Thread-safe — multiple goroutines (parallel jobs) can write concurrently.
type RunLogger struct {
	mu   sync.Mutex
	file *os.File
	tee  bool // also write to stdout
}

// NewRunLogger creates a logger that writes to the given file path.
// If tee is true, output also goes to stdout.
func NewRunLogger(path string, tee bool) (*RunLogger, error) {
	os.MkdirAll(filepath.Dir(path), 0700)

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	return &RunLogger{file: f, tee: tee}, nil
}

func (l *RunLogger) Close() {
	if l.file != nil {
		l.file.Close()
	}
}

func (l *RunLogger) Emit(msg string) {
	line := fmt.Sprintf("[%s] %s\n", time.Now().UTC().Format("2006-01-02 15:04:05"), msg)
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file != nil {
		io.WriteString(l.file, line)
	}
	if l.tee {
		os.Stdout.WriteString(line)
	}
}

func (l *RunLogger) WorkflowStarted(name, runID string) {
	l.Emit(fmt.Sprintf("WORKFLOW %s RUN %s STARTED", name, runID))
}
func (l *RunLogger) WorkflowCompleted(name, runID, status string, dur float64) {
	l.Emit(fmt.Sprintf("WORKFLOW %s RUN %s COMPLETED status=%s duration=%.1fs", name, runID, status, dur))
}
func (l *RunLogger) JobStarted(name string) {
	l.Emit(fmt.Sprintf("JOB %s STARTED", name))
}
func (l *RunLogger) JobCompleted(name, status string) {
	l.Emit(fmt.Sprintf("JOB %s COMPLETED status=%s", name, status))
}
func (l *RunLogger) JobSkipped(name, reason string) {
	l.Emit(fmt.Sprintf("JOB %s SKIPPED reason=%q", name, reason))
}
func (l *RunLogger) JobFinallyStarted(name string) {
	l.Emit(fmt.Sprintf("JOB %s FINALLY STARTED", name))
}
func (l *RunLogger) JobFinallyCompleted(name string) {
	l.Emit(fmt.Sprintf("JOB %s FINALLY COMPLETED", name))
}
func (l *RunLogger) StepStarted(name string) {
	l.Emit(fmt.Sprintf("STEP %s STARTED", name))
}
func (l *RunLogger) StepCompleted(name string, exitCode int, dur float64) {
	l.Emit(fmt.Sprintf("STEP %s COMPLETED exit_code=%d duration=%.1fs", name, exitCode, dur))
}
func (l *RunLogger) StepFailed(name string, exitCode int, dur float64) {
	l.Emit(fmt.Sprintf("STEP %s FAILED exit_code=%d duration=%.1fs", name, exitCode, dur))
}
func (l *RunLogger) StepRetry(name string, attempt, max int) {
	l.Emit(fmt.Sprintf("STEP %s RETRY %d/%d", name, attempt, max))
}
func (l *RunLogger) StepSkipped(name, reason string) {
	l.Emit(fmt.Sprintf("STEP %s SKIPPED reason=%q", name, reason))
}
func (l *RunLogger) Error(msg string) {
	l.Emit(fmt.Sprintf("ERROR %s", msg))
}
