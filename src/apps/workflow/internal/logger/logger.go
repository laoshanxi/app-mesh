package logger

import (
	"fmt"
	"os"
	"time"
)

func ts() string {
	return time.Now().UTC().Format("2006-01-02 15:04:05")
}

func emit(msg string) {
	fmt.Fprintf(os.Stdout, "[%s] %s\n", ts(), msg)
}

func WorkflowStarted(name, runID string) {
	emit(fmt.Sprintf("WORKFLOW %s RUN %s STARTED", name, runID))
}
func WorkflowCompleted(name, runID, status string, dur float64) {
	emit(fmt.Sprintf("WORKFLOW %s RUN %s COMPLETED status=%s duration=%.1fs", name, runID, status, dur))
}
func JobStarted(name string)           { emit(fmt.Sprintf("JOB %s STARTED", name)) }
func JobCompleted(name, status string) { emit(fmt.Sprintf("JOB %s COMPLETED status=%s", name, status)) }
func JobSkipped(name, reason string)   { emit(fmt.Sprintf("JOB %s SKIPPED reason=%q", name, reason)) }
func JobFinallyStarted(name string)    { emit(fmt.Sprintf("JOB %s FINALLY STARTED", name)) }
func JobFinallyCompleted(name string)  { emit(fmt.Sprintf("JOB %s FINALLY COMPLETED", name)) }
func StepStarted(name string)          { emit(fmt.Sprintf("STEP %s STARTED", name)) }
func StepCompleted(name string, exitCode int, dur float64) {
	emit(fmt.Sprintf("STEP %s COMPLETED exit_code=%d duration=%.1fs", name, exitCode, dur))
}
func StepFailed(name string, exitCode int, dur float64) {
	emit(fmt.Sprintf("STEP %s FAILED exit_code=%d duration=%.1fs", name, exitCode, dur))
}
func StepRetry(name string, attempt, max int) {
	emit(fmt.Sprintf("STEP %s RETRY %d/%d", name, attempt, max))
}
func StepSkipped(name, reason string) { emit(fmt.Sprintf("STEP %s SKIPPED reason=%q", name, reason)) }
func Error(msg string)                { emit(fmt.Sprintf("ERROR %s", msg)) }
func Info(msg string)                 { emit(msg) }
