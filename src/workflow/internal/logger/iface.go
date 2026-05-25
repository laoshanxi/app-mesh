package logger

// Log is the interface used by the engine for structured logging.
// Both RunLogger (per-run file) and the global functions satisfy this.
type Log interface {
	WorkflowStarted(name, runID string)
	WorkflowCompleted(name, runID, status string, dur float64)
	JobStarted(name string)
	JobCompleted(name, status string)
	JobSkipped(name, reason string)
	JobFinallyStarted(name string)
	JobFinallyCompleted(name string)
	StepStarted(name string)
	StepCompleted(name string, exitCode int, dur float64)
	StepFailed(name string, exitCode int, dur float64)
	StepRetry(name string, attempt, max int)
	StepSkipped(name, reason string)
	Error(msg string)
}

// globalLog wraps the package-level functions to satisfy the Log interface.
type globalLog struct{}

func (g globalLog) WorkflowStarted(name, runID string) { WorkflowStarted(name, runID) }
func (g globalLog) WorkflowCompleted(name, runID, status string, dur float64) {
	WorkflowCompleted(name, runID, status, dur)
}
func (g globalLog) JobStarted(name string)           { JobStarted(name) }
func (g globalLog) JobCompleted(name, status string) { JobCompleted(name, status) }
func (g globalLog) JobSkipped(name, reason string)   { JobSkipped(name, reason) }
func (g globalLog) JobFinallyStarted(name string)    { JobFinallyStarted(name) }
func (g globalLog) JobFinallyCompleted(name string)  { JobFinallyCompleted(name) }
func (g globalLog) StepStarted(name string)          { StepStarted(name) }
func (g globalLog) StepCompleted(name string, exitCode int, dur float64) {
	StepCompleted(name, exitCode, dur)
}
func (g globalLog) StepFailed(name string, exitCode int, dur float64) {
	StepFailed(name, exitCode, dur)
}
func (g globalLog) StepRetry(name string, attempt, max int) { StepRetry(name, attempt, max) }
func (g globalLog) StepSkipped(name, reason string)         { StepSkipped(name, reason) }
func (g globalLog) Error(msg string)                        { Error(msg) }

// Global returns a Log backed by the package-level stdout functions.
func Global() Log { return globalLog{} }
