package utils

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Constants
const (
	defaultLevel       = "debug"
	defaultTimeFormat  = "2006-01-02 15:04:05.000"
	goroutineIDLength  = 64
	goroutineIDPadding = 3
)

// Log levels, ordered by severity
const (
	levelDebug int32 = iota
	levelInfo
	levelWarn
	levelError
	levelFatal
)

var levelNames = []string{"DEBUG", "INFO", "WARN", "ERROR", "FATAL"}

// Global variables
var (
	logger     atomic.Pointer[Logger]
	bufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
	once sync.Once
)

// Config represents logger configuration
type Config struct {
	Level        string   `json:"level"`
	Development  bool     `json:"development"`
	Encoding     string   `json:"encoding"`
	OutputPaths  []string `json:"outputPaths"`
	TimeFormat   string   `json:"timeFormat"`
	EnableCaller bool     `json:"enableCaller"`
}

// Logger is a leveled, goroutine-safe console logger. Its output format is
// compatible with the previous zap console encoding:
//
//	2006-01-02 15:04:05.000 [001]\tINFO\tpkg/file.go:42\tmessage
type Logger struct {
	level      atomic.Int32
	out        io.Writer
	mu         sync.Mutex
	timeFormat string
	caller     bool
}

// Public functions

// DefaultConfig returns the default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:        defaultLevel,
		Development:  false,
		Encoding:     "console",
		OutputPaths:  []string{"stdout"},
		TimeFormat:   defaultTimeFormat,
		EnableCaller: true,
	}
}

// InitLogger initializes the logger with custom configuration
func InitLogger(cfg *Config) error {
	var err error
	once.Do(func() {
		err = initLogger(cfg)
	})
	return err
}

// GetLogger returns the initialized logger instance
func GetLogger() *Logger {
	if l := logger.Load(); l != nil {
		return l
	}

	// Initialize with default configuration if not already initialized
	if err := InitLogger(DefaultConfig()); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init logger: %v\n", err)

		// Fallback to a plain stdout logger at debug level
		fallback := &Logger{out: os.Stdout, timeFormat: defaultTimeFormat, caller: true}
		logger.Store(fallback)
	}
	return logger.Load()
}

// SetLogLevel changes the logging level at runtime
func SetLogLevel(level string) error {
	l := GetLogger()
	if l == nil {
		return fmt.Errorf("logger not initialized")
	}

	parsedLevel, err := parseLevel(level)
	if err != nil {
		return err
	}
	l.level.Store(parsedLevel)
	return nil
}

// Sync flushes any buffered log entries (stdout is unbuffered; kept for API compatibility)
func Sync() error {
	return nil
}

// Shutdown performs cleanup and ensures all logs are written
func Shutdown() error {
	return Sync()
}

// Leveled logging methods, printf-style

func (l *Logger) Debugf(format string, args ...interface{}) { l.logf(levelDebug, format, args) }
func (l *Logger) Infof(format string, args ...interface{})  { l.logf(levelInfo, format, args) }
func (l *Logger) Warnf(format string, args ...interface{})  { l.logf(levelWarn, format, args) }
func (l *Logger) Errorf(format string, args ...interface{}) { l.logf(levelError, format, args) }

// Fatalf logs at fatal level and exits the process with code 1.
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.logf(levelFatal, format, args)
	os.Exit(1)
}

// Leveled logging methods, print-style (fmt.Sprint semantics)

func (l *Logger) Debug(args ...interface{}) { l.log(levelDebug, fmt.Sprint(args...)) }
func (l *Logger) Info(args ...interface{})  { l.log(levelInfo, fmt.Sprint(args...)) }
func (l *Logger) Warn(args ...interface{})  { l.log(levelWarn, fmt.Sprint(args...)) }
func (l *Logger) Error(args ...interface{}) { l.log(levelError, fmt.Sprint(args...)) }

// Fatal logs at fatal level and exits the process with code 1.
func (l *Logger) Fatal(args ...interface{}) {
	l.log(levelFatal, fmt.Sprint(args...))
	os.Exit(1)
}

// Private functions

// initLogger initializes the logger with the provided configuration
func initLogger(cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	level, err := parseLevel(cfg.Level)
	if err != nil {
		return err
	}

	out := io.Writer(os.Stdout)
	for _, path := range cfg.OutputPaths {
		if path == "stderr" {
			out = os.Stderr
		}
	}

	l := &Logger{
		out:        out,
		timeFormat: cfg.TimeFormat,
		caller:     cfg.EnableCaller,
	}
	l.level.Store(level)
	logger.Store(l)
	return nil
}

// parseLevel converts a level name (case-insensitive) to its numeric level
func parseLevel(level string) (int32, error) {
	switch strings.ToLower(level) {
	case "debug":
		return levelDebug, nil
	case "info":
		return levelInfo, nil
	case "warn", "warning":
		return levelWarn, nil
	case "error", "dpanic", "panic":
		return levelError, nil
	case "fatal":
		return levelFatal, nil
	}
	return 0, fmt.Errorf("invalid log level %q", level)
}

func (l *Logger) logf(level int32, format string, args []interface{}) {
	if level < l.level.Load() {
		return
	}
	l.write(level, fmt.Sprintf(format, args...))
}

func (l *Logger) log(level int32, msg string) {
	if level < l.level.Load() {
		return
	}
	l.write(level, msg)
}

// write emits one log line: "<time> [<gid>]\t<LEVEL>\t<caller>\t<msg>\n",
// followed by a stacktrace at error level and above.
func (l *Logger) write(level int32, msg string) {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	buf.WriteString(time.Now().Format(l.timeFormat))
	buf.WriteByte(' ')
	buf.WriteString(getGoroutineID())
	buf.WriteByte('\t')
	buf.WriteString(levelNames[level])
	buf.WriteByte('\t')
	if l.caller {
		buf.WriteString(callerLocation())
		buf.WriteByte('\t')
	}
	buf.WriteString(msg)
	buf.WriteByte('\n')
	if level >= levelError {
		buf.Write(stackTrace())
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Write(buf.Bytes())
}

// callerLocation returns the logging call site as "dir/file.go:line" (last
// two path segments, like zap's ShortCallerEncoder). Leading frames belonging
// to the Logger methods are skipped, so the result is stable regardless of
// compiler inlining.
func callerLocation() string {
	pcs := make([]uintptr, 16)
	n := runtime.Callers(2, pcs) // skip runtime.Callers and callerLocation itself
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		if !strings.Contains(frame.Function, "pkg/utils.(*Logger)") {
			file := frame.File
			if idx := strings.LastIndexByte(file, '/'); idx >= 0 {
				if prev := strings.LastIndexByte(file[:idx], '/'); prev >= 0 {
					file = file[prev+1:]
				}
			}
			return file + ":" + strconv.Itoa(frame.Line)
		}
		if !more {
			break
		}
	}
	return "unknown:0"
}

// stackTrace returns the current goroutine stack with logger-internal frames
// removed, formatted as "<func>\n\t<file>:<line>" per frame.
func stackTrace() []byte {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	pcs := make([]uintptr, 64)
	n := runtime.Callers(2, pcs) // skip runtime.Callers and stackTrace itself
	frames := runtime.CallersFrames(pcs[:n])
	for {
		frame, more := frames.Next()
		// Like zap's stack formatter, the final frame (always runtime.main or
		// runtime.goexit) is noise and is not printed.
		if !more {
			break
		}
		if !strings.Contains(frame.Function, "pkg/utils.(*Logger)") {
			fmt.Fprintf(buf, "%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line)
		}
	}

	out := make([]byte, buf.Len())
	copy(out, buf.Bytes())
	return out
}

// getGoroutineID extracts and formats the current goroutine ID
func getGoroutineID() string {
	buf := bufferPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufferPool.Put(buf)

	stack := make([]byte, goroutineIDLength)
	n := runtime.Stack(stack, false)
	idField := bytes.Fields(stack[:n])[1]
	id, _ := strconv.Atoi(string(idField))
	return fmt.Sprintf("[%0*d]", goroutineIDPadding, id)
}
