package utils

import (
	"bytes"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Constants
const (
	defaultLevel       = "debug"
	defaultEncoding    = "console"
	defaultTimeFormat  = "2006-01-02 15:04:05.000"
	goroutineIDLength  = 64
	goroutineIDPadding = 3
)

// Global variables
var (
	logger     atomic.Pointer[zap.SugaredLogger]
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

// Public functions

// DefaultConfig returns the default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:        defaultLevel,
		Development:  false,
		Encoding:     defaultEncoding,
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
func GetLogger() *zap.SugaredLogger {
	if l := logger.Load(); l != nil {
		return l
	}

	// Initialize with default configuration if not already initialized
	if err := InitLogger(DefaultConfig()); err != nil {
		l, _ := zap.NewProduction()
		logger.Store(l.Sugar())
	}
	return logger.Load()
}

// SetLogLevel changes the logging level at runtime
func SetLogLevel(level string) error {
	l := GetLogger()
	if l == nil {
		return fmt.Errorf("logger not initialized")
	}

	parsedLevel, err := zapcore.ParseLevel(level)
	if err != nil {
		return fmt.Errorf("invalid log level %q: %w", level, err)
	}

	l.Desugar().Core().Enabled(parsedLevel)
	return nil
}

// Sync flushes any buffered log entries
func Sync() error {
	if l := logger.Load(); l != nil {
		err := l.Sync()
		if err != nil && err != os.ErrInvalid {
			return fmt.Errorf("failed to sync logger: %w", err)
		}
	}
	return nil
}

// Shutdown performs cleanup and ensures all logs are written
func Shutdown() error {
	return Sync()
}

// Private functions

// initLogger initializes the logger with the provided configuration
func initLogger(cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return fmt.Errorf("invalid log level %q: %w", cfg.Level, err)
	}

	encoderConfig := zapcore.EncoderConfig{
		TimeKey:        "time",
		LevelKey:       "level",
		NameKey:        "logger",
		CallerKey:      "caller",
		FunctionKey:    zapcore.OmitKey,
		MessageKey:     "msg",
		StacktraceKey:  "stacktrace",
		LineEnding:     zapcore.DefaultLineEnding,
		EncodeLevel:    zapcore.CapitalColorLevelEncoder,
		EncodeTime:     makeTimeAndGoroutineEncoder(cfg.TimeFormat),
		EncodeCaller:   zapcore.ShortCallerEncoder,
		EncodeDuration: zapcore.StringDurationEncoder,
	}

	zapConfig := zap.Config{
		Level:            zap.NewAtomicLevelAt(level),
		Development:      cfg.Development,
		Encoding:         cfg.Encoding,
		EncoderConfig:    encoderConfig,
		OutputPaths:      cfg.OutputPaths,
		ErrorOutputPaths: []string{"stderr"},
	}

	l, err := zapConfig.Build(getZapOptions(cfg)...)
	if err != nil {
		return fmt.Errorf("build logger error: %w", err)
	}

	logger.Store(l.Sugar())
	return nil
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

// makeTimeAndGoroutineEncoder creates a custom time encoder that includes goroutine ID
func makeTimeAndGoroutineEncoder(timeFormat string) zapcore.TimeEncoder {
	return func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		goroutineID := getGoroutineID()
		enc.AppendString(fmt.Sprintf("%s %s", t.Format(timeFormat), goroutineID))
	}
}

// getZapOptions returns zap options based on the configuration
func getZapOptions(cfg *Config) []zap.Option {
	options := make([]zap.Option, 0, 3)

	if cfg.EnableCaller {
		options = append(options, zap.AddCaller())
	}

	if cfg.Development {
		options = append(options, zap.Development())
	}

	options = append(options, zap.AddStacktrace(zapcore.ErrorLevel))
	return options
}
