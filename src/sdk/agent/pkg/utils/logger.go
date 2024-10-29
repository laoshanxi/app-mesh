// logger/logger.go
package utils

import (
	"fmt"
	"os"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	logger *zap.SugaredLogger
	once   sync.Once
)

type Config struct {
	Level        string
	Development  bool
	Encoding     string
	OutputPaths  []string
	TimeFormat   string
	EnableCaller bool
}

// DefaultConfig returns the default logger configuration
func DefaultConfig() *Config {
	return &Config{
		Level:        "debug",
		Development:  false,
		Encoding:     "console",
		OutputPaths:  []string{"stdout"},
		TimeFormat:   "2006-01-02 15:04:05.000",
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

func initLogger(cfg *Config) error {
	if cfg == nil {
		cfg = DefaultConfig()
	}

	level, err := zapcore.ParseLevel(cfg.Level)
	if err != nil {
		return fmt.Errorf("parse log level error: %w", err)
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
		EncodeLevel:    zapcore.CapitalLevelEncoder,
		EncodeTime:     makeTimeEncoder(cfg.TimeFormat),
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

	logger = l.Sugar()
	return nil
}

func makeTimeEncoder(timeFormat string) zapcore.TimeEncoder {
	return func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.Format(timeFormat))
	}
}

func getZapOptions(cfg *Config) []zap.Option {
	var options []zap.Option

	if cfg.EnableCaller {
		options = append(options, zap.AddCaller())
	}

	if cfg.Development {
		options = append(options, zap.Development())
	}

	return options
}

// GetLogger returns the initialized logger instance
func GetLogger() *zap.SugaredLogger {
	if logger == nil {
		// Initialize with default configuration if not already initialized
		err := InitLogger(DefaultConfig())
		if err != nil {
			// Fallback to basic logger in case of initialization failure
			l, _ := zap.NewProduction()
			logger = l.Sugar()
		}
	}
	return logger
}

// Sync flushes any buffered log entries
func Sync() error {
	if logger != nil {
		return logger.Sync()
	}
	return nil
}

// Example shutdown function
func Shutdown() error {
	err := Sync()
	if err != nil && err != os.ErrInvalid {
		return fmt.Errorf("failed to sync logger: %w", err)
	}
	return nil
}
