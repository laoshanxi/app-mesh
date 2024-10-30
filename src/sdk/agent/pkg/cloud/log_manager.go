package cloud

import (
	"sync"
	"time"
)

type LogEntry struct {
	message   string
	timestamp time.Time
}

type LogManager struct {
	lastEntry     LogEntry
	mu            sync.Mutex
	printInterval time.Duration
}

func NewLogManager(printInterval time.Duration) *LogManager {
	logger.Infof("will refresh duplicate log after %d hours", int(printInterval.Hours()))
	return &LogManager{printInterval: printInterval}
}

func (lm *LogManager) Log(message string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now()

	if message != lm.lastEntry.message || now.Sub(lm.lastEntry.timestamp) >= lm.printInterval {
		logger.Info(message)
		lm.lastEntry = LogEntry{message: message, timestamp: now}
	}
}
