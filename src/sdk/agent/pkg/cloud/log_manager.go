package cloud

import (
	"log"
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
	log.Printf("will refresh log after %f hours", printInterval.Hours())
	return &LogManager{printInterval: printInterval}
}

func (lm *LogManager) Log(message string) {
	lm.mu.Lock()
	defer lm.mu.Unlock()

	now := time.Now()

	if message != lm.lastEntry.message || now.Sub(lm.lastEntry.timestamp) >= lm.printInterval {
		log.Println(message)
		lm.lastEntry = LogEntry{message: message, timestamp: now}
	}
}
