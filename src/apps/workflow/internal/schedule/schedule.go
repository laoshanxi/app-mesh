// Package schedule parses workflow cron expressions. It lives below both the
// parser (registration-time validation) and the trigger service (dispatch), so
// neither imports the other.
package schedule

import (
	"fmt"

	"github.com/robfig/cron/v3"
)

// Parser accepts the platform's 6-field expression (seconds first, like the
// daemon's cron_schedule) and falls back to the 5-field standard form.
var Parser = cron.NewParser(cron.SecondOptional | cron.Minute | cron.Hour | cron.Dom | cron.Month |
	cron.Dow | cron.Descriptor)

// Parse validates one cron expression and returns its schedule. Callers use it to
// reject typos at registration instead of silently never firing.
func Parse(expr string) (cron.Schedule, error) {
	schedule, err := Parser.Parse(expr)
	if err != nil {
		return nil, fmt.Errorf("invalid cron %q: %w", expr, err)
	}
	return schedule, nil
}
