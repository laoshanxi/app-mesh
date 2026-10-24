package trigger

import (
	"time"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/logger"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/schedule"
)

// Schedule dispatch (on: schedule). Runs execute exactly like app_event triggers:
// under a short-lived, run-scoped Engine capability — no user bearer and no
// credential at rest (the reason an external cron App cannot drive runs: it would
// need a non-expiring token, which the auth model forbids). Registering a schedule
// trigger already requires workflow-admin (task_handler), same as app_event.

// ParseSchedule validates one cron expression at registration time so a typo fails
// the workflow_add instead of silently never firing. The shared parser accepts the
// platform's 6-field form (seconds first) and the 5-field standard form.
var ParseSchedule = schedule.Parse

type schedState struct {
	wf *models.Workflow
	// last is the instant up to which the schedule has been accounted for (the
	// Kubernetes CronJob lastScheduleTime model): the next fire is always
	// schedule.Next(last), so a definition change naturally re-bases from the last
	// completed period without any extra bookkeeping.
	last time.Time
}

// ScheduleDispatcher fires due schedule triggers. Every method runs on the
// Service's single Run goroutine (dispatchSchedules), so no locking is needed.
type ScheduleDispatcher struct {
	byWF map[string]schedState
}

func NewScheduleDispatcher() *ScheduleDispatcher {
	return &ScheduleDispatcher{byWF: make(map[string]schedState)}
}

func hasSchedule(wf *models.Workflow) bool {
	return wf.On != nil && len(wf.On.Schedule) > 0
}

// reset reconciles tracked workflows with the registry: vanished workflows and
// definitions that lost their schedules drop out; newly scheduled workflows start
// from now. A fresh start therefore never back-fills missed periods.
func (d *ScheduleDispatcher) reset(all map[string]*models.Workflow, now time.Time) {
	for name, st := range d.byWF {
		wf, ok := all[name]
		if !ok || !hasSchedule(wf) {
			delete(d.byWF, name)
			continue
		}
		st.wf = wf
		d.byWF[name] = st
	}
	for name, wf := range all {
		if _, ok := d.byWF[name]; ok || !hasSchedule(wf) {
			continue
		}
		d.byWF[name] = schedState{wf: wf, last: now}
	}
}

// tick fires every workflow whose next period (after its last accounted instant)
// has passed. Firing advances `last` to now, so a late tick fires once and forgoes
// the intermediate missed periods instead of catching up.
func (d *ScheduleDispatcher) tick(now time.Time, fire func(wf *models.Workflow, source string)) int {
	type dueFire struct {
		st   schedState
		expr string
	}
	var due []dueFire
	for name, st := range d.byWF {
		next, expr := nextFire(st.wf, st.last)
		if next.IsZero() || next.After(now) {
			continue
		}
		st.last = now
		d.byWF[name] = st
		due = append(due, dueFire{st: st, expr: expr})
	}
	for _, f := range due {
		fire(f.st.wf, "schedule:"+f.expr)
	}
	return len(due)
}

// tracked reports how many workflows currently carry a schedule (observability for
// the dispatch tick).
func (d *ScheduleDispatcher) tracked() int {
	return len(d.byWF)
}

// nextFire returns the next fire time (and its cron text) strictly after `after`,
// or the zero time when the workflow has no (parseable) schedule. Invalid
// expressions are logged and skipped — registration already rejects them, so this
// only guards definitions written to disk behind the engine's back.
func nextFire(wf *models.Workflow, after time.Time) (time.Time, string) {
	var best time.Time
	var bestExpr string
	if wf.On == nil {
		return time.Time{}, ""
	}
	for _, s := range wf.On.Schedule {
		sched, err := schedule.Parse(s.Cron)
		if err != nil {
			logger.Error("workflow '" + wf.Name + "' schedule skipped: " + err.Error())
			continue
		}
		next := sched.Next(after)
		if next.IsZero() {
			continue
		}
		if best.IsZero() || next.Before(best) {
			best, bestExpr = next, s.Cron
		}
	}
	return best, bestExpr
}
