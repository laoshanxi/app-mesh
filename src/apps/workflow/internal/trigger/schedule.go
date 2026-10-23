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
	wf   *models.Workflow
	next time.Time
	expr string
	key  string // the workflow's schedule definition (cron set), to detect edits
}

// ScheduleDispatcher fires due schedule triggers. Every method runs on the
// Service's single Run goroutine (dispatchSchedules), so no locking is needed.
type ScheduleDispatcher struct {
	byWF map[string]schedState
}

func NewScheduleDispatcher() *ScheduleDispatcher {
	return &ScheduleDispatcher{byWF: make(map[string]schedState)}
}

// cronKey identifies a workflow's schedule definition so reset can tell an edit from
// an unchanged reload.
func cronKey(wf *models.Workflow) string {
	if wf.On == nil {
		return ""
	}
	key := ""
	for _, s := range wf.On.Schedule {
		key += s.Cron + "\n"
	}
	return key
}

// reset reconciles cached state with the current registry. A workflow that is new, or
// whose schedule definition changed, is based from now. An unchanged workflow KEEPS
// its pending fire time even if it is already due — recomputing from now on every
// tick would push a due fire perpetually into the future and it would never happen.
// Removed workflows drop out; a definition change or engine restart never back-fills
// missed periods (a new base is always now or later).
func (d *ScheduleDispatcher) reset(all map[string]*models.Workflow, now time.Time) {
	for name := range d.byWF {
		if _, ok := all[name]; !ok {
			delete(d.byWF, name)
		}
	}
	for name, wf := range all {
		next, expr := nextFire(wf, now)
		if next.IsZero() {
			delete(d.byWF, name)
			continue
		}
		key := cronKey(wf)
		if st, ok := d.byWF[name]; ok && st.key == key {
			st.wf = wf
			if next.Before(st.next) {
				st.next, st.expr = next, expr
			}
			d.byWF[name] = st
			continue
		}
		d.byWF[name] = schedState{wf: wf, next: next, expr: expr, key: key}
	}
}

// tick fires every workflow whose next fire time has passed. The state advances past
// now BEFORE firing, so a late tick fires once, not once per missed period.
func (d *ScheduleDispatcher) tick(now time.Time, fire func(wf *models.Workflow, source string)) int {
	var due []schedState
	for name, st := range d.byWF {
		if st.next.After(now) {
			continue
		}
		next, expr := nextFire(st.wf, now)
		if next.IsZero() {
			delete(d.byWF, name)
		} else {
			d.byWF[name] = schedState{wf: st.wf, next: next, expr: expr}
		}
		due = append(due, st)
	}
	for _, st := range due {
		fire(st.wf, "schedule:"+st.expr)
	}
	return len(due)
}

// tracked reports how many workflows currently have a pending next fire time
// (observability for the dispatch tick).
func (d *ScheduleDispatcher) tracked() int {
	return len(d.byWF)
}

// nextFire returns the earliest next fire time (and its cron text) for a workflow's
// schedule entries, or the zero time when it has none or none parse. Invalid
// expressions are logged and skipped — registration already rejects them, so this
// only guards definitions written to disk behind the engine's back.
func nextFire(wf *models.Workflow, now time.Time) (time.Time, string) {
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
		next := sched.Next(now)
		if next.IsZero() {
			continue
		}
		if best.IsZero() || next.Before(best) {
			best, bestExpr = next, s.Cron
		}
	}
	return best, bestExpr
}
