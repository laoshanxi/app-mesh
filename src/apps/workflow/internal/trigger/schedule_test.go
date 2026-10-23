package trigger

import (
	"testing"
	"time"

	"github.com/laoshanxi/app-mesh/src/apps/workflow/internal/models"
)

func schedWF(name string, crons ...string) *models.Workflow {
	wf := &models.Workflow{Name: name, On: &models.TriggerConfig{}}
	for _, c := range crons {
		wf.On.Schedule = append(wf.On.Schedule, models.ScheduleTrigger{Cron: c})
	}
	return wf
}

func TestParseScheduleAcceptsPlatformAndStandardForms(t *testing.T) {
	for _, expr := range []string{
		"0 */5 * * * *", // 6-field, seconds first (daemon cron_schedule style)
		"*/5 * * * *",   // 5-field standard
		"@hourly",       // descriptor
		"@every 90s",
	} {
		if _, err := ParseSchedule(expr); err != nil {
			t.Errorf("ParseSchedule(%q) = %v, want ok", expr, err)
		}
	}
	for _, expr := range []string{"", "not a cron", "61 * * * *", "* * * * * * *"} {
		if _, err := ParseSchedule(expr); err == nil {
			t.Errorf("ParseSchedule(%q) accepted, want error", expr)
		}
	}
}

func TestNextFirePicksEarliestEntryAndSkipsInvalid(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC)
	wf := schedWF("w", "0 0 * * *", "bogus", "* * * * *")
	next, expr := nextFire(wf, now)
	if expr != "* * * * *" {
		t.Fatalf("earliest entry = %q, want the every-minute one", expr)
	}
	if want := time.Date(2026, 1, 1, 12, 1, 0, 0, time.UTC); !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
	if n, _ := nextFire(&models.Workflow{Name: "none"}, now); !n.IsZero() {
		t.Fatalf("workflow without schedules must have no next fire, got %v", n)
	}
}

func TestTickFiresDueOnceAndAdvances(t *testing.T) {
	d := NewScheduleDispatcher()
	wf := schedWF("w", "* * * * *")
	d.reset(map[string]*models.Workflow{"w": wf}, time.Now())
	st := d.byWF["w"]

	var fired []string
	fire := func(w *models.Workflow, source string) { fired = append(fired, w.Name+"|"+source) }

	// Before the due instant nothing fires — and repeated reset+tick cycles (what the
	// dispatch loop does every 30s) must not push a due fire into the future.
	if n := d.tick(st.next.Add(-time.Second), fire); n != 0 || len(fired) != 0 {
		t.Fatalf("early tick fired %d (%v), want 0", n, fired)
	}
	late := st.next.Add(5 * time.Minute)
	for i := 0; i < 3; i++ { // reset between ticks, like dispatchSchedules
		d.reset(map[string]*models.Workflow{"w": wf}, late)
		if n := d.tick(late, fire); i == 0 && (n != 1 || len(fired) != 1) {
			t.Fatalf("tick %d: fired %d (%v), want the first to fire exactly once", i, n, fired)
		} else if i > 0 && n != 0 {
			t.Fatalf("tick %d: fired %d again, want 0", i, n)
		}
	}
	if fired[0] != "w|schedule:* * * * *" {
		t.Fatalf("source = %q", fired[0])
	}
	if !d.byWF["w"].next.After(late) {
		t.Fatalf("next fire %v not advanced past %v", d.byWF["w"].next, late)
	}
}

// Editing a workflow's cron re-bases its schedule from now (no back-fill of periods
// that were due under the old definition).
func TestResetRebasesOnDefinitionChange(t *testing.T) {
	d := NewScheduleDispatcher()
	old := schedWF("w", "* * * * *")
	base := time.Date(2026, 1, 1, 12, 0, 30, 0, time.Local)
	d.reset(map[string]*models.Workflow{"w": old}, base)
	due := d.byWF["w"].next
	now := due.Add(2 * time.Minute) // the old schedule is due by now

	edited := schedWF("w", "0 0 1 1 *") // yearly — definition changed
	d.reset(map[string]*models.Workflow{"w": edited}, now)
	var fired int
	if n := d.tick(now, func(*models.Workflow, string) { fired++ }); n != 0 || fired != 0 {
		t.Fatalf("edited definition fired %d time(s) for an old due period, want 0", fired)
	}
	if !d.byWF["w"].next.After(now) {
		t.Fatalf("rebased next %v must be in the future", d.byWF["w"].next)
	}
}

func TestResetDropsVanishedAndUnscheduledWorkflows(t *testing.T) {
	d := NewScheduleDispatcher()
	d.reset(map[string]*models.Workflow{
		"a": schedWF("a", "* * * * *"),
		"b": schedWF("b", "* * * * *"),
	}, time.Now())
	if len(d.byWF) != 2 {
		t.Fatalf("tracked %d, want 2", len(d.byWF))
	}
	// b removed from the registry, a lost its schedule, c is manual-only.
	d.reset(map[string]*models.Workflow{
		"a": &models.Workflow{Name: "a", On: &models.TriggerConfig{Manual: &models.ManualTrigger{}}},
		"c": &models.Workflow{Name: "c"},
	}, time.Now())
	if len(d.byWF) != 0 {
		t.Fatalf("still tracking %v after reset, want none", d.byWF)
	}
}
