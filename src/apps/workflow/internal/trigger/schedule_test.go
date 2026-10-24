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
	after := time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC)
	wf := schedWF("w", "0 0 * * *", "bogus", "* * * * *")
	next, expr := nextFire(wf, after)
	if expr != "* * * * *" {
		t.Fatalf("earliest entry = %q, want the every-minute one", expr)
	}
	if want := time.Date(2026, 1, 1, 12, 1, 0, 0, time.UTC); !next.Equal(want) {
		t.Fatalf("next = %v, want %v", next, want)
	}
	if n, _ := nextFire(&models.Workflow{Name: "none"}, after); !n.IsZero() {
		t.Fatalf("workflow without schedules must have no next fire, got %v", n)
	}
}

// The full dispatch cadence: reset+tick every 30s. A due fire must survive the
// resets (this is the regression for the first implementation, whose reset
// recomputed `next` from now every tick and never fired), a late tick fires once
// (missed periods are forgone, not caught up), and the cadence then resumes.
func TestTickFiresDueOnceAndResumesCadence(t *testing.T) {
	d := NewScheduleDispatcher()
	wf := schedWF("w", "* * * * *")
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	d.reset(map[string]*models.Workflow{"w": wf}, base)

	var fired []string
	fire := func(w *models.Workflow, source string) { fired = append(fired, w.Name+"|"+source) }

	// 12:00:30 — the 12:01 boundary is not due yet.
	if n := d.tick(base.Add(30*time.Second), fire); n != 0 {
		t.Fatalf("early tick fired %d, want 0", n)
	}
	// 12:06 — five minutes of periods were missed while the engine was down; the
	// fire happens once and the missed periods are forgone.
	late := base.Add(6 * time.Minute)
	for i := 0; i < 2; i++ { // reset between ticks, like dispatchSchedules
		d.reset(map[string]*models.Workflow{"w": wf}, late)
		if n := d.tick(late, fire); i == 0 && n != 1 {
			t.Fatalf("tick %d: fired %d, want exactly 1", i, n)
		} else if i > 0 && n != 0 {
			t.Fatalf("tick %d: fired %d again, want 0", i, n)
		}
	}
	if fired[0] != "w|schedule:* * * * *" {
		t.Fatalf("source = %q", fired[0])
	}
	// The cadence resumes: the next boundary after `late` fires, earlier ones don't.
	next, _ := nextFire(wf, late)
	if n := d.tick(next.Add(-time.Second), fire); n != 0 {
		t.Fatalf("fired %d before the resumed boundary, want 0", n)
	}
	if n := d.tick(next.Add(time.Second), fire); n != 1 {
		t.Fatalf("fired %d at the resumed boundary, want 1", n)
	}
}

// Editing a workflow's cron naturally re-bases through `last`: the next fire comes
// from the NEW definition after the last accounted instant — at most one fire for
// the elapsed window, never a stale catch-up burst.
func TestResetRebasesOnDefinitionChange(t *testing.T) {
	d := NewScheduleDispatcher()
	old := schedWF("w", "* * * * *")
	base := time.Date(2026, 1, 1, 12, 0, 30, 0, time.UTC)
	d.reset(map[string]*models.Workflow{"w": old}, base)
	now := base.Add(2 * time.Minute) // periods were missed under the old definition

	edited := schedWF("w", "0 0 1 1 *") // yearly — definition changed
	d.reset(map[string]*models.Workflow{"w": edited}, now)
	var fired int
	if n := d.tick(now.Add(time.Hour), func(*models.Workflow, string) { fired++ }); n != 0 || fired != 0 {
		t.Fatalf("edited definition fired %d time(s), want 0 before its first boundary", fired)
	}

	// Edit the other way — to an every-minute schedule: the elapsed window yields
	// exactly one fire, then the cadence resumes.
	frequent := schedWF("w", "* * * * *")
	d.reset(map[string]*models.Workflow{"w": frequent}, now)
	if n := d.tick(now.Add(90*time.Second), func(*models.Workflow, string) { fired++ }); n != 1 || fired != 1 {
		t.Fatalf("frequent definition fired %d, want exactly 1 for the elapsed window", fired)
	}
	if n := d.tick(now.Add(91*time.Second), func(*models.Workflow, string) { fired++ }); n != 0 {
		t.Fatalf("fired %d again before the next boundary, want 0", n)
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
