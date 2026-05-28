package dag

import (
	"strings"
	"testing"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

func job(name string, needs ...string) *models.Job {
	return &models.Job{Name: name, Needs: needs}
}

func setOf(ss []string) map[string]bool {
	m := make(map[string]bool, len(ss))
	for _, s := range ss {
		m[s] = true
	}
	return m
}

func TestSingleJob(t *testing.T) {
	layers, err := TopoSort(map[string]*models.Job{"a": job("a")})
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 1 || layers[0][0] != "a" {
		t.Errorf("unexpected: %v", layers)
	}
}

func TestLinearChain(t *testing.T) {
	jobs := map[string]*models.Job{
		"a": job("a"),
		"b": job("b", "a"),
		"c": job("c", "b"),
	}
	layers, err := TopoSort(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 3 {
		t.Fatalf("want 3 layers, got %d", len(layers))
	}
	if layers[0][0] != "a" || layers[1][0] != "b" || layers[2][0] != "c" {
		t.Errorf("unexpected order: %v", layers)
	}
}

func TestDiamond(t *testing.T) {
	jobs := map[string]*models.Job{
		"build":     job("build"),
		"test-unit": job("test-unit", "build"),
		"test-e2e":  job("test-e2e", "build"),
		"deploy":    job("deploy", "test-unit", "test-e2e"),
	}
	layers, err := TopoSort(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 3 {
		t.Fatalf("want 3 layers, got %d", len(layers))
	}
	if layers[0][0] != "build" {
		t.Errorf("layer 0: %v", layers[0])
	}
	s := setOf(layers[1])
	if !s["test-unit"] || !s["test-e2e"] {
		t.Errorf("layer 1: %v", layers[1])
	}
	if layers[2][0] != "deploy" {
		t.Errorf("layer 2: %v", layers[2])
	}
}

func TestAllIndependent(t *testing.T) {
	jobs := map[string]*models.Job{"a": job("a"), "b": job("b"), "c": job("c")}
	layers, err := TopoSort(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 1 {
		t.Fatalf("want 1 layer, got %d", len(layers))
	}
	if len(layers[0]) != 3 {
		t.Errorf("want 3 jobs, got %d", len(layers[0]))
	}
}

func TestCyclicRaises(t *testing.T) {
	jobs := map[string]*models.Job{
		"a": job("a", "b"),
		"b": job("b", "a"),
	}
	_, err := TopoSort(jobs)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "cyclic") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestSelfLoop(t *testing.T) {
	_, err := TopoSort(map[string]*models.Job{"a": job("a", "a")})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestUnknownDep(t *testing.T) {
	_, err := TopoSort(map[string]*models.Job{"a": job("a", "nope")})
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "unknown") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestWideFanOut(t *testing.T) {
	jobs := map[string]*models.Job{"root": job("root")}
	for i := range 10 {
		name := "leaf-" + strings.Repeat("x", i)
		jobs[name] = job(name, "root")
	}
	layers, err := TopoSort(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 2 {
		t.Fatalf("want 2 layers, got %d", len(layers))
	}
	if len(layers[1]) != 10 {
		t.Errorf("want 10 in layer 1, got %d", len(layers[1]))
	}
}

func TestDeepChain(t *testing.T) {
	names := []string{"a", "b", "c", "d", "e"}
	jobs := map[string]*models.Job{names[0]: job(names[0])}
	for i := 1; i < len(names); i++ {
		jobs[names[i]] = job(names[i], names[i-1])
	}
	layers, err := TopoSort(jobs)
	if err != nil {
		t.Fatal(err)
	}
	if len(layers) != 5 {
		t.Fatalf("want 5 layers, got %d", len(layers))
	}
}
