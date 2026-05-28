package dag

import (
	"fmt"
	"sort"

	"github.com/laoshanxi/app-mesh/src/workflow/internal/models"
)

// TopoSort returns jobs grouped into parallel execution layers.
// Each layer contains jobs whose dependencies are satisfied by previous layers.
func TopoSort(jobs map[string]*models.Job) ([][]string, error) {
	inDegree := make(map[string]int, len(jobs))
	dependents := make(map[string][]string, len(jobs))
	for name := range jobs {
		inDegree[name] = 0
	}
	for name, job := range jobs {
		for _, dep := range job.Needs {
			if _, ok := jobs[dep]; !ok {
				return nil, fmt.Errorf("job %q depends on unknown job %q", name, dep)
			}
			inDegree[name]++
			dependents[dep] = append(dependents[dep], name)
		}
	}

	var queue []string
	for name, deg := range inDegree {
		if deg == 0 {
			queue = append(queue, name)
		}
	}

	var layers [][]string
	visited := make(map[string]bool, len(jobs))

	for len(queue) > 0 {
		// Sort so layer ordering (and thus logs) is deterministic across runs;
		// Go map iteration would otherwise randomize it.
		sort.Strings(queue)
		layer := queue
		queue = nil
		layers = append(layers, layer)
		for _, name := range layer {
			visited[name] = true
			for _, dep := range dependents[name] {
				inDegree[dep]--
				if inDegree[dep] == 0 {
					queue = append(queue, dep)
				}
			}
		}
	}

	if len(visited) != len(jobs) {
		unvisited := make([]string, 0)
		for name := range jobs {
			if !visited[name] {
				unvisited = append(unvisited, name)
			}
		}
		return nil, fmt.Errorf("cyclic dependency detected among jobs: %v", unvisited)
	}

	return layers, nil
}
