package sim

import (
	"fmt"
	"math"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// maxSide bounds grid dimensions so a typo cannot allocate gigabytes.
const maxSide = 1000

// Grid is a rectangular network topology where each node talks to its four
// orthogonal neighbours. Distance is measured in hops (Manhattan distance).
type Grid struct {
	w, h  int
	ids   []pheromone.NodeID
	index map[pheromone.NodeID]int
}

// NewGrid builds a w×h grid.
func NewGrid(w, h int) (*Grid, error) {
	if w < 1 || h < 1 || w > maxSide || h > maxSide {
		return nil, fmt.Errorf("sim: grid must be between 1x1 and %dx%d, got %dx%d", maxSide, maxSide, w, h)
	}
	g := &Grid{w: w, h: h, ids: make([]pheromone.NodeID, 0, w*h), index: make(map[pheromone.NodeID]int, w*h)}
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			id := pheromone.NodeID(fmt.Sprintf("n-%d-%d", x, y))
			g.index[id] = len(g.ids)
			g.ids = append(g.ids, id)
		}
	}
	return g, nil
}

// Nodes returns every node in row-major order.
func (g *Grid) Nodes() []pheromone.NodeID {
	return append([]pheromone.NodeID(nil), g.ids...)
}

// ID returns the node at (x, y).
func (g *Grid) ID(x, y int) pheromone.NodeID { return g.ids[y*g.w+x] }

// Center returns the node closest to the middle of the grid.
func (g *Grid) Center() pheromone.NodeID { return g.ID(g.w/2, g.h/2) }

func (g *Grid) coords(id pheromone.NodeID) (x, y int, ok bool) {
	i, ok := g.index[id]
	if !ok {
		return 0, 0, false
	}
	return i % g.w, i / g.w, true
}

// Hops returns the hop distance between two nodes, or -1 if either is unknown.
func (g *Grid) Hops(a, b pheromone.NodeID) int {
	ax, ay, ok1 := g.coords(a)
	bx, by, ok2 := g.coords(b)
	if !ok1 || !ok2 {
		return -1
	}
	return abs(ax-bx) + abs(ay-by)
}

// Neighbors returns the directly connected nodes of id.
func (g *Grid) Neighbors(id pheromone.NodeID) []pheromone.NodeID {
	return g.Within(id, 1)
}

// Within returns every node at most r hops from id, excluding id itself, in
// a deterministic order.
func (g *Grid) Within(id pheromone.NodeID, r int) []pheromone.NodeID {
	cx, cy, ok := g.coords(id)
	if !ok {
		return nil
	}
	var out []pheromone.NodeID
	for y := max(0, cy-r); y <= min(g.h-1, cy+r); y++ {
		for x := max(0, cx-r); x <= min(g.w-1, cx+r); x++ {
			d := abs(x-cx) + abs(y-cy)
			if d > 0 && d <= r {
				out = append(out, g.ID(x, y))
			}
		}
	}
	return out
}

// Proximity returns a pheromone.Proximity that decays by exp(-falloff) per
// hop and is zero beyond maxHops.
func (g *Grid) Proximity(falloff float64, maxHops int) pheromone.Proximity {
	return func(at, subject pheromone.NodeID) float64 {
		h := g.Hops(at, subject)
		if h < 0 || h > maxHops {
			return 0
		}
		return math.Exp(-falloff * float64(h))
	}
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
