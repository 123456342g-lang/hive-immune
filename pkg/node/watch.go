package node

import (
	"context"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/pheromone"
	"github.com/123456342g-lang/hive-immune/pkg/quorum"
	"github.com/123456342g-lang/hive-immune/pkg/swarm"
)

// Change is a transition of one member's response level.
type Change struct {
	Time   time.Time        `json:"time"`
	Node   pheromone.NodeID `json:"node"`
	From   quorum.Level     `json:"from"`
	To     quorum.Level     `json:"to"`
	Status swarm.Status     `json:"status"`
}

// Watch evaluates the swarm every interval until ctx is cancelled and calls
// onChange for every level transition. It also prunes expired state.
func (n *Node) Watch(ctx context.Context, interval time.Duration, onChange func(Change)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	prev := make(map[pheromone.NodeID]quorum.Level)
	for {
		for _, c := range n.changes(prev) {
			onChange(c)
		}
		n.Prune()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// changes evaluates once and returns transitions relative to prev, which it
// updates to the new levels.
func (n *Node) changes(prev map[pheromone.NodeID]quorum.Level) []Change {
	now := n.cfg.Now().UTC()
	var out []Change
	for _, st := range n.Evaluate() {
		if old := prev[st.Node]; old != st.Level {
			out = append(out, Change{Time: now, Node: st.Node, From: old, To: st.Level, Status: st})
		}
		prev[st.Node] = st.Level
	}
	return out
}
