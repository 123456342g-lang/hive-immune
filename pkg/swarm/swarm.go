// Package swarm turns the shared pheromone field into a response level for
// every member of the swarm.
//
// Evidence about a node comes from two places, treated differently:
//
//   - Self-reports (the node's own sensors): a node may escalate itself all
//     the way to isolation on its own evidence. This is safe because a lying
//     node can only harm itself, and a compromised node that suppresses its
//     own reports gains nothing either.
//   - Peer reports: evidence from other nodes goes through the reputation-
//     weighted quorum, so fewer than Policy.MinVoters peers can never push
//     another node past observation. MinVoters is therefore the collusion
//     threshold of the swarm.
//
// Finally, when any member of a zone is contained or isolated, every other
// member of that zone is raised to at least observation: the swarm goes on
// alert around an incident.
package swarm

import (
	"fmt"
	"slices"
	"time"

	"github.com/hive-immune/hive-immune/pkg/cluster"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/quorum"
)

// Params tunes evaluation.
type Params struct {
	Policy quorum.Policy
	// Scale converts accumulated evidence into a [0, 1) score: a single
	// origin's evidence of Scale gives a score of ~0.63.
	Scale float64
	// Weigher supplies voter reputation. Nil means every voter counts fully.
	Weigher quorum.Weigher
}

// DefaultParams returns the default policy with Scale 1: one Falco Warning
// (0.6) contains a node, sustained Warnings or one Critical isolate it.
func DefaultParams() Params {
	return Params{Policy: quorum.DefaultPolicy(), Scale: 1}
}

// Validate reports whether the params are usable.
func (p Params) Validate() error {
	if err := p.Policy.Validate(); err != nil {
		return err
	}
	if !(p.Scale > 0) {
		return fmt.Errorf("swarm: Scale must be positive")
	}
	return nil
}

// Status is the swarm's view of one node.
type Status struct {
	Node      pheromone.NodeID `json:"node"`
	Level     quorum.Level     `json:"level"`
	SelfScore float64          `json:"self_score"`
	PeerScore float64          `json:"peer_score"`
	Voters    int              `json:"voters"`
	Reason    string           `json:"reason,omitempty"`
}

// Evaluate computes a Status for every member, sorted by node id.
func Evaluate(field *pheromone.Field, members []cluster.Member, now time.Time, p Params) []Status {
	w := p.Weigher
	if w == nil {
		w = quorum.Uniform{}
	}
	out := make([]Status, 0, len(members))
	for _, m := range members {
		out = append(out, evaluateOne(field.Contributions(m.ID, now), m.ID, p, w))
	}
	raiseZones(out, members)
	slices.SortFunc(out, func(a, b Status) int {
		switch {
		case a.Node < b.Node:
			return -1
		case a.Node > b.Node:
			return 1
		}
		return 0
	})
	return out
}

func evaluateOne(contrib map[pheromone.NodeID]float64, id pheromone.NodeID, p Params, w quorum.Weigher) Status {
	st := Status{Node: id, SelfScore: pheromone.Saturate(contrib[id], p.Scale)}
	var votes []quorum.Vote
	for origin, v := range contrib {
		if origin != id {
			votes = append(votes, quorum.Vote{Voter: origin, Suspect: id, Score: pheromone.Saturate(v, p.Scale)})
		}
	}
	d := p.Policy.Decide(id, votes, w)
	st.PeerScore, st.Voters = d.Score, d.Voters

	self := p.Policy.Classify(st.SelfScore)
	switch {
	case self == quorum.LevelNone && d.Level == quorum.LevelNone:
	case self >= d.Level:
		st.Level, st.Reason = self, "self-report"
	default:
		st.Level, st.Reason = d.Level, fmt.Sprintf("peer quorum (%d voters)", d.Voters)
	}
	return st
}

// raiseZones puts every zone with a contained or isolated member on alert.
// Statuses and members are in the same order.
func raiseZones(statuses []Status, members []cluster.Member) {
	incident := make(map[string]pheromone.NodeID)
	for i, st := range statuses {
		zone := members[i].Zone
		if zone == "" || st.Level < quorum.LevelContain {
			continue
		}
		if prev, ok := incident[zone]; !ok || st.Node < prev {
			incident[zone] = st.Node
		}
	}
	for i := range statuses {
		src, ok := incident[members[i].Zone]
		if ok && statuses[i].Level < quorum.LevelObserve {
			statuses[i].Level = quorum.LevelObserve
			statuses[i].Reason = "zone alert: " + string(src)
		}
	}
}
