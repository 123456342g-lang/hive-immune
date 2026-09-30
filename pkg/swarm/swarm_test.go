package swarm

import (
	"testing"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/cluster"
	"github.com/123456342g-lang/hive-immune/pkg/pheromone"
	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

var now = time.Date(2026, 9, 28, 12, 0, 0, 0, time.UTC)

func members(zone string, ids ...pheromone.NodeID) []cluster.Member {
	out := make([]cluster.Member, len(ids))
	for i, id := range ids {
		out[i] = cluster.Member{ID: id, Zone: zone}
	}
	return out
}

func fieldWith(t *testing.T, sigs ...pheromone.Signal) *pheromone.Field {
	t.Helper()
	f, err := pheromone.NewField(pheromone.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range sigs {
		s.At = now
		s.Kind = "test"
		if err := f.Deposit(s, now); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func byNode(sts []Status) map[pheromone.NodeID]Status {
	out := make(map[pheromone.NodeID]Status, len(sts))
	for _, s := range sts {
		out[s.Node] = s
	}
	return out
}

func TestQuietSwarmTakesNoAction(t *testing.T) {
	sts := Evaluate(fieldWith(t), members("z", "a", "b"), now, DefaultParams())

	for _, s := range sts {
		if s.Level != quorum.LevelNone || s.Reason != "" {
			t.Fatalf("unexpected %+v", s)
		}
	}
}

func TestSelfReportEscalatesOnlyThatNodeAndAlertsZone(t *testing.T) {
	f := fieldWith(t, pheromone.Signal{Origin: "b", Subject: "b", Strength: 0.6})

	got := byNode(Evaluate(f, append(members("prod", "a", "b", "c"), cluster.Member{ID: "d", Zone: "dev"}), now, DefaultParams()))

	if got["b"].Level != quorum.LevelContain || got["b"].Reason != "self-report" {
		t.Errorf("b: %+v", got["b"])
	}
	for _, id := range []pheromone.NodeID{"a", "c"} {
		if got[id].Level != quorum.LevelObserve || got[id].Reason != "zone alert: b" {
			t.Errorf("%s must be on zone alert: %+v", id, got[id])
		}
	}
	if got["d"].Level != quorum.LevelNone {
		t.Errorf("other zones must be unaffected: %+v", got["d"])
	}
}

func TestStrongSelfReportIsolates(t *testing.T) {
	f := fieldWith(t, pheromone.Signal{Origin: "a", Subject: "a", Strength: 1})

	if lvl := Evaluate(f, members("", "a"), now, DefaultParams())[0].Level; lvl != quorum.LevelIsolate {
		t.Fatalf("got %v", lvl)
	}
}

func TestTooFewPeersCannotContainAnotherNode(t *testing.T) {
	f := fieldWith(t,
		pheromone.Signal{Origin: "liar-1", Subject: "victim", Strength: 1},
		pheromone.Signal{Origin: "liar-2", Subject: "victim", Strength: 1},
	)

	st := byNode(Evaluate(f, members("", "victim", "liar-1", "liar-2"), now, DefaultParams()))["victim"]

	if st.Level != quorum.LevelObserve || st.Voters != 2 {
		t.Fatalf("two peers must not exceed observe: %+v", st)
	}
}

func TestPeerQuorumContains(t *testing.T) {
	var sigs []pheromone.Signal
	for _, o := range []pheromone.NodeID{"p1", "p2", "p3"} {
		sigs = append(sigs, pheromone.Signal{Origin: o, Subject: "x", Strength: 0.6})
	}

	st := byNode(Evaluate(fieldWith(t, sigs...), members("", "x", "p1", "p2", "p3"), now, DefaultParams()))["x"]

	if st.Level != quorum.LevelContain || st.Voters != 3 || st.Reason != "peer quorum (3 voters)" {
		t.Fatalf("got %+v", st)
	}
}

func TestResultsAreSorted(t *testing.T) {
	sts := Evaluate(fieldWith(t), members("", "c", "a", "b"), now, DefaultParams())

	if sts[0].Node != "a" || sts[1].Node != "b" || sts[2].Node != "c" {
		t.Fatalf("got %v", sts)
	}
}

func TestParamsValidate(t *testing.T) {
	if err := DefaultParams().Validate(); err != nil {
		t.Fatal(err)
	}
	p := DefaultParams()
	p.Scale = 0
	if p.Validate() == nil {
		t.Error("zero scale must fail")
	}
	p = DefaultParams()
	p.Policy.MinVoters = 0
	if p.Validate() == nil {
		t.Error("bad policy must fail")
	}
}
