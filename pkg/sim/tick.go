package sim

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/quorum"
)

// pruneEpsilon is the strength below which a faded signal is discarded.
const pruneEpsilon = 0.01

const signalKind = "net.anomaly"

// observation is one agent's local view of a neighbour during a tick.
type observation struct {
	observer, subject pheromone.NodeID
	score             float64
}

type pair [2]pheromone.NodeID

// step advances the world by one tick.
func (w *world) step(tick int) (TickStats, error) {
	now := epoch.Add(time.Duration(tick) * w.cfg.TickInterval)
	if tick > 0 {
		w.spread()
	}
	obs := w.observe()
	if err := w.deposit(obs, now); err != nil {
		return TickStats{}, err
	}
	w.forge(now)
	votes := w.vote(obs, now)
	w.respond(votes)
	w.learn(votes)
	w.field.Prune(now, pruneEpsilon)
	return w.stats(tick), nil
}

// spread lets the intruder move laterally from every active foothold.
// Containment halves the chance; isolation stops it completely.
func (w *world) spread() {
	var newly []*agent
	for _, a := range w.agents {
		if !a.compromised || a.isolated {
			continue
		}
		p := w.cfg.SpreadRate
		if a.level == quorum.LevelContain {
			p /= 2
		}
		for _, n := range w.grid.Neighbors(a.id) {
			if t := w.byID[n]; !t.compromised && !t.isolated && w.rng.Float64() < p {
				newly = append(newly, t)
			}
		}
	}
	for _, t := range newly {
		t.compromised = true
	}
}

func (w *world) observe() []observation {
	var out []observation
	for _, a := range w.agents {
		if a.silent() {
			continue
		}
		for _, n := range w.grid.Neighbors(a.id) {
			if s := w.sense(a, w.byID[n]); s > 0 {
				out = append(out, observation{observer: a.id, subject: n, score: s})
			}
		}
	}
	return out
}

// sense is an agent's local detector reading about a neighbour.
func (w *world) sense(observer, subject *agent) float64 {
	if observer.malicious {
		if subject.id == observer.victim {
			return 1 // frame the victim
		}
		return 0 // and cover for the intruder
	}
	if subject.compromised && !subject.isolated && w.rng.Float64() < w.cfg.DetectRate {
		return 0.4 + 0.5*w.rng.Float64()
	}
	if w.rng.Float64() < w.cfg.NoiseRate {
		return 0.5 * w.rng.Float64()
	}
	return 0
}

func (w *world) deposit(obs []observation, now time.Time) error {
	for _, o := range obs {
		if o.score < w.cfg.DepositMin {
			continue
		}
		env, err := w.byID[o.observer].signer.Seal(pheromone.Signal{
			Origin: o.observer, Subject: o.subject, Kind: signalKind, Strength: o.score, At: now,
		})
		if err != nil {
			return fmt.Errorf("sealing signal from %s: %w", o.observer, err)
		}
		w.receive(env, now)
	}
	return nil
}

// forge has every malicious agent try to speak in an honest neighbour's name.
func (w *world) forge(now time.Time) {
	for _, a := range w.agents {
		if !a.malicious || a.silent() || a.victim == "" {
			continue
		}
		targets := w.honestNeighbors(a.id)
		if len(targets) == 0 {
			continue
		}
		fake := pheromone.Signal{
			Origin: targets[w.rng.IntN(len(targets))], Subject: a.victim,
			Kind: signalKind, Strength: 1, At: now,
		}
		w.receive(envelope.Envelope{Signal: fake, Signature: ed25519.Sign(a.key, []byte(fake.Origin))}, now)
	}
}

// receive is what a node does with an envelope arriving from the network.
func (w *world) receive(env envelope.Envelope, now time.Time) {
	sig, err := w.ring.Open(env)
	if err != nil {
		w.counters.ForgeriesRejected++
		return
	}
	if w.ledger.Weight(sig.Origin) < w.cfg.MinReputation {
		w.counters.Muted++
		return
	}
	if err := w.field.Deposit(sig, now); err != nil {
		w.counters.InvalidRejected++
		return
	}
	w.counters.Accepted++
}

func (w *world) vote(obs []observation, now time.Time) map[pheromone.NodeID][]quorum.Vote {
	local := make(map[pair]float64, len(obs))
	for _, o := range obs {
		local[pair{o.observer, o.subject}] = o.score
	}
	votes := make(map[pheromone.NodeID][]quorum.Vote)
	for _, suspect := range w.agents {
		if suspect.isolated {
			continue
		}
		fieldScore := pheromone.Saturate(w.field.Intensity(suspect.id, now, w.prox), w.cfg.FieldScale)
		for _, vid := range w.grid.Within(suspect.id, w.cfg.VoteRadius) {
			voter := w.byID[vid]
			if voter.silent() {
				continue
			}
			score := w.opinion(voter, suspect, local, fieldScore)
			votes[suspect.id] = append(votes[suspect.id], quorum.Vote{Voter: vid, Suspect: suspect.id, Score: score})
		}
	}
	return votes
}

// opinion blends first-hand evidence (direct neighbours only) with the
// shared field.
func (w *world) opinion(voter, suspect *agent, local map[pair]float64, fieldScore float64) float64 {
	if voter.malicious {
		if suspect.id == voter.victim {
			return 1
		}
		return 0
	}
	if w.grid.Hops(voter.id, suspect.id) == 1 {
		return 0.5*local[pair{voter.id, suspect.id}] + 0.5*fieldScore
	}
	return fieldScore
}

// respond applies the quorum decision to every reachable node. Decisions are
// computed from votes gathered before any of them is applied, so the order
// of this loop does not matter. Isolation is sticky; lesser levels are
// re-evaluated every tick.
func (w *world) respond(votes map[pheromone.NodeID][]quorum.Vote) {
	for _, a := range w.agents {
		if a.isolated {
			continue
		}
		a.level = w.cfg.Policy.Decide(a.id, votes[a.id], w.ledger).Level
		if a.level == quorum.LevelIsolate {
			a.isolated = true
		}
	}
}

// learn updates reputation from ground truth. A vote is judged wrong if it
// failed to flag a compromised node (score below ObserveAt) or pushed a
// healthy one toward containment (score at or above ContainAt).
func (w *world) learn(votes map[pheromone.NodeID][]quorum.Vote) {
	outcomes := make(map[pheromone.NodeID]bool)
	for _, suspect := range w.agents {
		for _, v := range votes[suspect.id] {
			correct := v.Score < w.cfg.Policy.ContainAt
			if suspect.compromised {
				correct = v.Score >= w.cfg.Policy.ObserveAt
			}
			prev, seen := outcomes[v.Voter]
			outcomes[v.Voter] = correct && (!seen || prev)
		}
	}
	w.ledger = w.ledger.Record(outcomes)
}
