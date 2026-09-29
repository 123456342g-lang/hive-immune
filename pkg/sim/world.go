package sim

import (
	"crypto/ed25519"
	"encoding/binary"
	"math/rand/v2"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/quorum"
)

// epoch anchors simulated time so runs are reproducible.
var epoch = time.Unix(1_700_000_000, 0).UTC()

// initialTrust is the reputation every agent starts with.
const initialTrust = 0.5

type agent struct {
	id          pheromone.NodeID
	key         ed25519.PrivateKey
	signer      *envelope.Signer
	malicious   bool             // Byzantine: lies in its reports and votes
	victim      pheromone.NodeID // healthy node a malicious agent tries to frame
	compromised bool             // host owned by the intruder
	isolated    bool             // cut off by the swarm
	level       quorum.Level     // latest collective response
}

// silent reports whether the agent no longer senses or votes: its host is
// either cut off or owned by the intruder (who kills the sensor).
func (a *agent) silent() bool { return a.isolated || a.compromised }

type world struct {
	cfg      Config
	grid     *Grid
	agents   []*agent
	byID     map[pheromone.NodeID]*agent
	field    *pheromone.Field
	ring     *envelope.Keyring
	ledger   quorum.Ledger
	prox     pheromone.Proximity
	rng      *rand.Rand
	counters Counters
}

func newWorld(cfg Config) (*world, error) {
	grid, err := NewGrid(cfg.Width, cfg.Height)
	if err != nil {
		return nil, err
	}
	field, err := pheromone.NewField(cfg.Field)
	if err != nil {
		return nil, err
	}
	ledger, err := quorum.NewLedger(initialTrust, cfg.LearningRate)
	if err != nil {
		return nil, err
	}
	w := &world{
		cfg: cfg, grid: grid, field: field, ledger: ledger,
		byID: make(map[pheromone.NodeID]*agent, cfg.Width*cfg.Height),
		prox: grid.Proximity(cfg.Falloff, cfg.VoteRadius),
		rng:  rand.New(rand.NewPCG(cfg.Seed, cfg.Seed^0x9e3779b97f4a7c15)),
	}
	if err := w.spawnAgents(); err != nil {
		return nil, err
	}
	w.recruitTraitors()
	w.byID[grid.Center()].compromised = true
	return w, nil
}

func (w *world) spawnAgents() error {
	pubs := make(map[pheromone.NodeID]ed25519.PublicKey, len(w.grid.ids))
	for _, id := range w.grid.Nodes() {
		key := ed25519.NewKeyFromSeed(w.seedBytes())
		signer, err := envelope.NewSigner(id, key)
		if err != nil {
			return err
		}
		a := &agent{id: id, key: key, signer: signer}
		w.agents = append(w.agents, a)
		w.byID[id] = a
		pubs[id] = key.Public().(ed25519.PublicKey)
	}
	ring, err := envelope.NewKeyring(pubs)
	if err != nil {
		return err
	}
	w.ring = ring
	return nil
}

// seedBytes derives key material from the run's RNG. This keeps simulations
// reproducible and must never be used for real keys.
func (w *world) seedBytes() []byte {
	b := make([]byte, 0, ed25519.SeedSize)
	for len(b) < ed25519.SeedSize {
		b = binary.LittleEndian.AppendUint64(b, w.rng.Uint64())
	}
	return b
}

func (w *world) recruitTraitors() {
	start := w.grid.Center()
	want := int(float64(len(w.agents)) * w.cfg.MaliciousRatio)
	for _, i := range w.rng.Perm(len(w.agents)) {
		if want == 0 {
			break
		}
		if a := w.agents[i]; a.id != start {
			a.malicious = true
			want--
		}
	}
	for _, a := range w.agents {
		if !a.malicious {
			continue
		}
		if targets := w.honestNeighbors(a.id); len(targets) > 0 {
			a.victim = targets[w.rng.IntN(len(targets))]
		}
	}
}

func (w *world) honestNeighbors(id pheromone.NodeID) []pheromone.NodeID {
	var out []pheromone.NodeID
	for _, n := range w.grid.Neighbors(id) {
		if !w.byID[n].malicious {
			out = append(out, n)
		}
	}
	return out
}
