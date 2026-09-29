package sim

import "fmt"

// Run executes one simulation. The same Config always produces the same
// Result.
func Run(cfg Config) (Result, error) {
	if err := cfg.Validate(); err != nil {
		return Result{}, err
	}
	w, err := newWorld(cfg)
	if err != nil {
		return Result{}, fmt.Errorf("sim: building world: %w", err)
	}

	res := Result{Config: cfg, FirstDetection: -1, ContainedAt: -1}
	for tick := 0; tick < cfg.Ticks; tick++ {
		st, err := w.step(tick)
		if err != nil {
			return Result{}, fmt.Errorf("sim: tick %d: %w", tick, err)
		}
		res.Ticks = append(res.Ticks, st)
		res.PeakActive = max(res.PeakActive, st.Active)
		if res.FirstDetection < 0 && w.detected() {
			res.FirstDetection = tick
		}
		if res.ContainedAt < 0 && st.Active == 0 {
			res.ContainedAt = tick
		}
		if cfg.SnapshotEvery > 0 && (tick%cfg.SnapshotEvery == 0 || tick == cfg.Ticks-1) {
			res.Frames = append(res.Frames, Frame{Tick: tick, Map: w.render()})
		}
	}
	res.Counters = w.counters
	res.HonestTrust, res.LiarTrust, res.Malicious = w.trust()
	return res, nil
}
