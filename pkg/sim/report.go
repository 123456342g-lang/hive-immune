package sim

import (
	"fmt"
	"strings"
	"time"

	"github.com/123456342g-lang/hive-immune/pkg/quorum"
)

// Legend explains the glyphs used in rendered frames.
const Legend = "X intruder  # isolated intruder  ! falsely isolated  m malicious agent  + contained  o observed  . healthy"

// TickStats summarises the network after one tick.
type TickStats struct {
	Tick          int
	Compromised   int // every node the intruder has ever owned
	Active        int // compromised and still connected
	Isolated      int
	FalseIsolated int // healthy nodes the swarm wrongly cut off
	Contained     int // nodes under partial containment
}

// Counters tracks what happened to signals on the wire.
type Counters struct {
	Accepted          int // verified and added to the field
	ForgeriesRejected int // failed signature verification
	Muted             int // valid, but the origin's reputation is too low
	InvalidRejected   int // valid signature but malformed signal
}

// Frame is a rendered snapshot of the network.
type Frame struct {
	Tick int
	Map  string
}

// Result is the outcome of a run.
type Result struct {
	Config         Config
	Ticks          []TickStats
	Frames         []Frame
	Counters       Counters
	FirstDetection int // first tick the swarm contained or isolated an intruder; -1 if never
	ContainedAt    int // first tick with no active intruder left; -1 if never
	PeakActive     int
	Malicious      int
	LiarTrust      float64 // mean final reputation of malicious agents
	HonestTrust    float64 // mean final reputation of honest agents
}

// Final returns the last tick's stats.
func (r Result) Final() TickStats {
	if len(r.Ticks) == 0 {
		return TickStats{}
	}
	return r.Ticks[len(r.Ticks)-1]
}

// Summary renders a human-readable report.
func (r Result) Summary() string {
	f := r.Final()
	var b strings.Builder
	fmt.Fprintf(&b, "network           %dx%d nodes, %d malicious agents (%.0f%%)\n",
		r.Config.Width, r.Config.Height, r.Malicious, r.Config.MaliciousRatio*100)
	fmt.Fprintf(&b, "first detection   %s\n", tickOrNever(r.FirstDetection, r.Config))
	fmt.Fprintf(&b, "fully contained   %s\n", tickOrNever(r.ContainedAt, r.Config))
	fmt.Fprintf(&b, "peak active       %d nodes\n", r.PeakActive)
	fmt.Fprintf(&b, "total compromised %d nodes (%.1f%% of network)\n",
		f.Compromised, 100*float64(f.Compromised)/float64(r.Config.Width*r.Config.Height))
	fmt.Fprintf(&b, "false isolations  %d\n", f.FalseIsolated)
	fmt.Fprintf(&b, "signals           %d accepted, %d forgeries rejected, %d muted (low reputation)\n",
		r.Counters.Accepted, r.Counters.ForgeriesRejected, r.Counters.Muted)
	fmt.Fprintf(&b, "reputation        honest %.2f vs malicious %.2f\n", r.HonestTrust, r.LiarTrust)
	return b.String()
}

func tickOrNever(tick int, cfg Config) string {
	if tick < 0 {
		return "never"
	}
	return fmt.Sprintf("tick %d (t+%s)", tick, cfg.TickInterval*time.Duration(tick))
}

func (w *world) stats(tick int) TickStats {
	s := TickStats{Tick: tick}
	for _, a := range w.agents {
		switch {
		case a.isolated && a.compromised:
			s.Compromised++
			s.Isolated++
		case a.isolated:
			s.Isolated++
			s.FalseIsolated++
		case a.compromised:
			s.Compromised++
			s.Active++
		}
		if !a.isolated && a.level == quorum.LevelContain {
			s.Contained++
		}
	}
	return s
}

func (w *world) detected() bool {
	for _, a := range w.agents {
		if a.compromised && (a.isolated || a.level >= quorum.LevelContain) {
			return true
		}
	}
	return false
}

func (w *world) trust() (honest, liars float64, malicious int) {
	var hSum float64
	honestCount := 0
	for _, a := range w.agents {
		if a.malicious {
			liars += w.ledger.Weight(a.id)
			malicious++
		} else {
			hSum += w.ledger.Weight(a.id)
			honestCount++
		}
	}
	if malicious > 0 {
		liars /= float64(malicious)
	}
	if honestCount > 0 {
		honest = hSum / float64(honestCount)
	}
	return honest, liars, malicious
}

func (w *world) render() string {
	var b strings.Builder
	for y := 0; y < w.grid.h; y++ {
		for x := 0; x < w.grid.w; x++ {
			b.WriteByte(glyph(w.byID[w.grid.ID(x, y)]))
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func glyph(a *agent) byte {
	switch {
	case a.isolated && a.compromised:
		return '#'
	case a.isolated:
		return '!'
	case a.compromised:
		return 'X'
	case a.malicious:
		return 'm'
	case a.level == quorum.LevelContain:
		return '+'
	case a.level == quorum.LevelObserve:
		return 'o'
	}
	return '.'
}
