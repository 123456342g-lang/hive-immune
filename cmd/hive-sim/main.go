// Command hive-sim runs a local hive-immune swarm simulation and prints how
// the swarm detects and contains a spreading intruder while some of its own
// agents lie.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/hive-immune/hive-immune/pkg/sim"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "hive-sim:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	cfg := sim.DefaultConfig()
	fs := flag.NewFlagSet("hive-sim", flag.ContinueOnError)
	fs.SetOutput(out)
	fs.IntVar(&cfg.Width, "width", cfg.Width, "grid width (nodes)")
	fs.IntVar(&cfg.Height, "height", cfg.Height, "grid height (nodes)")
	fs.IntVar(&cfg.Ticks, "ticks", cfg.Ticks, "number of ticks to simulate")
	fs.Uint64Var(&cfg.Seed, "seed", cfg.Seed, "random seed (same seed, same run)")
	fs.Float64Var(&cfg.MaliciousRatio, "malicious", cfg.MaliciousRatio, "fraction of lying agents, in [0, 1)")
	fs.Float64Var(&cfg.NoiseRate, "noise", cfg.NoiseRate, "false-alarm rate per neighbour per tick")
	fs.Float64Var(&cfg.SpreadRate, "spread", cfg.SpreadRate, "intruder lateral-movement rate per tick")
	fs.Float64Var(&cfg.DetectRate, "detect", cfg.DetectRate, "chance per tick a neighbour notices the intruder")
	fs.Float64Var(&cfg.FieldScale, "field-scale", cfg.FieldScale, "field intensity for ~63% suspicion (higher = needs more independent witnesses)")
	fs.IntVar(&cfg.VoteRadius, "vote-radius", cfg.VoteRadius, "hops within which agents vote on a suspect")
	fs.IntVar(&cfg.SnapshotEvery, "every", cfg.SnapshotEvery, "print a map every N ticks (0 = summary only)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	res, err := sim.Run(cfg)
	if err != nil {
		return err
	}
	for _, f := range res.Frames {
		st := res.Ticks[f.Tick]
		fmt.Fprintf(out, "tick %-3d  active=%-3d isolated=%-3d contained=%-3d false=%d\n%s\n",
			f.Tick, st.Active, st.Isolated, st.Contained, st.FalseIsolated, f.Map)
	}
	if len(res.Frames) > 0 {
		fmt.Fprintf(out, "legend: %s\n\n", sim.Legend)
	}
	fmt.Fprint(out, res.Summary())
	return nil
}
