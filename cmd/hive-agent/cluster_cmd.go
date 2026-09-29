package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/hive-immune/hive-immune/pkg/cluster"
	"github.com/hive-immune/hive-immune/pkg/keyfile"
)

// initCluster generates keys and a membership file for a new swarm. It is
// meant for demos and first deployments; in production, generate each key on
// its own node with keygen and collect only the public keys.
func initCluster(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init-cluster", flag.ContinueOnError)
	fs.SetOutput(stderr)
	nodes := fs.String("nodes", "", "comma-separated node ids (required)")
	addr := fs.String("addr", "http://{id}:7946", "gossip URL template; {id} is replaced by the node id")
	zone := fs.String("zone", "default", "zone for all nodes (empty for none)")
	out := fs.String("out", "cluster", "output directory")
	ifMissing := fs.Bool("if-missing", false, "succeed without changes if the directory is already initialised")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if strings.TrimSpace(*nodes) == "" {
		return errors.New("init-cluster: -nodes is required")
	}
	peersPath := filepath.Join(*out, "peers.json")
	if _, err := os.Stat(peersPath); err == nil {
		if *ifMissing {
			fmt.Fprintln(stdout, "cluster already initialised:", peersPath)
			return nil
		}
		return fmt.Errorf("init-cluster: %s already exists", peersPath)
	}

	c, keys, err := cluster.Generate(strings.Split(*nodes, ","), *addr, *zone, rand.Reader)
	if err != nil {
		return err
	}
	for _, m := range c.Members {
		// Ids become file names below; refuse anything that could escape -out.
		if id := string(m.ID); id != filepath.Base(id) || id == "." || id == ".." || strings.ContainsAny(id, `/\:`) {
			return fmt.Errorf("init-cluster: node id %q cannot be used as a file name", id)
		}
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		return fmt.Errorf("init-cluster: %w", err)
	}
	for _, m := range c.Members {
		if err := keyfile.Save(filepath.Join(*out, string(m.ID)+".key"), keys[m.ID]); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(peersPath, append(raw, '\n'), 0o644); err != nil {
		return fmt.Errorf("init-cluster: %w", err)
	}
	fmt.Fprintf(stdout, "initialised %d nodes in %s\n", len(c.Members), *out)
	return nil
}
