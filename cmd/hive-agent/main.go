// Command hive-agent turns a Falco or Tetragon event stream into signed
// hive-immune pheromone signals.
//
//	hive-agent keygen -out node.key
//	hive-agent pubkey -key node.key
//	falco -o json_output=true | hive-agent run -node web-1 -key node.key -source falco
//
// Signed envelopes are written to stdout as JSON lines; statistics go to
// stderr when the input ends.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/keyfile"
	"github.com/hive-immune/hive-immune/pkg/node"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/sensor"
)

const usage = `usage: hive-agent <command> [flags]

commands:
  init-cluster  generate keys and peers.json for a new swarm
  serve         run a swarm node (gossip, decisions, optional Falco input)
  run           convert sensor events on stdin (or -in) into signed signals
  verify        check signed gateway credentials against a public key
  keygen        create a new node identity key
  pubkey        print a key's public half for distribution
  version       print the version

run "hive-agent <command> -h" for command flags`

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hive-agent:", err)
		os.Exit(1)
	}
}

func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "init-cluster":
		return initCluster(args[1:], stdout, stderr)
	case "serve":
		return serve(args[1:], stdout, stderr)
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "pubkey":
		return pubkey(args[1:], stdout, stderr)
	case "run":
		return run(args[1:], stdin, stdout, stderr)
	case "verify":
		return verify(args[1:], stdin, stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "hive-agent", version)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

func keygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "node.key", "where to write the private key (never overwritten)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := keyfile.Generate(rand.Reader)
	if err != nil {
		return err
	}
	if err := keyfile.Save(*out, key); err != nil {
		return err
	}
	fmt.Fprintln(stdout, keyfile.PublicHex(key))
	return nil
}

func pubkey(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("pubkey", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("key", "node.key", "private key file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := keyfile.Load(*path)
	if err != nil {
		return err
	}
	fmt.Fprintln(stdout, keyfile.PublicHex(key))
	return nil
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	nodeID := fs.String("node", "", "this node's identity (required)")
	keyPath := fs.String("key", "node.key", "private key file")
	source := fs.String("source", "", "sensor format: falco or tetragon (required)")
	in := fs.String("in", "-", "input file, or - for stdin")
	defaults := sensor.DefaultMapperConfig("")
	host := fs.String("host", "", "only accept events reported for this sensor host name")
	minStrength := fs.Float64("min", defaults.MinStrength, "drop events weaker than this, in (0, 1]")
	cooldown := fs.Duration("cooldown", defaults.Cooldown, "suppress repeats of the same kind for this long")
	maxAge := fs.Duration("max-age", defaults.MaxAge, "drop events older than this")
	policies := policyFlag{}
	fs.Var(policies, "policy", "tetragon policy mapping name=strength (repeatable)")
	push := fs.String("push", "", "send envelopes to this node URL (e.g. http://127.0.0.1:7946) instead of stdout")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *nodeID == "" {
		return errors.New("run: -node is required")
	}

	parser, err := newParser(*source, policies)
	if err != nil {
		return err
	}
	key, err := keyfile.Load(*keyPath)
	if err != nil {
		return err
	}
	signer, err := envelope.NewSigner(pheromone.NodeID(*nodeID), key)
	if err != nil {
		return err
	}
	cfg := sensor.DefaultMapperConfig(pheromone.NodeID(*nodeID))
	cfg.Host, cfg.MinStrength, cfg.Cooldown, cfg.MaxAge = *host, *minStrength, *cooldown, *maxAge
	mapper, err := sensor.NewMapper(cfg)
	if err != nil {
		return err
	}

	input, closeInput, err := openInput(*in, stdin)
	if err != nil {
		return err
	}
	defer closeInput()

	out := bufio.NewWriter(stdout)
	enc := json.NewEncoder(out)
	emit := func(e envelope.Envelope) error {
		if err := enc.Encode(e); err != nil {
			return err
		}
		// Flush per envelope so downstream consumers see signals immediately.
		return out.Flush()
	}
	if *push != "" {
		emit = pusher(strings.TrimRight(*push, "/")+node.EnvelopesPath, stderr)
	}
	p := sensor.Pipeline{Parser: parser, Mapper: mapper, Signer: signer, Now: time.Now, Emit: emit}
	st, err := p.Run(context.Background(), input)
	fmt.Fprintf(stderr, "hive-agent: lines=%d emitted=%d skipped=%d throttled=%d rejected=%d malformed=%d\n",
		st.Lines, st.Emitted, st.Skipped, st.Throttled, st.Rejected, st.Malformed)
	return err
}

// pusher posts each envelope to a node. Failures are reported but do not
// stop the agent, so a restarting node does not kill the sensor pipe.
func pusher(url string, stderr io.Writer) func(envelope.Envelope) error {
	client := &http.Client{Timeout: 5 * time.Second}
	return func(e envelope.Envelope) error {
		body, err := json.Marshal([]envelope.Envelope{e})
		if err != nil {
			return err
		}
		resp, err := client.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			fmt.Fprintln(stderr, "hive-agent: push failed:", err)
			return nil
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			fmt.Fprintln(stderr, "hive-agent: push rejected:", resp.Status)
		}
		return nil
	}
}

func newParser(source string, policies policyFlag) (sensor.Parser, error) {
	switch source {
	case "falco":
		if len(policies) > 0 {
			return nil, errors.New("run: -policy only applies to -source tetragon")
		}
		return sensor.Falco{}, nil
	case "tetragon":
		return sensor.NewTetragon(policies)
	}
	return nil, fmt.Errorf("run: -source must be falco or tetragon, got %q", source)
}

func openInput(path string, stdin io.Reader) (io.Reader, func(), error) {
	if path == "-" {
		return stdin, func() {}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	return f, func() { _ = f.Close() }, nil
}

// policyFlag collects repeated -policy name=strength flags.
type policyFlag map[string]float64

func (p policyFlag) String() string {
	parts := make([]string, 0, len(p))
	for name, s := range p {
		parts = append(parts, name+"="+strconv.FormatFloat(s, 'g', -1, 64))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func (p policyFlag) Set(v string) error {
	name, raw, ok := strings.Cut(v, "=")
	if !ok || name == "" {
		return fmt.Errorf("want name=strength, got %q", v)
	}
	s, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fmt.Errorf("bad strength in %q: %w", v, err)
	}
	p[name] = s
	return nil
}
