package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/hive-immune/hive-immune/pkg/cluster"
	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/keyfile"
	"github.com/hive-immune/hive-immune/pkg/node"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/sensor"
)

const shutdownGrace = 5 * time.Second

func serve(args []string, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveContext(ctx, args, stdout, stderr, nil)
}

type serveOptions struct {
	node, keyPath, clusterPath, listen, sensorListen, webhook, logLevel string
	interval, halfLife, maxAge, cooldown                                time.Duration
	scale, minStrength                                                  float64
	minVoters                                                           int
}

func parseServe(args []string, stderr io.Writer) (serveOptions, error) {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var o serveOptions
	fs.StringVar(&o.node, "node", "", "this node's id in the cluster file (required)")
	fs.StringVar(&o.keyPath, "key", "node.key", "private key file")
	fs.StringVar(&o.clusterPath, "cluster", "peers.json", "cluster membership file")
	fs.StringVar(&o.listen, "listen", ":7946", "gossip and status listen address")
	fs.StringVar(&o.sensorListen, "sensor-listen", "", "local address for Falco http_output, e.g. 127.0.0.1:7947 (empty disables)")
	fs.StringVar(&o.webhook, "webhook", "", "POST every level change as JSON to this URL")
	fs.StringVar(&o.logLevel, "log-level", "info", "debug, info, warn or error")
	fs.DurationVar(&o.interval, "interval", 2*time.Second, "how often to evaluate the swarm")
	fs.DurationVar(&o.halfLife, "half-life", 2*time.Minute, "time for evidence to lose half its weight")
	fs.DurationVar(&o.maxAge, "max-age", 10*time.Minute, "reject signals older than this (replay window)")
	fs.Float64Var(&o.scale, "field-scale", 1, "evidence that yields a ~63% score; higher needs more evidence")
	fs.IntVar(&o.minVoters, "min-voters", 3, "distinct peers needed to contain another node")
	fs.Float64Var(&o.minStrength, "min", 0.5, "sensor: drop events weaker than this")
	fs.DurationVar(&o.cooldown, "cooldown", 10*time.Second, "sensor: suppress repeats of the same kind")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.node == "" {
		return o, errors.New("serve: -node is required")
	}
	if o.webhook != "" {
		if u, err := url.Parse(o.webhook); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return o, fmt.Errorf("serve: -webhook %q must be an http(s) URL", o.webhook)
		}
	}
	if o.interval <= 0 {
		return o, errors.New("serve: -interval must be positive")
	}
	return o, nil
}

// serveContext runs a node until ctx is cancelled. onReady, if set, receives
// the bound gossip and sensor addresses (tests listen on port 0).
func serveContext(ctx context.Context, args []string, stdout, stderr io.Writer, onReady func(gossip, sensor string)) error {
	o, err := parseServe(args, stderr)
	if err != nil {
		return err
	}
	var level slog.Level
	if err := level.UnmarshalText([]byte(o.logLevel)); err != nil {
		return fmt.Errorf("serve: -log-level: %w", err)
	}
	logger := slog.New(slog.NewTextHandler(stderr, &slog.HandlerOptions{Level: level}))

	n, signer, err := buildNode(o, logger)
	if err != nil {
		return err
	}
	gossipLn, err := net.Listen("tcp", o.listen)
	if err != nil {
		return fmt.Errorf("serve: %w", err)
	}
	servers := []*http.Server{newServer(n.Handler())}
	listeners := []net.Listener{gossipLn}
	sensorAddr := ""
	if o.sensorListen != "" {
		cfg := sensor.DefaultMapperConfig(pheromone.NodeID(o.node))
		cfg.MinStrength, cfg.Cooldown = o.minStrength, o.cooldown
		mapper, err := sensor.NewMapper(cfg)
		if err != nil {
			gossipLn.Close()
			return err
		}
		sensorLn, err := net.Listen("tcp", o.sensorListen)
		if err != nil {
			gossipLn.Close()
			return fmt.Errorf("serve: %w", err)
		}
		sensorAddr = sensorLn.Addr().String()
		servers = append(servers, newServer(n.SensorHandler(sensor.Falco{}, mapper, signer)))
		listeners = append(listeners, sensorLn)
	}

	for i, srv := range servers {
		go func(srv *http.Server, ln net.Listener) {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				logger.Error("listener failed", "addr", ln.Addr().String(), "err", err)
			}
		}(srv, listeners[i])
	}
	logger.Info("hive-agent serving", "version", version, "node", o.node,
		"gossip", gossipLn.Addr().String(), "sensor", sensorAddr, "peers", len(n.Peers()))
	if onReady != nil {
		onReady(gossipLn.Addr().String(), sensorAddr)
	}

	go n.Run(ctx)
	report := newReporter(stdout, o.webhook, logger)
	n.Watch(ctx, o.interval, report.change)
	report.wait()

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, srv := range servers {
		_ = srv.Shutdown(shutdownCtx)
	}
	logger.Info("hive-agent stopped")
	return nil
}

func buildNode(o serveOptions, logger *slog.Logger) (*node.Node, *envelope.Signer, error) {
	c, err := cluster.Load(o.clusterPath)
	if err != nil {
		return nil, nil, err
	}
	self, ok := c.Member(pheromone.NodeID(o.node))
	if !ok {
		return nil, nil, fmt.Errorf("serve: node %q is not in %s", o.node, o.clusterPath)
	}
	key, err := keyfile.Load(o.keyPath)
	if err != nil {
		return nil, nil, err
	}
	if keyfile.PublicHex(key) != self.PublicKey {
		return nil, nil, fmt.Errorf("serve: %s does not match the public key listed for %q in %s", o.keyPath, o.node, o.clusterPath)
	}
	signer, err := envelope.NewSigner(self.ID, key)
	if err != nil {
		return nil, nil, err
	}
	cfg := node.DefaultConfig(self.ID, c)
	cfg.Field.HalfLife, cfg.MaxAge, cfg.Logger = o.halfLife, o.maxAge, logger
	cfg.Params.Scale, cfg.Params.Policy.MinVoters = o.scale, o.minVoters
	n, err := node.New(cfg)
	if err != nil {
		return nil, nil, err
	}
	return n, signer, nil
}

func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second,
	}
}

// reporter writes level changes to stdout and, optionally, a webhook.
type reporter struct {
	mu      sync.Mutex
	enc     *json.Encoder
	webhook string
	client  *http.Client
	logger  *slog.Logger
	pending sync.WaitGroup
}

func newReporter(w io.Writer, webhook string, logger *slog.Logger) *reporter {
	return &reporter{enc: json.NewEncoder(w), webhook: webhook, client: &http.Client{Timeout: 5 * time.Second}, logger: logger}
}

func (r *reporter) change(c node.Change) {
	r.mu.Lock()
	err := r.enc.Encode(c)
	r.mu.Unlock()
	if err != nil {
		r.logger.Error("writing decision failed", "err", err)
	}
	if r.webhook == "" {
		return
	}
	body, err := json.Marshal(c)
	if err != nil {
		r.logger.Error("encoding webhook body failed", "err", err)
		return
	}
	r.pending.Add(1)
	go func() {
		defer r.pending.Done()
		resp, err := r.client.Post(r.webhook, "application/json", bytes.NewReader(body))
		if err != nil {
			r.logger.Warn("webhook failed", "err", err)
			return
		}
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			r.logger.Warn("webhook rejected decision", "status", resp.Status)
		}
	}()
}

func (r *reporter) wait() { r.pending.Wait() }
