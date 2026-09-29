package gateway

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/hive-immune/hive-immune/pkg/capability"
	"github.com/hive-immune/hive-immune/pkg/credential"
	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// DenyStyle is how a refused call is reported to the MCP client.
type DenyStyle string

// The two denial shapes. ToolResult is the default: agent frameworks treat
// it as a failed tool and keep going, which keeps the false-positive cost
// of the gateway visible as ordinary retries instead of protocol errors.
const (
	// DenyToolResult answers with a successful JSON-RPC response whose
	// result carries isError: true.
	DenyToolResult DenyStyle = "tool-result"
	// DenyError answers with a JSON-RPC error (-32001).
	DenyError DenyStyle = "error"
)

// errCodeDenied is the JSON-RPC error code used by DenyError.
const errCodeDenied = -32001

// Approval is a call waiting for a human decision.
type Approval struct {
	Session     string    `json:"session"`
	Agent       string    `json:"agent"`
	CallID      string    `json:"call_id,omitempty"`
	Tool        string    `json:"tool"`
	Risk        Risk      `json:"risk"`
	ArgsDigest  string    `json:"args_digest"`
	Reason      string    `json:"reason"`
	RequestedAt time.Time `json:"requested_at"`
}

// Approver resolves approval requests. A nil Approver means approval is
// unavailable, which the decision engine turns into a deny: the gateway
// never silently upgrades "needs a human" into "allowed".
type Approver interface {
	Approve(ctx context.Context, a Approval) (bool, error)
}

// Config configures one gateway run.
type Config struct {
	// Command is the upstream MCP server to spawn, e.g.
	// []string{"npx", "-y", "@modelcontextprotocol/server-everything"}.
	Command []string
	// PolicyPath is tools.yaml. Empty puts the gateway in failure mode.
	PolicyPath string
	Agent      string
	SessionID  string
	AuditPath  string
	DenyStyle  DenyStyle
	AdminAddr  string
	Env        []string

	// Client-side transport. Nil means os.Stdin/os.Stdout.
	ClientIn  io.Reader
	ClientOut io.Writer
	// Stderr receives gateway logs and the upstream's stderr.
	Stderr io.Writer

	Logger     *slog.Logger
	Now        func() time.Time
	Approver   Approver
	OnDecision func(Record)
	// Capability, when set, is the biscuit token the session must present:
	// every tools/call is checked against its subject, scope and expiry
	// before the policy engine runs. Nil means no token is required.
	Capability *capability.Checker
	// Credential, when set, signs every decision as a DSSE envelope so that
	// someone who does not trust the audit file can still verify it.
	Credential *credential.Log

	// RateLimit caps tools/call attempts per LimitWindow for this session;
	// Budget caps their total cost. Zero disables each limit.
	RateLimit int
	Budget    int
	// LimitWindow is the accounting window for the two limits. Zero means
	// DefaultLimitWindow.
	LimitWindow time.Duration

	// NodeURL is the base URL of the local swarm node (e.g.
	// http://127.0.0.1:7946). When set, the gateway reads this agent's
	// response level from the node before every decision, so an isolate
	// verdict freezes the session here too. Empty disables swarm feedback.
	NodeURL string
	// NodeKey, together with NodeURL, lets the gateway deposit signed
	// signals about its own refusals into the swarm. The matching public
	// key must be listed in peers.json under Agent. Nil means read-only.
	NodeKey ed25519.PrivateKey
	// SignalCooldown suppresses repeat reports of the same rule; zero
	// means DefaultSignalCooldown.
	SignalCooldown time.Duration

	// Enrich runs after the built-in swarm level and limit checks and
	// before the hard gates: it may tighten (or, knowing the risks,
	// loosen) the conditions, but it can neither widen a capability
	// denial nor reach past the policy engine. It may be nil.
	Enrich func(*Input)
}

// pendingCall is a forwarded tools/call waiting for its response.
type pendingCall struct {
	param         CallParam
	cls           Class
	d             Decision
	argsDigest    string
	taintedBefore bool
	start         time.Time
}

type server struct {
	cfg      Config
	log      *slog.Logger
	policies *policyStore
	session  *Session
	audit    *Audit
	limits   *limiter
	feed     *swarmFeed
	emitter  *emitter

	// clientMu serialises writes to the client; serverMu serialises writes
	// to the upstream. The two pumps run concurrently.
	clientMu sync.Mutex
	serverMu sync.Mutex

	mu      sync.Mutex
	pending map[string]*pendingCall
	order   []string
}

// maxPendingCalls bounds outstanding forwarded calls; the oldest is evicted
// when the client pipelines more than this (the evicted audit record is
// recovered from the counters, and the response is then dropped).
var maxPendingCalls = 8192

// Run starts the gateway: spawn the upstream MCP server, proxy stdio
// through the policy engine, and serve the admin endpoint until ctx is
// cancelled or either side closes.
func Run(ctx context.Context, cfg Config) error {
	if len(cfg.Command) == 0 {
		return errors.New("gateway: no upstream command given (usage: hive-gateway serve [flags] -- <command>)")
	}
	if cfg.DenyStyle == "" {
		cfg.DenyStyle = DenyToolResult
	}
	if cfg.DenyStyle != DenyToolResult && cfg.DenyStyle != DenyError {
		return fmt.Errorf("gateway: unknown -deny-style %q", cfg.DenyStyle)
	}
	if cfg.ClientIn == nil {
		cfg.ClientIn = os.Stdin
	}
	if cfg.ClientOut == nil {
		cfg.ClientOut = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(cfg.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}

	s, err := newServer(cfg)
	if err != nil {
		return err
	}
	defer s.audit.Close()

	up, err := startUpstream(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		_ = up.stdin.Close()
		_ = up.cmd.Process.Kill()
		_ = up.cmd.Wait()
	}()

	stopAdmin, err := s.startAdmin()
	if err != nil {
		return err
	}
	defer stopAdmin()

	return s.proxy(ctx, up)
}

type upstream struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
}

func startUpstream(ctx context.Context, cfg Config) (*upstream, error) {
	cmd := exec.CommandContext(ctx, cfg.Command[0], cfg.Command[1:]...)
	cmd.Stderr = cfg.Stderr
	if len(cfg.Env) > 0 {
		cmd.Env = append(os.Environ(), cfg.Env...)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("gateway: upstream stdin: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("gateway: upstream stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("gateway: starting upstream %q: %w", cfg.Command[0], err)
	}
	go func() {
		<-ctx.Done()
		_ = cmd.Process.Kill()
	}()
	cfg.Logger.Info("upstream started", "cmd", cfg.Command[0], "args", len(cfg.Command)-1)
	return &upstream{cmd: cmd, stdin: stdin, stdout: stdout}, nil
}

func newServer(cfg Config) (*server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(cfg.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.DenyStyle == "" {
		cfg.DenyStyle = DenyToolResult
	}
	log := cfg.Logger
	policies, err := newPolicyStore(cfg.PolicyPath, cfg.Now, func(err error) {
		log.Error("policy reload failed; keeping last good policy", "err", err)
	})
	if err != nil {
		return nil, err
	}
	audit, err := OpenAudit(cfg.AuditPath)
	if err != nil {
		return nil, err
	}
	if cfg.PolicyPath == "" {
		log.Warn("no policy configured; running in failure mode (every call denied)")
	} else {
		p := policies.Current()
		log.Info("policy loaded", "path", cfg.PolicyPath, "tools", p.Count())
	}
	if cfg.RateLimit < 0 || cfg.Budget < 0 {
		return nil, errors.New("gateway: rate and budget limits must not be negative")
	}
	var limits *limiter
	if cfg.RateLimit > 0 || cfg.Budget > 0 {
		limits = newLimiter(cfg.RateLimit, cfg.Budget, cfg.LimitWindow, cfg.Now)
	}
	var feed *swarmFeed
	var emit *emitter
	switch {
	case cfg.NodeURL != "":
		if cfg.Agent == "" {
			return nil, errors.New("gateway: NodeURL requires an agent id: the swarm only knows members by name")
		}
		client := &http.Client{Timeout: nodeClientTimeout}
		feed = newSwarmFeed(cfg.NodeURL, cfg.Agent, client, cfg.Now, log, DefaultStatusTTL, DefaultStatusMaxStale)
		if cfg.NodeKey != nil {
			signer, err := envelope.NewSigner(pheromone.NodeID(cfg.Agent), cfg.NodeKey)
			if err != nil {
				return nil, fmt.Errorf("gateway: swarm signal key: %w", err)
			}
			emit = newEmitter(signer, cfg.NodeURL, client, cfg.Now, cfg.SignalCooldown, log)
		}
	case cfg.NodeKey != nil:
		return nil, errors.New("gateway: a swarm signal key requires NodeURL")
	}
	return &server{
		cfg:      cfg,
		log:      log,
		policies: policies,
		session:  NewSession(cfg.SessionID, cfg.Agent),
		audit:    audit,
		limits:   limits,
		feed:     feed,
		emitter:  emit,
		pending:  make(map[string]*pendingCall),
	}, nil
}

// proxy runs the two pumps until either fails or ctx is cancelled.
func (s *server) proxy(ctx context.Context, up *upstream) error {
	// The upstream's stdout pipe reaches EOF when the process dies, which
	// is exactly the signal that ends the server-to-client pump.
	errc := make(chan error, 2)
	pumpCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {
		err := s.pumpClient(pumpCtx, s.cfg.ClientIn, up.stdin)
		_ = up.stdin.Close()
		errc <- err
	}()
	go func() {
		errc <- s.pumpServer(pumpCtx, up.stdout, s.cfg.ClientOut)
	}()

	err := <-errc
	cancel()
	// Closing upstream stdin on client EOF makes it exit, which closes its
	// stdout and ends the other pump; cancel() does the same on context
	// cancellation.
	<-errc
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) && ctx.Err() == nil {
		return err
	}
	return nil
}
