// Command hive-gateway proxies an MCP stdio server through the hive-immune
// behaviour policy: every tools/call is classified by tools.yaml, audited,
// and refused when the session has read untrusted content and nobody
// approved the egress.
//
//	hive-gateway serve -agent a1 -policy tools.yaml -- npx -y @modelcontextprotocol/server-everything
//
// The MCP client talks to the gateway exactly as it would talk to the
// server: the upstream address is the only thing that changes. Capability
// tokens (keygen/pubkey/issue) narrow what a session may do regardless of
// what the policy or the swarm says.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hive-immune/hive-immune/pkg/capability"
	"github.com/hive-immune/hive-immune/pkg/gateway"
	"github.com/hive-immune/hive-immune/pkg/keyfile"
)

const usage = `usage: hive-gateway <command> [flags]

commands:
  serve     proxy an MCP stdio server through the behaviour policy
  keygen    create a new capability root key
  pubkey    print a key's public half for distribution
  issue     mint a capability token for one agent
  version   print the version

serve flags (with the upstream command after --):
  -agent id      identity recorded in the audit log (required)
  -policy path   tools.yaml classification (default "tools.yaml"; "" = failure mode, every call denied)
  -session id    session id (default: process start time)
  -audit path    audit log file (default "audit.jsonl"; "" disables)
  -deny-style s  how refusals reach the client: tool-result (default) or error
  -approve url   approval webhook: POSTed every call that needs a human ("" disables)
  -approve-timeout d  how long a call may wait for the operator (default 60s)
  -capability path     capability token file (requires -capability-key)
  -capability-key path capability root public key file (requires -capability)
  -admin addr    control plane listen address, e.g. 127.0.0.1:8787 ("" disables)
  -env k=v       extra environment variable for the upstream (repeatable)

issue flags:
  -key path   root key file (default "capability-root.key")
  -agent id   agent the token belongs to (required)
  -tool name  tool the token allows (repeatable, required)
  -ttl d      how long the token stays valid (default 24h)
  -out path   write the token to this file instead of stdout

example:
  hive-gateway keygen -out root.key
  hive-gateway pubkey -key root.key > root.pub
  hive-gateway issue -key root.key -agent a1 -tool read_file -ttl 24h -out a1.cap
  hive-gateway serve -agent a1 -capability a1.cap -capability-key root.pub -- npx -y @modelcontextprotocol/server-everything`

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	if err := dispatch(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "hive-gateway:", err)
		os.Exit(1)
	}
}

func dispatch(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New(usage)
	}
	switch args[0] {
	case "serve":
		return serve(args[1:], stdin, stdout, stderr)
	case "keygen":
		return keygen(args[1:], stdout, stderr)
	case "pubkey":
		return pubkey(args[1:], stdout, stderr)
	case "issue":
		return issue(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, "hive-gateway", version)
		return nil
	}
	return fmt.Errorf("unknown command %q\n%s", args[0], usage)
}

type serveConfig struct {
	agent, session, policy, audit, denyStyle, admin string
	approve                                         string
	approveTimeout                                  time.Duration
	capability, capabilityKey                       string
	env                                             []string
	command                                         []string
}

// envFlag collects repeated -env k=v pairs.
type envFlag []string

func (e *envFlag) String() string { return strings.Join(*e, ",") }
func (e *envFlag) Set(v string) error {
	if i := strings.IndexByte(v, '='); i <= 0 {
		return fmt.Errorf("-env %q must be k=v", v)
	}
	*e = append(*e, v)
	return nil
}

// stringSlice collects a repeated string flag such as -tool.
type stringSlice []string

func (s *stringSlice) String() string { return strings.Join(*s, ",") }
func (s *stringSlice) Set(v string) error {
	if strings.TrimSpace(v) == "" {
		return errors.New("empty value")
	}
	*s = append(*s, v)
	return nil
}

func parseServe(args []string, stderr io.Writer) (serveConfig, error) {
	var c serveConfig
	var envs envFlag
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.StringVar(&c.agent, "agent", "", "identity recorded in the audit log (required)")
	fs.StringVar(&c.session, "session", "", "session id (default: process start time)")
	fs.StringVar(&c.policy, "policy", "tools.yaml", "tools.yaml classification (empty = failure mode)")
	fs.StringVar(&c.audit, "audit", "audit.jsonl", "audit log file (empty disables)")
	fs.StringVar(&c.denyStyle, "deny-style", string(gateway.DenyToolResult), "tool-result or error")
	fs.StringVar(&c.approve, "approve", "", "approval webhook URL (empty disables the human in the loop)")
	fs.DurationVar(&c.approveTimeout, "approve-timeout", gateway.DefaultApproveTimeout, "how long a call may wait for the operator")
	fs.StringVar(&c.capability, "capability", "", "capability token file (requires -capability-key)")
	fs.StringVar(&c.capabilityKey, "capability-key", "", "capability root public key file (requires -capability)")
	fs.StringVar(&c.admin, "admin", "", "control plane listen address (empty disables)")
	fs.Var(&envs, "env", "extra environment variable for the upstream, k=v (repeatable)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return c, nil
		}
		return c, err
	}
	c.env, c.command = envs, fs.Args()
	if c.agent == "" {
		return c, errors.New("serve: -agent is required")
	}
	if len(c.command) == 0 {
		return c, errors.New("serve: no upstream command (usage: hive-gateway serve [flags] -- <command>)")
	}
	switch gateway.DenyStyle(c.denyStyle) {
	case gateway.DenyToolResult, gateway.DenyError:
	default:
		return c, fmt.Errorf("serve: -deny-style %q must be tool-result or error", c.denyStyle)
	}
	if c.approveTimeout <= 0 {
		return c, errors.New("serve: -approve-timeout must be positive")
	}
	if (c.capability == "") != (c.capabilityKey == "") {
		return c, errors.New("serve: -capability and -capability-key must be used together")
	}
	return c, nil
}

func serve(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serveContext(ctx, args, stdin, stdout, stderr)
}

func serveContext(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	c, err := parseServe(args, stderr)
	if err != nil || len(c.command) == 0 {
		return err
	}
	var approver gateway.Approver
	if c.approve != "" {
		if approver, err = gateway.NewWebhookApprover(c.approve, c.approveTimeout); err != nil {
			return err
		}
	}
	var checker *capability.Checker
	if c.capability != "" {
		if checker, err = loadChecker(c.capability, c.capabilityKey); err != nil {
			return err
		}
	}
	return gateway.Run(ctx, gateway.Config{
		Command: c.command, Env: c.env,
		PolicyPath: c.policy, Agent: c.agent, SessionID: c.session,
		AuditPath: c.audit, DenyStyle: gateway.DenyStyle(c.denyStyle),
		AdminAddr: c.admin, Approver: approver, Capability: checker,
		ClientIn: stdin, ClientOut: stdout, Stderr: stderr,
	})
}

// loadChecker reads the token and the root public key and verifies the
// token's signature chain, so a wrong or forged token fails at startup.
func loadChecker(tokenPath, keyPath string) (*capability.Checker, error) {
	rawToken, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("serve: -capability: %w", err)
	}
	pub, err := loadPublicKey(keyPath)
	if err != nil {
		return nil, err
	}
	checker, err := capability.NewChecker(strings.TrimSpace(string(rawToken)), pub)
	if err != nil {
		return nil, fmt.Errorf("serve: -capability: %w", err)
	}
	return checker, nil
}

func loadPublicKey(path string) (ed25519.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("serve: -capability-key: %w", err)
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("serve: -capability-key: %s must contain a %d-byte hex public key", path, ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}

func keygen(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "capability-root.key", "where to write the private key (never overwritten)")
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
	path := fs.String("key", "capability-root.key", "private key file")
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

func issue(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyPath := fs.String("key", "capability-root.key", "root key file")
	agent := fs.String("agent", "", "agent the token belongs to (required)")
	ttl := fs.Duration("ttl", 24*time.Hour, "how long the token stays valid")
	out := fs.String("out", "", "write the token to this file instead of stdout")
	var tools stringSlice
	fs.Var(&tools, "tool", "tool the token allows (repeatable, required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *agent == "" {
		return errors.New("issue: -agent is required")
	}
	if len(tools) == 0 {
		return errors.New("issue: at least one -tool is required")
	}
	key, err := keyfile.Load(*keyPath)
	if err != nil {
		return err
	}
	token, err := capability.Issue(key, capability.IssueRequest{Subject: *agent, Tools: tools, TTL: *ttl}, time.Now())
	if err != nil {
		return err
	}
	if *out != "" {
		if err := os.WriteFile(*out, []byte(token+"\n"), 0o600); err != nil {
			return fmt.Errorf("issue: writing %s: %w", *out, err)
		}
		fmt.Fprintln(stderr, "wrote", *out)
		return nil
	}
	fmt.Fprintln(stdout, token)
	return nil
}
