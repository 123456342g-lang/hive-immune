// Command hive-gateway proxies an MCP stdio server through the hive-immune
// behaviour policy: every tools/call is classified by tools.yaml, audited,
// and refused when the session has read untrusted content and nobody
// approved the egress.
//
//	hive-gateway serve -agent a1 -policy tools.yaml -- npx -y @modelcontextprotocol/server-everything
//
// The MCP client talks to the gateway exactly as it would talk to the
// server: the upstream address is the only thing that changes.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/hive-immune/hive-immune/pkg/gateway"
)

const usage = `usage: hive-gateway <command> [flags] -- <upstream mcp server>

commands:
  serve     proxy an MCP stdio server through the behaviour policy
  version   print the version

serve flags:
  -agent id      identity recorded in the audit log (required)
  -policy path   tools.yaml classification (default "tools.yaml"; "" = failure mode, every call denied)
  -session id    session id (default: process start time)
  -audit path    audit log file (default "audit.jsonl"; "" disables)
  -deny-style s  how refusals reach the client: tool-result (default) or error
  -approve url   approval webhook: POSTed every call that needs a human ("" disables)
  -approve-timeout d  how long a call may wait for the operator (default 60s)
  -admin addr    control plane listen address, e.g. 127.0.0.1:8787 ("" disables)
  -env k=v       extra environment variable for the upstream (repeatable)

everything after -- (or after the last flag) is the upstream command:

  hive-gateway serve -agent a1 -- npx -y @modelcontextprotocol/server-everything`

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
	return gateway.Run(ctx, gateway.Config{
		Command: c.command, Env: c.env,
		PolicyPath: c.policy, Agent: c.agent, SessionID: c.session,
		AuditPath: c.audit, DenyStyle: gateway.DenyStyle(c.denyStyle),
		AdminAddr: c.admin, Approver: approver,
		ClientIn: stdin, ClientOut: stdout, Stderr: stderr,
	})
}
