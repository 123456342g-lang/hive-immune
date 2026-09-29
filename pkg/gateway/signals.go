// signals lets the gateway report its own refusals to the swarm: one
// signed pheromone signal per rule, deposited into the local node, which
// gossips it on. The loop closes through swarmFeed - the very level this
// agent's next call is judged against.
//
// Only behaviour worth smelling is deposited (see signalStrength); level
// verdicts and configuration failures are deliberately kept out so the
// field cannot echo itself into an alarm.
package gateway

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/node"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// DefaultSignalCooldown suppresses repeat reports of the same rule.
const DefaultSignalCooldown = 30 * time.Second

// signalKindPrefix namespaces gateway signals, e.g. "gateway.taint.egress".
const signalKindPrefix = "gateway."

// signalStrength maps a denial rule to the strength deposited about this
// agent. The gateway reports on itself (origin = subject = the agent), so
// the swarm escalates it without quorum - safe, because a lying gateway
// can then only freeze its own agent.
//
// The numbers line up with the field's saturation: one taint.egress
// refusal (0.6) classifies as contain - the agent stays read-only; a
// repeat while the first is still warm caps the origin's contribution,
// which classifies as isolate. An agent that keeps trying to send data
// out after being stopped takes itself off the field.
//
// Rules that must not feed back into the field return ok=false: level.* is
// the swarm's own verdict (echoing it would amplify it) and degraded.* is
// the operator's configuration problem, not the agent's behaviour.
func signalStrength(rule string) (float64, bool) {
	switch {
	case rule == "taint.egress":
		return 0.6, true
	case rule == "taint.write-internal":
		return 0.5, true
	case strings.HasPrefix(rule, "capability."):
		return 0.4, true
	case strings.HasPrefix(rule, "limits."):
		return 0.3, true
	case rule == "malformed.call":
		return 0.2, true
	}
	return 0, false
}

// emitter deposits signed denial signals into the local node.
type emitter struct {
	signer   *envelope.Signer
	url      string
	client   *http.Client
	now      func() time.Time
	cooldown time.Duration
	log      *slog.Logger

	mu   sync.Mutex
	last map[string]time.Time
}

func newEmitter(signer *envelope.Signer, baseURL string, client *http.Client, now func() time.Time, cooldown time.Duration, log *slog.Logger) *emitter {
	if cooldown <= 0 {
		cooldown = DefaultSignalCooldown
	}
	return &emitter{
		signer: signer, url: strings.TrimRight(baseURL, "/") + node.EnvelopesPath,
		client: client, now: now, cooldown: cooldown, log: log,
		last: make(map[string]time.Time),
	}
}

// notify deposits one signal for rule, at most once per cooldown. It is
// called after the client already has its answer: a slow node can delay
// the next message by its timeout, but never the decision itself, and a
// failed deposit is logged rather than raised - the audit log already
// holds the refusal.
func (e *emitter) notify(rule string) {
	strength, ok := signalStrength(rule)
	if !ok || !e.admit(rule) {
		return
	}
	env, err := e.signer.Seal(pheromone.Signal{
		Origin: e.signer.ID(), Subject: e.signer.ID(),
		Kind: signalKindPrefix + rule, Strength: strength, At: e.now(),
	})
	if err != nil {
		e.log.Warn("signal not sealed", "rule", rule, "err", err)
		return
	}
	body, err := json.Marshal([]envelope.Envelope{env})
	if err != nil {
		e.log.Warn("signal not encoded", "rule", rule, "err", err)
		return
	}
	resp, err := e.client.Post(e.url, "application/json", bytes.NewReader(body))
	if err != nil {
		e.log.Warn("signal deposit failed", "rule", rule, "err", err)
		return
	}
	defer resp.Body.Close()
	var res node.BatchResult
	_ = json.NewDecoder(io.LimitReader(resp.Body, maxStatusBytes)).Decode(&res)
	switch {
	case res.Rejected > 0:
		// Almost always "unknown origin": the gateway's key is not in
		// peers.json under this agent id.
		e.log.Warn("node rejected signal", "rule", rule, "rejected", res.Rejected)
	case resp.StatusCode != http.StatusOK:
		e.log.Warn("signal deposit refused", "rule", rule, "status", resp.Status)
	}
}

// admit applies the per-rule cooldown. The time is recorded when the
// signal is allowed, so a failed deposit still waits out the cooldown
// instead of retrying on every refusal.
func (e *emitter) admit(rule string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.now()
	if last, ok := e.last[rule]; ok && t.Sub(last) < e.cooldown {
		return false
	}
	e.last[rule] = t
	return true
}
