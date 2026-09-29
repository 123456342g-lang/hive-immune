package gateway

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/hive-immune/hive-immune/pkg/taint"
	"gopkg.in/yaml.v3"
)

// Risk is how much damage a tool can do if it is misused.
type Risk string

// The three risk classes. They are deliberately few: the whole policy
// matrix has to be something an operator can hold in their head.
const (
	// RiskRead only reads from inside the trust boundary.
	RiskRead Risk = "read"
	// RiskWriteInternal changes internal state (create a ticket, update a
	// record) but nothing leaves the organisation.
	RiskWriteInternal Risk = "write-internal"
	// RiskEgress moves data or effects out of the organisation: send email,
	// upload, HTTP call to anywhere external, shell execution.
	RiskEgress Risk = "egress"
)

// ErrInvalidPolicy means a policy document cannot be used.
var ErrInvalidPolicy = errors.New("gateway: invalid policy")

// DefaultVersion is the only tools.yaml version this build understands.
const DefaultVersion = 1

// Class is the policy entry for one tool: what it may do, whether its
// output counts as untrusted content, and what one call costs the budget.
type Class struct {
	Risk  Risk         `yaml:"risk"`
	Taint taint.Source `yaml:"taint"`
	// Cost is charged to the session budget on every attempt (0 = free).
	Cost int `yaml:"cost,omitempty"`
}

// Validate checks one classification.
func (c Class) Validate(what string) error {
	switch c.Risk {
	case RiskRead, RiskWriteInternal, RiskEgress:
	default:
		return fmt.Errorf("%w: %s: risk %q is not read, write-internal or egress", ErrInvalidPolicy, what, c.Risk)
	}
	switch c.Taint {
	case taint.SourceInternal, taint.SourceExternal:
	default:
		return fmt.Errorf("%w: %s: taint %q is not internal or external", ErrInvalidPolicy, what, c.Taint)
	}
	if c.Cost < 0 {
		return fmt.Errorf("%w: %s: cost %d must not be negative", ErrInvalidPolicy, what, c.Cost)
	}
	return nil
}

// FailClosed is the classification used when nothing else applies: an
// unregistered tool is treated as outward-facing and untrusted.
func FailClosed() Class { return Class{Risk: RiskEgress, Taint: taint.SourceExternal} }

// document is the on-disk shape of tools.yaml.
type document struct {
	Version  int              `yaml:"version"`
	Defaults *Class           `yaml:"defaults,omitempty"`
	Tools    map[string]Class `yaml:"tools,omitempty"`
}

// Policy is a loaded, validated tools.yaml.
type Policy struct {
	Version  int
	Defaults Class
	Tools    map[string]Class
}

// ParsePolicy decodes and validates a tools.yaml document. Unknown fields
// and unknown enum values are rejected: a typo must not silently downgrade
// a tool to a safer class than the operator intended.
func ParsePolicy(data []byte) (*Policy, error) {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	var doc document
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	return buildPolicy(doc)
}

// LoadPolicy reads a policy file. An empty path returns a nil policy, which
// puts the gateway into its documented failure mode: every tool is
// unclassified, hence egress, hence denied.
func LoadPolicy(path string) (*Policy, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	return ParsePolicy(raw)
}

func buildPolicy(doc document) (*Policy, error) {
	if doc.Version != DefaultVersion {
		return nil, fmt.Errorf("%w: version = %d, want %d", ErrInvalidPolicy, doc.Version, DefaultVersion)
	}
	// Absent defaults fall back to the fail-closed classification rather
	// than an error, so a minimal file stays usable.
	defaults := FailClosed()
	if doc.Defaults != nil {
		defaults = *doc.Defaults
	}
	if err := defaults.Validate("defaults"); err != nil {
		return nil, err
	}
	tools := make(map[string]Class, len(doc.Tools))
	for name, c := range doc.Tools {
		if strings.TrimSpace(name) == "" {
			return nil, fmt.Errorf("%w: tool with an empty name", ErrInvalidPolicy)
		}
		// A tool that does not say where its output comes from is assumed
		// to be able to carry instructions from outside.
		if c.Taint == "" {
			c.Taint = taint.SourceExternal
		}
		if err := c.Validate("tools." + name); err != nil {
			return nil, err
		}
		tools[name] = c
	}
	return &Policy{Version: doc.Version, Defaults: defaults, Tools: tools}, nil
}

// Classify returns the class for a tool, falling back to the document
// defaults for anything unregistered.
func (p *Policy) Classify(tool string) Class {
	if p == nil {
		return FailClosed()
	}
	if c, ok := p.Tools[tool]; ok {
		return c
	}
	return p.Defaults
}

// Count returns how many tools are registered, for logging and the admin
// endpoint.
func (p *Policy) Count() int {
	if p == nil {
		return 0
	}
	return len(p.Tools)
}

// policyStore holds the current policy and re-reads the file when it may
// have changed, so a tools.yaml edit takes effect without restarting the
// gateway (control plane separate from data plane). Re-reads are throttled
// and failures keep the last good policy.
type policyStore struct {
	mu       sync.RWMutex
	path     string
	policy   *Policy
	err      error
	lastTick time.Time
	interval time.Duration
	now      func() time.Time
	onError  func(error)
}

func newPolicyStore(path string, now func() time.Time, onError func(error)) (*policyStore, error) {
	if now == nil {
		now = time.Now
	}
	p, err := LoadPolicy(path)
	if err != nil {
		return nil, err
	}
	return &policyStore{
		path: path, policy: p, interval: time.Second, now: now, onError: onError,
	}, nil
}

// Current returns the active policy. nil means the gateway runs in its
// failure mode (every call denied).
func (s *policyStore) Current() *Policy {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" || s.policy == nil {
		return nil
	}
	if tick := s.now(); tick.Sub(s.lastTick) >= s.interval {
		s.lastTick = tick
		s.reloadLocked()
	}
	return s.policy
}

// Reload forces a re-read, used by the admin endpoint.
func (s *policyStore) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastTick = s.now()
	s.reloadLocked()
	return s.err
}

func (s *policyStore) reloadLocked() {
	p, err := LoadPolicy(s.path)
	if err != nil {
		// Keep the last good policy in effect; report the failure to the
		// operator without taking the data plane down.
		s.err = err
		if s.onError != nil {
			s.onError(err)
		}
		return
	}
	s.policy, s.err = p, nil
}

// Error returns the last reload failure, if any.
func (s *policyStore) Error() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.err
}
