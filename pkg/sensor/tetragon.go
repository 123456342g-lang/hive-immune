package sensor

import (
	"encoding/json"
	"fmt"
	"maps"
)

// Tetragon parses Tetragon JSON events (the export file, or
// `tetra getevents -o json`).
//
// Tetragon emits raw telemetry rather than alerts, so severity comes from
// the operator: only events produced by a TracingPolicy listed in the
// policy map become signals, with the strength given there. process_exec,
// process_exit and events from unlisted policies are skipped.
type Tetragon struct {
	policies map[string]float64
}

// NewTetragon builds a parser from policy name → strength in (0, 1].
func NewTetragon(policies map[string]float64) (*Tetragon, error) {
	if len(policies) == 0 {
		return nil, fmt.Errorf("sensor: tetragon needs at least one policy mapping")
	}
	for name, s := range policies {
		if err := validateRule(name); err != nil {
			return nil, fmt.Errorf("sensor: policy %q: %w", name, err)
		}
		if !(s > 0 && s <= 1) {
			return nil, fmt.Errorf("sensor: policy %q strength %v outside (0, 1]", name, s)
		}
	}
	return &Tetragon{policies: maps.Clone(policies)}, nil
}

// Name implements Parser.
func (*Tetragon) Name() string { return "tetragon" }

type policyEvent struct {
	PolicyName string `json:"policy_name"`
}

// Parse implements Parser.
func (t *Tetragon) Parse(line []byte) (Event, error) {
	var raw struct {
		NodeName   string       `json:"node_name"`
		Time       string       `json:"time"`
		Kprobe     *policyEvent `json:"process_kprobe"`
		Tracepoint *policyEvent `json:"process_tracepoint"`
		Uprobe     *policyEvent `json:"process_uprobe"`
		LSM        *policyEvent `json:"process_lsm"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	pe := firstNonNil(raw.Kprobe, raw.Tracepoint, raw.Uprobe, raw.LSM)
	if pe == nil {
		return Event{}, ErrSkip
	}
	sev, ok := t.policies[pe.PolicyName]
	if !ok {
		return Event{}, ErrSkip
	}
	at, err := parseTime(raw.Time)
	if err != nil {
		return Event{}, err
	}
	return Event{Source: "tetragon", Rule: pe.PolicyName, Host: raw.NodeName, Severity: sev, At: at}, nil
}

func firstNonNil(events ...*policyEvent) *policyEvent {
	for _, e := range events {
		if e != nil {
			return e
		}
	}
	return nil
}
