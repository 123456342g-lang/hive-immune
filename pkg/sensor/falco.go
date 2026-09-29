package sensor

import (
	"encoding/json"
	"fmt"
	"strings"
)

// falcoSeverity maps Falco priorities (syslog levels) to signal strength.
var falcoSeverity = map[string]float64{
	"emergency":     1.0,
	"alert":         1.0,
	"critical":      1.0,
	"error":         0.8,
	"warning":       0.6,
	"notice":        0.4,
	"informational": 0.2,
	"info":          0.2,
	"debug":         0.1,
}

// Falco parses Falco alerts written with json_output enabled.
type Falco struct{}

// Name implements Parser.
func (Falco) Name() string { return "falco" }

// Parse implements Parser. Only the top-level time is used: Falco encodes
// output_fields["evt.time.iso8601"] as an integer, not a timestamp string.
func (Falco) Parse(line []byte) (Event, error) {
	var raw struct {
		Time     string `json:"time"`
		Rule     string `json:"rule"`
		Priority string `json:"priority"`
		Hostname string `json:"hostname"`
	}
	if err := json.Unmarshal(line, &raw); err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrMalformed, err)
	}
	if err := validateRule(raw.Rule); err != nil {
		return Event{}, err
	}
	sev, ok := falcoSeverity[strings.ToLower(raw.Priority)]
	if !ok {
		return Event{}, fmt.Errorf("%w: unknown priority %q", ErrMalformed, raw.Priority)
	}
	at, err := parseTime(raw.Time)
	if err != nil {
		return Event{}, err
	}
	return Event{Source: "falco", Rule: raw.Rule, Host: raw.Hostname, Severity: sev, At: at}, nil
}
