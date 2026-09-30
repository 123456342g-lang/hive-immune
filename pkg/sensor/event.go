// Package sensor turns events from existing eBPF runtime sensors (Falco,
// Tetragon) into signed hive-immune pheromone signals.
//
// hive-immune deliberately does not ship its own kernel probes. Falco and
// Tetragon are mature, widely deployed eBPF sensors; this package consumes
// their JSON event streams, normalises them into Events, and maps those to
// signals about the local node.
//
// Every line of sensor output is treated as untrusted input: it is bounded
// in size, strictly validated, and anything unexpected is skipped rather
// than guessed at.
package sensor

import (
	"errors"
	"fmt"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxRuleLen bounds rule and policy names so they stay reasonable signal
// kinds.
const MaxRuleLen = 128

var (
	// ErrSkip means the event is well formed but not relevant.
	ErrSkip = errors.New("sensor: event skipped")
	// ErrMalformed means the input could not be understood.
	ErrMalformed = errors.New("sensor: malformed event")
)

// Event is a sensor-agnostic security event.
type Event struct {
	Source   string    // sensor name, e.g. "falco"
	Rule     string    // Falco rule or Tetragon policy that fired
	Host     string    // host name reported by the sensor
	Severity float64   // (0, 1]
	At       time.Time // when the sensor observed it
}

// Parser decodes one line of sensor output.
type Parser interface {
	// Name identifies the sensor, and prefixes signal kinds.
	Name() string
	// Parse returns ErrSkip for irrelevant events and ErrMalformed for
	// input it cannot decode.
	Parse(line []byte) (Event, error)
}

func validateRule(rule string) error {
	if rule == "" || len(rule) > MaxRuleLen || !utf8.ValidString(rule) {
		return fmt.Errorf("%w: rule name must be 1-%d bytes of UTF-8", ErrMalformed, MaxRuleLen)
	}
	for _, r := range rule {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: rule name contains control characters", ErrMalformed)
		}
	}
	return nil
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339Nano, s)
	// "0001-01-01T00:00:00Z" is valid RFC3339 but is the zero time; a
	// sensor event without a real timestamp must not be accepted.
	if err != nil || t.IsZero() {
		return time.Time{}, fmt.Errorf("%w: bad time %q", ErrMalformed, s)
	}
	return t, nil
}
