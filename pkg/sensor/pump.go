package sensor

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
)

// MaxLineBytes bounds one line of sensor output. Longer lines are discarded
// (and counted as malformed) instead of stopping the agent.
const MaxLineBytes = 1 << 20

var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

// Stats counts what happened to each line of input.
type Stats struct {
	Lines     int `json:"lines"`
	Emitted   int `json:"emitted"`
	Skipped   int `json:"skipped"`   // irrelevant or below MinStrength
	Throttled int `json:"throttled"` // suppressed by cooldown
	Rejected  int `json:"rejected"`  // foreign host or outside time window
	Malformed int `json:"malformed"`
}

// Pipeline wires a parser, mapper and signer together.
type Pipeline struct {
	Parser Parser
	Mapper *Mapper
	Signer *envelope.Signer
	Emit   func(envelope.Envelope) error
	Now    func() time.Time
}

// Run processes r line by line until EOF or ctx is cancelled. It only
// returns an error if reading, signing or emitting fails; bad input lines
// are counted, never fatal.
func (p Pipeline) Run(ctx context.Context, r io.Reader) (Stats, error) {
	if p.Parser == nil || p.Mapper == nil || p.Signer == nil || p.Emit == nil || p.Now == nil {
		return Stats{}, errors.New("sensor: pipeline is missing a component")
	}
	if p.Mapper.cfg.Node != p.Signer.ID() {
		return Stats{}, fmt.Errorf("sensor: mapper node %q does not match signer %q", p.Mapper.cfg.Node, p.Signer.ID())
	}
	br := bufio.NewReaderSize(r, 64*1024)
	var st Stats
	for first := true; ; first = false {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		line, tooLong, err := readLine(br)
		if first {
			// Windows PowerShell pipes and some editors prepend a UTF-8 BOM.
			line = bytes.TrimPrefix(line, utf8BOM)
		}
		if len(line) > 0 || tooLong {
			st.Lines++
			if tooLong {
				st.Malformed++
			} else if perr := p.handle(line, &st); perr != nil {
				return st, perr
			}
		}
		if errors.Is(err, io.EOF) {
			return st, nil
		}
		if err != nil {
			return st, fmt.Errorf("sensor: reading input: %w", err)
		}
	}
}

func (p Pipeline) handle(line []byte, st *Stats) error {
	ev, err := p.Parser.Parse(line)
	switch {
	case errors.Is(err, ErrSkip):
		st.Skipped++
		return nil
	case err != nil:
		st.Malformed++
		return nil
	}
	signal, err := p.Mapper.Map(ev, p.Now())
	switch {
	case errors.Is(err, ErrSkip):
		st.Skipped++
		return nil
	case errors.Is(err, ErrThrottled):
		st.Throttled++
		return nil
	case errors.Is(err, ErrForeignHost), errors.Is(err, ErrStale):
		st.Rejected++
		return nil
	case err != nil:
		return err
	}
	env, err := p.Signer.Seal(signal)
	if err != nil {
		return fmt.Errorf("sensor: signing: %w", err)
	}
	if err := p.Emit(env); err != nil {
		return fmt.Errorf("sensor: emitting: %w", err)
	}
	st.Emitted++
	return nil
}

// readLine returns the next line without its terminator. If the line
// exceeds MaxLineBytes the rest of it is consumed and tooLong is set.
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	var buf []byte
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong {
			if len(buf)+len(chunk) > MaxLineBytes+2 { // allow for "\r\n"
				tooLong, buf = true, nil
			} else {
				buf = append(buf, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if tooLong {
			return nil, true, err
		}
		line = bytes.TrimRight(buf, "\r\n")
		if len(line) > MaxLineBytes {
			return nil, true, err
		}
		return line, false, err
	}
}
