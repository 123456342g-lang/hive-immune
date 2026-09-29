package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/hive-immune/hive-immune/pkg/taint"
)

// pumpClient reads the MCP client's messages, decides on every tools/call
// and forwards everything else untouched.
func (s *server) pumpClient(ctx context.Context, in io.Reader, up io.Writer) error {
	br := bufio.NewReader(in)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := ReadMessage(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if m.IsRequest() && m.Method == "tools/call" {
			if err := s.handleCall(ctx, m, up); err != nil {
				return err
			}
			continue
		}
		if err := s.writeUpstream(up, m); err != nil {
			return err
		}
	}
}

// pumpServer forwards upstream messages and finishes the audit record for
// every response to a call we forwarded.
func (s *server) pumpServer(ctx context.Context, in io.Reader, out io.Writer) error {
	br := bufio.NewReader(in)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		m, err := ReadMessage(br)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if m.IsResponse() {
			if p := s.takePending(m.IDKey()); p != nil {
				s.complete(m, p)
			}
		}
		if err := s.writeClient(out, m); err != nil {
			return err
		}
	}
}

func (s *server) handleCall(ctx context.Context, m Message, up io.Writer) error {
	start := s.cfg.Now()
	s.session.count(func(c *SessionCounters) { c.Calls++ })

	param, err := m.ParseCall()
	if err != nil {
		// A call we cannot even parse cannot be classified, so it is not
		// forwarded. The model gets an ordinary tool error back.
		d := Decision{Action: ActionDeny, Rule: "malformed.call", Risk: RiskEgress, Reason: "tools/call params invalid: " + err.Error()}
		s.session.count(func(c *SessionCounters) { c.Denied++ })
		s.append(Record{Time: start, CallID: m.IDKey(), Tool: param.Name, Risk: d.Risk,
			Action: d.Action, Rule: d.Rule, Reason: d.Reason})
		return s.reply(m, d)
	}

	argsDigest := DigestArgs(param.Arguments)
	in := Input{
		Tool:                param.Name,
		Tainted:             s.session.Taint.Tainted(),
		ApprovalUnavailable: s.cfg.Approver == nil,
	}
	if s.cfg.Enrich != nil {
		s.cfg.Enrich(&in)
	}
	d := Decide(s.policies.Current(), in)
	taintedBefore := in.Tainted

	switch d.Action {
	case ActionDeny:
		s.session.count(func(c *SessionCounters) {
			c.Denied++
			if strings.HasPrefix(d.Rule, "capability.") {
				c.OutOfScope++
			}
		})
		s.append(s.record(m.IDKey(), param, d, argsDigest, taintedBefore, start))
		return s.reply(m, d)

	case ActionApprove:
		s.session.count(func(c *SessionCounters) { c.Approvals++ })
		ok, why := s.approve(ctx, d, param, argsDigest, start)
		if !ok {
			s.session.count(func(c *SessionCounters) { c.Rejected++; c.Denied++ })
			d.Action = ActionDeny
			d.Reason += "; approval refused: " + why
			s.append(s.record(m.IDKey(), param, d, argsDigest, taintedBefore, start))
			return s.reply(m, d)
		}
		s.session.count(func(c *SessionCounters) { c.Approved++ })
		d.Reason += "; approved by an operator"
	}
	return s.forward(m, up, param, d, argsDigest, taintedBefore, start)
}

func (s *server) approve(ctx context.Context, d Decision, param CallParam, argsDigest string, start time.Time) (bool, string) {
	if s.cfg.Approver == nil {
		return false, "no approval channel"
	}
	req := Approval{
		Session: s.session.ID, Agent: s.session.Agent, Tool: param.Name, Risk: d.Risk,
		ArgsDigest: argsDigest, Reason: d.Reason, RequestedAt: start,
	}
	ok, err := s.cfg.Approver.Approve(ctx, req)
	if err != nil {
		return false, err.Error()
	}
	if !ok {
		return false, "operator rejected the call"
	}
	return true, ""
}

func (s *server) forward(m Message, up io.Writer, param CallParam, d Decision, argsDigest string, taintedBefore bool, start time.Time) error {
	key := m.IDKey()
	s.mu.Lock()
	if _, dup := s.pending[key]; !dup {
		s.order = append(s.order, key)
	}
	s.pending[key] = &pendingCall{
		param: param, d: d, argsDigest: argsDigest,
		taintedBefore: taintedBefore, start: start,
	}
	for len(s.order) > maxPendingCalls {
		oldest := s.order[0]
		s.order = s.order[1:]
		delete(s.pending, oldest)
	}
	s.mu.Unlock()

	if d.Action == ActionAllow || d.Action == ActionApprove {
		s.session.count(func(c *SessionCounters) { c.Allowed++ })
	}
	if err := s.writeUpstream(up, m); err != nil {
		s.takePending(key)
		return err
	}
	return nil
}

func (s *server) takePending(key string) *pendingCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.pending[key]
	if !ok {
		return nil
	}
	delete(s.pending, key)
	for i, k := range s.order {
		if k == key {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	return p
}

// complete writes the audit record for a response to a forwarded call and
// updates session taint when the tool's output came from outside.
func (s *server) complete(m Message, p *pendingCall) {
	now := s.cfg.Now()
	rec := s.record(m.IDKey(), p.param, p.d, p.argsDigest, p.taintedBefore, p.start)
	if m.Error != nil {
		rec.UpstreamError = m.Error.Message
	} else {
		rec.ResultDigest = Digest(m.Result)
		if r, ok := ParseToolResult(m.Result); ok && !r.IsError && p.d.Taint == taint.SourceExternal {
			s.session.Taint.Mark(p.param.Name, now)
		}
	}
	rec.TaintedAfter = s.session.Taint.Tainted()
	s.append(rec)
}

func (s *server) record(callID string, param CallParam, d Decision, argsDigest string, taintedBefore bool, start time.Time) Record {
	now := s.cfg.Now()
	return Record{
		Time: now, Session: s.session.ID, Agent: s.session.Agent, CallID: callID,
		Tool: param.Name, Risk: d.Risk, NeedsApproval: d.NeedsApproval,
		TaintedBefore: taintedBefore, TaintedAfter: s.session.Taint.Tainted(),
		Action: d.Action, Rule: d.Rule, Reason: d.Reason,
		ArgsDigest: argsDigest, DurationMS: now.Sub(start).Milliseconds(),
	}
}

func (s *server) append(r Record) {
	if err := s.audit.Append(r); err != nil {
		s.log.Error("audit write failed", "err", err)
	}
	if s.cfg.OnDecision != nil {
		s.cfg.OnDecision(r)
	}
}

// reply sends a denial to the client in the configured style.
func (s *server) reply(m Message, d Decision) error {
	resp := Message{JSONRPC: "2.0", ID: m.ID}
	if s.cfg.DenyStyle == DenyError {
		data, _ := json.Marshal(map[string]string{"rule": d.Rule, "risk": string(d.Risk), "gateway": "hive-gateway"})
		resp.Error = &RPCError{Code: errCodeDenied, Message: "hive-gateway: " + d.Reason, Data: data}
	} else {
		res, _ := json.Marshal(map[string]any{
			"content": []map[string]string{{"type": "text", "text": "hive-gateway denied: " + d.Reason + " (rule " + d.Rule + ")"}},
			"isError": true,
		})
		resp.Result = res
	}
	return s.writeClient(s.cfg.ClientOut, resp)
}

func (s *server) writeClient(w io.Writer, m Message) error {
	s.clientMu.Lock()
	defer s.clientMu.Unlock()
	return WriteMessage(w, m)
}

func (s *server) writeUpstream(w io.Writer, m Message) error {
	s.serverMu.Lock()
	defer s.serverMu.Unlock()
	return WriteMessage(w, m)
}
