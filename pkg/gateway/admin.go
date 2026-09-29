package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"time"
)

// startAdmin serves the control plane on its own listener, separate from
// the stdio data plane: policy reloads, session state and the audit tail
// are reachable without ever passing through the MCP stream.
func (s *server) startAdmin() (func(), error) {
	if s.cfg.AdminAddr == "" {
		return func() {}, nil
	}
	ln, err := net.Listen("tcp", s.cfg.AdminAddr)
	if err != nil {
		return nil, err
	}
	srv := &http.Server{
		Handler:           s.adminHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			s.log.Error("admin listener failed", "addr", ln.Addr().String(), "err", err)
		}
	}()
	s.log.Info("admin listening", "addr", ln.Addr().String())
	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}, nil
}

func (s *server) adminHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("GET /v1/session", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, s.state())
	})
	mux.HandleFunc("POST /v1/taint/reset", func(w http.ResponseWriter, _ *http.Request) {
		// The operator, having looked at what the session read, declares it
		// clean again. The decision is audited like any other so that a
		// later review can see who re-enabled egress.
		before := s.session.Taint.Snapshot()
		reset := s.session.Taint.Reset()
		after := s.session.Taint.Snapshot()
		_ = s.audit.Append(Record{
			Time: s.cfg.Now(), Session: s.session.ID, Agent: s.session.Agent,
			Action: ActionReset, Rule: "admin.taint-reset",
			TaintedBefore: before.Tainted, TaintedAfter: after.Tainted,
			Reason: "operator reset the session taint",
		})
		s.log.Info("session taint reset", "session", s.session.ID, "was_tainted", reset)
		writeJSON(w, map[string]any{"reset": reset, "taint": after})
	})
	mux.HandleFunc("POST /v1/reload", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.policies.Reload(); err != nil {
			writeJSON(w, map[string]any{"reloaded": false, "error": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"reloaded": true, "tools": s.policies.Current().Count()})
	})
	mux.HandleFunc("GET /v1/audit", func(w http.ResponseWriter, r *http.Request) {
		n := 100
		if raw := r.URL.Query().Get("n"); raw != "" {
			v, err := strconv.Atoi(raw)
			if err != nil || v < 1 || v > 1000 {
				http.Error(w, "n must be 1-1000", http.StatusBadRequest)
				return
			}
			n = v
		}
		recs, err := s.audit.Tail(n)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if recs == nil {
			recs = []Record{}
		}
		writeJSON(w, recs)
	})
	return mux
}

// state is the admin view of the session.
func (s *server) state() SessionState {
	ps := &PolicyState{Path: s.cfg.PolicyPath, Degraded: s.policies.Current() == nil}
	if p := s.policies.Current(); p != nil {
		ps.Tools = p.Count()
	}
	if err := s.policies.Error(); err != nil {
		ps.Error = err.Error()
	}
	return SessionState{
		ID: s.session.ID, Agent: s.session.Agent,
		Taint: s.session.Taint.Snapshot(), Counters: s.session.Count(),
		Policy: ps,
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}
