package node

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
	"github.com/hive-immune/hive-immune/pkg/sensor"
	"github.com/hive-immune/hive-immune/pkg/swarm"
)

// maxBodyBytes bounds request bodies on both listeners.
const maxBodyBytes = 2 << 20

// FalcoPath is where the sensor listener accepts Falco http_output alerts.
const FalcoPath = "/v1/sensor/falco"

// StatusPath is where the node reports its swarm view (levels per member).
// The gateway reads it to learn its own response level.
const StatusPath = "/v1/status"

// BatchResult reports what happened to a batch of envelopes.
type BatchResult struct {
	Accepted  int `json:"accepted"`
	Duplicate int `json:"duplicate"`
	Rejected  int `json:"rejected"`
}

// StatusReport is served at /v1/status.
type StatusReport struct {
	Node    pheromone.NodeID `json:"node"`
	Time    time.Time        `json:"time"`
	Members []swarm.Status   `json:"members"`
	Stats   Stats            `json:"stats"`
}

// Handler serves the gossip and status API. Every envelope is verified
// against the cluster keyring, so the listener accepts nothing unsigned.
func (n *Node) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+EnvelopesPath, n.handleEnvelopes)
	mux.HandleFunc("GET "+StatusPath, n.handleStatus)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok\n"))
	})
	return mux
}

func (n *Node) handleEnvelopes(w http.ResponseWriter, r *http.Request) {
	var batch []envelope.Envelope
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&batch); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "body must be a JSON array of envelopes", http.StatusBadRequest)
		return
	}
	if len(batch) > MaxBatch {
		http.Error(w, "too many envelopes in one request", http.StatusRequestEntityTooLarge)
		return
	}
	var res BatchResult
	for _, e := range batch {
		switch err := n.Receive(e); {
		case err == nil:
			res.Accepted++
		case errors.Is(err, ErrDuplicate):
			res.Duplicate++
		default:
			res.Rejected++
			n.cfg.Logger.Debug("envelope rejected", "origin", e.Signal.Origin, "err", err)
		}
	}
	writeJSON(w, res)
}

func (n *Node) handleStatus(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, StatusReport{Node: n.cfg.Self, Time: n.cfg.Now().UTC(), Members: n.Evaluate(), Stats: n.Stats()})
}

// SensorHandler accepts sensor output posted by a local sensor (Falco's
// http_output), signs it as this node and feeds it into the swarm. It must
// only be exposed on a local address: whoever can reach it can make this
// node report on itself.
func (n *Node) SensorHandler(parser sensor.Parser, mapper *sensor.Mapper, signer *envelope.Signer) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+FalcoPath, func(w http.ResponseWriter, r *http.Request) {
		p := sensor.Pipeline{
			Parser: parser, Mapper: mapper, Signer: signer, Now: n.cfg.Now,
			Emit: func(e envelope.Envelope) error {
				if err := n.Receive(e); err != nil && !errors.Is(err, ErrDuplicate) {
					n.cfg.Logger.Warn("own signal rejected", "kind", e.Signal.Kind, "err", err)
				}
				return nil
			},
		}
		st, err := p.Run(r.Context(), http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil && !errors.Is(err, context.Canceled) {
			http.Error(w, "reading sensor input failed", http.StatusBadRequest)
			return
		}
		writeJSON(w, st)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
