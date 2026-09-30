package node

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"

	"github.com/123456342g-lang/hive-immune/pkg/cluster"
	"github.com/123456342g-lang/hive-immune/pkg/envelope"
)

// MaxBatch is the largest number of envelopes sent or accepted per request.
const MaxBatch = 256

// EnvelopesPath is the gossip endpoint every node serves.
const EnvelopesPath = "/v1/envelopes"

type peer struct {
	member cluster.Member
	url    string
	queue  chan envelope.Envelope
}

func newPeer(m cluster.Member, size int) *peer {
	return &peer{member: m, url: strings.TrimRight(m.Addr, "/") + EnvelopesPath, queue: make(chan envelope.Envelope, size)}
}

// Run delivers queued envelopes to peers until ctx is cancelled. Delivery is
// best effort: a failed batch is counted and dropped, since every signal is
// also flooded through the other peers.
func (n *Node) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for _, p := range n.peers {
		wg.Add(1)
		go func(p *peer) {
			defer wg.Done()
			n.deliver(ctx, p)
		}(p)
	}
	wg.Wait()
}

func (n *Node) deliver(ctx context.Context, p *peer) {
	for {
		var first envelope.Envelope
		select {
		case <-ctx.Done():
			return
		case first = <-p.queue:
		}
		batch := []envelope.Envelope{first}
	drain:
		for len(batch) < MaxBatch {
			select {
			case e := <-p.queue:
				batch = append(batch, e)
			default:
				break drain
			}
		}
		if err := n.send(ctx, p, batch); err != nil {
			n.stats.sendErrors.Add(1)
			n.cfg.Logger.Warn("gossip delivery failed", "peer", p.member.ID, "envelopes", len(batch), "err", err)
		}
	}
}

func (n *Node) send(ctx context.Context, p *peer, batch []envelope.Envelope) error {
	body, err := json.Marshal(batch)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.cfg.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("peer answered %s", resp.Status)
	}
	return nil
}
