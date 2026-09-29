// Package cluster describes swarm membership: which nodes exist, their
// public keys, where to reach them, and which zone they belong to.
//
// Membership is a static, operator-distributed file (peers.json). It is the
// trust anchor of the swarm: only members listed here can sign signals that
// other nodes accept.
package cluster

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// MaxMembers bounds the membership list. Gossip is all-to-all, so very large
// swarms need a different transport anyway.
const MaxMembers = 1000

// maxFileBytes bounds the membership file.
const maxFileBytes = 4 << 20

// ErrInvalid is returned for an unusable membership file.
var ErrInvalid = errors.New("cluster: invalid membership")

// Member is one node of the swarm.
type Member struct {
	ID        pheromone.NodeID `json:"id"`
	PublicKey string           `json:"public_key"` // hex Ed25519 public key
	Addr      string           `json:"addr"`       // gossip base URL, e.g. http://10.0.0.5:7946
	Zone      string           `json:"zone"`       // optional group sharing alert posture
}

// Config is the full membership list.
type Config struct {
	Members []Member `json:"members"`
}

// Load reads and validates a membership file.
func Load(path string) (Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("cluster: %w", err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return Config{}, fmt.Errorf("cluster: reading %s: %w", path, err)
	}
	if len(raw) > maxFileBytes {
		return Config{}, fmt.Errorf("%w: %s is larger than %d bytes", ErrInvalid, path, maxFileBytes)
	}
	return Parse(raw)
}

// Parse decodes and validates membership JSON. Unknown fields are rejected
// so typos do not silently disable settings.
func Parse(raw []byte) (Config, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return Config{}, fmt.Errorf("%w: %v", ErrInvalid, err)
	}
	if err := c.Validate(); err != nil {
		return Config{}, err
	}
	return c, nil
}

// Validate checks ids, keys and addresses.
func (c Config) Validate() error {
	if len(c.Members) == 0 || len(c.Members) > MaxMembers {
		return fmt.Errorf("%w: need 1-%d members, got %d", ErrInvalid, MaxMembers, len(c.Members))
	}
	seen := make(map[pheromone.NodeID]bool, len(c.Members))
	for _, m := range c.Members {
		if m.ID == "" || len(m.ID) > 128 || strings.ContainsAny(string(m.ID), " \t\r\n") {
			return fmt.Errorf("%w: member id %q must be 1-128 characters without whitespace", ErrInvalid, m.ID)
		}
		if seen[m.ID] {
			return fmt.Errorf("%w: duplicate member %q", ErrInvalid, m.ID)
		}
		seen[m.ID] = true
		if _, err := decodeKey(m.PublicKey); err != nil {
			return fmt.Errorf("%w: member %q: %v", ErrInvalid, m.ID, err)
		}
		if m.Addr != "" {
			u, err := url.Parse(m.Addr)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				return fmt.Errorf("%w: member %q addr %q must be an http(s) URL", ErrInvalid, m.ID, m.Addr)
			}
		}
	}
	return nil
}

// Keyring builds the verification keyring for all members.
func (c Config) Keyring() (*envelope.Keyring, error) {
	keys := make(map[pheromone.NodeID]ed25519.PublicKey, len(c.Members))
	for _, m := range c.Members {
		k, err := decodeKey(m.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("%w: member %q: %v", ErrInvalid, m.ID, err)
		}
		keys[m.ID] = k
	}
	return envelope.NewKeyring(keys)
}

// Member looks up a member by id.
func (c Config) Member(id pheromone.NodeID) (Member, bool) {
	for _, m := range c.Members {
		if m.ID == id {
			return m, true
		}
	}
	return Member{}, false
}

// Peers returns every reachable member other than self, sorted by id.
func (c Config) Peers(self pheromone.NodeID) []Member {
	var out []Member
	for _, m := range c.Members {
		if m.ID != self && m.Addr != "" {
			out = append(out, m)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Generate creates a membership config and private keys for ids. addrTmpl
// may contain "{id}", e.g. "http://{id}:7946".
func Generate(ids []string, addrTmpl, zone string, rand io.Reader) (Config, map[pheromone.NodeID]ed25519.PrivateKey, error) {
	keys := make(map[pheromone.NodeID]ed25519.PrivateKey, len(ids))
	var c Config
	for _, raw := range ids {
		id := pheromone.NodeID(strings.TrimSpace(raw))
		pub, priv, err := ed25519.GenerateKey(rand)
		if err != nil {
			return Config{}, nil, fmt.Errorf("cluster: generating key for %q: %w", id, err)
		}
		keys[id] = priv
		c.Members = append(c.Members, Member{
			ID: id, PublicKey: hex.EncodeToString(pub),
			Addr: strings.ReplaceAll(addrTmpl, "{id}", string(id)), Zone: zone,
		})
	}
	if err := c.Validate(); err != nil {
		return Config{}, nil, err
	}
	return c, keys, nil
}

func decodeKey(h string) (ed25519.PublicKey, error) {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public_key must be %d hex-encoded bytes", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
