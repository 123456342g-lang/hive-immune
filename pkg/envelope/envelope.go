// Package envelope signs and verifies pheromone signals with Ed25519.
//
// A swarm defense is only as trustworthy as its signals. If an attacker can
// deposit signals in another node's name, they can frame healthy nodes or
// drown out real alarms. Every signal therefore travels in a signed envelope,
// and receivers only accept it when the signature matches the key registered
// for the claimed origin.
package envelope

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/123456342g-lang/hive-immune/pkg/pheromone"
)

// domain separates hive-immune signal signatures from any other use of the
// same key, and versions the canonical encoding.
const domain = "hive-immune/signal/v1\x00"

var (
	// ErrUnknownOrigin means no public key is registered for the origin.
	ErrUnknownOrigin = errors.New("envelope: unknown origin")
	// ErrBadSignature means the signature does not verify.
	ErrBadSignature = errors.New("envelope: bad signature")
	// ErrOriginMismatch means a signer was asked to sign for another node.
	ErrOriginMismatch = errors.New("envelope: origin does not match signer")
	// ErrInvalidKey means a key has the wrong size.
	ErrInvalidKey = errors.New("envelope: invalid key")
)

// Envelope carries a signal and its signature over the canonical encoding.
// Its JSON form ({"signal": ..., "signature": "<base64>"}) is the wire format
// emitted by hive-agent.
type Envelope struct {
	Signal    pheromone.Signal `json:"signal"`
	Signature []byte           `json:"signature"`
}

// Signer signs signals on behalf of exactly one node.
type Signer struct {
	id  pheromone.NodeID
	key ed25519.PrivateKey
}

// NewSigner binds a private key to a node identity.
func NewSigner(id pheromone.NodeID, key ed25519.PrivateKey) (*Signer, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: empty node id", ErrInvalidKey)
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key must be %d bytes", ErrInvalidKey, ed25519.PrivateKeySize)
	}
	return &Signer{id: id, key: key}, nil
}

// ID returns the node this signer speaks for.
func (s *Signer) ID() pheromone.NodeID { return s.id }

// Seal signs sig. The signal's origin must be the signer's own node.
func (s *Signer) Seal(sig pheromone.Signal) (Envelope, error) {
	if sig.Origin != s.id {
		return Envelope{}, fmt.Errorf("%w: signer %q, origin %q", ErrOriginMismatch, s.id, sig.Origin)
	}
	return Envelope{Signal: sig, Signature: ed25519.Sign(s.key, canonical(sig))}, nil
}

// Keyring maps node identities to their public keys. It is immutable after
// construction and safe for concurrent use.
type Keyring struct {
	keys map[pheromone.NodeID]ed25519.PublicKey
}

// NewKeyring copies keys into a new keyring, rejecting malformed entries.
func NewKeyring(keys map[pheromone.NodeID]ed25519.PublicKey) (*Keyring, error) {
	copied := make(map[pheromone.NodeID]ed25519.PublicKey, len(keys))
	for id, k := range keys {
		if id == "" || len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: entry for %q", ErrInvalidKey, id)
		}
		copied[id] = append(ed25519.PublicKey(nil), k...)
	}
	return &Keyring{keys: copied}, nil
}

// Open verifies an envelope and returns its signal.
func (k *Keyring) Open(e Envelope) (pheromone.Signal, error) {
	pub, ok := k.keys[e.Signal.Origin]
	if !ok {
		return pheromone.Signal{}, fmt.Errorf("%w: %q", ErrUnknownOrigin, e.Signal.Origin)
	}
	if !ed25519.Verify(pub, canonical(e.Signal), e.Signature) {
		return pheromone.Signal{}, fmt.Errorf("%w: origin %q", ErrBadSignature, e.Signal.Origin)
	}
	return e.Signal, nil
}

// Digest identifies a signal by the content its signature covers. Two
// envelopes with the same digest carry the same signed statement, which is
// what replay and duplicate detection need.
func Digest(s pheromone.Signal) [32]byte { return sha256.Sum256(canonical(s)) }

// canonical returns an unambiguous byte encoding of a signal. Variable-length
// fields are length-prefixed so that no two distinct signals share an
// encoding (unlike naive concatenation or map-ordered JSON).
func canonical(s pheromone.Signal) []byte {
	buf := make([]byte, 0, len(domain)+len(s.Origin)+len(s.Subject)+len(s.Kind)+40)
	buf = append(buf, domain...)
	buf = appendString(buf, string(s.Origin))
	buf = appendString(buf, string(s.Subject))
	buf = appendString(buf, s.Kind)
	buf = binary.BigEndian.AppendUint64(buf, math.Float64bits(s.Strength))
	buf = binary.BigEndian.AppendUint64(buf, uint64(s.At.UnixNano()))
	return buf
}

func appendString(buf []byte, s string) []byte {
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(s)))
	return append(buf, s...)
}
