// Package credential writes the gateway's decisions as DSSE envelopes: one
// signed statement per tools/call, appended to a JSONL file.
//
// The audit log answers "what happened" for the people who run the
// gateway; a credential answers the same question for people who do not
// trust the file it came from. Verification needs only the public key, so
// a reviewer, a customer or another swarm can check that this decision was
// really made by this gateway - and that nobody edited the line afterwards.
package credential

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/123456342g-lang/hive-immune/pkg/dsse"
)

// PayloadType is the DSSE payload type of every credential written here.
// It is covered by the signature, so a credential can never be replayed as
// a different kind of statement.
const PayloadType = "hive-immune/gateway-decision+json"

// Schema versions the decision payload itself.
const Schema = "hive-immune/gateway-decision/v1"

// Payload is the signed statement: a schema marker plus the decision the
// gateway made, exactly as the audit log records it.
type Payload struct {
	Schema   string          `json:"schema"`
	Decision json.RawMessage `json:"decision"`
}

// Log appends signed decisions. A nil *Log discards them, which is what a
// gateway without a credential key gets.
type Log struct {
	mu    sync.Mutex
	enc   *json.Encoder
	f     *os.File
	key   ed25519.PrivateKey
	keyID string
}

// KeyID is the default key identifier: the hex public key, so a verifier
// can pick the right signature out of an envelope.
func KeyID(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}

// Open starts appending signed credentials to path. An empty path returns
// a nil log (credentials disabled).
func Open(path string, key ed25519.PrivateKey) (*Log, error) {
	if path == "" {
		return nil, nil
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("credential: signing key must be %d bytes", ed25519.PrivateKeySize)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("credential: opening %s: %w", path, err)
	}
	return &Log{enc: json.NewEncoder(f), f: f, key: key, keyID: KeyID(key)}, nil
}

// Append signs one decision and writes it as a single JSON line. A closed
// log reports the failure instead of panicking; the caller keeps going
// because the audit line already holds the decision.
func (l *Log) Append(decision any) error {
	if l == nil {
		return nil
	}
	raw, err := json.Marshal(decision)
	if err != nil {
		return fmt.Errorf("credential: encoding decision: %w", err)
	}
	payload, err := json.Marshal(Payload{Schema: Schema, Decision: raw})
	if err != nil {
		return fmt.Errorf("credential: encoding payload: %w", err)
	}
	env, err := dsse.Sign(PayloadType, payload, l.key, l.keyID)
	if err != nil {
		return fmt.Errorf("credential: signing: %w", err)
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.enc == nil {
		return errors.New("credential: log is closed")
	}
	if err := l.enc.Encode(env); err != nil {
		return fmt.Errorf("credential: writing: %w", err)
	}
	return nil
}

// Close flushes and closes the file.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f, l.enc = nil, nil
	return err
}

// Verify checks an envelope against pub and returns its payload. The
// schema is validated so that a future payload type cannot be read as a
// decision by accident.
func Verify(env dsse.Envelope, pub ed25519.PublicKey) (Payload, error) {
	raw, err := dsse.Verify(env, pub, "")
	if err != nil {
		return Payload{}, err
	}
	var p Payload
	if err := json.Unmarshal(raw, &p); err != nil {
		return Payload{}, fmt.Errorf("credential: payload is not JSON: %w", err)
	}
	if p.Schema != Schema {
		return Payload{}, fmt.Errorf("credential: schema %q, want %q", p.Schema, Schema)
	}
	return p, nil
}
