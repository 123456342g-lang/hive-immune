package envelope

import (
	"bytes"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// FuzzOpen feeds arbitrary envelopes to the verifier. It must never panic,
// and it must only ever accept a signal whose canonical encoding is exactly
// the one alice signed.
func FuzzOpen(f *testing.F) {
	alice, err := NewSigner("alice", testKey(1))
	if err != nil {
		f.Fatal(err)
	}
	ring, err := NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{
		"alice": testKey(1).Public().(ed25519.PublicKey),
	})
	if err != nil {
		f.Fatal(err)
	}
	genuine, err := alice.Seal(aliceSignal())
	if err != nil {
		f.Fatal(err)
	}
	want := canonical(genuine.Signal)

	s := genuine.Signal
	f.Add(string(s.Origin), string(s.Subject), s.Kind, s.Strength, s.At.UnixNano(), genuine.Signature)
	f.Add("alice", "", "", 0.0, int64(0), []byte{})
	f.Add("mallory", "x", "y", 1.0, int64(-1), make([]byte, ed25519.SignatureSize))

	f.Fuzz(func(t *testing.T, origin, subject, kind string, strength float64, unixNano int64, sig []byte) {
		env := Envelope{
			Signal: pheromone.Signal{
				Origin: pheromone.NodeID(origin), Subject: pheromone.NodeID(subject),
				Kind: kind, Strength: strength, At: time.Unix(0, unixNano),
			},
			Signature: sig,
		}
		got, err := ring.Open(env)
		if err != nil {
			return
		}
		if !bytes.Equal(canonical(got), want) {
			t.Fatalf("accepted a signal alice never signed: %+v", got)
		}
	})
}
