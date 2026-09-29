package envelope

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

func testKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func setup(t *testing.T) (*Signer, *Signer, *Keyring) {
	t.Helper()
	alice, err := NewSigner("alice", testKey(1))
	if err != nil {
		t.Fatal(err)
	}
	mallory, err := NewSigner("mallory", testKey(2))
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{
		"alice":   testKey(1).Public().(ed25519.PublicKey),
		"mallory": testKey(2).Public().(ed25519.PublicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	return alice, mallory, ring
}

func aliceSignal() pheromone.Signal {
	return pheromone.Signal{
		Origin: "alice", Subject: "db-1", Kind: "net.lateral",
		Strength: 0.9, At: time.Unix(1_700_000_000, 42),
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	alice, _, ring := setup(t)
	env, err := alice.Seal(aliceSignal())
	if err != nil {
		t.Fatal(err)
	}

	got, err := ring.Open(env)

	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got != aliceSignal() {
		t.Fatalf("signal changed in transit: %+v", got)
	}
}

func TestTamperedFieldsAreRejected(t *testing.T) {
	alice, _, ring := setup(t)
	env, err := alice.Seal(aliceSignal())
	if err != nil {
		t.Fatal(err)
	}

	tamper := map[string]func(*pheromone.Signal){
		"subject":  func(s *pheromone.Signal) { s.Subject = "web-1" },
		"kind":     func(s *pheromone.Signal) { s.Kind = "proc.exec" },
		"strength": func(s *pheromone.Signal) { s.Strength = 0.1 },
		"time":     func(s *pheromone.Signal) { s.At = s.At.Add(time.Nanosecond) },
	}
	for name, mutate := range tamper {
		forged := env
		mutate(&forged.Signal)
		if _, err := ring.Open(forged); !errors.Is(err, ErrBadSignature) {
			t.Errorf("tampered %s: want ErrBadSignature, got %v", name, err)
		}
	}
}

func TestCannotForgeAnotherOrigin(t *testing.T) {
	alice, mallory, ring := setup(t)

	// A signer refuses to sign in someone else's name...
	if _, err := mallory.Seal(aliceSignal()); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("want ErrOriginMismatch, got %v", err)
	}

	// ...and a hand-built envelope signed with the wrong key fails to verify.
	forged := Envelope{Signal: aliceSignal(), Signature: ed25519.Sign(testKey(2), canonical(aliceSignal()))}
	if _, err := ring.Open(forged); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("want ErrBadSignature, got %v", err)
	}
	_ = alice
}

func TestUnknownOriginIsRejected(t *testing.T) {
	_, _, ring := setup(t)
	stranger, err := NewSigner("stranger", testKey(3))
	if err != nil {
		t.Fatal(err)
	}
	s := aliceSignal()
	s.Origin = "stranger"
	env, err := stranger.Seal(s)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := ring.Open(env); !errors.Is(err, ErrUnknownOrigin) {
		t.Fatalf("want ErrUnknownOrigin, got %v", err)
	}
}

func TestCanonicalEncodingIsUnambiguous(t *testing.T) {
	// Naive concatenation would encode these two identically.
	a := pheromone.Signal{Origin: "ab", Subject: "c", At: time.Unix(1, 0)}
	b := pheromone.Signal{Origin: "a", Subject: "bc", At: time.Unix(1, 0)}

	if bytes.Equal(canonical(a), canonical(b)) {
		t.Fatal("distinct signals must have distinct encodings")
	}
}

func TestInvalidKeys(t *testing.T) {
	if _, err := NewSigner("", testKey(1)); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("empty id: got %v", err)
	}
	if _, err := NewSigner("x", ed25519.PrivateKey{1, 2, 3}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("short key: got %v", err)
	}
	if _, err := NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{"x": {1}}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("short public key: got %v", err)
	}
}

func TestKeyringIsIsolatedFromCallerMutation(t *testing.T) {
	pub := append(ed25519.PublicKey(nil), testKey(1).Public().(ed25519.PublicKey)...)
	keys := map[pheromone.NodeID]ed25519.PublicKey{"alice": pub}
	ring, err := NewKeyring(keys)
	if err != nil {
		t.Fatal(err)
	}
	alice, _ := NewSigner("alice", testKey(1))
	env, _ := alice.Seal(aliceSignal())

	pub[0] ^= 0xff
	delete(keys, "alice")

	if _, err := ring.Open(env); err != nil {
		t.Fatalf("keyring must not share state with caller: %v", err)
	}
	if alice.ID() != "alice" {
		t.Fatal("ID mismatch")
	}
}
