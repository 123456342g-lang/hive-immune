package credential

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"testing"

	"github.com/123456342g-lang/hive-immune/pkg/dsse"
)

// fuzzKey is a fixed signing key so every run of the corpus looks the same.
func fuzzKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, ed25519.SeedSize))
}

// FuzzVerify walks the exact path hive-agent verify uses: a JSONL line in,
// a payload out. Arbitrary lines and keys must never panic, and anything
// accepted must carry the gateway decision schema.
func FuzzVerify(f *testing.F) {
	key := fuzzKey()
	pub := key.Public().(ed25519.PublicKey)
	payload, err := json.Marshal(Payload{Schema: Schema, Decision: json.RawMessage(`{"tool":"send_email"}`)})
	if err != nil {
		f.Fatal(err)
	}
	env, err := dsse.Sign(PayloadType, payload, key, KeyID(key))
	if err != nil {
		f.Fatal(err)
	}
	line, err := json.Marshal(env)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(string(line), []byte(pub))
	f.Add("", []byte(pub))
	f.Add("{}", []byte(pub))
	f.Add(string(line), []byte("short"))
	f.Add(string(line), []byte{})
	f.Add(string(line), bytes.Repeat([]byte{1}, ed25519.PublicKeySize))

	f.Fuzz(func(t *testing.T, line string, pub []byte) {
		var env dsse.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			return
		}
		p, err := Verify(env, ed25519.PublicKey(pub))
		if err != nil {
			return
		}
		if p.Schema != Schema {
			t.Fatalf("accepted schema %q", p.Schema)
		}
		if len(p.Decision) == 0 {
			t.Fatal("accepted payload without a decision")
		}
	})
}
