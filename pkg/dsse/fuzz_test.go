package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

// FuzzVerify: whatever an attacker puts in an envelope - truncated keys,
// junk base64, swapped payload types - Verify either rejects it or returns
// the payload it signed, and never disagrees with itself between two runs.
// The envelope fields are passed individually because fuzz targets only
// take primitive arguments.
func FuzzVerify(f *testing.F) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	good, err := Sign("hive-immune/test+json", []byte(`{"hello":"world"}`), priv, "k1")
	if err != nil {
		f.Fatal(err)
	}

	f.Add(good.Payload, good.PayloadType, good.Signatures[0].KeyID, good.Signatures[0].Sig, []byte(pub))
	f.Add(good.Payload, good.PayloadType, good.Signatures[0].KeyID, good.Signatures[0].Sig, []byte{})
	f.Add("", "", "", "", []byte(pub))
	f.Add("%%%", "t", "k1", good.Signatures[0].Sig, []byte(pub))
	f.Add(good.Payload, "", "k1", good.Signatures[0].Sig, []byte(pub))
	f.Add(good.Payload, "hive-immune/other+json", "k1", good.Signatures[0].Sig, []byte(pub))
	f.Add(good.Payload, good.PayloadType, "k1", "!", []byte(pub))

	f.Fuzz(func(t *testing.T, payload, payloadType, keyID, sig string, pub []byte) {
		env := Envelope{
			Payload:     payload,
			PayloadType: payloadType,
			Signatures:  []Signature{{KeyID: keyID, Sig: sig}},
		}
		got, err := Verify(env, pub, "")
		if err != nil {
			return
		}
		again, err := Verify(env, pub, "")
		if err != nil {
			t.Fatalf("verify accepted then rejected: %v", err)
		}
		if !bytes.Equal(got, again) {
			t.Fatalf("verify returned %q then %q", got, again)
		}
	})
}
