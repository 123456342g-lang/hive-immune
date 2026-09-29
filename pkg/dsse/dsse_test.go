package dsse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"testing"
)

func newKey(t *testing.T) (ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	priv, pub := newKey(t)
	payload := []byte(`{"action":"allow","tool":"read_file"}`)
	env, err := Sign("hive-immune/gateway-decision+json", payload, priv, "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Verify(env, pub, "cred-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("payload = %s", got)
	}
	// Key id is optional for the verifier.
	if _, err := Verify(env, pub, ""); err != nil {
		t.Fatalf("verify without key id: %v", err)
	}
}

func TestCanonicalBindsPayloadType(t *testing.T) {
	priv, pub := newKey(t)
	payload := []byte("same bytes")
	env, err := Sign("type/a", payload, priv, "")
	if err != nil {
		t.Fatal(err)
	}
	// Rewriting the type invalidates the signature: an envelope signed as
	// one type cannot be replayed as another.
	env.PayloadType = "type/b"
	if _, err := Verify(env, pub, ""); err == nil {
		t.Fatal("payload type swap must fail")
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	priv, pub := newKey(t)
	env, err := Sign("t", []byte("original"), priv, "k")
	if err != nil {
		t.Fatal(err)
	}

	tampered := env
	tampered.Payload = base64.StdEncoding.EncodeToString([]byte("forged"))
	if _, err := Verify(tampered, pub, ""); err == nil {
		t.Fatal("a rewritten payload must fail")
	}

	raw, _ := base64.StdEncoding.DecodeString(env.Payload)
	tampered = env
	tampered.Payload = base64.StdEncoding.EncodeToString(append(raw, '!'))
	if _, err := Verify(tampered, pub, ""); err == nil {
		t.Fatal("an extended payload must fail")
	}

	otherPub := func() ed25519.PublicKey { _, p := newKey(t); return p }()
	if _, err := Verify(env, otherPub, ""); err == nil {
		t.Fatal("the wrong public key must fail")
	}

	noSigs := env
	noSigs.Signatures = nil
	if _, err := Verify(noSigs, pub, ""); err != ErrNoSignatures {
		t.Fatalf("err = %v, want ErrNoSignatures", err)
	}

	badSig := env
	badSig.Signatures = []Signature{{KeyID: "k", Sig: "not base64!"}}
	if _, err := Verify(badSig, pub, ""); err == nil {
		t.Fatal("an undecodable signature must fail")
	}

	emptyType := env
	emptyType.PayloadType = ""
	if _, err := Verify(emptyType, pub, ""); err == nil {
		t.Fatal("an envelope without payload type must fail")
	}
}

func TestSignRejectsBadInput(t *testing.T) {
	priv, _ := newKey(t)
	if _, err := Sign("", []byte("x"), priv, ""); err == nil {
		t.Fatal("empty payload type must fail")
	}
	if _, err := Sign("t", []byte("x"), make([]byte, 4), ""); err == nil {
		t.Fatal("short signing key must fail")
	}
}

// TestVerifyPicksKeyID: a multi-signer envelope only counts the signature
// the verifier asked for.
func TestVerifyPicksKeyID(t *testing.T) {
	privA, _ := newKey(t)
	_, pubB := newKey(t)
	env, err := Sign("t", []byte("x"), privA, "a")
	if err != nil {
		t.Fatal(err)
	}
	env.Signatures = append(env.Signatures, Signature{KeyID: "b", Sig: env.Signatures[0].Sig})
	if _, err := Verify(env, pubB, "b"); err == nil {
		t.Fatal("signature from key a must not satisfy key b")
	}
	if _, err := Verify(env, pubB, ""); err == nil {
		t.Fatal("no key id means every signature must verify against pub")
	}
}

func TestCanonicalLayout(t *testing.T) {
	got := string(Canonical("abc", []byte("12345")))
	want := "DSSEv1 3 abc 5 12345"
	if got != want {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, "DSSEv1 ") {
		t.Fatal("DSSEv1 prefix is part of the spec")
	}
}
