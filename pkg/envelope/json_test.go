package envelope

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDigestTracksSignedContent(t *testing.T) {
	a := aliceSignal()
	b := aliceSignal()
	b.Strength = 0.5

	if Digest(a) != Digest(aliceSignal()) || Digest(a) == Digest(b) {
		t.Fatal("digest must be stable for equal signals and differ otherwise")
	}
}

// The JSON wire format must round-trip exactly, including nanosecond
// timestamps and float strengths, or signatures would stop verifying.
func TestJSONRoundTripKeepsSignatureValid(t *testing.T) {
	alice, _, ring := setup(t)
	env, err := alice.Seal(aliceSignal())
	if err != nil {
		t.Fatal(err)
	}

	raw, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Envelope
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}

	if _, err := ring.Open(decoded); err != nil {
		t.Fatalf("decoded envelope must verify: %v\n%s", err, raw)
	}
	for _, field := range []string{`"signal"`, `"signature"`, `"origin"`, `"strength"`, `"at"`} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("wire format missing %s: %s", field, raw)
		}
	}
}
