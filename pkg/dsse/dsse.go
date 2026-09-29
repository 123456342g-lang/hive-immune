// Package dsse implements the Dead Simple Signing Envelope: a payload, a
// payload type and one or more signatures over a canonical form of both.
//
// DSSE is used because the credential a gateway emits has to be checkable
// by someone who does not run the gateway: the verifier needs nothing but
// the public key and the envelope itself. The signed string is
//
//	DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
//
// so the payload type is covered by the signature too - a signature over a
// "log line" can never be replayed as a signature over an "attestation".
package dsse

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
)

// ErrNoSignatures means the envelope carries nothing to verify.
var ErrNoSignatures = errors.New("dsse: envelope has no signatures")

// Signature is one signer's opinion over the payload.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"`
}

// Envelope is the wire form of a DSSE envelope (JSON object).
type Envelope struct {
	Payload     string      `json:"payload"` // standard base64
	PayloadType string      `json:"payloadType"`
	Signatures  []Signature `json:"signatures"`
}

// Canonical returns the byte string that is signed for this payload.
func Canonical(payloadType string, payload []byte) []byte {
	return []byte("DSSEv1 " + strconv.Itoa(len(payloadType)) + " " + payloadType +
		" " + strconv.Itoa(len(payload)) + " " + string(payload))
}

// Sign builds a signed envelope for payload. keyID is informational: it
// lets a verifier pick the right signature in a multi-signer envelope.
func Sign(payloadType string, payload []byte, key ed25519.PrivateKey, keyID string) (Envelope, error) {
	if payloadType == "" {
		return Envelope{}, errors.New("dsse: payload type must not be empty")
	}
	if len(key) != ed25519.PrivateKeySize {
		return Envelope{}, fmt.Errorf("dsse: signing key must be %d bytes", ed25519.PrivateKeySize)
	}
	sig := ed25519.Sign(key, Canonical(payloadType, payload))
	return Envelope{
		Payload:     base64.StdEncoding.EncodeToString(payload),
		PayloadType: payloadType,
		Signatures:  []Signature{{KeyID: keyID, Sig: base64.StdEncoding.EncodeToString(sig)}},
	}, nil
}

// Verify checks the envelope against pub and returns the payload. When
// keyID is not empty the matching signature must exist; otherwise the
// first signature that verifies wins.
func Verify(env Envelope, pub ed25519.PublicKey, keyID string) ([]byte, error) {
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("dsse: public key must be %d bytes", ed25519.PublicKeySize)
	}
	if len(env.Signatures) == 0 {
		return nil, ErrNoSignatures
	}
	if env.PayloadType == "" {
		return nil, errors.New("dsse: envelope has no payload type")
	}
	payload, err := base64.StdEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("dsse: payload is not base64: %w", err)
	}
	canonical := Canonical(env.PayloadType, payload)
	for _, sig := range env.Signatures {
		if keyID != "" && sig.KeyID != keyID {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			continue
		}
		if ed25519.Verify(pub, canonical, raw) {
			return payload, nil
		}
	}
	if keyID != "" {
		return nil, fmt.Errorf("dsse: no valid signature for key id %q", keyID)
	}
	return nil, errors.New("dsse: no valid signature")
}
