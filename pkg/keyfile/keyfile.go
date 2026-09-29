// Package keyfile stores a node's Ed25519 identity key on disk.
//
// The file holds the 32-byte seed as hex followed by a newline. It is
// created with mode 0600 and never overwritten, so a mistyped command
// cannot silently replace a node's identity.
package keyfile

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrBadKeyFile means the file does not contain a valid seed.
var ErrBadKeyFile = errors.New("keyfile: invalid key file")

// Generate creates a new private key from rand (use crypto/rand.Reader).
func Generate(rand io.Reader) (ed25519.PrivateKey, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, fmt.Errorf("keyfile: reading randomness: %w", err)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Save writes key to a new file at path. It fails if the file exists.
func Save(path string, key ed25519.PrivateKey) (err error) {
	if len(key) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: private key must be %d bytes", ErrBadKeyFile, ed25519.PrivateKeySize)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keyfile: creating %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); err == nil && cerr != nil {
			err = fmt.Errorf("keyfile: closing %s: %w", path, cerr)
		}
	}()
	if _, err := fmt.Fprintln(f, hex.EncodeToString(key.Seed())); err != nil {
		return fmt.Errorf("keyfile: writing %s: %w", path, err)
	}
	return nil
}

// Load reads a key written by Save.
func Load(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keyfile: reading %s: %w", path, err)
	}
	seed, err := hex.DecodeString(string(bytes.TrimSpace(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: %s must contain a %d-byte hex seed", ErrBadKeyFile, path, ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// PublicHex returns the hex public key, for distribution to other nodes.
func PublicHex(key ed25519.PrivateKey) string {
	return hex.EncodeToString(key.Public().(ed25519.PublicKey))
}
