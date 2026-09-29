// verify checks a file of signed gateway credentials: every line must be
// a DSSE envelope whose payload is a hive-immune decision signed by the
// gateway key the operator holds.
//
//	hive-gateway pubkey -key cred.key          # prints the hex public key
//	hive-agent verify -in credentials.jsonl -pub <hex>
//
// It reads like a receipt checker: one "ok" per line, a "fail" with the
// reason for anything edited or signed by someone else, and a non-zero
// exit as soon as one line does not hold up - so it can sit in a review
// pipeline between a customer and the audit trail they were handed.
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hive-immune/hive-immune/pkg/credential"
	"github.com/hive-immune/hive-immune/pkg/dsse"
)

// maxCredentialLine bounds one credential line: decisions carry digests
// and reasons, never tool payloads, so 4 MiB is already generous.
const maxCredentialLine = 4 << 20

// decision is the part of a signed gateway credential that verify reads.
type decision struct {
	Time   time.Time `json:"time"`
	Agent  string    `json:"agent"`
	Tool   string    `json:"tool"`
	Action string    `json:"action"`
	Rule   string    `json:"rule"`
	Reason string    `json:"reason"`
}

func verify(args []string, stdin io.Reader, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	in := fs.String("in", "-", "file with signed credentials, or - for stdin")
	pub := fs.String("pub", "", "hex public key of the gateway that signed them (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	key, err := decodePub(*pub)
	if err != nil {
		return err
	}
	input, closeInput, err := openInput(*in, stdin)
	if err != nil {
		return err
	}
	defer closeInput()

	total, failed := 0, 0
	sc := bufio.NewScanner(input)
	sc.Buffer(make([]byte, 0, 64*1024), maxCredentialLine)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		total++
		var env dsse.Envelope
		if err := json.Unmarshal([]byte(line), &env); err != nil {
			fmt.Fprintf(stdout, "fail line %d: not a credential envelope: %v\n", total, err)
			failed++
			continue
		}
		p, err := credential.Verify(env, key)
		if err != nil {
			fmt.Fprintf(stdout, "fail line %d: %v\n", total, err)
			failed++
			continue
		}
		var d decision
		if err := json.Unmarshal(p.Decision, &d); err != nil {
			fmt.Fprintf(stdout, "fail line %d: unreadable decision: %v\n", total, err)
			failed++
			continue
		}
		fmt.Fprintf(stdout, "ok   line %d %s agent=%s tool=%s action=%s rule=%s\n",
			total, d.Time.UTC().Format(time.RFC3339), d.Agent, d.Tool, d.Action, d.Rule)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("verify: reading: %w", err)
	}
	if total == 0 {
		return errors.New("verify: no credentials found")
	}
	if failed > 0 {
		return fmt.Errorf("verify: %d of %d credentials failed", failed, total)
	}
	fmt.Fprintf(stderr, "hive-agent: verified %d credentials\n", total)
	return nil
}

// decodePub accepts the hex public key that hive-gateway pubkey prints.
func decodePub(raw string) (ed25519.PublicKey, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, errors.New("verify: -pub is required (hive-gateway pubkey -key cred.key)")
	}
	b, err := hex.DecodeString(raw)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("verify: -pub must be a %d-byte hex public key", ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(b), nil
}
