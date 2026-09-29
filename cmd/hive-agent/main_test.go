package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hive-immune/hive-immune/pkg/envelope"
	"github.com/hive-immune/hive-immune/pkg/pheromone"
)

// The captured fixtures are from a fixed date, so accept any age in tests.
const anyAge = "876000h"

func newKey(t *testing.T) (path string, pub ed25519.PublicKey) {
	t.Helper()
	path = filepath.Join(t.TempDir(), "node.key")
	var out bytes.Buffer
	if err := dispatch([]string{"keygen", "-out", path}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}
	raw, err := hex.DecodeString(strings.TrimSpace(out.String()))
	if err != nil {
		t.Fatal(err)
	}
	return path, ed25519.PublicKey(raw)
}

func decodeEnvelopes(t *testing.T, out string, node pheromone.NodeID, pub ed25519.PublicKey) []envelope.Envelope {
	t.Helper()
	ring, err := envelope.NewKeyring(map[pheromone.NodeID]ed25519.PublicKey{node: pub})
	if err != nil {
		t.Fatal(err)
	}
	var envs []envelope.Envelope
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		var e envelope.Envelope
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad output line %q: %v", sc.Text(), err)
		}
		if _, err := ring.Open(e); err != nil {
			t.Fatalf("output does not verify with the published key: %v", err)
		}
		envs = append(envs, e)
	}
	return envs
}

func TestKeygenPubkeyAgree(t *testing.T) {
	path, pub := newKey(t)
	var out bytes.Buffer

	if err := dispatch([]string{"pubkey", "-key", path}, nil, &out, &out); err != nil {
		t.Fatal(err)
	}

	if strings.TrimSpace(out.String()) != hex.EncodeToString(pub) {
		t.Fatalf("pubkey %q does not match keygen output", out.String())
	}
	if err := dispatch([]string{"keygen", "-out", path}, nil, &out, &out); err == nil {
		t.Fatal("keygen must refuse to overwrite an existing key")
	}
}

func TestRunFalcoFromStdin(t *testing.T) {
	keyPath, pub := newKey(t)
	input, err := os.ReadFile("../../pkg/sensor/testdata/falco.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer

	err = dispatch([]string{"run", "-node", "web-1", "-key", keyPath, "-source", "falco", "-max-age", anyAge},
		bytes.NewReader(input), &stdout, &stderr)

	if err != nil {
		t.Fatal(err)
	}
	envs := decodeEnvelopes(t, stdout.String(), "web-1", pub)
	if len(envs) != 1 || envs[0].Signal.Kind != "falco.Read sensitive file untrusted" || envs[0].Signal.Subject != "web-1" {
		t.Fatalf("unexpected output: %+v", envs)
	}
	if !strings.Contains(stderr.String(), "emitted=1") {
		t.Fatalf("stats missing: %s", stderr.String())
	}
}

func TestRunTetragonFromFile(t *testing.T) {
	keyPath, pub := newKey(t)
	var stdout, stderr bytes.Buffer

	err := dispatch([]string{"run", "-node", "db-1", "-key", keyPath, "-source", "tetragon",
		"-in", "../../pkg/sensor/testdata/tetragon.jsonl", "-max-age", anyAge,
		"-policy", "hive-sensitive-files=0.8", "-policy", "hive-tcp-connect=0.1"}, nil, &stdout, &stderr)

	if err != nil {
		t.Fatal(err)
	}
	envs := decodeEnvelopes(t, stdout.String(), "db-1", pub)
	if len(envs) != 1 || envs[0].Signal.Kind != "tetragon.hive-sensitive-files" {
		t.Fatalf("unexpected output: %+v", envs)
	}
	if !strings.Contains(stderr.String(), "skipped=2") {
		t.Fatalf("stats: %s", stderr.String())
	}
}

func TestRunRejectsBadUsage(t *testing.T) {
	keyPath, _ := newKey(t)
	bad := [][]string{
		{},
		{"nope"},
		{"run", "-source", "falco", "-key", keyPath},
		{"run", "-node", "n", "-key", keyPath, "-source", "snort"},
		{"run", "-node", "n", "-key", keyPath, "-source", "tetragon"},
		{"run", "-node", "n", "-key", keyPath, "-source", "falco", "-policy", "p=0.5"},
		{"run", "-node", "n", "-key", keyPath, "-source", "tetragon", "-policy", "p"},
		{"run", "-node", "n", "-key", keyPath, "-source", "tetragon", "-policy", "p=high"},
		{"run", "-node", "n", "-key", keyPath, "-source", "falco", "-min", "0"},
		{"run", "-node", "n", "-key", keyPath, "-source", "falco", "-in", "does-not-exist"},
		{"run", "-node", "n", "-key", "missing.key", "-source", "falco"},
		{"pubkey", "-key", "missing.key"},
		{"keygen", "-bogus"},
		{"pubkey", "-bogus"},
		{"run", "-bogus"},
	}
	for _, args := range bad {
		var out bytes.Buffer
		if err := dispatch(args, strings.NewReader(""), &out, &out); err == nil {
			t.Errorf("args %v should fail", args)
		}
	}
}

func TestPolicyFlagString(t *testing.T) {
	p := policyFlag{}
	_ = p.Set("b=0.5")
	_ = p.Set("a=1")
	if p.String() != "a=1,b=0.5" {
		t.Fatalf("got %q", p.String())
	}
}
