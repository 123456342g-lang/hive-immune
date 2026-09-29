package cluster

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func demo(t *testing.T) Config {
	t.Helper()
	c, keys, err := Generate([]string{"node-2", "node-1", " node-3 "}, "http://{id}:7946", "demo", rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 3 {
		t.Fatalf("want 3 keys, got %d", len(keys))
	}
	return c
}

func TestGenerateAndRoundTrip(t *testing.T) {
	c := demo(t)
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "peers.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	loaded, err := Load(path)

	if err != nil {
		t.Fatal(err)
	}
	m, ok := loaded.Member("node-3")
	if !ok || m.Addr != "http://node-3:7946" || m.Zone != "demo" {
		t.Fatalf("member node-3: %+v %v", m, ok)
	}
	if _, ok := loaded.Member("nope"); ok {
		t.Fatal("unknown member found")
	}
	if _, err := loaded.Keyring(); err != nil {
		t.Fatal(err)
	}
}

func TestPeersExcludeSelfAndUnreachable(t *testing.T) {
	c := demo(t)
	c.Members[0].Addr = "" // node-2 has no address

	peers := c.Peers("node-1")

	if len(peers) != 1 || peers[0].ID != "node-3" {
		t.Fatalf("got %+v", peers)
	}
}

func TestValidateRejects(t *testing.T) {
	base := demo(t)
	cases := map[string]func(*Config){
		"empty":        func(c *Config) { c.Members = nil },
		"no id":        func(c *Config) { c.Members[0].ID = "" },
		"space in id":  func(c *Config) { c.Members[0].ID = "a b" },
		"duplicate":    func(c *Config) { c.Members[1].ID = c.Members[0].ID },
		"bad key":      func(c *Config) { c.Members[0].PublicKey = "abcd" },
		"bad scheme":   func(c *Config) { c.Members[0].Addr = "ftp://x" },
		"missing host": func(c *Config) { c.Members[0].Addr = "http://" },
	}
	for name, mutate := range cases {
		c := Config{Members: append([]Member(nil), base.Members...)}
		mutate(&c)
		if err := c.Validate(); !errors.Is(err, ErrInvalid) {
			t.Errorf("%s: want ErrInvalid, got %v", name, err)
		}
		if name == "bad key" {
			if _, err := c.Keyring(); err == nil {
				t.Error("keyring must reject bad key")
			}
		}
	}
}

func TestParseRejectsUnknownFieldsAndGarbage(t *testing.T) {
	raw, _ := json.Marshal(demo(t))
	withTypo := bytes.Replace(raw, []byte(`"zone"`), []byte(`"zoen"`), 1)

	if _, err := Parse(withTypo); !errors.Is(err, ErrInvalid) {
		t.Errorf("typo must be rejected, got %v", err)
	}
	if _, err := Parse([]byte("{")); !errors.Is(err, ErrInvalid) {
		t.Errorf("garbage must be rejected, got %v", err)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.json")); err == nil {
		t.Error("missing file must fail")
	}
	big := filepath.Join(dir, "big.json")
	if err := os.WriteFile(big, []byte(strings.Repeat(" ", maxFileBytes+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(big); !errors.Is(err, ErrInvalid) {
		t.Errorf("oversized file: got %v", err)
	}
}

func TestGenerateErrors(t *testing.T) {
	if _, _, err := Generate([]string{"a"}, "", "", bytes.NewReader(nil)); err == nil {
		t.Error("randomness failure must surface")
	}
	if _, _, err := Generate([]string{"a", "a"}, "", "", rand.Reader); err == nil {
		t.Error("duplicate ids must fail")
	}
}
