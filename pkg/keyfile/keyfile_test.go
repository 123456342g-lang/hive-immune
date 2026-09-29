package keyfile

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	key, err := Generate(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := Save(path, key); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)

	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("loaded key differs")
	}
	if len(PublicHex(key)) != 64 {
		t.Fatalf("public hex %q", PublicHex(key))
	}
}

func TestSaveNeverOverwrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "node.key")
	first, _ := Generate(rand.Reader)
	second, _ := Generate(rand.Reader)
	if err := Save(path, first); err != nil {
		t.Fatal(err)
	}

	if err := Save(path, second); err == nil {
		t.Fatal("second Save must fail")
	}
	got, err := Load(path)
	if err != nil || !bytes.Equal(got, first) {
		t.Fatal("original key must be untouched")
	}
}

func TestLoadRejectsBadFiles(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{"not hex": "zz", "short": "abcd", "empty": ""}
	for name, content := range cases {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(path); !errors.Is(err, ErrBadKeyFile) {
			t.Errorf("%s: want ErrBadKeyFile, got %v", name, err)
		}
	}
	if _, err := Load(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file must fail")
	}
}

func TestSaveRejectsBadKey(t *testing.T) {
	if err := Save(filepath.Join(t.TempDir(), "k"), []byte{1}); !errors.Is(err, ErrBadKeyFile) {
		t.Fatalf("got %v", err)
	}
}

func TestGeneratePropagatesRandomnessFailure(t *testing.T) {
	if _, err := Generate(bytes.NewReader(nil)); err == nil {
		t.Fatal("empty randomness must fail")
	}
}
