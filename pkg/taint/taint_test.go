package taint

import (
	"testing"
	"time"
)

func TestParseSource(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Source
		ok   bool
	}{
		{"internal", SourceInternal, true},
		{"external", SourceExternal, true},
		{"", "", false},
		{"Internal", "", false},
		{"untrusted", "", false},
	} {
		got, err := ParseSource(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("ParseSource(%q) error = %v, want ok=%v", tc.in, err, tc.ok)
			continue
		}
		if got != tc.want {
			t.Errorf("ParseSource(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestMarkIsIdempotent is the state machine's core property: the first
// external read taints the session, later ones do not compound, and a reset
// makes the next external read count again.
func TestMarkIsIdempotent(t *testing.T) {
	s := New()
	at := time.Unix(1_700_000_000, 0)

	if s.Tainted() {
		t.Fatal("new session must start clean")
	}
	if !s.Mark("search_web", at) {
		t.Fatal("first mark must change state")
	}
	if s.Mark("read_email", at.Add(time.Second)) {
		t.Fatal("second mark must be a no-op")
	}
	st := s.Snapshot()
	if !st.Tainted || st.Marks != 1 || len(st.Sources) != 1 || st.Sources[0] != "search_web" {
		t.Fatalf("snapshot = %+v, want tainted with only the first source", st)
	}
	if !st.TaintedAt.Equal(at) {
		t.Fatalf("tainted_at = %v, want %v", st.TaintedAt, at)
	}

	if !s.Reset() {
		t.Fatal("reset of a tainted session must report true")
	}
	if s.Reset() {
		t.Fatal("second reset must report false")
	}
	if s.Tainted() {
		t.Fatal("session must be clean after reset")
	}
	if !s.Mark("read_email", at) {
		t.Fatal("mark after reset must change state again")
	}
	if st := s.Snapshot(); st.Marks != 2 || st.Resets != 1 || len(st.Sources) != 1 {
		t.Fatalf("snapshot after re-taint = %+v", st)
	}
}

func TestSnapshotIsACopy(t *testing.T) {
	s := New()
	s.Mark("a", time.Now())
	st := s.Snapshot()
	st.Sources[0] = "mutated"
	if s.Snapshot().Sources[0] != "a" {
		t.Fatal("Snapshot must not alias internal state")
	}
}
