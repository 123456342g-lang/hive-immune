package gateway

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/hive-immune/hive-immune/pkg/taint"
)

const goodPolicy = `version: 1
defaults:
  risk: egress
  taint: external
tools:
  read_file:
    risk: read
    taint: internal
  query_db:
    risk: read
    taint: internal
  create_ticket:
    risk: write-internal
    taint: internal
  send_email:
    risk: egress
    taint: internal
  search_web:
    risk: read
    taint: external
`

func TestParsePolicy(t *testing.T) {
	p, err := ParsePolicy([]byte(goodPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if p.Version != 1 || p.Count() != 5 {
		t.Fatalf("version=%d tools=%d", p.Version, p.Count())
	}
	for tool, want := range map[string]Class{
		"read_file":    {Risk: RiskRead, Taint: taint.SourceInternal},
		"send_email":   {Risk: RiskEgress, Taint: taint.SourceInternal},
		"search_web":   {Risk: RiskRead, Taint: taint.SourceExternal},
		"unknown_tool": {Risk: RiskEgress, Taint: taint.SourceExternal}, // defaults
	} {
		if got := p.Classify(tool); got != want {
			t.Errorf("Classify(%q) = %+v, want %+v", tool, got, want)
		}
	}
}

func TestParsePolicyRejectsBadDocuments(t *testing.T) {
	for name, doc := range map[string]string{
		"missing version": `defaults: {risk: read, taint: internal}`,
		"wrong version":   "version: 2\ntools: {}",
		"unknown field":   "version: 1\nnope: true",
		"unknown risk":    "version: 1\ntools:\n  x: {risk: delete, taint: internal}",
		"unknown taint":   "version: 1\ntools:\n  x: {risk: read, taint: maybe}",
		"empty tool name": "version: 1\ntools:\n  \"\": {risk: read, taint: internal}",
		"negative cost":   "version: 1\ntools:\n  x: {risk: read, taint: internal, cost: -1}",
		"not yaml":        "::::",
		"bad defaults":    "version: 1\ndefaults: {risk: half, taint: internal}",
	} {
		if _, err := ParsePolicy([]byte(doc)); err == nil {
			t.Errorf("%s: want error, got nil", name)
		}
	}
}

// TestPolicyCost: cost is what one attempt charges the session budget;
// tools that do not declare one are free.
func TestPolicyCost(t *testing.T) {
	p, err := ParsePolicy([]byte(`version: 1
defaults: {risk: egress, taint: external}
tools:
  send_email: {risk: egress, taint: internal, cost: 5}
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("send_email").Cost; got != 5 {
		t.Fatalf("send_email cost = %d, want 5", got)
	}
	if got := p.Classify("read_file").Cost; got != 0 {
		t.Fatalf("unregistered tool cost = %d, want 0 (free)", got)
	}
}

// TestTaintDefaultsExternal covers the fail-safe default: a tool that does
// not declare where its output comes from is assumed to carry instructions
// from outside, which taints the session rather than staying quiet.
func TestTaintDefaultsExternal(t *testing.T) {
	p, err := ParsePolicy([]byte("version: 1\ntools:\n  mystery: {risk: read}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := p.Classify("mystery"); got.Taint != taint.SourceExternal {
		t.Fatalf("taint = %q, want external", got.Taint)
	}
	if got := p.Classify("mystery"); got.Risk != RiskRead {
		t.Fatalf("risk = %q, want read", got.Risk)
	}
}

func TestNilPolicyClassifiesFailClosed(t *testing.T) {
	var p *Policy
	if got := p.Classify("anything"); got != FailClosed() {
		t.Fatalf("nil policy classify = %+v, want fail-closed", got)
	}
	if p.Count() != 0 {
		t.Fatal("nil policy must report zero tools")
	}
}

func TestLoadPolicyPaths(t *testing.T) {
	p, err := LoadPolicy("")
	if err != nil || p != nil {
		t.Fatalf("empty path: policy=%v err=%v, want nil,nil", p, err)
	}
	if _, err := LoadPolicy(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing file must fail")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(path, []byte(goodPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err = LoadPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.Count() != 5 {
		t.Fatalf("tools = %d, want 5", p.Count())
	}
}

// TestPolicyStoreReload checks the control-plane contract: an edit takes
// effect without a restart, and a broken edit keeps the last good policy
// instead of taking the data plane down.
func TestPolicyStoreReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tools.yaml")
	if err := os.WriteFile(path, []byte(goodPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	var errs []error
	store, err := newPolicyStore(path, func() time.Time { return now }, func(e error) { errs = append(errs, e) })
	if err != nil {
		t.Fatal(err)
	}
	if store.Current().Count() != 5 {
		t.Fatalf("initial tools = %d", store.Current().Count())
	}

	// Unchanged file: re-read keeps an equivalent policy.
	before := store.Current()
	now = now.Add(time.Hour)
	if after := store.Current(); !reflect.DeepEqual(before, after) {
		t.Fatalf("unchanged file changed the policy: %+v vs %+v", before, after)
	}

	// Edit: new tool appears. The store throttles re-reads to once per
	// second of its clock, so the test clock has to move on as well.
	if err := os.WriteFile(path, []byte("version: 1\ntools:\n  only: {risk: read, taint: internal}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	after := store.Current()
	if after.Count() != 1 {
		t.Fatalf("after reload tools = %d, want 1", after.Count())
	}

	// Broken edit: keep last good, surface the error.
	if err := os.WriteFile(path, []byte("version: 1\ntools:\n  bad: {risk: nope}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err == nil {
		t.Fatal("Reload must report a broken document")
	}
	if store.Current().Count() != 1 {
		t.Fatal("a broken edit must not drop the last good policy")
	}
	if len(errs) == 0 {
		t.Fatal("onError must be called for a broken edit")
	}
	// Fixing the file recovers.
	if err := os.WriteFile(path, []byte(goodPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := store.Reload(); err != nil {
		t.Fatal(err)
	}
	if store.Current().Count() != 5 {
		t.Fatal("fixed policy not loaded")
	}
}

func TestPolicyStoreWithoutPath(t *testing.T) {
	store, err := newPolicyStore("", time.Now, nil)
	if err != nil {
		t.Fatal(err)
	}
	if store.Current() != nil {
		t.Fatal("no path means degraded mode")
	}
	if err := store.Reload(); err != nil {
		t.Fatalf("Reload with no path: %v", err)
	}
}

func TestPolicyStoreStartupFailure(t *testing.T) {
	if _, err := newPolicyStore(filepath.Join(t.TempDir(), "nope.yaml"), time.Now, nil); err == nil {
		t.Fatal("a missing policy file at startup must fail loudly")
	}
	if _, err := newPolicyStore(filepath.Join(t.TempDir(), "nope.yaml"), time.Now, nil); err == nil {
		t.Fatal("an invalid policy file at startup must fail loudly")
	}
}
