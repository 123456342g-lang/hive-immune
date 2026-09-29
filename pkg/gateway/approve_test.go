package gateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewWebhookApproverValidates(t *testing.T) {
	if _, err := NewWebhookApprover("ftp://ops", time.Second); err == nil {
		t.Fatal("non-http scheme must be rejected")
	}
	if _, err := NewWebhookApprover("http://", time.Second); err == nil {
		t.Fatal("missing host must be rejected")
	}
	w, err := NewWebhookApprover("https://ops.example/approve", 0)
	if err != nil {
		t.Fatal(err)
	}
	if w.Timeout != DefaultApproveTimeout {
		t.Fatalf("timeout = %s, want the default", w.Timeout)
	}
}

func TestWebhookApproverOutcomes(t *testing.T) {
	for name, tc := range map[string]struct {
		handler func(http.ResponseWriter, *http.Request)
		grant   bool
		err     bool
	}{
		"granted": {
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("request = %s %s, content-type %q", r.Method, r.URL, r.Header.Get("Content-Type"))
				}
				w.WriteHeader(http.StatusNoContent)
			},
			grant: true,
		},
		"refused": {
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) },
			grant:   false,
		},
		"channel failure": {
			handler: func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) },
			err:     true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(tc.handler))
			defer ts.Close()
			w, err := NewWebhookApprover(ts.URL, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			grant, err := w.Approve(context.Background(), Approval{Agent: "a1", Tool: "send_email"})
			if grant != tc.grant {
				t.Fatalf("grant = %v, want %v", grant, tc.grant)
			}
			if (err != nil) != tc.err {
				t.Fatalf("err = %v, want error: %v", err, tc.err)
			}
		})
	}
}

// TestWebhookApproverTimeoutAndDeadChannel: a slow or unreachable approver
// must turn into a refusal, never into a hang or an accidental grant.
func TestWebhookApproverTimeoutAndDeadChannel(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(5 * time.Second):
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer slow.Close()
	w, err := NewWebhookApprover(slow.URL, 30*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	grant, err := w.Approve(context.Background(), Approval{Tool: "send_email"})
	if grant || err == nil {
		t.Fatalf("grant=%v err=%v, want a timeout refusal", grant, err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("timeout took %s", elapsed)
	}

	// Nothing listening: connection refused, also a refusal.
	dead, err := NewWebhookApprover("http://127.0.0.1:1", 200*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if grant, err := dead.Approve(context.Background(), Approval{}); grant || err == nil {
		t.Fatalf("grant=%v err=%v", grant, err)
	}
}

// TestNoApprovalChannelDenies covers the nil-Approver path end to end: the
// decision engine must refuse instead of silently allowing.
func TestNoApprovalChannelDenies(t *testing.T) {
	s, out := testServer(t, func(c *Config) { c.PolicyPath = withPolicy(t) })
	if s.cfg.Approver != nil {
		t.Fatal("no approver was configured")
	}
	taintSession(t, s, out, 1)
	up := feed(t, s, callLine(2, "send_email"))
	if up.Len() != 0 {
		t.Fatal("nil approver must deny, not allow")
	}
	if !strings.Contains(out.String(), "no approval channel") {
		t.Fatalf("client got %q", out.String())
	}
}

func TestApproveUsesRequestContext(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer ts.Close()
	w, _ := NewWebhookApprover(ts.URL, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if grant, err := w.Approve(ctx, Approval{}); grant || !errors.Is(err, context.Canceled) {
		t.Fatalf("grant=%v err=%v, want a context cancellation", grant, err)
	}
}
