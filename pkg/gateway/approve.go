package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// DefaultApproveTimeout bounds how long a tools/call may block waiting for
// a human. Beyond it the call is refused: the gateway fails closed, it
// never lets an unanswered request turn into an allowed one.
const DefaultApproveTimeout = 60 * time.Second

// WebhookApprover is the approval channel: it POSTs the request to an
// operator endpoint and waits for the answer.
//
// The protocol is deliberately trivial so that anything that can receive a
// POST can be the approver (a chat bot, a ticket bot, a curl one-liner):
//
//	POST {approval}        -> 2xx    granted
//	                     -> 403    refused by the operator
//	                     -> other  channel failure, the call is denied
type WebhookApprover struct {
	URL     string
	Timeout time.Duration
	Client  *http.Client
}

// NewWebhookApprover validates the endpoint up front so that a typo in the
// flag fails at startup rather than on the first approval.
func NewWebhookApprover(rawURL string, timeout time.Duration) (*WebhookApprover, error) {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("gateway: -approve %q must be an http(s) URL", rawURL)
	}
	if timeout <= 0 {
		timeout = DefaultApproveTimeout
	}
	return &WebhookApprover{URL: rawURL, Timeout: timeout}, nil
}

// Approve blocks until the operator answers or Timeout expires.
func (w *WebhookApprover) Approve(ctx context.Context, a Approval) (bool, error) {
	body, err := json.Marshal(a)
	if err != nil {
		return false, fmt.Errorf("gateway: encoding approval request: %w", err)
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = DefaultApproveTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hive-gateway")

	client := w.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("gateway: approval webhook: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
	}()
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return true, nil
	case resp.StatusCode == http.StatusForbidden:
		return false, nil
	}
	return false, fmt.Errorf("gateway: approval webhook answered %s", resp.Status)
}
