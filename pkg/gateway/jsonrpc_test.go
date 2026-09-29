package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func msg(t *testing.T, line string) Message {
	t.Helper()
	var m Message
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestMessageKinds(t *testing.T) {
	req := msg(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	if !req.IsRequest() || req.IsResponse() || req.IsNotification() {
		t.Fatalf("request misclassified: %+v", req)
	}
	if req.IDKey() != "1" {
		t.Fatalf("IDKey = %q", req.IDKey())
	}
	if _, err := req.ParseCall(); err != nil {
		t.Fatal(err)
	}

	notif := msg(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	if !notif.IsNotification() || notif.IsRequest() || notif.IsResponse() {
		t.Fatal("notification misclassified")
	}
	if notif.IDKey() != "" {
		t.Fatal("notification must have an empty id key")
	}

	resp := msg(t, `{"jsonrpc":"2.0","id":"abc","result":{"ok":true}}`)
	if !resp.IsResponse() || resp.IsRequest() {
		t.Fatal("response misclassified")
	}
	if resp.IDKey() != `"abc"` {
		t.Fatalf("IDKey = %s", resp.IDKey())
	}
}

func TestValidate(t *testing.T) {
	for name, m := range map[string]Message{
		"wrong version": {JSONRPC: "1.0", Method: "x"},
		"neither":       {JSONRPC: "2.0"},
		"good request":  {JSONRPC: "2.0", ID: rawID("1"), Method: "x"},
		"good response": {JSONRPC: "2.0", ID: rawID("1")},
		"good notif":    {JSONRPC: "2.0", Method: "x"},
	} {
		err := m.Validate()
		switch name {
		case "wrong version", "neither":
			if err == nil {
				t.Errorf("%s: want error", name)
			}
		default:
			if err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

func rawID(s string) *json.RawMessage {
	r := json.RawMessage(s)
	return &r
}

func TestParseCallErrors(t *testing.T) {
	var bad Message
	bad.JSONRPC, bad.ID, bad.Method, bad.Params = "2.0", rawID("1"), "tools/call", json.RawMessage(`{`)
	if _, err := bad.ParseCall(); err == nil {
		t.Error("unparsable params must fail")
	}
	bad.Params = json.RawMessage(`{}`)
	if _, err := bad.ParseCall(); err == nil {
		t.Error("missing tool name must fail")
	}
}

// TestReadWriteRoundTrip exercises the framing: one message per line, no
// embedded newlines, survives a round trip byte for byte.
func TestReadWriteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := msg(t, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"a@b.c"}}}`)
	if err := WriteMessage(&buf, in); err != nil {
		t.Fatal(err)
	}
	if strings.Count(buf.String(), "\n") != 1 {
		t.Fatalf("framing must be exactly one line, got %q", buf.String())
	}
	out, err := ReadMessage(bufio.NewReader(&buf))
	if err != nil {
		t.Fatal(err)
	}
	if out.IDKey() != in.IDKey() || out.Method != in.Method || !bytes.Equal(out.Params, in.Params) {
		t.Fatalf("round trip changed the message: %+v vs %+v", out, in)
	}
}

func TestWriteMessageRejectsInvalid(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMessage(&buf, Message{JSONRPC: "1.0", Method: "x"}); !errors.Is(err, ErrNotJSONRPC) {
		t.Fatalf("err = %v", err)
	}
}

func TestReadMessageErrors(t *testing.T) {
	cases := map[string]string{
		"not json":     "hello\n",
		"wrong ver":    `{"jsonrpc":"1.0","id":1,"method":"x"}` + "\n",
		"no method/id": `{"jsonrpc":"2.0"}` + "\n",
	}
	for name, line := range cases {
		if _, err := ReadMessage(bufio.NewReader(strings.NewReader(line))); !errors.Is(err, ErrNotJSONRPC) {
			t.Errorf("%s: err = %v, want ErrNotJSONRPC", name, err)
		}
	}
	if _, err := ReadMessage(bufio.NewReader(strings.NewReader(""))); !errors.Is(err, io.EOF) {
		t.Errorf("empty input: err = %v, want EOF", err)
	}
}

func TestReadMessageAcceptsFinalLineWithoutNewline(t *testing.T) {
	m, err := ReadMessage(bufio.NewReader(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"x"}`)))
	if err != nil {
		t.Fatal(err)
	}
	if m.Method != "x" {
		t.Fatalf("method = %q", m.Method)
	}
}

func TestReadMessageRejectsOversizedLine(t *testing.T) {
	big := `{"jsonrpc":"2.0","id":1,"method":"x","params":"` + strings.Repeat("a", MaxMessageBytes) + `"}`
	if _, err := ReadMessage(bufio.NewReader(strings.NewReader(big))); !errors.Is(err, ErrMessageTooLarge) {
		t.Fatalf("err = %v, want ErrMessageTooLarge", err)
	}
}

func TestParseToolResult(t *testing.T) {
	if _, ok := ParseToolResult(nil); ok {
		t.Error("empty result is not a tool result")
	}
	if _, ok := ParseToolResult(json.RawMessage(`[`)); ok {
		t.Error("garbage is not a tool result")
	}
	r, ok := ParseToolResult(json.RawMessage(`{"content":[{"type":"text","text":"hi"}]}`))
	if !ok || r.IsError {
		t.Fatalf("plain result: %+v ok=%v", r, ok)
	}
	r, ok = ParseToolResult(json.RawMessage(`{"content":[],"isError":true}`))
	if !ok || !r.IsError {
		t.Fatalf("error result: %+v ok=%v", r, ok)
	}
	// isError:false must count as success.
	r, ok = ParseToolResult(json.RawMessage(`{"isError":false}`))
	if !ok || r.IsError {
		t.Fatalf("explicit false: %+v ok=%v", r, ok)
	}
}

func TestRPCErrorString(t *testing.T) {
	e := &RPCError{Code: -32001, Message: "denied"}
	if !strings.Contains(e.Error(), "-32001") || !strings.Contains(e.Error(), "denied") {
		t.Fatalf("Error() = %q", e.Error())
	}
}
