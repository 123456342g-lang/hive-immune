package gateway

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// MaxMessageBytes bounds a single stdio message. MCP payloads are small
// JSON documents; a bound keeps a hostile or broken peer from making the
// gateway buffer without limit.
const MaxMessageBytes = 8 << 20 // 8 MiB

var (
	// ErrMessageTooLarge means one line exceeded MaxMessageBytes.
	ErrMessageTooLarge = errors.New("gateway: message too large")
	// ErrNotJSONRPC means a line was not a JSON-RPC 2.0 object.
	ErrNotJSONRPC = errors.New("gateway: not a JSON-RPC 2.0 message")
)

// Message is one JSON-RPC 2.0 message on the MCP stdio transport.
//
// The stdio transport frames messages as individual newline-delimited JSON
// documents that must not contain embedded newlines (MCP spec,
// "Transports"). Fields the gateway does not understand are carried
// through untouched: only tools/call requests and their responses are
// interpreted.
type Message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *RPCError        `json:"error,omitempty"`
}

// RPCError is a JSON-RPC error object.
type RPCError struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *RPCError) Error() string { return fmt.Sprintf("jsonrpc error %d: %s", e.Code, e.Message) }

// IsRequest reports whether the message is a request (it carries a method
// and an id, so a response is expected).
func (m Message) IsRequest() bool { return m.Method != "" && m.ID != nil }

// IsResponse reports whether the message answers a client request.
func (m Message) IsResponse() bool { return m.Method == "" && m.ID != nil }

// IsNotification reports whether the message expects no reply.
func (m Message) IsNotification() bool { return m.Method != "" && m.ID == nil }

// IDKey returns the message id as a string suitable for map keys. The
// zero value returns "".
func (m Message) IDKey() string {
	if m.ID == nil {
		return ""
	}
	return string(*m.ID)
}

// Validate checks the fields JSON-RPC 2.0 requires on every message.
func (m Message) Validate() error {
	if m.JSONRPC != "2.0" {
		return fmt.Errorf("%w: jsonrpc = %q, want \"2.0\"", ErrNotJSONRPC, m.JSONRPC)
	}
	if m.Method == "" && m.ID == nil {
		return fmt.Errorf("%w: message has neither method nor id", ErrNotJSONRPC)
	}
	return nil
}

// CallParam is the params object of a tools/call request.
type CallParam struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ParseCall extracts and validates the params of a tools/call request.
func (m Message) ParseCall() (CallParam, error) {
	var p CallParam
	if err := json.Unmarshal(m.Params, &p); err != nil {
		return CallParam{}, fmt.Errorf("gateway: tools/call params: %w", err)
	}
	if p.Name == "" {
		return CallParam{}, errors.New("gateway: tools/call without a tool name")
	}
	return p, nil
}

// ToolResult is the subset of a tools/call result the gateway cares about:
// whether the call failed, and how big the payload was.
type ToolResult struct {
	IsError bool `json:"isError,omitempty"`
}

// ParseToolResult decodes a tools/call result. ok is false when the result
// is not a tool result object at all (for example an error response).
func ParseToolResult(result json.RawMessage) (ToolResult, bool) {
	if len(result) == 0 {
		return ToolResult{}, false
	}
	var r struct {
		IsError *bool `json:"isError"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return ToolResult{}, false
	}
	return ToolResult{IsError: r.IsError != nil && *r.IsError}, true
}

// ReadMessage reads one newline-delimited message. A final line without a
// trailing newline (peer closed the stream) is accepted; a truncated line
// that is not valid JSON is then rejected by the caller.
func ReadMessage(r *bufio.Reader) (Message, error) {
	line, err := readLine(r)
	if err != nil {
		return Message{}, err
	}
	var m Message
	if err := json.Unmarshal(line, &m); err != nil {
		return Message{}, fmt.Errorf("%w: %v", ErrNotJSONRPC, err)
	}
	if err := m.Validate(); err != nil {
		return Message{}, err
	}
	return m, nil
}

// WriteMessage encodes one message as a single line. json.Marshal never
// emits raw newlines inside strings, so the framing invariant holds.
func WriteMessage(w io.Writer, m Message) error {
	if err := m.Validate(); err != nil {
		return err
	}
	buf, err := json.Marshal(m)
	if err != nil {
		return fmt.Errorf("gateway: encoding message: %w", err)
	}
	buf = append(buf, '\n')
	_, err = w.Write(buf)
	return err
}

func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		part, err := r.ReadSlice('\n')
		if len(buf)+len(part) > MaxMessageBytes {
			return nil, ErrMessageTooLarge
		}
		buf = append(buf, part...)
		switch {
		case err == bufio.ErrBufferFull:
			continue
		case err == io.EOF:
			if len(buf) == 0 {
				return nil, io.EOF
			}
			return trimEOL(buf), nil
		case err != nil:
			return nil, err
		}
		return trimEOL(buf), nil
	}
}

func trimEOL(b []byte) []byte {
	return bytes.TrimRight(b, "\r\n")
}
