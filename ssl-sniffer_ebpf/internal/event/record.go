package event

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// A Sink receives the full, unfiltered decoding of every event, independent of
// the terminal's verbosity level. It backs the -o log file a UI reads.
type Sink interface {
	Emit(Record) error
}

// Record is one event as written to the log. It carries both the decoded
// view (Lines, each tagged with the verbosity level that would show it) and
// the raw plaintext (Data), so a reader can show a summary, expand the
// headers and bodies, or work with the bytes directly.
type Record struct {
	Time      time.Time `json:"time"`
	PID       uint32    `json:"pid"`
	TID       uint32    `json:"tid"`
	Comm      string    `json:"comm"`
	Conn      string    `json:"conn"`     // connection handle, hex (e.g. "0x7f..")
	Dir       string    `json:"dir"`      // "send" or "recv"
	Protocol  string    `json:"protocol"` // "http2", "http1", "" (unknown/raw)
	OrigLen   uint32    `json:"orig_len"` // bytes the TLS call transferred
	Captured  int       `json:"captured"` // bytes we actually got (<= OrigLen)
	Truncated bool      `json:"truncated"`
	Lines     []Line    `json:"lines,omitempty"` // decoded, level-tagged output
	Data      string    `json:"data,omitempty"`  // raw plaintext, base64
}

// Line is one piece of decoded output and the lowest verbosity level that
// shows it (0 summary, 1 headers, 2 bodies, 3 everything).
type Line struct {
	Level int    `json:"level"`
	Text  string `json:"text"`
}

// JSONSink writes one JSON object per line (JSON Lines / NDJSON). Each Emit is
// flushed as it happens, so a UI can tail the file live.
type JSONSink struct {
	enc *json.Encoder
}

// NewJSONSink writes records to w. If w is also an io.Closer, the caller still
// owns closing it.
func NewJSONSink(w io.Writer) *JSONSink {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false) // URLs and bodies read better unescaped
	return &JSONSink{enc: enc}
}

func (s *JSONSink) Emit(r Record) error { return s.enc.Encode(r) }

func protoTag(tag string) string {
	switch tag {
	case "HTTP/2":
		return "http2"
	case "HTTP/1.1":
		return "http1"
	default:
		return ""
	}
}

// record turns an event and its decoded lines into a Record. raw is the event
// payload; includeData controls whether the bytes are logged.
func record(e Event, tag string, l lines, raw []byte, includeData bool) Record {
	dir := "recv"
	if e.Dir == Write {
		dir = "send"
	}

	lns := make([]Line, 0, len(l))
	for _, it := range l {
		lns = append(lns, Line{Level: it.min, Text: it.text})
	}

	r := Record{
		Time:      e.Time,
		PID:       e.PID,
		TID:       e.TID,
		Comm:      e.Comm,
		Conn:      fmt.Sprintf("%#x", e.SSL),
		Dir:       dir,
		Protocol:  protoTag(tag),
		OrigLen:   e.OrigLen,
		Captured:  len(raw),
		Truncated: e.Truncated,
		Lines:     lns,
	}
	if includeData && len(raw) > 0 {
		r.Data = base64.StdEncoding.EncodeToString(raw)
	}
	return r
}
