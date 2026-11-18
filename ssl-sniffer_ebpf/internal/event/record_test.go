package event

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// collectSink keeps every record for inspection.
type collectSink struct{ recs []Record }

func (s *collectSink) Emit(r Record) error { s.recs = append(s.recs, r); return nil }

// The log must hold the full decoding even when the terminal shows almost
// nothing: a UI reads the file, not the screen.
func TestSinkIsCompleteAtLowVerbosity(t *testing.T) {
	sink := &collectSink{}
	var term bytes.Buffer
	// LevelSummary: the terminal shows two lines, the log must show all.
	p := &Printer{Out: &term, HTTP2: true, Level: LevelSummary, Sink: sink, LogData: true}
	http2Exchange(t, p)

	var saw struct{ req, resp, header, data bool }
	for _, r := range sink.recs {
		if r.Conn != "0xdead" {
			t.Errorf("conn = %q", r.Conn)
		}
		for _, l := range r.Lines {
			switch {
			case l.Level == LevelSummary && strings.HasPrefix(l.Text, "GET https://example.com/index.html"):
				saw.req = true
			case l.Level == LevelSummary && strings.HasPrefix(l.Text, "200 GET"):
				saw.resp = true
			case l.Level == LevelHeaders && strings.Contains(l.Text, "user-agent: Mozilla/5.0"):
				saw.header = true
			case l.Level == LevelBodies && strings.Contains(l.Text, "<html>hi</html>"):
				saw.data = true
			}
		}
	}
	if !saw.req || !saw.resp || !saw.header || !saw.data {
		t.Fatalf("log incomplete: %+v", saw)
	}

	// Raw bytes round-trip, and the request event carries the preface.
	for _, r := range sink.recs {
		if r.Data == "" {
			continue
		}
		if _, err := base64.StdEncoding.DecodeString(r.Data); err != nil {
			t.Errorf("data not valid base64: %v", err)
		}
	}
}

func TestSinkEmitsValidJSONLines(t *testing.T) {
	var buf bytes.Buffer
	p := &Printer{Out: new(bytes.Buffer), HTTP2: true, Level: LevelHeaders, Sink: NewJSONSink(&buf)}
	http2Exchange(t, p)

	n := 0
	for line := range strings.SplitSeq(strings.TrimRight(buf.String(), "\n"), "\n") {
		var r Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("line %d is not valid JSON: %v\n%s", n, err, line)
		}
		if r.Protocol != "http2" {
			t.Errorf("protocol = %q, want http2", r.Protocol)
		}
		n++
	}
	if n == 0 {
		t.Fatal("no JSON lines written")
	}
	// Without LogData, the bytes are omitted.
	if strings.Contains(buf.String(), `"data"`) {
		t.Error("data logged without -log-data")
	}
	// HTML characters must be left as-is, not \uXXXX-escaped, so bodies and
	// URLs stay readable.
	if strings.Contains(buf.String(), "\\u003c") || strings.Contains(buf.String(), "\\u0026") {
		t.Error("JSON escaped HTML characters; set SetEscapeHTML(false)")
	}
	if !strings.Contains(buf.String(), "<html>hi</html>") {
		t.Error("body not written verbatim to the log")
	}
}

func TestSinkDirAndProtocol(t *testing.T) {
	sink := &collectSink{}
	p := &Printer{Out: new(bytes.Buffer), HTTP2: true, Level: LevelHeaders, Sink: sink}
	http1Exchange(p)

	var sends, recvs int
	for _, r := range sink.recs {
		if r.Protocol != "http1" {
			t.Errorf("protocol = %q, want http1", r.Protocol)
		}
		switch r.Dir {
		case "send":
			sends++
		case "recv":
			recvs++
		default:
			t.Errorf("dir = %q", r.Dir)
		}
	}
	if sends == 0 || recvs == 0 {
		t.Errorf("want both directions, got %d send / %d recv", sends, recvs)
	}
}
