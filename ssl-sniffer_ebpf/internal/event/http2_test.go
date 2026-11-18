package event

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/net/http2/hpack"
)

// frame builds one HTTP/2 frame: 3-byte length, type, flags, 4-byte stream id,
// then the payload.
func frame(typ, flags byte, streamID uint32, payload []byte) []byte {
	h := []byte{
		byte(len(payload) >> 16), byte(len(payload) >> 8), byte(len(payload)),
		typ, flags,
		byte(streamID >> 24), byte(streamID >> 16), byte(streamID >> 8), byte(streamID),
	}
	return append(h, payload...)
}

func hpackBlock(t *testing.T, enc *hpack.Encoder, buf *bytes.Buffer, fields []hpack.HeaderField) []byte {
	t.Helper()
	buf.Reset()
	for _, f := range fields {
		if err := enc.WriteField(f); err != nil {
			t.Fatal(err)
		}
	}
	return append([]byte(nil), buf.Bytes()...)
}

// feed runs raw bytes through the printer, split into chunk-sized events to
// prove frames reassemble across the boundaries the kernel would create.
func feed(p *Printer, conn uint64, dir Direction, data []byte, chunk int) {
	for off := 0; off < len(data); off += chunk {
		part := data[off:min(off+chunk, len(data))]
		p.Print(Event{SSL: conn, Dir: dir, OrigLen: uint32(len(part)), Data: part, Comm: "firefox:Socket Thread"})
	}
}

func newPrinter(level int) (*Printer, *bytes.Buffer) {
	var out bytes.Buffer
	return &Printer{Out: &out, HTTP2: true, Level: level}, &out
}

// http2Exchange feeds one Firefox-like request and its response.
func http2Exchange(t *testing.T, p *Printer) {
	t.Helper()
	var hb bytes.Buffer
	cEnc, sEnc := hpack.NewEncoder(&hb), hpack.NewEncoder(&hb)

	var client bytes.Buffer
	client.WriteString(http2Preface)
	client.Write(frame(frameSettings, 0, 0, make([]byte, 18)))
	client.Write(frame(frameWindowUpdate, 0, 0, []byte{0, 0x0f, 0, 1}))
	client.Write(frame(frameHeaders, flagEndHeaders|flagEndStream, 1, hpackBlock(t, cEnc, &hb, []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":path", Value: "/index.html"},
		{Name: "user-agent", Value: "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0"},
	})))
	// Chunk size 7 splits both the preface and the frames.
	feed(p, 0xdead, Write, client.Bytes(), 7)

	var server bytes.Buffer
	server.Write(frame(frameSettings, 0, 0, nil))
	server.Write(frame(frameHeaders, flagEndHeaders, 1, hpackBlock(t, sEnc, &hb, []hpack.HeaderField{
		{Name: ":status", Value: "200"},
		{Name: "content-type", Value: "text/html; charset=UTF-8"},
		{Name: "content-length", Value: "15"},
	})))
	// Padded DATA frame: pad length 3, body, 3 bytes of padding.
	server.Write(frame(frameData, flagPadded|flagEndStream, 1, append([]byte{3}, "<html>hi</html>\x00\x00\x00"...)))
	server.Write(frame(framePing, 0, 0, make([]byte, 8)))
	feed(p, 0xdead, Read, server.Bytes(), 5)
}

func check(t *testing.T, got string, want, notWant []string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(got, w) {
			t.Errorf("output missing %q", w)
		}
	}
	for _, w := range notWant {
		if strings.Contains(got, w) {
			t.Errorf("output should not contain %q", w)
		}
	}
	if t.Failed() {
		t.Logf("--- got ---\n%s", got)
	}
}

func TestHTTP2Levels(t *testing.T) {
	cases := []struct {
		level         int
		want, notWant []string
	}{
		{LevelSummary,
			[]string{
				"firefox[0] -> GET https://example.com/index.html",
				"<- 200 GET https://example.com/index.html (text/html, 15 bytes)",
			},
			[]string{"user-agent", "Socket Thread", "<html>", "SETTINGS", "PING", "HEADERS"}},
		{LevelHeaders,
			[]string{"HEADERS stream=1 END_STREAM", ":path: /index.html", "user-agent: Mozilla/5.0", ":status: 200", "HTTP/2"},
			[]string{"<html>", "DATA", "SETTINGS", "PING", "WINDOW_UPDATE"}},
		{LevelBodies,
			[]string{":status: 200", "DATA stream=1 (15 bytes) END_STREAM", "<html>hi</html>"},
			[]string{"SETTINGS", "PING", "WINDOW_UPDATE"}},
		{LevelAll,
			[]string{":status: 200", "<html>hi</html>", "SETTINGS", "PING", "WINDOW_UPDATE"},
			nil},
	}
	for _, c := range cases {
		p, out := newPrinter(c.level)
		http2Exchange(t, p)
		t.Run(map[int]string{0: "summary", 1: "headers", 2: "bodies", 3: "all"}[c.level], func(t *testing.T) {
			check(t, out.String(), c.want, c.notWant)
		})
	}
}

// Events that consist only of control frames must not even print an event
// header below LevelAll: that was most of the noise.
func TestControlOnlyEventsAreSilent(t *testing.T) {
	p, out := newPrinter(LevelBodies)
	feed(p, 1, Write, []byte(http2Preface), 100)
	feed(p, 1, Write, frame(frameSettings, 0, 0, nil), 100)
	feed(p, 1, Read, frame(framePing, 0, 0, make([]byte, 8)), 100)
	if out.Len() != 0 {
		t.Errorf("expected no output, got:\n%s", out.String())
	}
}

func http1Exchange(p *Printer) {
	feed(p, 0xbeef, Write, []byte("GET /api/v1/items?id=3 HTTP/1.1\r\nHost: api.example.com\r\nAccept: */*\r\n\r\n"), 1024)
	feed(p, 0xbeef, Read, []byte("HTTP/1.1 404 Not Found\r\nContent-Type: application/json\r\nContent-Length: 20\r\n\r\n{\"error\":\"missing\"}"), 1024)
	feed(p, 0xbeef, Read, []byte("more body bytes"), 1024)
}

func TestHTTP1Levels(t *testing.T) {
	p, out := newPrinter(LevelSummary)
	http1Exchange(p)
	check(t, out.String(),
		[]string{"-> GET https://api.example.com/api/v1/items?id=3", "<- 404 GET https://api.example.com/api/v1/items?id=3 (application/json, 20 bytes)"},
		[]string{"Accept", "error", "more body"})

	p, out = newPrinter(LevelHeaders)
	http1Exchange(p)
	check(t, out.String(),
		[]string{"GET /api/v1/items?id=3 HTTP/1.1", "Accept: */*", "HTTP/1.1 404 Not Found", "HTTP/1.1"},
		[]string{"error", "more body"})

	p, out = newPrinter(LevelBodies)
	http1Exchange(p)
	check(t, out.String(), []string{`{"error":"missing"}`, "more body bytes"}, nil)
}

// The output from the bug report: 1-byte reads that aren't HTTP. Below
// LevelAll they print nothing.
func TestNoiseOnlyAtLevelAll(t *testing.T) {
	for level := LevelSummary; level <= LevelAll; level++ {
		p, out := newPrinter(level)
		for range 10 {
			feed(p, 0x7f6ca498ae50, Read, []byte("M"), 1)
		}
		shown := out.Len() > 0
		if shown != (level == LevelAll) {
			t.Errorf("level %d: noise shown=%v\n%s", level, shown, out.String())
		}
	}
}

// Short first writes that are a prefix of "PRI * HTTP/2.0" but then diverge
// must still be printed, not swallowed.
func TestSplitNonPrefaceIsReplayed(t *testing.T) {
	p, out := newPrinter(LevelAll)
	feed(p, 1, Write, []byte("PRI"), 3)
	feed(p, 1, Write, []byte("NT hello"), 100)
	if got := out.String(); !strings.Contains(got, "PRINT hello") {
		t.Errorf("held bytes were not replayed\n%s", got)
	}
}

func TestTruncationDesyncsDirection(t *testing.T) {
	p, out := newPrinter(LevelAll)
	feed(p, 3, Write, []byte(http2Preface), 100)
	p.Print(Event{SSL: 3, Dir: Write, OrigLen: 20000, Truncated: true, Data: make([]byte, 16)})
	feed(p, 3, Write, frame(framePing, 0, 0, make([]byte, 8)), 100)

	got := out.String()
	if !strings.Contains(got, "capture truncated") || !strings.Contains(got, "desynced earlier") {
		t.Errorf("truncation not handled\n%s", got)
	}
	if strings.Contains(got, "PING") {
		t.Errorf("decoded a frame after the stream lost sync\n%s", got)
	}
}

func TestRawModeShowsEverything(t *testing.T) {
	var out bytes.Buffer
	p := &Printer{Out: &out, HTTP2: false, Level: LevelSummary}
	feed(p, 9, Read, []byte("M"), 1)
	if !strings.Contains(out.String(), "M") {
		t.Errorf("raw mode dropped an event\n%s", out.String())
	}
}
