package main

import (
	"bytes"
	"io"
	"os"
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

// buildClientStream produces the bytes a real HTTP/2 client writes: the preface,
// an (empty) SETTINGS frame, then a HEADERS frame whose block is encoded with
// the authoritative HPACK encoder.
func buildClientStream(t *testing.T, headers []hpack.HeaderField) []byte {
	t.Helper()
	var hb bytes.Buffer
	enc := hpack.NewEncoder(&hb)
	for _, h := range headers {
		if err := enc.WriteField(h); err != nil {
			t.Fatal(err)
		}
	}

	var out bytes.Buffer
	out.WriteString(http2Preface)
	out.Write(frame(frameSettings, 0, 0, nil))
	// flags: END_HEADERS (0x4) | END_STREAM (0x1)
	out.Write(frame(frameHeaders, flagEndHeaders|0x1, 1, hb.Bytes()))
	return out.Bytes()
}

// feed runs raw bytes through the sniffer's event path and returns everything
// printed, split into small chunks to prove frames reassemble across the event
// boundaries the kernel would create.
func feed(t *testing.T, connID uint64, dir uint8, data []byte, chunk int) string {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	defer func() { os.Stdout = old }()

	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		part := data[off:end]

		ev := &codeEvent{Conn: connID, Direction: dir, Total: uint32(len(part)), Len: uint32(len(part))}
		for i, b := range part {
			ev.Data[i] = int8(b)
		}
		printEvent(ev)
	}

	w.Close()
	out, _ := io.ReadAll(r)
	return string(out)
}

func TestHTTP2HeadersDecode(t *testing.T) {
	conns = map[uint64]*conn{} // isolate from other tests

	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":path", Value: "/index.html"},
		{Name: ":authority", Value: "example.com"},
		{Name: ":scheme", Value: "https"},
		{Name: "user-agent", Value: "sniffer-test/1.0"},
	}
	stream := buildClientStream(t, headers)

	// Chunk size 7 deliberately splits the preface and the frames so the
	// reassembly buffer is exercised.
	out := feed(t, 0xdead, dirWrite, stream, 7)

	for _, h := range headers {
		want := h.Name + ": " + h.Value
		if !strings.Contains(out, want) {
			t.Errorf("decoded output missing %q\n--- got ---\n%s", want, out)
		}
	}
	if !strings.Contains(out, "HEADERS stream=1") {
		t.Errorf("missing HEADERS frame line\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "SETTINGS") {
		t.Errorf("missing SETTINGS frame line\n--- got ---\n%s", out)
	}
}

func TestNonHTTP2IsPlainText(t *testing.T) {
	conns = map[uint64]*conn{}

	req := "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
	out := feed(t, 0xbeef, dirWrite, []byte(req), 1024)

	if !strings.Contains(out, "GET / HTTP/1.1") {
		t.Errorf("HTTP/1.1 request not printed as text\n--- got ---\n%s", out)
	}
	if !strings.Contains(out, "Host: example.com") {
		t.Errorf("HTTP/1.1 header not printed\n--- got ---\n%s", out)
	}
}
