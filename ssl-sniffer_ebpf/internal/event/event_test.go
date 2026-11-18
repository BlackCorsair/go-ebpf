package event

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// offsetof(struct ssl_event, data) in bpf/ssl_sniffer.bpf.c.
const cHeaderSize = 56

func TestHeaderSizeMatchesC(t *testing.T) {
	if HeaderSize != cHeaderSize {
		t.Fatalf("Go header is %d bytes, C header is %d", HeaderSize, cHeaderSize)
	}
}

func TestDecode(t *testing.T) {
	h := header{SSLPtr: 0xdead, PID: 42, TID: 43, Len: 5, OrigLen: 5, Dir: uint8(Write)}
	copy(h.Comm[:], "curl")
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, h)
	buf.WriteString("hello")

	e, err := Decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if e.Comm != "curl" || e.PID != 42 || e.Dir != Write || string(e.Data) != "hello" {
		t.Fatalf("unexpected event: %+v", e)
	}

	if _, err := Decode(buf.Bytes()[:buf.Len()-1]); err == nil {
		t.Fatal("expected error on truncated record")
	}
}

func TestPrintable(t *testing.T) {
	got := printable([]byte("GET / HTTP/1.1\r\nHost: x\r\n\x00\x01"))
	want := "GET / HTTP/1.1\nHost: x\n.."
	if got != want {
		t.Fatalf("got %q want %q", got, want)
	}
}
