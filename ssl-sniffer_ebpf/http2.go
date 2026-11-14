package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// The 24-byte string every HTTP/2 client sends first, before any frame. Seeing
// it on the write side is how we recognise an HTTP/2 connection with certainty.
const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// HTTP/2 frame types we care to name (RFC 7540 §6).
const (
	frameData         = 0x0
	frameHeaders      = 0x1
	framePriority     = 0x2
	frameRSTStream    = 0x3
	frameSettings     = 0x4
	framePushPromise  = 0x5
	framePing         = 0x6
	frameGoAway       = 0x7
	frameWindowUpdate = 0x8
	frameContinuation = 0x9
)

// HEADERS / DATA flags we need to find the header block or strip padding.
const (
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

// stream is one direction of one connection. HPACK keeps a dynamic table that
// is per-connection and per-direction, so each direction owns its decoder and
// its own leftover bytes.
type stream struct {
	buf      []byte         // bytes received but not yet consumed as whole frames
	block    []byte         // header-block fragment accumulating over HEADERS+CONTINUATION
	dec      *hpack.Decoder // HPACK state for this direction
	desynced bool           // a gap (truncation / bad HPACK) means we can no longer trust this side
}

// conn is one TLS connection, identified by the library's connection handle.
type conn struct {
	http2   bool
	decided bool       // whether we've classified this connection yet
	pending []byte     // write bytes held while a split preface is still arriving
	dirs    [2]*stream // indexed by DIR_WRITE / DIR_READ
}

// Keyed by the connection handle the kernel sent (SSL* / session / PRFileDesc*).
// A fresh HTTP/2 preface on a handle resets its entry, which also covers the
// case where the allocator reuses a freed handle address for a new connection.
var conns = map[uint64]*conn{}

func (c *conn) stream(dir uint8) *stream {
	if c.dirs[dir] == nil {
		c.dirs[dir] = &stream{dec: hpack.NewDecoder(4096, nil)}
	}
	return c.dirs[dir]
}

// handleHTTP2 renders an event as HTTP/2 and returns true, or returns false if
// the connection isn't (known to be) HTTP/2, leaving the caller to print it as
// plain text.
func handleHTTP2(ev *codeEvent) bool {
	data := toBytes(ev.Data[:ev.Len])

	// A client preface that arrives whole marks a new HTTP/2 connection; start
	// its state fresh (this also handles a freed handle address being reused).
	if ev.Direction == dirWrite && bytes.HasPrefix(data, []byte(http2Preface)) {
		conns[ev.Conn] = &conn{http2: true, decided: true}
		data = data[len(http2Preface):]
	}

	c := conns[ev.Conn]
	if c == nil {
		c = &conn{}
		conns[ev.Conn] = c
	}

	// Not yet classified: the preface may be split across several small writes,
	// so hold write bytes until there are enough to compare against it.
	if !c.decided {
		if ev.Direction != dirWrite {
			// A read before any client write (e.g. attached mid-connection):
			// we can't rebuild HPACK state, so treat the whole thing as text.
			c.decided = true
			return false
		}
		c.pending = append(c.pending, data...)

		// Still shorter than the preface: keep holding only while what we have
		// remains a possible prefix of it.
		if len(c.pending) < len(http2Preface) {
			if bytes.HasPrefix([]byte(http2Preface), c.pending) {
				return true // could still become a preface; print nothing yet
			}
			c.decided = true // diverged: not HTTP/2, replay the held bytes as text
			printEventHeader(ev)
			fmt.Println(printableBytes(c.pending))
			c.pending = nil
			return true
		}

		// Enough bytes to decide for certain.
		c.decided = true
		if !bytes.HasPrefix(c.pending, []byte(http2Preface)) {
			printEventHeader(ev)
			fmt.Println(printableBytes(c.pending))
			c.pending = nil
			return true
		}
		c.http2 = true
		data = c.pending[len(http2Preface):]
		c.pending = nil
	}

	if !c.http2 {
		return false
	}

	printEventHeader(ev)
	st := c.stream(ev.Direction)

	// The capture was cut short: the frame stream has a hole in it, so nothing
	// after this point lines up. Drop what we were holding and stop trusting
	// this direction (HPACK's dynamic table is now out of sync too).
	if ev.Total > ev.Len {
		fmt.Printf("  [capture truncated at %d bytes; HTTP/2 framing lost for this direction]\n", ev.Len)
		st.buf = nil
		st.block = nil
		st.desynced = true
		return true
	}
	if st.desynced {
		fmt.Println("  [direction desynced earlier; not decoding]")
		return true
	}

	st.buf = append(st.buf, data...)
	parseFrames(st)
	return true
}

// parseFrames pulls every complete frame out of st.buf, leaving any partial
// trailing frame for the next event to finish.
func parseFrames(st *stream) {
	for len(st.buf) >= 9 {
		length := int(st.buf[0])<<16 | int(st.buf[1])<<8 | int(st.buf[2])
		if len(st.buf) < 9+length {
			break // the rest of this frame hasn't arrived yet
		}
		typ := st.buf[3]
		flags := st.buf[4]
		streamID := binary.BigEndian.Uint32(st.buf[5:9]) & 0x7fffffff
		payload := st.buf[9 : 9+length]

		printFrame(st, typ, flags, streamID, payload)
		st.buf = st.buf[9+length:]
	}
}

func printFrame(st *stream, typ, flags byte, streamID uint32, payload []byte) {
	switch typ {
	case frameHeaders:
		// Optional pad-length byte, then optional 5-byte priority block, then
		// the HPACK header-block fragment, then the trailing padding.
		frag := payload
		var pad int
		if flags&flagPadded != 0 && len(frag) > 0 {
			pad = int(frag[0])
			frag = frag[1:]
		}
		if flags&flagPriority != 0 && len(frag) >= 5 {
			frag = frag[5:]
		}
		if pad <= len(frag) {
			frag = frag[:len(frag)-pad]
		}
		st.block = append(st.block, frag...)
		fmt.Printf("  HEADERS stream=%d\n", streamID)
		if flags&flagEndHeaders != 0 {
			emitHeaders(st)
		}

	case framePushPromise:
		// Carries HPACK too, so it must go through the decoder or the dynamic
		// table desyncs. Pad-length, then 4-byte promised stream id, then block.
		frag := payload
		var pad int
		if flags&flagPadded != 0 && len(frag) > 0 {
			pad = int(frag[0])
			frag = frag[1:]
		}
		if len(frag) >= 4 {
			frag = frag[4:]
		}
		if pad <= len(frag) {
			frag = frag[:len(frag)-pad]
		}
		st.block = append(st.block, frag...)
		fmt.Printf("  PUSH_PROMISE stream=%d\n", streamID)
		if flags&flagEndHeaders != 0 {
			emitHeaders(st)
		}

	case frameContinuation:
		st.block = append(st.block, payload...)
		if flags&flagEndHeaders != 0 {
			emitHeaders(st)
		}

	case frameData:
		body := payload
		if flags&flagPadded != 0 && len(body) > 0 {
			pad := int(body[0])
			body = body[1:]
			if pad <= len(body) {
				body = body[:len(body)-pad]
			}
		}
		fmt.Printf("  DATA stream=%d (%d bytes)\n", streamID, len(body))
		if text := printableBytes(body); strings.TrimSpace(text) != "" {
			fmt.Println(indent(text))
		}

	case frameSettings:
		fmt.Printf("  SETTINGS (%d bytes)\n", len(payload))
	case frameWindowUpdate:
		fmt.Printf("  WINDOW_UPDATE stream=%d\n", streamID)
	case framePing:
		fmt.Println("  PING")
	case frameRSTStream:
		fmt.Printf("  RST_STREAM stream=%d\n", streamID)
	case frameGoAway:
		fmt.Println("  GOAWAY")
	case framePriority:
		fmt.Printf("  PRIORITY stream=%d\n", streamID)
	default:
		fmt.Printf("  frame type=0x%x stream=%d (%d bytes)\n", typ, streamID, len(payload))
	}
}

// emitHeaders decodes one complete header block with this direction's HPACK
// decoder and prints the header lines. A decode error means the dynamic table
// is no longer in step, so the direction is marked desynced.
func emitHeaders(st *stream) {
	block := st.block
	st.block = nil

	fields, err := st.dec.DecodeFull(block)
	if err != nil {
		fmt.Printf("  [HPACK decode failed: %v; direction desynced]\n", err)
		st.desynced = true
		return
	}
	for _, f := range fields {
		fmt.Printf("    %s: %s\n", f.Name, f.Value)
	}
}

func indent(s string) string {
	var b strings.Builder
	for line := range strings.SplitSeq(s, "\n") {
		b.WriteString("    ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return strings.TrimRight(b.String(), "\n")
}
