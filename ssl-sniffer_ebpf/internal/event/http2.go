package event

import (
	"encoding/binary"
	"strings"

	"golang.org/x/net/http2/hpack"
)

// The 24-byte string every HTTP/2 client sends first, before any frame. Seeing
// it on the write side is how we recognise an HTTP/2 connection with certainty.
const http2Preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// HTTP/2 frame types we care to name (RFC 9113 §6).
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
	flagEndStream  = 0x1
	flagEndHeaders = 0x4
	flagPadded     = 0x8
	flagPriority   = 0x20
)

// h2stream is one direction of one connection. HPACK keeps a dynamic table
// that is per-connection and per-direction, so each direction owns its
// decoder and its own leftover bytes.
type h2stream struct {
	buf      []byte           // bytes received but not yet consumed as whole frames
	block    []byte           // header block accumulating over HEADERS+CONTINUATION
	blockID  uint32           // stream the pending header block belongs to
	dec      *hpack.Decoder   // HPACK state for this direction
	desynced bool             // a gap (truncation / bad HPACK) broke this side for good
	bodies   map[uint32]*body // DATA accumulating per HTTP/2 stream id
}

func (c *conn) stream(d Direction) *h2stream {
	if c.dirs[d] == nil {
		c.dirs[d] = &h2stream{dec: hpack.NewDecoder(4096, nil), bodies: map[uint32]*body{}}
	}
	return c.dirs[d]
}

// decodeHTTP2 reassembles frames from one event's bytes and renders them.
func (p *Printer) decodeHTTP2(e Event, c *conn, data []byte) {
	var l lines
	st := c.stream(e.Dir)

	switch {
	case e.Truncated:
		// The capture was cut short: the frame stream has a hole in it, so
		// nothing after this point lines up, and HPACK's dynamic table is now
		// out of step too. Stop trusting this direction.
		if !st.desynced {
			l.at(LevelHeaders, "  [capture truncated at %d bytes; can't decode this direction any more]", len(e.Data))
		}
		st.buf, st.block, st.desynced, st.bodies = nil, nil, true, map[uint32]*body{}
	case st.desynced:
		l.at(LevelAll, "  [direction desynced earlier; not decoding]")
	default:
		st.buf = append(st.buf, data...)
		p.parseFrames(&l, c, st)
	}

	p.render(e, "HTTP/2", l)
}

// parseFrames pulls every complete frame out of st.buf, leaving any partial
// trailing frame for the next event to finish.
func (p *Printer) parseFrames(l *lines, c *conn, st *h2stream) {
	for len(st.buf) >= 9 {
		length := int(st.buf[0])<<16 | int(st.buf[1])<<8 | int(st.buf[2])
		if len(st.buf) < 9+length {
			break // the rest of this frame hasn't arrived yet
		}
		typ, flags := st.buf[3], st.buf[4]
		streamID := binary.BigEndian.Uint32(st.buf[5:9]) & 0x7fffffff
		payload := st.buf[9 : 9+length]

		p.frame(l, c, st, typ, flags, streamID, payload)
		st.buf = st.buf[9+length:]
	}
	// Don't let the backing array grow forever on a long-lived connection.
	if len(st.buf) == 0 {
		st.buf = nil
	}
}

// stripPadding removes the pad-length byte and the trailing padding of a
// PADDED frame payload.
func stripPadding(flags byte, payload []byte) []byte {
	if flags&flagPadded == 0 || len(payload) == 0 {
		return payload
	}
	pad := int(payload[0])
	payload = payload[1:]
	if pad > len(payload) {
		return nil // malformed
	}
	return payload[:len(payload)-pad]
}

func (p *Printer) frame(l *lines, c *conn, st *h2stream, typ, flags byte, streamID uint32, payload []byte) {
	end := ""
	if flags&flagEndStream != 0 {
		end = " END_STREAM"
	}

	switch typ {
	case frameHeaders:
		frag := stripPadding(flags, payload)
		if flags&flagPriority != 0 && len(frag) >= 5 {
			frag = frag[5:] // stream dependency + weight
		}
		st.block, st.blockID = append(st.block, frag...), streamID
		l.at(LevelHeaders, "  HEADERS stream=%d%s", streamID, end)
		if flags&flagEndHeaders != 0 {
			p.headers(l, c, st)
		}

	case framePushPromise:
		// Carries HPACK too, so it must go through the decoder or the dynamic
		// table desyncs. Promised stream id first, then the block.
		frag := stripPadding(flags, payload)
		if len(frag) >= 4 {
			frag = frag[4:]
		}
		st.block, st.blockID = append(st.block, frag...), streamID
		l.at(LevelHeaders, "  PUSH_PROMISE stream=%d", streamID)
		if flags&flagEndHeaders != 0 {
			p.headers(l, c, st)
		}

	case frameContinuation:
		st.block = append(st.block, payload...)
		if flags&flagEndHeaders != 0 {
			p.headers(l, c, st)
		}

	case frameData:
		data := stripPadding(flags, payload)
		b := st.bodies[streamID]
		if b == nil {
			b = &body{}
			st.bodies[streamID] = b
		}
		b.add(data)
		l.at(LevelBodies, "  DATA stream=%d (%d bytes)%s", streamID, len(data), end)
		if flags&flagEndStream != 0 {
			p.flushStream(l, st, streamID)
		}

	case frameSettings:
		l.at(LevelAll, "  SETTINGS (%d bytes)", len(payload))
	case frameWindowUpdate:
		l.at(LevelAll, "  WINDOW_UPDATE stream=%d", streamID)
	case framePing:
		l.at(LevelAll, "  PING")
	case frameRSTStream:
		l.at(LevelAll, "  RST_STREAM stream=%d", streamID)
	case frameGoAway:
		l.at(LevelAll, "  GOAWAY")
	case framePriority:
		l.at(LevelAll, "  PRIORITY stream=%d", streamID)
	default:
		l.at(LevelAll, "  frame type=0x%x stream=%d (%d bytes)", typ, streamID, len(payload))
	}
}

// headers decodes one complete header block with this direction's HPACK
// decoder. A decode error means the dynamic table is no longer in step, so
// the direction is marked desynced.
func (p *Printer) headers(l *lines, c *conn, st *h2stream) {
	block, id := st.block, st.blockID
	st.block = nil

	fields, err := st.dec.DecodeFull(block)
	if err != nil {
		l.at(LevelHeaders, "  [HPACK decode failed: %v; can't decode this direction any more]", err)
		st.desynced = true
		return
	}

	h := map[string]string{}
	for _, f := range fields {
		l.at(LevelHeaders, "    %s: %s", f.Name, f.Value)
		if _, dup := h[f.Name]; !dup {
			h[f.Name] = f.Value
		}
	}

	// Remember how this stream's body is encoded, so the DATA frames that
	// follow can be de-chunked (not in HTTP/2) and decompressed on END_STREAM.
	if h["content-encoding"] != "" || h["content-type"] != "" {
		b := st.bodies[id]
		if b == nil {
			b = &body{}
			st.bodies[id] = b
		}
		b.encoding, b.ctype = h["content-encoding"], h["content-type"]
	}

	// One summary line per request and per response. Trailers (a second
	// header block with neither pseudo-header) get none.
	switch {
	case h[":method"] != "":
		req := h[":method"] + " " + h2URL(h)
		if c.reqs == nil {
			c.reqs = map[uint32]string{}
		}
		c.reqs[id] = req
		l.summary("%s", req)
	case h[":status"] != "":
		req := c.reqs[id]
		delete(c.reqs, id)
		l.summary("%s", responseSummary(h[":status"], req, h["content-type"], h["content-length"]))
	}
}

// flushStream decodes and prints a finished HTTP/2 stream body.
func (p *Printer) flushStream(l *lines, st *h2stream, id uint32) {
	b := st.bodies[id]
	delete(st.bodies, id)
	if b != nil {
		p.renderBody(l, b)
	}
}

// renderBody de-chunks, decompresses and prints a message body at
// LevelBodies, cut to MaxBytes. A note records any decoding that happened or
// failed. It is shared by the HTTP/2 and HTTP/1 paths.
func (p *Printer) renderBody(l *lines, b *body) {
	if len(b.buf) == 0 {
		return
	}
	data, note := b.decoded()
	if note != "" {
		l.at(LevelBodies, "  body%s", note)
	}

	cut := 0
	if p.MaxBytes > 0 && len(data) > p.MaxBytes {
		cut = len(data) - p.MaxBytes
		data = data[:p.MaxBytes]
	}
	text := printable(data)
	if strings.TrimSpace(strings.Trim(text, ".\n")) == "" {
		l.at(LevelBodies, "    [%d bytes of binary data]", len(data)+cut)
		return
	}
	l.at(LevelBodies, "%s", indent(text))
	if cut > 0 {
		l.at(LevelBodies, "    [... %d more bytes]", cut)
	}
}

func h2URL(h map[string]string) string {
	scheme := h[":scheme"]
	if scheme == "" {
		scheme = "https"
	}
	if h[":authority"] == "" {
		return h[":path"]
	}
	return scheme + "://" + h[":authority"] + h[":path"]
}
