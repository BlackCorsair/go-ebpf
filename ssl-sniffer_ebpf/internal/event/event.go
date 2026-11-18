// Package event decodes and pretty-prints the records produced by
// ssl_sniffer.bpf.c.
package event

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Direction mirrors enum ssl_dir in the BPF program.
type Direction uint8

const (
	Read  Direction = 0 // received, after decryption
	Write Direction = 1 // sent, before encryption
)

func (d Direction) String() string {
	if d == Write {
		return "WRITE"
	}
	return "READ"
}

// header mirrors every field of struct ssl_event that precedes data[]. The
// BPF side only sends header + len bytes, so the generated Go type (which
// includes the full 16 KiB array) cannot be used with binary.Read directly.
type header struct {
	TsNs      uint64
	SSLPtr    uint64
	PID       uint32
	TID       uint32
	Len       uint32
	OrigLen   uint32
	Dir       uint8
	Truncated uint8
	_         [6]uint8
	Comm      [16]byte
}

// HeaderSize must equal offsetof(struct ssl_event, data).
var HeaderSize = binary.Size(header{})

// Event is a decoded chunk of plaintext.
type Event struct {
	Time      time.Time
	SSL       uint64 // connection handle (SSL* / gnutls session / PRFileDesc*)
	PID, TID  uint32
	Comm      string
	Dir       Direction
	OrigLen   uint32 // bytes transferred by the SSL call
	Truncated bool   // Data holds fewer bytes than OrigLen
	Data      []byte
}

// Decode parses one ring buffer record.
func Decode(raw []byte) (Event, error) {
	var h header
	if len(raw) < HeaderSize {
		return Event{}, fmt.Errorf("short record: %d bytes", len(raw))
	}
	if err := binary.Read(bytes.NewReader(raw[:HeaderSize]), binary.LittleEndian, &h); err != nil {
		return Event{}, err
	}
	if int(h.Len) > len(raw)-HeaderSize {
		return Event{}, fmt.Errorf("record claims %d bytes, has %d", h.Len, len(raw)-HeaderSize)
	}

	return Event{
		Time:      monoToWall(h.TsNs),
		SSL:       h.SSLPtr,
		PID:       h.PID,
		TID:       h.TID,
		Comm:      unix.ByteSliceToString(h.Comm[:]),
		Dir:       Direction(h.Dir),
		OrigLen:   h.OrigLen,
		Truncated: h.Truncated != 0,
		Data:      raw[HeaderSize : HeaderSize+int(h.Len)],
	}, nil
}

// monoToWall converts a bpf_ktime_get_ns() timestamp (CLOCK_MONOTONIC) into
// wall-clock time by measuring how long ago it happened.
func monoToWall(ns uint64) time.Time {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
		return time.Now()
	}
	ago := time.Duration(now.Nano() - int64(ns))
	return time.Now().Add(-ago)
}

// Verbosity levels. Each output line is tagged with the lowest level that
// shows it; see lines.at.
const (
	LevelSummary = 0 // one line per HTTP request / response
	LevelHeaders = 1 // + full headers (default)
	LevelBodies  = 2 // + bodies (DATA frames, HTTP/1 bodies)
	LevelAll     = 3 // + control frames and data that isn't recognised HTTP
)

// Printer renders events in a human friendly form. It is not safe for
// concurrent use: protocol decoding keeps per-connection state.
type Printer struct {
	Out      io.Writer
	Level    int  // LevelSummary .. LevelAll
	Hex      bool // raw mode: hexdump every event, no protocol decoding
	MaxBytes int  // print at most this many body bytes per event, 0 = all
	Color    bool
	HTTP2    bool // decode HTTP/2; false is raw mode, like Hex but as text

	// Sink, if set, receives the full decoding of every event regardless of
	// Level, for the -o log a UI reads. LogData adds the raw bytes to it.
	Sink    Sink
	LogData bool

	conns map[uint64]*conn // protocol state per connection handle
}

const (
	colorReset = "\033[0m"
	colorRead  = "\033[32m" // green
	colorWrite = "\033[36m" // cyan
	colorDim   = "\033[2m"
)

// maxConns bounds the per-connection state. Handles of closed connections
// are never announced, so the table is simply reset when it gets this big.
const maxConns = 4096

// Print renders one event at the configured verbosity.
func (p *Printer) Print(e Event) {
	// Raw mode: every event, as captured.
	if p.Hex || !p.HTTP2 {
		p.printPlain(e, e.Data)
		return
	}
	p.decode(e)
}

func (p *Printer) conn(id uint64) *conn {
	if p.conns == nil || len(p.conns) >= maxConns {
		p.conns = map[uint64]*conn{}
	}
	c := p.conns[id]
	if c == nil {
		c = &conn{}
		p.conns[id] = c
	}
	return c
}

// item is one output line and the verbosity range that shows it.
type item struct {
	min, max int
	text     string
	summary  bool // printed with its own timestamp prefix, no event header
}

// lines collects what one event has to say, before deciding what to show.
// Decoding must run on every event regardless of the level (HPACK state
// depends on it), so filtering happens at the end, here.
type lines []item

// at adds a line shown at level min and above.
func (l *lines) at(min int, format string, args ...any) {
	*l = append(*l, item{min: min, max: LevelAll, text: fmt.Sprintf(format, args...)})
}

// summary adds a line shown only at LevelSummary; higher levels show the
// same information in full.
func (l *lines) summary(format string, args ...any) {
	*l = append(*l, item{min: LevelSummary, max: LevelSummary, text: fmt.Sprintf(format, args...), summary: true})
}

// render prints the lines visible at the current level. At LevelSummary
// each line stands alone; above it, visible lines go under the event header.
func (p *Printer) render(e Event, tag string, l lines) {
	if p.Sink != nil && len(l) > 0 {
		p.Sink.Emit(record(e, tag, l, e.Data, p.LogData))
	}

	var visible []item
	for _, it := range l {
		if p.Level >= it.min && p.Level <= it.max {
			visible = append(visible, it)
		}
	}
	if len(visible) == 0 {
		return
	}

	if p.Level == LevelSummary {
		for _, it := range visible {
			p.printSummary(e, it.text)
		}
		return
	}

	p.printHeader(e, tag)
	for _, it := range visible {
		fmt.Fprintln(p.Out, it.text)
	}
	fmt.Fprintln(p.Out)
}

func (p *Printer) colors(e Event) (dirColor, reset, dim string) {
	if !p.Color {
		return "", "", ""
	}
	if e.Dir == Write {
		return colorWrite, colorReset, colorDim
	}
	return colorRead, colorReset, colorDim
}

func arrow(d Direction) string {
	if d == Write {
		return "->"
	}
	return "<-"
}

// printSummary prints one self-contained LevelSummary line.
func (p *Printer) printSummary(e Event, text string) {
	dirColor, reset, dim := p.colors(e)
	proc := e.Comm
	if i := strings.IndexByte(proc, ':'); i >= 0 {
		proc = proc[:i] // the thread name adds nothing here
	}
	fmt.Fprintf(p.Out, "%s%s %s[%d]%s %s%s %s%s\n",
		dim, e.Time.Format("15:04:05.000"), proc, e.PID, reset,
		dirColor, arrow(e.Dir), text, reset)
}

// printHeader writes the one-line summary that starts every event. tag, if
// not empty, names the protocol that was recognised.
func (p *Printer) printHeader(e Event, tag string) {
	dirColor, reset, dim := p.colors(e)

	size := fmt.Sprintf("%d bytes", e.OrigLen)
	if e.Truncated {
		size = fmt.Sprintf("%d bytes (captured %d)", e.OrigLen, len(e.Data))
	}
	if tag != "" {
		size += " " + tag
	}

	fmt.Fprintf(p.Out, "%s%s %s[%d/%d] conn=%#x%s %s%s %-5s %s%s\n",
		dim, e.Time.Format("15:04:05.000000"), e.Comm, e.PID, e.TID, e.SSL, reset,
		dirColor, arrow(e.Dir), e.Dir, size, reset)
}

// printPlain writes the header and then data as text or hexdump (raw mode).
func (p *Printer) printPlain(e Event, data []byte) {
	if p.Sink != nil {
		var l lines
		l.at(LevelSummary, "%s", printable(e.Data))
		p.Sink.Emit(record(e, "", l, e.Data, p.LogData))
	}

	_, reset, dim := p.colors(e)
	p.printHeader(e, "")

	cut := 0
	if p.MaxBytes > 0 && len(data) > p.MaxBytes {
		cut = len(data) - p.MaxBytes
		data = data[:p.MaxBytes]
	}

	if p.Hex {
		fmt.Fprint(p.Out, hex.Dump(data))
	} else {
		fmt.Fprintln(p.Out, printable(data))
	}
	if cut > 0 {
		fmt.Fprintf(p.Out, "%s[... %d more bytes]%s\n", dim, cut, reset)
	}
	fmt.Fprintln(p.Out)
}

// printable keeps text-like bytes and replaces everything else with '.',
// so binary protocols (HTTP/2 frames, gzip bodies...) don't wreck the
// terminal. CRLF line endings are normalised to LF.
func printable(b []byte) string {
	var sb strings.Builder
	sb.Grow(len(b))
	for i, c := range b {
		switch {
		case c == '\r' && i+1 < len(b) && b[i+1] == '\n':
			// dropped, the '\n' follows
		case c == '\n' || c == '\t' || (c >= 0x20 && c < 0x7f):
			sb.WriteByte(c)
		default:
			sb.WriteByte('.')
		}
	}
	return strings.TrimRight(sb.String(), "\n")
}
