package event

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
)

// conn is the protocol state of one TLS connection, keyed by the library's
// connection handle (SSL* for OpenSSL, PRFileDesc* for NSS).
type conn struct {
	decided bool   // classified as HTTP/2 or not yet
	http2   bool   //
	pending []byte // write bytes held while a split HTTP/2 preface may be arriving

	// HTTP/2
	dirs [2]*h2stream      // per direction, indexed by Direction
	reqs map[uint32]string // stream id -> request summary, to label responses

	// HTTP/1.x
	http1  bool     // a request or response line has been seen
	h1reqs []string // request summaries awaiting a response, oldest first
	h1body [2]*body // body being reassembled per direction, nil between messages
}

// decode routes one event to the HTTP/2 or the HTTP/1 / unknown path.
func (p *Printer) decode(e Event) {
	data := e.Data

	// A client preface that arrives whole marks a new HTTP/2 connection; start
	// its state fresh. This also handles the allocator handing a freed handle
	// address to a new connection.
	if e.Dir == Write && bytes.HasPrefix(data, []byte(http2Preface)) {
		p.conn(e.SSL) // makes sure the table exists
		p.conns[e.SSL] = &conn{decided: true, http2: true}
		data = data[len(http2Preface):]
	}

	c := p.conn(e.SSL)

	// Not yet classified: the preface may be split across several small
	// writes, so hold write bytes until there are enough to compare.
	if !c.decided {
		if e.Dir != Write {
			// A read before any client write: we attached mid-connection.
			// HPACK state can't be rebuilt, so this can't be decoded as HTTP/2.
			c.decided = true
		} else {
			c.pending = append(c.pending, data...)
			if len(c.pending) < len(http2Preface) && bytes.HasPrefix([]byte(http2Preface), c.pending) {
				return // may still become a preface; print nothing yet
			}
			c.decided = true
			data, c.pending = c.pending, nil
			if bytes.HasPrefix(data, []byte(http2Preface)) {
				c.http2 = true
				data = data[len(http2Preface):]
			}
		}
	}

	if c.http2 {
		p.decodeHTTP2(e, c, data)
		return
	}
	p.decodeText(e, c, data)
}

var (
	requestLine  = regexp.MustCompile(`^([A-Z]+) (\S+) HTTP/1\.[01]$`)
	responseLine = regexp.MustCompile(`^HTTP/1\.[01] ([0-9]{3})(?: (.*))?$`)
)

// decodeText handles everything that isn't HTTP/2: HTTP/1.x messages, their
// bodies, and anything else (WebSocket frames, other protocols).
func (p *Printer) decodeText(e Event, c *conn, data []byte) {
	var l lines

	head, body, hasBody := splitHead(data)
	first, rest, _ := strings.Cut(head, "\n")
	first = strings.TrimSuffix(first, "\r")

	switch {
	case requestLine.MatchString(first):
		c.http1 = true
		m := requestLine.FindStringSubmatch(first)
		hdrs := parseHeaderLines(rest)
		req := m[1] + " " + requestURL(hdrs["host"], m[2])
		c.h1reqs = append(c.h1reqs, req)
		l.summary("%s", req)
		p.headText(&l, head)
		p.startH1Body(&l, c, e.Dir, hdrs, body, hasBody)
		p.render(e, "HTTP/1.1", l)

	case responseLine.MatchString(first):
		c.http1 = true
		m := responseLine.FindStringSubmatch(first)
		hdrs := parseHeaderLines(rest)
		var req string
		if len(c.h1reqs) > 0 {
			req, c.h1reqs = c.h1reqs[0], c.h1reqs[1:]
		}
		l.summary("%s", responseSummary(m[1], req, hdrs["content-type"], hdrs["content-length"]))
		p.headText(&l, head)
		p.startH1Body(&l, c, e.Dir, hdrs, body, hasBody)
		p.render(e, "HTTP/1.1", l)

	case c.http1 && c.h1body[e.Dir] != nil:
		// The rest of an HTTP/1 body, spread over several reads.
		b := c.h1body[e.Dir]
		b.add(data)
		if b.complete() {
			p.renderBody(&l, b)
			c.h1body[e.Dir] = nil
		}
		p.render(e, "HTTP/1.1", l)

	default:
		// Not HTTP, or a connection already open when we attached.
		l.at(LevelAll, "%s", printableCut(data, p.MaxBytes))
		p.render(e, "", l)
	}
}

// startH1Body sets up body reassembly for an HTTP/1 message from its headers,
// feeds the bytes that arrived with them, and renders the body if it already
// completed in this one event.
func (p *Printer) startH1Body(l *lines, c *conn, dir Direction, hdrs map[string]string, first []byte, hasBody bool) {
	if !hasBody {
		c.h1body[dir] = nil
		return
	}
	b := &body{encoding: hdrs["content-encoding"], ctype: hdrs["content-type"]}
	if strings.Contains(strings.ToLower(hdrs["transfer-encoding"]), "chunked") {
		b.chunked = true
	}
	if n, err := strconv.Atoi(strings.TrimSpace(hdrs["content-length"])); err == nil {
		b.hasLength, b.length = true, n
	}
	// A message with neither length nor chunked framing (e.g. a bare 304) has
	// no body to wait for.
	if !b.chunked && !b.hasLength && len(first) == 0 {
		c.h1body[dir] = nil
		return
	}

	b.add(first)
	c.h1body[dir] = b
	if b.complete() {
		p.renderBody(l, b)
		c.h1body[dir] = nil
	}
}

// headText adds the request/response line and headers at LevelHeaders.
func (p *Printer) headText(l *lines, head string) {
	l.at(LevelHeaders, "%s", indent(strings.TrimRight(printable([]byte(head)), "\n")))
}

// splitHead separates an HTTP/1 header section from the body. Without a
// blank line, the whole event is header (the rest comes in the next one).
func splitHead(data []byte) (head string, body []byte, hasBody bool) {
	if i := bytes.Index(data, []byte("\r\n\r\n")); i >= 0 {
		return string(data[:i]), data[i+4:], true
	}
	return string(data), nil, false
}

// parseHeaderLines turns "Name: value" lines into a map with lowercase keys.
func parseHeaderLines(s string) map[string]string {
	h := map[string]string{}
	for line := range strings.SplitSeq(s, "\n") {
		name, value, ok := strings.Cut(strings.TrimSuffix(line, "\r"), ":")
		if ok {
			h[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(value)
		}
	}
	return h
}

// requestURL rebuilds the URL of a request. Everything we see went through
// TLS, so the scheme is https.
func requestURL(host, target string) string {
	if host == "" || !strings.HasPrefix(target, "/") {
		return target // absolute-form, authority-form (CONNECT) or no Host
	}
	return "https://" + host + target
}

// responseSummary builds "200 GET https://host/path (text/html, 1256 bytes)".
func responseSummary(status, req, contentType, contentLength string) string {
	var b strings.Builder
	b.WriteString(status)
	if req != "" {
		b.WriteString(" " + req)
	}
	var extra []string
	if contentType != "" {
		ct, _, _ := strings.Cut(contentType, ";")
		extra = append(extra, ct)
	}
	if contentLength != "" {
		extra = append(extra, contentLength+" bytes")
	}
	if len(extra) > 0 {
		b.WriteString(" (" + strings.Join(extra, ", ") + ")")
	}
	return b.String()
}

func printableCut(data []byte, max int) string {
	if max > 0 && len(data) > max {
		return printable(data[:max]) + "\n[... " + strconv.Itoa(len(data)-max) + " more bytes]"
	}
	return printable(data)
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
