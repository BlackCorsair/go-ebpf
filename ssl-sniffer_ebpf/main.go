package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event -cc clang code code.bpf.c -- -I/usr/include/linux/bpf.h -D__TARGET_ARCH_x86

// Must match DIR_WRITE / DIR_READ in code.bpf.c.
const (
	dirWrite uint8 = 0
	dirRead  uint8 = 1
)

// tlsLib is one TLS library we know how to hook. The write/read functions of
// OpenSSL, GnuTLS and NSS all share the shape (handle, buf, count), so the same
// BPF programs attach to all of them (see code.bpf.c).
type tlsLib struct {
	name     string   // shown in logs
	paths    []string // candidate locations; the first one that exists is used
	writeSym string   // function carrying plaintext being sent
	readSym  string   // function receiving decrypted plaintext
}

// Standard library locations across common distros (Arch, Debian/Ubuntu,
// Fedora). NSS is hooked at the NSPR layer: PR_Write/PR_Read see the app's
// plaintext, since the SSL layer below talks to the socket through internal
// method pointers rather than the exported symbols.
var knownLibs = []tlsLib{
	{
		name: "OpenSSL",
		paths: []string{
			"/usr/lib/libssl.so.3", "/usr/lib64/libssl.so.3",
			"/usr/lib/x86_64-linux-gnu/libssl.so.3", "/lib/x86_64-linux-gnu/libssl.so.3",
			"/usr/lib/libssl.so.1.1", "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
		},
		writeSym: "SSL_write", readSym: "SSL_read",
	},
	{
		name: "GnuTLS",
		paths: []string{
			"/usr/lib/libgnutls.so.30", "/usr/lib64/libgnutls.so.30",
			"/usr/lib/x86_64-linux-gnu/libgnutls.so.30",
		},
		writeSym: "gnutls_record_send", readSym: "gnutls_record_recv",
	},
	{
		name: "NSS (NSPR)",
		paths: []string{
			"/usr/lib/libnspr4.so", "/usr/lib64/libnspr4.so",
			"/usr/lib/x86_64-linux-gnu/libnspr4.so",
		},
		writeSym: "PR_Write", readSym: "PR_Read",
	},
}

func main() {
	pid := flag.Int("pid", 0, "only trace this process (0 = every process)")
	extraLib := flag.String("lib", "", "additional OpenSSL-ABI library to hook (optional)")
	flag.Parse()

	libs := knownLibs
	if *extraLib != "" {
		libs = append(libs, tlsLib{
			name:  "custom:" + *extraLib,
			paths: []string{*extraLib},
			// Assume the OpenSSL ABI for a user-supplied library.
			writeSym: "SSL_write", readSym: "SSL_read",
		})
	}

	objs := codeObjects{}
	if err := loadCodeObjects(&objs, nil); err != nil {
		// %+v prints the whole verifier log, not just its last line.
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			log.Fatalf("loading objects: %+v", verr)
		}
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Uprobes are attached to a file, not to a process: every program that
	// loads this library (now or later) gets hooked, unless -pid is set.
	opts := &link.UprobeOptions{PID: *pid}

	var links []link.Link
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	attached := 0
	for _, lib := range libs {
		path := firstExisting(lib.paths)
		if path == "" {
			log.Printf("skipping %s: not found", lib.name)
			continue
		}
		ex, err := link.OpenExecutable(path)
		if err != nil {
			log.Printf("skipping %s (%s): %v", lib.name, path, err)
			continue
		}

		// A single missing symbol (e.g. a stripped build) shouldn't take down
		// the whole run, so attach failures here are warnings, not fatal.
		ls, err := attachLib(ex, lib, &objs, opts)
		if err != nil {
			log.Printf("skipping %s (%s): %v", lib.name, path, err)
			continue
		}
		links = append(links, ls...)
		attached++
		log.Printf("hooked %s at %s", lib.name, path)
	}
	if attached == 0 {
		log.Fatal("no TLS libraries could be hooked")
	}

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ring buffer: %v", err)
	}
	defer rd.Close()

	// Closing the reader is what unblocks rd.Read() below on Ctrl+C.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigs
		rd.Close()
	}()

	fmt.Println("Listening for plaintext TLS traffic. Press Ctrl+C to exit.")

	var ev codeEvent
	for {
		record, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			break
		}
		if err != nil {
			log.Printf("reading ring buffer: %v", err)
			continue
		}

		// Unmarshal: turn the raw bytes the kernel sent into a Go struct.
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decoding event: %v", err)
			continue
		}

		printEvent(&ev)
	}

	fmt.Println("\nExiting...")
}

// attachLib wires the three programs to one library's write/read symbols.
func attachLib(ex *link.Executable, lib tlsLib, objs *codeObjects, opts *link.UprobeOptions) ([]link.Link, error) {
	var out []link.Link
	add := func(l link.Link, err error, what string) error {
		if err != nil {
			return fmt.Errorf("%s: %w", what, err)
		}
		out = append(out, l)
		return nil
	}

	l, err := ex.Uprobe(lib.writeSym, objs.ProbeWrite, opts)
	if err := add(l, err, lib.writeSym); err != nil {
		return nil, err
	}
	l, err = ex.Uprobe(lib.readSym, objs.ProbeReadEnter, opts)
	if err := add(l, err, lib.readSym); err != nil {
		return nil, err
	}
	l, err = ex.Uretprobe(lib.readSym, objs.ProbeReadExit, opts)
	if err := add(l, err, lib.readSym+" (ret)"); err != nil {
		return nil, err
	}
	return out, nil
}

func firstExisting(paths []string) string {
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// printEvent routes an event to the HTTP/2 decoder when the connection is known
// to speak HTTP/2, and otherwise prints the plaintext as-is (HTTP/1.1 and any
// other text-ish protocol read fine; binary bodies become dots).
func printEvent(ev *codeEvent) {
	if handleHTTP2(ev) {
		return
	}

	printEventHeader(ev)
	fmt.Println(printableBytes(toBytes(ev.Data[:ev.Len])))
}

func printEventHeader(ev *codeEvent) {
	arrow, verb := ">>>", "sent"
	if ev.Direction == dirRead {
		arrow, verb = "<<<", "received"
	}

	comm := cString(ev.Comm[:])
	fmt.Printf("\n%s %s (pid %d, conn 0x%x) %s %d bytes", arrow, comm, ev.Pid, ev.Conn, verb, ev.Total)
	if ev.Total > ev.Len {
		fmt.Printf(" (showing the first %d)", ev.Len)
	}
	fmt.Println()
}

// cString cuts a fixed-size C char array at its first NUL byte.
func cString(b []int8) string {
	var sb strings.Builder
	for _, c := range b {
		if c == 0 {
			break
		}
		sb.WriteByte(byte(c))
	}
	return sb.String()
}

// toBytes reinterprets the kernel's []int8 data as []byte.
func toBytes(b []int8) []byte {
	out := make([]byte, len(b))
	for i, c := range b {
		out[i] = byte(c)
	}
	return out
}

// printableBytes keeps text readable and swaps anything else (compressed
// bodies, binary payloads...) for dots, so it doesn't wreck the terminal.
func printableBytes(b []byte) string {
	var sb strings.Builder
	for _, ch := range b {
		switch {
		case ch == '\n' || ch == '\t':
			sb.WriteByte(ch)
		case ch == '\r':
			// HTTP ends every line with \r\n, the \n alone is enough.
		case ch >= 0x20 && ch < 0x7f:
			sb.WriteByte(ch)
		default:
			sb.WriteByte('.')
		}
	}
	return sb.String()
}
