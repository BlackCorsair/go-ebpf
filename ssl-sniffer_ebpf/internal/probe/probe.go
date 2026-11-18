// Package probe loads ssl_sniffer.bpf.c and attaches its programs to the
// plaintext read/write functions of TLS libraries (OpenSSL, NSS/NSPR).
package probe

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang sniffer ../../bpf/ssl_sniffer.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

// Dir is the direction of the data a hooked function carries. It must match
// enum ssl_dir in the BPF program.
type Dir uint8

const (
	DirRead  Dir = 0
	DirWrite Dir = 1
)

// SymSpec describes one function to hook.
//
// Every supported function has the shape (handle, buf, count, ...): the first
// argument identifies the connection, the second is the plaintext buffer. That
// is why the same BPF programs serve OpenSSL and NSPR alike.
type SymSpec struct {
	Symbol string
	Dir    Dir
	// Ex marks the OpenSSL *_ex variants: they return 1 on success and report
	// the byte count through a size_t * fourth argument.
	Ex bool
	// Optional symbols may be missing from a library without failing it.
	Optional bool
	// NSPR marks PR_Read/PR_Write & co. Their entry probe keeps only calls on
	// TCP sockets, dropping file and pipe I/O in the kernel.
	NSPR bool
}

// Target is one ELF file (shared library or executable) and the functions to
// hook in it.
type Target struct {
	Path string    // file to attach to
	Lib  string    // library family, for logs ("OpenSSL", "NSS")
	Syms []SymSpec // functions to hook
}

// Options tunes how the probes are attached.
type Options struct {
	// PID restricts the uprobes to a single process. The filtering is done by
	// the kernel's uprobe machinery itself, so other processes never even run
	// our BPF programs. 0 means every process.
	PID int
}

// Attachment reports which symbols were hooked in a given file.
type Attachment struct {
	Target  Target
	Symbols []string
	Skipped []string // optional symbols the file does not export
}

// Sniffer owns the loaded BPF objects, their links and the ring buffer reader.
type Sniffer struct {
	objs  snifferObjects
	links []link.Link

	// Events yields one raw struct ssl_event per record; see package event.
	Events *ringbuf.Reader
}

// New loads the BPF objects and attaches them to every target. A target that
// cannot be instrumented is reported in failed instead of aborting the run,
// so one odd library doesn't take the others down.
func New(targets []Target, opts Options) (s *Sniffer, ok []Attachment, failed []error, err error) {
	// Only needed on kernels older than 5.11, where BPF memory was charged
	// against RLIMIT_MEMLOCK instead of the memory cgroup.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, nil, nil, fmt.Errorf("removing memlock rlimit: %w", err)
	}

	s = &Sniffer{}
	if err := loadSnifferObjects(&s.objs, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return nil, nil, nil, fmt.Errorf("loading BPF objects: %+v", verr)
		}
		return nil, nil, nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	for _, t := range targets {
		a, err := s.attachTarget(t, opts)
		if err != nil {
			failed = append(failed, err)
			continue
		}
		ok = append(ok, a)
	}
	if len(ok) == 0 {
		s.Close()
		return nil, nil, failed, errors.New("no library could be instrumented")
	}

	rd, err := ringbuf.NewReader(s.objs.Events)
	if err != nil {
		s.Close()
		return nil, nil, failed, fmt.Errorf("opening ring buffer: %w", err)
	}
	s.Events = rd

	return s, ok, failed, nil
}

// programs picks the entry and return programs for one function.
func (s *Sniffer) programs(spec SymSpec) (enter, exit *ebpf.Program) {
	switch {
	case spec.NSPR && spec.Dir == DirWrite:
		return s.objs.NsprRwEnter, s.objs.SslWriteExit
	case spec.NSPR:
		return s.objs.NsprRwEnter, s.objs.SslReadExit
	case spec.Ex && spec.Dir == DirWrite:
		return s.objs.SslRwExEnter, s.objs.SslWriteExExit
	case spec.Ex:
		return s.objs.SslRwExEnter, s.objs.SslReadExExit
	case spec.Dir == DirWrite:
		return s.objs.SslRwEnter, s.objs.SslWriteExit
	default:
		return s.objs.SslRwEnter, s.objs.SslReadExit
	}
}

func (s *Sniffer) attachTarget(t Target, opts Options) (Attachment, error) {
	a := Attachment{Target: t}

	ex, err := link.OpenExecutable(t.Path)
	if err != nil {
		return a, fmt.Errorf("%s %s: %w", t.Lib, t.Path, err)
	}

	// Links for this target only, so a failure half-way through can be undone
	// without leaving a partially hooked library behind.
	var links []link.Link
	undo := func() {
		for _, l := range links {
			l.Close()
		}
	}

	uopts := &link.UprobeOptions{PID: opts.PID}
	for _, spec := range t.Syms {
		enter, exit := s.programs(spec)

		// The return probe goes in first. If the entry probe were attached
		// first, a call in progress at that moment could leave a stale entry
		// in active_calls; the other way around, a return without a saved
		// entry is simply ignored by the BPF side.
		ret, err := ex.Uretprobe(spec.Symbol, exit, uopts)
		if err != nil {
			if spec.Optional && errors.Is(err, link.ErrNoSymbol) {
				a.Skipped = append(a.Skipped, spec.Symbol)
				continue
			}
			undo()
			return a, fmt.Errorf("%s %s: uretprobe %s: %w", t.Lib, t.Path, spec.Symbol, err)
		}
		links = append(links, ret)

		ent, err := ex.Uprobe(spec.Symbol, enter, uopts)
		if err != nil {
			undo()
			return a, fmt.Errorf("%s %s: uprobe %s: %w", t.Lib, t.Path, spec.Symbol, err)
		}
		links = append(links, ent)

		a.Symbols = append(a.Symbols, spec.Symbol)
	}

	s.links = append(s.links, links...)
	return a, nil
}

// Dropped returns how many events the BPF side failed to push because the
// ring buffer was full, summed over all CPUs.
func (s *Sniffer) Dropped() (uint64, error) {
	var perCPU []uint64
	if err := s.objs.Dropped.Lookup(uint32(0), &perCPU); err != nil {
		return 0, err
	}
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	return total, nil
}

// Close detaches every probe and releases all BPF resources.
func (s *Sniffer) Close() {
	if s.Events != nil {
		s.Events.Close()
	}
	for _, l := range s.links {
		l.Close()
	}
	s.objs.Close()
}
