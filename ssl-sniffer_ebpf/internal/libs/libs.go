// Package libs finds the TLS libraries worth hooking on this machine.
//
// Candidates come from three places:
//
//   - the dynamic linker cache (ldconfig -p): system OpenSSL, GnuTLS and NSPR;
//   - well-known browser install locations (tarballs in /opt, Snap, flatpak);
//   - the memory maps of running processes, which also finds copies inside
//     flatpak/Snap sandboxes through /proc/<pid>/root.
//
// Every candidate is then classified by the symbols it exports, not by its
// name. That matters for Mozilla's official builds, which fold NSPR into
// libnss3.so: there PR_Write lives in libnss3.so and libnspr4.so may not exist.
package libs

import (
	"bufio"
	"bytes"
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/Rattle-Brain/go-ebpf/ssl-sniffer_ebpf/internal/probe"
)

// Kind is a TLS library family.
type Kind string

const (
	OpenSSL Kind = "openssl"
	GnuTLS  Kind = "gnutls"
	NSS     Kind = "nss" // hooked at the NSPR layer
)

// AllKinds lists every supported family.
var AllKinds = []Kind{OpenSSL, GnuTLS, NSS}

// family describes how to recognise a library and what to hook in it.
type family struct {
	kind  Kind
	label string
	probe string // symbol whose presence identifies the family
	syms  []probe.SymSpec
}

var families = []family{
	{
		kind: OpenSSL, label: "OpenSSL", probe: "SSL_write",
		syms: []probe.SymSpec{
			{Symbol: "SSL_write", Dir: probe.DirWrite},
			{Symbol: "SSL_read", Dir: probe.DirRead},
			// Only since OpenSSL 1.1.1; Python's ssl module and others use them.
			{Symbol: "SSL_write_ex", Dir: probe.DirWrite, Ex: true, Optional: true},
			{Symbol: "SSL_read_ex", Dir: probe.DirRead, Ex: true, Optional: true},
		},
	},
	{
		// ssize_t gnutls_record_send(gnutls_session_t, const void *, size_t).
		// The return value is a ssize_t; the BPF side reads it as an int,
		// which is exact for any record size and keeps negative errors negative.
		kind: GnuTLS, label: "GnuTLS", probe: "gnutls_record_send",
		syms: []probe.SymSpec{
			{Symbol: "gnutls_record_send", Dir: probe.DirWrite},
			{Symbol: "gnutls_record_recv", Dir: probe.DirRead},
		},
	},
	{
		// Firefox and its forks (LibreWolf, Floorp, Zen, Waterfox, Tor Browser,
		// Thunderbird...) do TLS with NSS. NSS's SSL code is an NSPR I/O layer
		// pushed on top of the socket, so the application's PR_Write/PR_Read on
		// that socket carry plaintext. The SSL layer itself reaches the TCP
		// socket through method pointers (fd->lower->methods->write), never
		// through these exported functions, so no ciphertext shows up here.
		//
		// PR_Send/PR_Recv take extra (flags, timeout) arguments, but the
		// handle, buffer and count are the first three, as everywhere else.
		kind: NSS, label: "NSS", probe: "PR_Write",
		syms: []probe.SymSpec{
			{Symbol: "PR_Write", Dir: probe.DirWrite, NSPR: true},
			{Symbol: "PR_Read", Dir: probe.DirRead, NSPR: true},
			{Symbol: "PR_Send", Dir: probe.DirWrite, Optional: true, NSPR: true},
			{Symbol: "PR_Recv", Dir: probe.DirRead, Optional: true, NSPR: true},
		},
	},
}

// Base names that may hold one of the families above.
var candidateName = regexp.MustCompile(`^(libssl\.so\.[0-9.]+|libgnutls\.so\.[0-9.]+|libnspr4\.so|libnss3\.so)$`)

// Find returns one target per (library file, family) for the requested
// kinds. Files reachable through several paths are reported once.
func Find(kinds []Kind) []probe.Target {
	var paths []string
	paths = append(paths, fromLdconfig()...)
	paths = append(paths, fromKnownLocations()...)
	paths = append(paths, fromRunningProcesses()...)
	return Classify(paths, kinds)
}

// Classify turns file paths into targets, keeping the requested kinds. It
// deduplicates by inode: a uprobe is attached to the file itself, so hooking
// the same inode twice through two paths would report every call twice.
func Classify(paths []string, kinds []Kind) []probe.Target {
	want := map[Kind]bool{}
	for _, k := range kinds {
		want[k] = true
	}

	type fileID struct{ dev, ino uint64 }
	seen := map[fileID]bool{}

	var out []probe.Target
	for _, p := range paths {
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			id := fileID{uint64(sys.Dev), sys.Ino}
			if seen[id] {
				continue
			}
			seen[id] = true
		}

		exported := dynamicSymbols(p)
		for _, f := range families {
			if want[f.kind] && exported[f.probe] {
				out = append(out, probe.Target{Path: p, Lib: f.label, Syms: f.syms})
			}
		}
	}
	return out
}

// dynamicSymbols returns the names of the functions an ELF file exports.
func dynamicSymbols(path string) map[string]bool {
	f, err := elf.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	syms, err := f.DynamicSymbols()
	if err != nil {
		return nil
	}
	out := make(map[string]bool, len(syms))
	for _, s := range syms {
		// Undefined symbols are imports, not exports.
		if s.Section != elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			out[s.Name] = true
		}
	}
	return out
}

// ldconfig -p lines look like:
//
//	libssl.so.3 (libc6,x86-64) => /usr/lib/libssl.so.3
var ldconfigLine = regexp.MustCompile(`^\s*(\S+) \(([^)]*)\) => (\S+)$`)

func fromLdconfig() []string {
	out, err := exec.Command("ldconfig", "-p").Output()
	if err != nil {
		return fallbackSystem()
	}

	var paths []string
	sc := bufio.NewScanner(bytes.NewReader(out))
	for sc.Scan() {
		m := ldconfigLine.FindStringSubmatch(sc.Text())
		// The BPF code targets x86-64; 32-bit entries show up as plain "libc6".
		if m == nil || !candidateName.MatchString(m[1]) || !strings.Contains(m[2], "x86-64") {
			continue
		}
		paths = append(paths, m[3])
	}
	if len(paths) == 0 {
		return fallbackSystem()
	}
	return paths
}

func fallbackSystem() []string {
	var paths []string
	for _, dir := range []string{"/usr/lib", "/usr/lib64", "/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu"} {
		paths = append(paths, globCandidates(dir)...)
	}
	return paths
}

// fromKnownLocations covers browsers that ship their own NSS: official
// tarballs unpacked in /opt, Snap packages and flatpak apps. Unlike the
// /proc scan, this also works for browsers that aren't running yet, since the
// uprobe on the file catches every process started later.
func fromKnownLocations() []string {
	dirs := []string{
		"/usr/lib/*",                // /usr/lib/firefox, /usr/lib/librewolf, ...
		"/usr/lib64/*",              //
		"/opt/*",                    // tarball installs (zen, floorp, tor-browser...)
		"/opt/*/*",                  //
		"/snap/*/current/usr/lib/*", // Snap (snap/firefox/current/usr/lib/firefox)
		"/var/lib/flatpak/app/*/current/active/files/lib",
		"/var/lib/flatpak/app/*/current/active/files/lib/*",
	}

	// Per-user flatpak installs. Under sudo, $HOME is root's, so also look in
	// the home of the user who ran sudo.
	for _, home := range userHomes() {
		dirs = append(dirs,
			filepath.Join(home, ".local/share/flatpak/app/*/current/active/files/lib"),
			filepath.Join(home, ".local/share/flatpak/app/*/current/active/files/lib/*"),
		)
	}

	var paths []string
	for _, pattern := range dirs {
		matches, _ := filepath.Glob(pattern)
		for _, dir := range matches {
			paths = append(paths, globCandidates(dir)...)
		}
	}
	return paths
}

func userHomes() []string {
	var homes []string
	if h, err := os.UserHomeDir(); err == nil {
		homes = append(homes, h)
	}
	if u := os.Getenv("SUDO_USER"); u != "" && u != "root" {
		homes = append(homes, filepath.Join("/home", u))
	}
	return homes
}

// globCandidates lists the files in dir whose names may hold a TLS library.
func globCandidates(dir string) []string {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var paths []string
	for _, e := range entries {
		if candidateName.MatchString(e.Name()) {
			paths = append(paths, filepath.Join(dir, e.Name()))
		}
	}
	return paths
}

// fromRunningProcesses looks at what running programs actually loaded.
//
// Paths in /proc/<pid>/maps are relative to that process's mount namespace.
// For a sandboxed app (flatpak, Snap), /usr/lib/... inside the sandbox is a
// completely different file from /usr/lib/... on the host. Prefixing the path
// with /proc/<pid>/root resolves it the way that process sees it, which
// reaches the right inode from the host.
func fromRunningProcesses() []string {
	procs, _ := filepath.Glob("/proc/[0-9]*")

	seen := map[string]bool{}
	var paths []string
	for _, proc := range procs {
		f, err := os.Open(filepath.Join(proc, "maps"))
		if err != nil {
			continue // gone already, or not ours to read without root
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			// address perms offset dev inode pathname
			fields := strings.Fields(sc.Text())
			if len(fields) < 6 {
				continue
			}
			mapped := fields[5]
			if !candidateName.MatchString(filepath.Base(mapped)) {
				continue
			}
			// The same library shows up once per mapping and once per process.
			key := fields[3] + ":" + fields[4]
			if seen[key] {
				continue
			}
			seen[key] = true
			paths = append(paths, filepath.Join(proc, "root", mapped))
		}
		f.Close()
	}
	return paths
}
