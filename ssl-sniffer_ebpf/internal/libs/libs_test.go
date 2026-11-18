package libs

import (
	"os"
	"path/filepath"
	"testing"
)

// The test runs against whatever this machine has installed and skips what
// it can't find, so it never fails just because a library is missing.
func TestClassifyRealLibraries(t *testing.T) {
	cases := []struct {
		path string
		want string
	}{
		{"/usr/lib/libnspr4.so", "NSS"},
		{"/usr/lib/x86_64-linux-gnu/libnspr4.so", "NSS"},
		{"/usr/lib/libssl.so.3", "OpenSSL"},
		{"/usr/lib/x86_64-linux-gnu/libssl.so.3", "OpenSSL"},
		{"/usr/lib/libgnutls.so.30", "GnuTLS"},
	}
	found := false
	for _, c := range cases {
		if _, err := os.Stat(c.path); err != nil {
			continue
		}
		found = true
		got := Classify([]string{c.path}, AllKinds)
		if len(got) != 1 || got[0].Lib != c.want {
			t.Errorf("Classify(%s) = %+v, want one %s target", c.path, got, c.want)
		}
	}
	if !found {
		t.Skip("no known TLS library on this machine")
	}
}

// NSS's own libssl3.so has a misleading name but exports none of the
// functions we hook; it must not be picked up as OpenSSL.
func TestNSSLibssl3IsNotOpenSSL(t *testing.T) {
	p := "/usr/lib/libssl3.so"
	if _, err := os.Stat(p); err != nil {
		t.Skip("no libssl3.so")
	}
	if got := Classify([]string{p}, AllKinds); len(got) != 0 {
		t.Errorf("libssl3.so classified as %+v", got)
	}
}

func TestClassifyDedupsByInode(t *testing.T) {
	p := "/usr/lib/libnspr4.so"
	if _, err := os.Stat(p); err != nil {
		t.Skip("no libnspr4.so")
	}
	link := filepath.Join(t.TempDir(), "libnspr4.so")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if got := Classify([]string{p, link}, AllKinds); len(got) != 1 {
		t.Errorf("same file through two paths gave %d targets", len(got))
	}
}

func TestKindFilter(t *testing.T) {
	p := "/usr/lib/libnspr4.so"
	if _, err := os.Stat(p); err != nil {
		t.Skip("no libnspr4.so")
	}
	if got := Classify([]string{p}, []Kind{OpenSSL}); len(got) != 0 {
		t.Errorf("NSPR library returned when only OpenSSL was requested: %+v", got)
	}
}
