//go:build ignore

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

// Bytes copied per event. Anything past this is cut off (the Go side says so).
// Kept generous so a whole HTTP/2 HEADERS/SETTINGS burst usually fits in one
// event; HTTP/2 framing can't be decoded across a truncation gap.
#define MAX_DATA 16384

// Must match dirWrite / dirRead in main.go.
#define DIR_WRITE 0
#define DIR_READ 1

struct event {
  __u64 conn;          // connection handle: SSL* / gnutls_session_t / PRFileDesc*
  __u32 pid;           // process (thread group) that called the TLS function
  __u32 len;           // bytes actually copied into data
  __u32 total;         // bytes the call really handled, may be > len
  __u8 direction;      // DIR_WRITE or DIR_READ
  char comm[16];       // process name
  char data[MAX_DATA]; // the plaintext itself
};

// Only sizeof(struct event) is used below, which leaves no trace of the type
// in the object file. This unused pointer keeps it there, so that bpf2go
// (-type event) can generate the matching Go struct.
const struct event *unused_event __attribute__((unused));

// At 16KB+ per event, struct event is way over the 512-byte BPF stack, so it
// can't be built as a local variable. bpf_ringbuf_reserve hands out the
// memory straight from the ring buffer instead.
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

// A read's buffer is still empty when the function starts, so what we need on
// return (the buffer address and the connection handle) is saved here on entry
// (keyed by thread) and read again on return.
struct read_args {
  __u64 buf;  // address of the buffer the caller passed in
  __u64 conn; // connection handle (first argument)
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u64);               // pid_tgid of the calling thread
  __type(value, struct read_args);
} read_bufs SEC(".maps");

static __always_inline int send_event(__u64 conn, const void *buf, int num,
                                      __u8 direction) {
  // The traced functions return <= 0 on errors (or "try again later").
  if (num <= 0)
    return 0;

  struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
  if (!e)
    return 0;

  e->conn = conn;
  e->pid = bpf_get_current_pid_tgid() >> 32;
  e->direction = direction;
  e->total = num;
  bpf_get_current_comm(&e->comm, sizeof(e->comm));

  // The verifier must be able to prove len never exceeds sizeof(e->data),
  // otherwise it refuses to load the program.
  __u32 len = num;
  if (len > MAX_DATA)
    len = MAX_DATA;
  e->len = len;

  // buf lives in the traced process's memory, not the kernel's.
  if (bpf_probe_read_user(e->data, len, buf) != 0) {
    bpf_ringbuf_discard(e, 0);
    return 0;
  }

  bpf_ringbuf_submit(e, 0);
  return 0;
}

// These three programs are deliberately library-agnostic. The TLS write/read
// calls we hook all share the same shape:
//
//   OpenSSL:  int     SSL_write(SSL *ssl, const void *buf, int num)
//             int     SSL_read (SSL *ssl, void *buf, int num)
//   GnuTLS:   ssize_t gnutls_record_send(gnutls_session_t s, const void *d, size_t n)
//             ssize_t gnutls_record_recv(gnutls_session_t s, void *d, size_t n)
//   NSS:      PRInt32 PR_Write(PRFileDesc *fd, const void *buf, PRInt32 amount)
//             PRInt32 PR_Read (PRFileDesc *fd, void *buf, PRInt32 amount)
//
// First argument: the connection handle. Second: the plaintext buffer. Third:
// a byte count. So the same programs can be attached to all of them from Go.

// The plaintext is already in buf when a write starts: read it right away.
SEC("uprobe/tls_write")
int BPF_UPROBE(probe_write, void *conn, const void *buf, int num) {
  return send_event((__u64)conn, buf, num, DIR_WRITE);
}

// On entry a read's buf is empty, the library hasn't decrypted anything yet.
// Save the buffer address and the connection handle for the return probe.
SEC("uprobe/tls_read")
int BPF_UPROBE(probe_read_enter, void *conn, void *buf, int num) {
  __u64 id = bpf_get_current_pid_tgid();
  struct read_args a = {.buf = (__u64)buf, .conn = (__u64)conn};

  bpf_map_update_elem(&read_bufs, &id, &a, BPF_ANY);
  return 0;
}

// On return buf holds the decrypted data, and the return value says how much.
SEC("uretprobe/tls_read")
int BPF_URETPROBE(probe_read_exit, int ret) {
  __u64 id = bpf_get_current_pid_tgid();

  struct read_args *a = bpf_map_lookup_elem(&read_bufs, &id);
  if (!a)
    return 0;

  __u64 buf = a->buf;
  __u64 conn = a->conn;
  bpf_map_delete_elem(&read_bufs, &id);

  return send_event(conn, (const void *)buf, ret, DIR_READ);
}
