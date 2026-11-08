//go:build darwin && cgo

// Package peer identifies the process on the other end of a Unix socket.
// Identity comes from the audit token captured at connect time, never from a
// PID: a PID survives execve, so a later program could stand in for the one that
// connected. The audit token's pidversion changes on execve.
package peer

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation -lbsm
#include <sys/socket.h>
#include <unistd.h>
#include <sys/un.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/proc_info.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

static int peer_token(int fd, audit_token_t *tok) {
	socklen_t len = sizeof(*tok);
	return getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, tok, &len);
}

static int token_pid(audit_token_t *tok) { return audit_token_to_pid(*tok); }
static int token_pidversion(audit_token_t *tok) { return audit_token_to_pidversion(*tok); }

// Copies the cdhash of a validly signed code object into out. Returns its length, or <0.
static int code_cdhash(SecCodeRef code, unsigned char *out, int cap) {
	if (SecCodeCheckValidity(code, kSecCSDefaultFlags, NULL) != errSecSuccess) return -2;
	CFDictionaryRef info = NULL;
	if (SecCodeCopySigningInformation((SecStaticCodeRef)code, kSecCSDefaultFlags, &info) != errSecSuccess) return -3;
	int n = -4;
	CFDataRef unique = CFDictionaryGetValue(info, kSecCodeInfoUnique);
	if (unique != NULL && CFDataGetLength(unique) <= cap) {
		n = (int)CFDataGetLength(unique);
		CFDataGetBytes(unique, CFRangeMake(0, n), out);
	}
	CFRelease(info);
	return n;
}

static int token_cdhash(audit_token_t *tok, unsigned char *out, int cap) {
	CFDataRef data = CFDataCreate(NULL, (const UInt8 *)tok, sizeof(*tok));
	const void *keys[] = { kSecGuestAttributeAudit };
	const void *vals[] = { data };
	CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	SecCodeRef code = NULL;
	OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
	CFRelease(attrs);
	CFRelease(data);
	if (st != errSecSuccess) return -1;
	int n = code_cdhash(code, out, cap);
	CFRelease(code);
	return n;
}

static int self_cdhash(unsigned char *out, int cap) {
	SecCodeRef code = NULL;
	if (SecCodeCopySelf(kSecCSDefaultFlags, &code) != errSecSuccess) return -1;
	int n = code_cdhash(code, out, cap);
	CFRelease(code);
	return n;
}

static int proc_info(int pid, int *ppid, unsigned long long *start_us) {
	struct proc_bsdinfo bsd;
	if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsd, sizeof(bsd)) != sizeof(bsd)) return -1;
	*ppid = (int)bsd.pbi_ppid;
	*start_us = bsd.pbi_start_tvsec * 1000000ULL + bsd.pbi_start_tvusec;
	return 0;
}

// csops lives in a private header; the kernel interface is stable.
int csops(pid_t pid, unsigned int ops, void *useraddr, size_t usersize);

static int self_cs_status(unsigned int *status) {
	return csops(getpid(), 0, status, sizeof(*status)); // 0 = CS_OPS_STATUS
}
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/unix"
)

var ErrUntrusted = errors.New("peer is not the same signed james binary")

// Identity is a verified peer, pinned to one exec of one process.
type Identity struct {
	PID        int
	PIDVersion int
	CDHash     []byte
}

// HardenedRuntime reports whether this process runs with the hardened runtime,
// which keeps other processes, even root, from reading its memory.
func HardenedRuntime() bool {
	var status C.uint
	return C.self_cs_status(&status) == 0 && status&0x10000 != 0 // CS_RUNTIME
}

func SelfCDHash() ([]byte, error) {
	buf := make([]byte, 64)
	n := C.self_cdhash((*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n < 0 {
		return nil, fmt.Errorf("read own code signature: code %d", int(n))
	}
	return buf[:n], nil
}

// PeerPID returns the PID from the peer's audit token, without checking its signature.
func PeerPID(conn *net.UnixConn) (int, error) {
	tok, err := token(conn)
	if err != nil {
		return 0, err
	}
	return int(C.token_pid(&tok)), nil
}

func token(conn *net.UnixConn) (C.audit_token_t, error) {
	var tok C.audit_token_t
	raw, err := conn.SyscallConn()
	if err != nil {
		return tok, err
	}
	var sockErr error
	if err := raw.Control(func(fd uintptr) {
		if C.peer_token(C.int(fd), &tok) != 0 {
			sockErr = errors.New("LOCAL_PEERTOKEN failed")
		}
	}); err != nil {
		return tok, err
	}
	return tok, sockErr
}

// Verify checks that the peer of conn runs exactly the same signed binary as this process.
func Verify(conn *net.UnixConn) (Identity, error) {
	tok, err := token(conn)
	if err != nil {
		return Identity{}, err
	}

	id := Identity{
		PID:        int(C.token_pid(&tok)),
		PIDVersion: int(C.token_pidversion(&tok)),
	}
	buf := make([]byte, 64)
	n := C.token_cdhash(&tok, (*C.uchar)(unsafe.Pointer(&buf[0])), C.int(len(buf)))
	if n < 0 {
		return id, fmt.Errorf("%w: pid %d signature check failed (code %d)", ErrUntrusted, id.PID, int(n))
	}
	id.CDHash = buf[:n]

	self, err := SelfCDHash()
	if err != nil {
		return id, err
	}
	if !bytes.Equal(self, id.CDHash) {
		return id, fmt.Errorf("%w: pid %d", ErrUntrusted, id.PID)
	}
	return id, nil
}

type procInfo struct {
	ppid    int
	startUS uint64
}

func info(pid int) (procInfo, bool) {
	var ppid C.int
	var start C.ulonglong
	if C.proc_info(C.int(pid), &ppid, &start) != 0 {
		return procInfo{}, false
	}
	return procInfo{ppid: int(ppid), startUS: uint64(start)}, true
}

func Lookup(pid int) (Proc, error) {
	i, ok := info(pid)
	if !ok {
		return Proc{}, fmt.Errorf("process %d not found", pid)
	}
	return Proc{PID: pid, StartUS: i.startUS, Name: procName(pid)}, nil
}

// Ancestors returns pid and its ancestors, nearest first. A parent that started
// after its child is a reused PID, so the chain stops there.
func Ancestors(pid int) []Proc {
	child, ok := info(pid)
	if !ok {
		return nil
	}
	chain := []Proc{{PID: pid, StartUS: child.startUS, Name: procName(pid)}}
	for cur := child.ppid; cur > 1 && len(chain) < 64; {
		parent, ok := info(cur)
		if !ok || parent.startUS > child.startUS {
			break
		}
		chain = append(chain, Proc{PID: cur, StartUS: parent.startUS, Name: procName(cur)})
		child, cur = parent, parent.ppid
	}
	return chain
}

// FindAncestor returns the nearest ancestor of pid whose argv[0] or executable
// basename is in names.
func FindAncestor(pid int, names []string) (Proc, bool) {
	chain := Ancestors(pid)
	for _, p := range chain[min(1, len(chain)):] {
		for _, n := range names {
			if p.Name == n || exeName(p.PID) == n {
				return p, true
			}
		}
	}
	return Proc{}, false
}

// Alive reports whether p is still the same running process.
func Alive(p Proc) bool {
	i, ok := info(p.PID)
	return ok && i.startUS == p.StartUS
}

// procName is the basename of argv[0], from kern.procargs2.
func procName(pid int) string {
	buf, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(buf) < 4 {
		return exeName(pid)
	}
	rest := buf[4:]
	i := bytes.IndexByte(rest, 0)
	if i < 0 {
		return exeName(pid)
	}
	rest = bytes.TrimLeft(rest[i:], "\x00")
	if j := bytes.IndexByte(rest, 0); j > 0 {
		return filepath.Base(string(rest[:j]))
	}
	return exeName(pid)
}

// ExeName is the basename of the executable running as pid, or "" if unknown.
func ExeName(pid int) string { return exeName(pid) }

func exeName(pid int) string {
	buf := make([]byte, C.PROC_PIDPATHINFO_MAXSIZE)
	n := C.proc_pidpath(C.int(pid), unsafe.Pointer(&buf[0]), C.uint32_t(len(buf)))
	if n <= 0 {
		return ""
	}
	return filepath.Base(string(buf[:n]))
}
