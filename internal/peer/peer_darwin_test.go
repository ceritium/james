//go:build darwin && cgo

package peer

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func listen(t *testing.T) (*net.UnixListener, string) {
	t.Helper()
	// Short dir: Unix socket paths are limited to 104 bytes.
	dir, err := os.MkdirTemp("/tmp", "jp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func TestVerifyAcceptsSameBinary(t *testing.T) {
	l, path := listen(t)
	go func() {
		c, err := net.Dial("unix", path)
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	id, err := Verify(conn)
	if err != nil {
		t.Fatalf("Verify same binary: %v", err)
	}
	if id.PID != os.Getpid() || len(id.CDHash) == 0 {
		t.Fatalf("identity = %+v", id)
	}
}

func TestVerifyRejectsOtherBinary(t *testing.T) {
	l, path := listen(t)
	cmd := exec.Command("/usr/bin/nc", "-U", path)
	cmd.Stdin = nil
	if err := cmd.Start(); err != nil {
		t.Skip("nc unavailable:", err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := Verify(conn); !errors.Is(err, ErrUntrusted) {
		t.Fatalf("Verify other binary error = %v, want ErrUntrusted", err)
	}
}

func TestFindAncestor(t *testing.T) {
	parent, err := Lookup(os.Getppid())
	if err != nil {
		t.Fatal(err)
	}
	got, ok := FindAncestor(os.Getpid(), []string{parent.Name})
	if !ok || got.PID != parent.PID || got.StartUS != parent.StartUS {
		t.Fatalf("FindAncestor = %+v %v, want %+v", got, ok, parent)
	}
	if !Alive(got) {
		t.Fatal("parent should be alive")
	}
	if _, ok := FindAncestor(os.Getpid(), []string{"no-such-agent"}); ok {
		t.Fatal("found nonexistent ancestor")
	}
	if Alive(Proc{PID: got.PID, StartUS: got.StartUS + 1}) {
		t.Fatal("Alive must reject a different start time")
	}
}
