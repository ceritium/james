//go:build darwin && cgo

package daemon

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/ceritium/james/internal/approve"
	"github.com/ceritium/james/internal/audit"
	"github.com/ceritium/james/internal/config"
	"github.com/ceritium/james/internal/paths"
	"github.com/ceritium/james/internal/peer"
	"github.com/ceritium/james/internal/provider"
	"github.com/ceritium/james/internal/provider/onepassword"
)

// Run serves until a signal arrives or the james binary on disk changes.
func Run(version string) error {
	// Secrets pass through this process; a core dump would write them to disk.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{}); err != nil {
		return err
	}
	if !peer.HardenedRuntime() {
		log.Print("warning: not signed with the hardened runtime; root can read secrets from daemon memory. Install with make install.")
	}
	if err := paths.PrivateDir(paths.StateDir()); err != nil {
		return err
	}
	l, err := listen(paths.Socket())
	if err != nil {
		return err
	}
	defer os.Remove(paths.Socket())
	sshL, err := listen(paths.SSHSocket())
	if err != nil {
		return err
	}
	defer os.Remove(paths.SSHSocket())

	auditLog, err := audit.Open(paths.LogDir())
	if err != nil {
		return err
	}

	// Read once for the provider default account; profiles are re-read per request.
	var defaultAccount string
	bootstrap, _ := provider.NewRegistry(onepassword.New(onepassword.Options{}))
	if cfg, err := config.Load(paths.Config(), bootstrap.Parse); err == nil {
		defaultAccount = cfg.Providers.OnePassword.DefaultAccount
	} else {
		log.Printf("config: %v", err)
	}
	reg, err := provider.NewRegistry(onepassword.New(onepassword.Options{
		DefaultAccount: defaultAccount, IntegrationName: "james", IntegrationVersion: version,
	}))
	if err != nil {
		return err
	}

	srv := NewServer(Deps{
		Verify: func(c *net.UnixConn) (int, error) {
			id, err := peer.Verify(c)
			return id.PID, err
		},
		FindAnchor: peer.FindAncestor,
		Alive:      peer.Alive,
		Approve:    approve.TouchID,
		Notify:     notify,
		LoadConfig: func() (*config.Config, error) { return config.Load(paths.Config(), reg.Parse) },
		Registry:   reg,
		Audit:      auditLog,
		PeerPID:    peer.PeerPID,
		Ancestors:  peer.Ancestors,
		SSHSocket:  paths.SSHSocket(),
	})

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	go exitOnBinaryChange(ctx, stop)

	log.Printf("james daemon %s listening on %s", version, paths.Socket())
	go func() {
		if err := srv.ServeSSH(ctx, sshL); err != nil {
			log.Printf("ssh agent: %v", err)
			stop()
		}
	}()
	return srv.Serve(ctx, l)
}

func listen(path string) (*net.UnixListener, error) {
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return nil, errors.New("daemon already running")
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	old := syscall.Umask(0o177)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	syscall.Umask(old)
	if err != nil {
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

// After a rebuild, clients carry a new code signature that this process would
// reject; exiting lets the next client start the new binary.
func exitOnBinaryChange(ctx context.Context, stop func()) {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	initial, err := os.Stat(exe)
	if err != nil {
		return
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			cur, err := os.Stat(exe)
			if err != nil || !os.SameFile(initial, cur) || !cur.ModTime().Equal(initial.ModTime()) {
				log.Printf("%s changed; exiting", exe)
				stop()
				return
			}
		}
	}
}

// Strings go through argv, never into the AppleScript source.
func notify(msg string) {
	cmd := exec.Command("/usr/bin/osascript",
		"-e", "on run argv",
		"-e", `display notification (item 1 of argv) with title "james"`,
		"-e", "end run", msg)
	if err := cmd.Start(); err != nil {
		log.Printf("notify: %v", err)
		return
	}
	go func() { _ = cmd.Wait() }()
}
