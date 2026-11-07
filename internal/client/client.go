//go:build darwin && cgo

// Package client talks to the daemon, starting it if needed, and refuses any
// daemon that is not the same signed james binary.
package client

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/ceritium/james/internal/paths"
	"github.com/ceritium/james/internal/peer"
	"github.com/ceritium/james/internal/protocol"
)

const startTimeout = 5 * time.Second

func Do(req protocol.Request) (protocol.Response, error) {
	conn, err := connect()
	if err != nil {
		return protocol.Response{}, err
	}
	defer conn.Close()
	if err := protocol.Write(conn, req); err != nil {
		return protocol.Response{}, err
	}
	var resp protocol.Response
	if err := protocol.Read(conn, &resp); err != nil {
		return protocol.Response{}, fmt.Errorf("read daemon response: %w", err)
	}
	if resp.Error != "" {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func connect() (*net.UnixConn, error) {
	started := false
	deadline := time.Now().Add(startTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := dial()
		if err == nil {
			return conn, nil
		}
		lastErr = err
		// A daemon from an older build exits by itself within seconds; keep retrying.
		if !started && !errors.Is(err, peer.ErrUntrusted) {
			if err := spawn(); err != nil {
				return nil, fmt.Errorf("start daemon: %w", err)
			}
			started = true
		}
		time.Sleep(150 * time.Millisecond)
	}
	return nil, fmt.Errorf("connect to daemon: %w", lastErr)
}

func dial() (*net.UnixConn, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: paths.Socket(), Net: "unix"})
	if err != nil {
		return nil, err
	}
	if _, err := peer.Verify(conn); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

func spawn() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(paths.LogDir(), 0o700); err != nil {
		return err
	}
	logf, err := os.OpenFile(filepath.Join(paths.LogDir(), "daemon.log"),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer logf.Close()
	cmd := exec.Command(exe, "daemon")
	cmd.Stdout, cmd.Stderr = logf, logf
	cmd.Dir = "/"
	cmd.Env = []string{"HOME=" + os.Getenv("HOME"), "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	return cmd.Process.Release()
}
