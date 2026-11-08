//go:build darwin && cgo

// Package client talks to the daemon and refuses any daemon that is not the
// same signed james binary.
package client

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/ceritium/james/internal/paths"
	"github.com/ceritium/james/internal/peer"
	"github.com/ceritium/james/internal/protocol"
)

const connectTimeout = 3 * time.Second

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

// connect never starts the daemon: launchd does, so it never inherits the
// environment or sandbox of whatever ran the client.
func connect() (*net.UnixConn, error) {
	deadline := time.Now().Add(connectTimeout)
	for {
		conn, id, err := dial()
		switch {
		case err == nil:
			return conn, nil
		case errors.Is(err, peer.ErrUntrusted):
			return nil, fmt.Errorf("the running daemon (pid %d) is a different james build; keep a single install and restart its daemon: %w", id.PID, err)
		case time.Now().After(deadline):
			return nil, fmt.Errorf("james daemon is not running; start it with its LaunchAgent or `james daemon`: %w", err)
		}
		// launchd may be restarting it, e.g. right after an upgrade.
		time.Sleep(200 * time.Millisecond)
	}
}

func dial() (*net.UnixConn, peer.Identity, error) {
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: paths.Socket(), Net: "unix"})
	if err != nil {
		return nil, peer.Identity{}, err
	}
	id, err := peer.Verify(conn)
	if err != nil {
		conn.Close()
		return nil, id, err
	}
	return conn, id, nil
}
