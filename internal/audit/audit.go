// Package audit appends one JSON line per decision. Never values, only names and refs.
package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Event struct {
	Time    time.Time `json:"time"`
	Event   string    `json:"event"` // approved, denied, used, revoked, error
	Profile string    `json:"profile,omitempty"`
	Refs    []string  `json:"refs,omitempty"`
	Env     []string  `json:"env,omitempty"`
	Anchor  string    `json:"anchor,omitempty"`
	PeerPID int       `json:"peer_pid,omitempty"`
	Command []string  `json:"command,omitempty"`
	Cwd     string    `json:"cwd,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	Error   string    `json:"error,omitempty"`
}

type Log struct {
	mu sync.Mutex
	f  *os.File
}

func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, "audit.jsonl"),
		os.O_WRONLY|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f}, nil
}

// Write fails closed: callers must not deliver secrets if the event was not recorded.
func (l *Log) Write(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err = l.f.Write(append(b, '\n'))
	return err
}
