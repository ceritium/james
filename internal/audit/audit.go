// Package audit appends one JSON line per decision. Never values, only names and refs.
package audit

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type Event struct {
	Time    time.Time `json:"time"`
	Event   string    `json:"event"` // approved, denied, used, ssh-sign, revoked, error
	Profile string    `json:"profile,omitempty"`
	Refs    []string  `json:"refs,omitempty"`
	Env     []string  `json:"env,omitempty"`
	Anchor  string    `json:"anchor,omitempty"`
	PeerPID int       `json:"peer_pid,omitempty"`
	Command []string  `json:"command,omitempty"`
	Cwd     string    `json:"cwd,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	TTL     string    `json:"ttl,omitempty"`
	Error   string    `json:"error,omitempty"`
}

type Log struct {
	mu sync.Mutex
	f  *os.File
}

func Path(dir string) string { return filepath.Join(dir, "audit.jsonl") }

func Open(dir string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(Path(dir),
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

// Lines reads complete lines from r and calls fn for each event. A partial last
// line (a write in progress) is returned so a follower can prepend it next time.
// Malformed lines are skipped.
func Lines(r io.Reader, partial []byte, fn func(Event)) ([]byte, error) {
	buf := partial
	chunk := make([]byte, 32<<10)
	for {
		n, err := r.Read(chunk)
		buf = append(buf, chunk[:n]...)
		for {
			i := bytes.IndexByte(buf, '\n')
			if i < 0 {
				break
			}
			var e Event
			if json.Unmarshal(buf[:i], &e) == nil {
				fn(e)
			}
			buf = buf[i+1:]
		}
		if err == io.EOF {
			return append([]byte(nil), buf...), nil
		}
		if err != nil {
			return buf, err
		}
	}
}
