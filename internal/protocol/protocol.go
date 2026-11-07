// Package protocol defines the JSON messages between the james CLI and daemon.
// One request and one response per connection.
package protocol

import (
	"encoding/json"
	"errors"
	"io"
	"time"
)

const MaxMessage = 1 << 20

const (
	OpPing   = "ping"
	OpBond   = "bond"
	OpRun    = "run"
	OpList   = "list"
	OpRevoke = "revoke"
)

type Request struct {
	Op      string `json:"op"`
	Profile string `json:"profile,omitempty"`
	// Secrets are one-off ENV → ref pairs outside any profile; never granted for reuse.
	Secrets map[string]string `json:"secrets,omitempty"`
	Account string            `json:"account,omitempty"`
	Reason  string            `json:"reason,omitempty"`
	Command []string          `json:"command,omitempty"`
	Cwd     string            `json:"cwd,omitempty"`
	All     bool              `json:"all,omitempty"`
}

type Response struct {
	Error   string            `json:"error,omitempty"`
	Message string            `json:"message,omitempty"`
	Env     map[string]string `json:"env,omitempty"`
	Grants  []Grant           `json:"grants,omitempty"`
}

type Grant struct {
	Profile   string    `json:"profile"`
	Anchor    string    `json:"anchor"`
	AnchorPID int       `json:"anchor_pid"`
	Granted   time.Time `json:"granted"`
	Expires   time.Time `json:"expires"`
	Uses      int       `json:"uses"`
}

func Write(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

func Read(r io.Reader, v any) error {
	dec := json.NewDecoder(io.LimitReader(r, MaxMessage))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		if errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return nil
}
