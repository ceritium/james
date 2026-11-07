package secret

import (
	"errors"
	"fmt"
	"log/slog"
)

const redacted = "[redacted]"

var ErrSerialize = errors.New("secret values cannot be serialized")

// Value holds a resolved secret. It refuses to print, log or serialize itself
// so a value cannot leak through an error message, log line or JSON payload.
type Value struct {
	b []byte
}

// New takes ownership of b.
func New(b []byte) Value { return Value{b: b} }

func FromString(s string) Value { return Value{b: []byte(s)} }

func (v Value) Bytes() []byte { return v.b }

func (v Value) Len() int { return len(v.b) }

// Wipe is best effort: providers that return Go strings leave copies we cannot reach.
func (v *Value) Wipe() {
	clear(v.b)
	v.b = nil
}

func (v Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

func (v Value) LogValue() slog.Value { return slog.StringValue(redacted) }

func (v Value) MarshalJSON() ([]byte, error) { return nil, ErrSerialize }

func (v Value) MarshalText() ([]byte, error) { return nil, ErrSerialize }
