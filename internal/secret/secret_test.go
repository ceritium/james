package secret

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const raw = "hunter2"

func TestValueNeverFormats(t *testing.T) {
	v := FromString(raw)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		if got := fmt.Sprintf(verb, v); strings.Contains(got, raw) || got != redacted {
			t.Errorf("%s formatted as %q", verb, got)
		}
	}
	wrapped := fmt.Sprintf("%v", struct{ Token Value }{v})
	if strings.Contains(wrapped, raw) {
		t.Errorf("struct field leaked: %q", wrapped)
	}
}

func TestValueNeverLogs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("resolved", "value", FromString(raw))
	if strings.Contains(buf.String(), raw) {
		t.Fatalf("log leaked value: %s", buf.String())
	}
}

func TestValueNeverSerializes(t *testing.T) {
	_, err := json.Marshal(struct{ Token Value }{FromString(raw)})
	if !errors.Is(err, ErrSerialize) {
		t.Fatalf("json.Marshal error = %v, want ErrSerialize", err)
	}
}

func TestWipe(t *testing.T) {
	b := []byte(raw)
	v := New(b)
	v.Wipe()
	if v.Len() != 0 || !bytes.Equal(b, make([]byte, len(raw))) {
		t.Fatalf("Wipe left data: len=%d backing=%q", v.Len(), b)
	}
}
