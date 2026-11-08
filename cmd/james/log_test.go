package main

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/ceritium/james/internal/audit"
)

func TestLogFilter(t *testing.T) {
	now := time.Now()
	f := logFilter{profile: "restic", since: now.Add(-time.Hour)}
	if !f.match(audit.Event{Profile: "restic", Time: now}) {
		t.Fatal("should match")
	}
	if f.match(audit.Event{Profile: "other", Time: now}) || f.match(audit.Event{Profile: "restic", Time: now.Add(-2 * time.Hour)}) {
		t.Fatal("should not match")
	}
}

func TestPrintEvent(t *testing.T) {
	var b bytes.Buffer
	printEvent(&b, audit.Event{Time: time.Now(), Event: "used", Profile: "restic", Anchor: "claude (pid 1)",
		Command: []string{"restic", "snapshots"}, Env: []string{"RESTIC_PASSWORD"}, Reason: "list backups"}, false)
	out := b.String()
	for _, want := range []string{"used", "restic snapshots", "RESTIC_PASSWORD", `reason: "list backups"`} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %q", want, out)
		}
	}
}
