package daemon

import (
	"testing"
	"time"

	"github.com/ceritium/james/internal/peer"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time { return c.t }

func newTestGrants() (*grants, *clock, map[int]bool) {
	c := &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	dead := map[int]bool{}
	return newGrants(c.now, func(p peer.Proc) bool { return !dead[p.PID] }), c, dead
}

var claude = peer.Proc{PID: 100, StartUS: 42, Name: "claude"}

func TestGrantExpires(t *testing.T) {
	g, c, _ := newTestGrants()
	g.add("restic", claude, time.Hour)

	c.t = c.t.Add(59 * time.Minute)
	if gr, ok := g.use("restic", claude); !ok || gr.uses != 1 {
		t.Fatalf("grant should be live: %+v %v", gr, ok)
	}
	c.t = c.t.Add(time.Minute)
	if _, ok := g.use("restic", claude); ok {
		t.Fatal("grant should have expired")
	}
	if len(g.list()) != 0 {
		t.Fatal("expired grant still listed")
	}
}

func TestGrantBoundToAnchorAndProfile(t *testing.T) {
	g, _, _ := newTestGrants()
	g.add("restic", claude, time.Hour)

	reusedPID := peer.Proc{PID: 100, StartUS: 43, Name: "claude"}
	other := peer.Proc{PID: 200, StartUS: 42, Name: "claude"}
	for _, p := range []peer.Proc{reusedPID, other} {
		if _, ok := g.use("restic", p); ok {
			t.Errorf("grant leaked to %+v", p)
		}
	}
	if _, ok := g.use("aws", claude); ok {
		t.Error("grant leaked to another profile")
	}
}

func TestGrantEndsWithAnchor(t *testing.T) {
	g, _, dead := newTestGrants()
	g.add("restic", claude, time.Hour)
	dead[claude.PID] = true
	if _, ok := g.use("restic", claude); ok {
		t.Fatal("grant outlived its agent process")
	}
}

func TestRevoke(t *testing.T) {
	g, _, _ := newTestGrants()
	g.add("restic", claude, time.Hour)
	g.add("aws", claude, time.Hour)
	if n := g.revoke("restic"); n != 1 {
		t.Fatalf("revoke restic = %d", n)
	}
	if n := g.revoke(""); n != 1 || len(g.list()) != 0 {
		t.Fatalf("revoke all = %d, left %d", n, len(g.list()))
	}
}
