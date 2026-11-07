package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ceritium/james/internal/audit"
	"github.com/ceritium/james/internal/config"
	"github.com/ceritium/james/internal/peer"
	"github.com/ceritium/james/internal/protocol"
	"github.com/ceritium/james/internal/provider"
	"github.com/ceritium/james/internal/secret"
)

type fakeProvider struct{ resolved []string }

func (f *fakeProvider) Scheme() string              { return "op" }
func (f *fakeProvider) Validate(provider.Ref) error { return nil }
func (f *fakeProvider) Resolve(_ context.Context, r provider.Ref) (secret.Value, error) {
	f.resolved = append(f.resolved, r.String())
	if strings.Contains(r.Path, "sshkey") {
		return secret.New(append([]byte(nil), testKeyPEM...)), nil
	}
	if strings.Contains(r.Path, "missing") {
		return secret.Value{}, errors.New("not found")
	}
	return secret.FromString("value-of-" + r.Path), nil
}

type fakeAudit struct {
	events []audit.Event
	fail   bool
}

func (a *fakeAudit) Write(e audit.Event) error {
	if a.fail {
		return errors.New("disk full")
	}
	a.events = append(a.events, e)
	return nil
}

type harness struct {
	s        *Server
	prompts  []string
	deny     bool
	anchor   *peer.Proc
	notified []string
	audit    *fakeAudit
	prov     *fakeProvider
	clock    *clock
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{audit: &fakeAudit{}, prov: &fakeProvider{}, clock: &clock{t: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}}
	a := claude
	h.anchor = &a
	reg, err := provider.NewRegistry(h.prov)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Anchors: []string{"claude"},
		Profiles: map[string]config.Profile{
			"restic": {TTL: config.Duration(time.Hour), Secrets: map[string]config.Secret{
				"RESTIC_PASSWORD": {Ref: "op://Personal/restic/password"},
			}},
			"broken": {Secrets: map[string]config.Secret{"X": {Ref: "op://V/missing/f"}}},
			"github": {SSHKeys: []config.Secret{{Ref: "op://Personal/sshkey/private key"}}},
		},
	}
	h.s = NewServer(Deps{
		FindAnchor: func(int, []string) (peer.Proc, bool) {
			if h.anchor == nil {
				return peer.Proc{}, false
			}
			return *h.anchor, true
		},
		Alive: func(peer.Proc) bool { return true },
		Approve: func(reason string) error {
			h.prompts = append(h.prompts, reason)
			if h.deny {
				return errors.New("denied")
			}
			return nil
		},
		Notify:     func(m string) { h.notified = append(h.notified, m) },
		LoadConfig: func() (*config.Config, error) { return cfg, nil },
		Registry:   reg,
		Audit:      h.audit,
		Now:        h.clock.now,
	})
	return h
}

func (h *harness) run(profile string) protocol.Response {
	return h.s.Dispatch(context.Background(), 4242, protocol.Request{
		Op: protocol.OpRun, Profile: profile, Command: []string{"restic", "backup"}, Cwd: "/tmp",
	})
}

func TestRunPromptsOnceThenReusesGrant(t *testing.T) {
	h := newHarness(t)
	for i := range 3 {
		resp := h.run("restic")
		if resp.Error != "" || resp.Env["RESTIC_PASSWORD"] != "value-of-Personal/restic/password" {
			t.Fatalf("run %d: %+v", i, resp)
		}
	}
	if len(h.prompts) != 1 {
		t.Fatalf("prompts = %d, want 1", len(h.prompts))
	}
	if !strings.Contains(h.prompts[0], "claude (pid 100)") || !strings.Contains(h.prompts[0], "$ restic backup") {
		t.Errorf("prompt lacks context: %q", h.prompts[0])
	}
	if len(h.notified) != 2 {
		t.Errorf("notifications = %d, want 2 (runs that did not prompt)", len(h.notified))
	}
	if g := h.s.listGrants(); len(g) != 1 || g[0].Uses != 3 {
		t.Errorf("grants = %+v", g)
	}
}

func TestRunPromptsAgainAfterExpiry(t *testing.T) {
	h := newHarness(t)
	h.run("restic")
	h.clock.t = h.clock.t.Add(time.Hour)
	h.run("restic")
	if len(h.prompts) != 2 {
		t.Fatalf("prompts = %d, want 2", len(h.prompts))
	}
}

func TestRunWithoutAgentPromptsEveryTime(t *testing.T) {
	h := newHarness(t)
	h.anchor = nil
	h.run("restic")
	h.run("restic")
	if len(h.prompts) != 2 || len(h.s.listGrants()) != 0 {
		t.Fatalf("prompts=%d grants=%d", len(h.prompts), len(h.s.listGrants()))
	}
}

func TestDeniedRunGetsNothing(t *testing.T) {
	h := newHarness(t)
	h.deny = true
	resp := h.run("restic")
	if resp.Error == "" || resp.Env != nil || len(h.prov.resolved) != 0 {
		t.Fatalf("denied run: %+v resolved=%v", resp, h.prov.resolved)
	}
	if h.audit.events[0].Event != "denied" {
		t.Errorf("audit = %+v", h.audit.events)
	}
}

func TestAuditFailureBlocksDelivery(t *testing.T) {
	h := newHarness(t)
	h.audit.fail = true
	if resp := h.run("restic"); resp.Error == "" || resp.Env != nil {
		t.Fatalf("delivered without audit: %+v", resp)
	}
}

func TestBondThenRunDoesNotPrompt(t *testing.T) {
	h := newHarness(t)
	resp := h.s.Dispatch(context.Background(), 4242, protocol.Request{Op: protocol.OpBond, Profile: "restic"})
	if resp.Error != "" {
		t.Fatal(resp.Error)
	}
	h.run("restic")
	if len(h.prompts) != 1 {
		t.Fatalf("prompts = %d", len(h.prompts))
	}
}

func TestBondWithoutAgentFails(t *testing.T) {
	h := newHarness(t)
	h.anchor = nil
	resp := h.s.Dispatch(context.Background(), 4242, protocol.Request{Op: protocol.OpBond, Profile: "restic"})
	if resp.Error == "" || len(h.prompts) != 0 {
		t.Fatalf("resp=%+v prompts=%d", resp, len(h.prompts))
	}
}

func TestOneOffAlwaysPromptsAndNeverGrants(t *testing.T) {
	h := newHarness(t)
	req := protocol.Request{Op: protocol.OpRun, Secrets: map[string]string{"TOKEN": "op://V/I/f"}, Command: []string{"env"}}
	for range 2 {
		if resp := h.s.Dispatch(context.Background(), 1, req); resp.Env["TOKEN"] != "value-of-V/I/f" {
			t.Fatalf("resp = %+v", resp)
		}
	}
	if len(h.prompts) != 2 || len(h.s.listGrants()) != 0 {
		t.Fatalf("prompts=%d grants=%d", len(h.prompts), len(h.s.listGrants()))
	}
	if !strings.Contains(h.prompts[0], "op://V/I/f as TOKEN") {
		t.Errorf("prompt should show the exact ref: %q", h.prompts[0])
	}
}

func TestRunErrors(t *testing.T) {
	h := newHarness(t)
	cases := map[string]protocol.Request{
		"unknown profile": {Op: protocol.OpRun, Profile: "nope", Command: []string{"x"}},
		"no command":      {Op: protocol.OpRun, Profile: "restic"},
		"both":            {Op: protocol.OpRun, Profile: "restic", Secrets: map[string]string{"A": "op://a/b/c"}, Command: []string{"x"}},
		"bad env":         {Op: protocol.OpRun, Secrets: map[string]string{"A-B": "op://a/b/c"}, Command: []string{"x"}},
		"resolve error":   {Op: protocol.OpRun, Profile: "broken", Command: []string{"x"}},
	}
	for name, req := range cases {
		if resp := h.s.Dispatch(context.Background(), 1, req); resp.Error == "" || resp.Env != nil {
			t.Errorf("%s: %+v", name, resp)
		}
	}
}
