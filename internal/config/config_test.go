package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ceritium/james/internal/provider"
)

func parse(raw, account string) (provider.Ref, error) { return provider.ParseRef(raw, account) }

func write(t *testing.T, body string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	path := write(t, `
providers:
  1password:
    default_account: ABC
profiles:
  restic:
    ttl: 30m
    secrets:
      RESTIC_PASSWORD: op://Personal/restic/password
      WORK_TOKEN:
        ref: op://Work/token/credential
        account: Work
  quick:
    secrets:
      A: op://V/I/f
  github:
    ssh_keys:
      - op://Personal/GitHub/private key?ssh-format=openssh
      - ref: op://Work/deploy key/private key
        account: Work
`, 0o600)
	c, err := Load(path, parse)
	if err != nil {
		t.Fatal(err)
	}
	r := c.Profiles["restic"]
	if r.EffectiveTTL() != 30*time.Minute || r.Secrets["WORK_TOKEN"].Account != "Work" || r.Secrets["RESTIC_PASSWORD"].Ref != "op://Personal/restic/password" {
		t.Fatalf("restic = %+v", r)
	}
	if c.Profiles["quick"].EffectiveTTL() != DefaultTTL || c.Anchors[0] != "claude" || !c.NotifyEnabled() {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if k := c.Profiles["github"].SSHKeys; len(k) != 2 || k[1].Account != "Work" || !strings.HasPrefix(k[0].Ref, "op://Personal/GitHub/") {
		t.Fatalf("ssh_keys = %+v", k)
	}
	if got := strings.Join(c.ProfileNames(), ","); got != "github,quick,restic" {
		t.Fatalf("ProfileNames = %s", got)
	}
}

func TestLoadRejects(t *testing.T) {
	cases := map[string]string{
		"unknown key":  "profiles:\n  a:\n    secretz: {}\n",
		"bad name":     "profiles:\n  Bad Name:\n    secrets: {A: op://v/i/f}\n",
		"bad env":      "profiles:\n  a:\n    secrets: {A-B: op://v/i/f}\n",
		"bad ref":      "profiles:\n  a:\n    secrets: {A: not-a-ref}\n",
		"ttl too long": "profiles:\n  a:\n    ttl: 48h\n    secrets: {A: op://v/i/f}\n",
		"no secrets":   "profiles:\n  a:\n    ttl: 1h\n",
		"bad ssh ref":  "profiles:\n  a:\n    ssh_keys: [nope]\n",
	}
	for name, body := range cases {
		if _, err := Load(write(t, body, 0o600), parse); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoadRejectsWritableByOthers(t *testing.T) {
	path := write(t, "profiles: {}\n", 0o600)
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, parse); err == nil || !strings.Contains(err.Error(), "chmod 600") {
		t.Fatalf("error = %v", err)
	}
}
