package main

import (
	"slices"
	"strings"
	"testing"
)

func TestCommandEnv(t *testing.T) {
	env, removed := commandEnv([]string{
		"PATH=/bin", "NODE_OPTIONS=--require /tmp/x.js", "DYLD_INSERT_LIBRARIES=/tmp/x.dylib",
		"GIT_CONFIG_KEY_0=core.sshCommand", "TOKEN=old", "HOME=/h",
	}, map[string]string{"TOKEN": "new"})
	slices.Sort(env)
	if got := strings.Join(env, " "); got != "HOME=/h PATH=/bin TOKEN=new" {
		t.Fatalf("env = %s", got)
	}
	if got := strings.Join(removed, ","); got != "NODE_OPTIONS,DYLD_INSERT_LIBRARIES,GIT_CONFIG_KEY_0" {
		t.Fatalf("removed = %s", got)
	}
}
