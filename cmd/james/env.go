package main

import (
	"slices"
	"strings"
)

// Variables that make the command load code it was not asked to run. Something that
// planted one in the agent's environment would run inside the process holding the secrets.
var injectionVars = []string{
	"BASH_ENV", "ENV",
	"NODE_OPTIONS",
	"PYTHONSTARTUP",
	"RUBYOPT",
	"PERL5OPT",
	"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS",
	"GIT_SSH", "GIT_SSH_COMMAND", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT",
}

var injectionPrefixes = []string{"DYLD_", "LD_", "GIT_CONFIG_KEY_", "GIT_CONFIG_VALUE_"}

func isInjectionVar(name string) bool {
	if slices.Contains(injectionVars, name) {
		return true
	}
	for _, p := range injectionPrefixes {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}

// commandEnv builds the command's environment: the inherited one minus injection
// variables, with secrets taking precedence. It returns the names it removed.
func commandEnv(inherited []string, secrets map[string]string) (env, removed []string) {
	env = make([]string, 0, len(inherited)+len(secrets))
	for _, kv := range inherited {
		name, _, _ := strings.Cut(kv, "=")
		if _, ok := secrets[name]; ok {
			continue
		}
		if isInjectionVar(name) {
			removed = append(removed, name)
			continue
		}
		env = append(env, kv)
	}
	for name, v := range secrets {
		env = append(env, name+"="+v)
	}
	return env, removed
}
