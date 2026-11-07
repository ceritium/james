// Package config loads the user-level profile file. Profiles live outside
// project repos so a project cannot widen what an agent may request.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/ceritium/james/internal/provider"
)

const (
	DefaultTTL = time.Hour
	MinTTL     = time.Minute
	MaxTTL     = 24 * time.Hour
)

var (
	profileName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	envName     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)
)

type Config struct {
	Providers Providers `yaml:"providers"`
	// Anchors are executable names of agent processes a grant binds to.
	Anchors  []string           `yaml:"anchors"`
	Notify   *bool              `yaml:"notify"`
	Profiles map[string]Profile `yaml:"profiles"`
}

type Providers struct {
	OnePassword OnePassword `yaml:"1password"`
}

type OnePassword struct {
	DefaultAccount string `yaml:"default_account"`
}

type Profile struct {
	TTL     Duration          `yaml:"ttl"`
	Secrets map[string]Secret `yaml:"secrets"`
}

type Secret struct {
	Ref     string `yaml:"ref"`
	Account string `yaml:"account"`
}

// UnmarshalYAML accepts either `VAR: op://...` or `VAR: {ref: ..., account: ...}`.
func (s *Secret) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		s.Ref = n.Value
		return nil
	}
	type plain Secret
	return n.Decode((*plain)(s))
}

type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: %w", n.Line, err)
	}
	*d = Duration(v)
	return nil
}

// Parser validates a reference; provider.Registry.Parse satisfies it.
type Parser func(raw, account string) (provider.Ref, error)

func DefaultPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "james", "config.yaml"), nil
}

func Load(path string, parse Parser) (*Config, error) {
	if err := checkOwnership(path); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(c.Anchors) == 0 {
		c.Anchors = []string{"claude"}
	}
	if err := c.validate(parse); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, nil
}

func (c *Config) NotifyEnabled() bool { return c.Notify == nil || *c.Notify }

func (c *Config) ProfileNames() []string {
	names := make([]string, 0, len(c.Profiles))
	for n := range c.Profiles {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

func (p Profile) EffectiveTTL() time.Duration {
	if p.TTL == 0 {
		return DefaultTTL
	}
	return time.Duration(p.TTL)
}

func (c *Config) validate(parse Parser) error {
	for name, p := range c.Profiles {
		if !profileName.MatchString(name) {
			return fmt.Errorf("profile %q: name must match %s", name, profileName)
		}
		if ttl := p.EffectiveTTL(); ttl < MinTTL || ttl > MaxTTL {
			return fmt.Errorf("profile %q: ttl %s outside %s..%s", name, ttl, MinTTL, MaxTTL)
		}
		if len(p.Secrets) == 0 {
			return fmt.Errorf("profile %q: no secrets", name)
		}
		for env, s := range p.Secrets {
			if err := ValidateEnvName(env); err != nil {
				return fmt.Errorf("profile %q: %w", name, err)
			}
			if _, err := parse(s.Ref, s.Account); err != nil {
				return fmt.Errorf("profile %q, %s: %w", name, env, err)
			}
		}
	}
	return nil
}

func ValidateEnvName(name string) error {
	if !envName.MatchString(name) {
		return fmt.Errorf("invalid environment variable name %q", name)
	}
	return nil
}

// The file decides what can be granted, so another local user must not be able to edit it.
func checkOwnership(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read config file owner")
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not owned by the current user", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is writable by group or others; run chmod 600", path)
	}
	return nil
}
