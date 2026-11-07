// Package provider routes secret references to the backend that resolves them.
package provider

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ceritium/james/internal/secret"
)

var (
	ErrInvalidRef      = errors.New("invalid secret reference")
	ErrUnknownProvider = errors.New("no provider for scheme")
	ErrDuplicateScheme = errors.New("duplicate provider scheme")
)

var schemePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Ref is a reference such as op://Vault/Item/field. Account means whatever the
// provider needs to pick a credential: a 1Password account, a token alias...
type Ref struct {
	Scheme  string
	Path    string
	Account string
}

func (r Ref) String() string { return r.Scheme + "://" + r.Path }

func ParseRef(raw, account string) (Ref, error) {
	scheme, path, ok := strings.Cut(raw, "://")
	if !ok || !schemePattern.MatchString(scheme) || path == "" {
		return Ref{}, fmt.Errorf("%w %q: expected scheme://path", ErrInvalidRef, raw)
	}
	if strings.TrimSpace(raw) != raw || strings.TrimSpace(account) != account {
		return Ref{}, fmt.Errorf("%w %q: surrounding whitespace", ErrInvalidRef, raw)
	}
	return Ref{Scheme: scheme, Path: path, Account: account}, nil
}

type Provider interface {
	// Scheme is the reference prefix this provider owns, without "://".
	Scheme() string
	// Validate checks a reference offline, so bad config fails before any prompt.
	Validate(ref Ref) error
	Resolve(ctx context.Context, ref Ref) (secret.Value, error)
}

type Registry struct {
	providers map[string]Provider
}

func NewRegistry(providers ...Provider) (*Registry, error) {
	r := &Registry{providers: make(map[string]Provider, len(providers))}
	for _, p := range providers {
		s := p.Scheme()
		if !schemePattern.MatchString(s) {
			return nil, fmt.Errorf("invalid provider scheme %q", s)
		}
		if _, dup := r.providers[s]; dup {
			return nil, fmt.Errorf("%w %q", ErrDuplicateScheme, s)
		}
		r.providers[s] = p
	}
	return r, nil
}

// Parse parses and validates raw against its provider.
func (r *Registry) Parse(raw, account string) (Ref, error) {
	ref, err := ParseRef(raw, account)
	if err != nil {
		return Ref{}, err
	}
	p, err := r.lookup(ref)
	if err != nil {
		return Ref{}, err
	}
	if err := p.Validate(ref); err != nil {
		return Ref{}, fmt.Errorf("%w %q: %w", ErrInvalidRef, raw, err)
	}
	return ref, nil
}

func (r *Registry) Resolve(ctx context.Context, ref Ref) (secret.Value, error) {
	p, err := r.lookup(ref)
	if err != nil {
		return secret.Value{}, err
	}
	v, err := p.Resolve(ctx, ref)
	if err != nil {
		return secret.Value{}, fmt.Errorf("resolve %s: %w", ref, err)
	}
	return v, nil
}

// ResolveAll resolves each distinct ref once. It is all or nothing: on error,
// values already fetched are wiped.
func (r *Registry) ResolveAll(ctx context.Context, refs []Ref) (map[Ref]secret.Value, error) {
	values := make(map[Ref]secret.Value, len(refs))
	for _, ref := range refs {
		if _, done := values[ref]; done {
			continue
		}
		v, err := r.Resolve(ctx, ref)
		if err != nil {
			Wipe(values)
			return nil, err
		}
		values[ref] = v
	}
	return values, nil
}

func Wipe(values map[Ref]secret.Value) {
	for ref, v := range values {
		v.Wipe()
		delete(values, ref)
	}
}

func (r *Registry) lookup(ref Ref) (Provider, error) {
	p, ok := r.providers[ref.Scheme]
	if !ok {
		return nil, fmt.Errorf("%w %q", ErrUnknownProvider, ref.Scheme)
	}
	return p, nil
}
