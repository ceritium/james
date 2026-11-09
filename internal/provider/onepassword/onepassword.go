// Package onepassword resolves op:// references through the 1Password desktop
// app, so the 1Password authorization belongs to the james daemon, not to a terminal.
package onepassword

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	onepassword "github.com/1password/onepassword-sdk-go"

	"github.com/ceritium/james/internal/provider"
	"github.com/ceritium/james/internal/secret"
)

const Scheme = "op"

var ErrNoAccount = errors.New("1Password account is required: set it on the reference or as the provider default")

type secretsAPI interface {
	Resolve(ctx context.Context, secretReference string) (string, error)
}

type clientFactory func(ctx context.Context, account string) (secretsAPI, error)

type Options struct {
	// DefaultAccount is used when a reference names no account.
	DefaultAccount     string
	IntegrationName    string
	IntegrationVersion string
}

type Provider struct {
	newClient clientFactory

	mu             sync.Mutex
	defaultAccount string
	clients        map[string]secretsAPI
}

var _ provider.Provider = (*Provider)(nil)

func New(opts Options) *Provider {
	name := cmpOr(opts.IntegrationName, "james")
	version := cmpOr(opts.IntegrationVersion, "dev")
	return newWithFactory(opts.DefaultAccount, func(ctx context.Context, account string) (secretsAPI, error) {
		client, err := onepassword.NewClient(ctx,
			onepassword.WithDesktopAppIntegration(account),
			onepassword.WithIntegrationInfo(name, version),
		)
		if err != nil {
			return nil, err
		}
		return clientSecrets{client: client}, nil
	})
}

func newWithFactory(defaultAccount string, f clientFactory) *Provider {
	return &Provider{
		defaultAccount: strings.TrimSpace(defaultAccount),
		newClient:      f,
		clients:        map[string]secretsAPI{},
	}
}

// SetDefaultAccount replaces the account used when a reference names none.
func (p *Provider) SetDefaultAccount(account string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.defaultAccount = strings.TrimSpace(account)
}

func (p *Provider) Scheme() string { return Scheme }

// Validate accepts op://vault/item[/section]/field, with an optional ?query on the field.
func (p *Provider) Validate(ref provider.Ref) error {
	parts := strings.Split(ref.Path, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return errors.New("expected op://vault/item[/section]/field")
	}
	if slices.Contains(parts, "") {
		return errors.New("path segments must be non-empty")
	}
	if strings.ContainsRune(strings.Join(parts[:len(parts)-1], "/"), '?') {
		return errors.New("query is only allowed on the field segment")
	}
	return nil
}

func (p *Provider) Resolve(ctx context.Context, ref provider.Ref) (secret.Value, error) {
	if err := p.Validate(ref); err != nil {
		return secret.Value{}, err
	}
	// The SDK client is not documented as safe for concurrent use.
	p.mu.Lock()
	defer p.mu.Unlock()

	account := cmpOr(ref.Account, p.defaultAccount)
	if account == "" {
		return secret.Value{}, ErrNoAccount
	}

	client, err := p.clientLocked(ctx, account)
	if err != nil {
		return secret.Value{}, err
	}
	value, err := client.Resolve(ctx, ref.String())
	if err != nil {
		return secret.Value{}, fmt.Errorf("1Password account %q: %w", account, err)
	}
	return secret.FromString(value), nil
}

func (p *Provider) clientLocked(ctx context.Context, account string) (secretsAPI, error) {
	if c, ok := p.clients[account]; ok {
		return c, nil
	}
	c, err := p.newClient(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("connect to 1Password desktop app for account %q: %w", account, err)
	}
	p.clients[account] = c
	return c, nil
}

// clientSecrets keeps the *Client reachable: the SDK releases its client ID in a finalizer.
type clientSecrets struct {
	client *onepassword.Client
}

func (c clientSecrets) Resolve(ctx context.Context, ref string) (string, error) {
	return c.client.Secrets().Resolve(ctx, ref)
}

func cmpOr(a, b string) string {
	if a = strings.TrimSpace(a); a != "" {
		return a
	}
	return b
}
