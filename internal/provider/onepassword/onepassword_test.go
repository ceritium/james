package onepassword

import (
	"context"
	"errors"
	"testing"

	"github.com/ceritium/james/internal/provider"
)

type fakeClient struct {
	account string
	refs    []string
}

func (f *fakeClient) Resolve(_ context.Context, ref string) (string, error) {
	f.refs = append(f.refs, ref)
	return f.account + ":" + ref, nil
}

type factory struct {
	clients map[string]*fakeClient
	created int
}

func (f *factory) new(_ context.Context, account string) (secretsAPI, error) {
	f.created++
	if account == "broken" {
		return nil, errors.New("desktop app locked")
	}
	c := &fakeClient{account: account}
	f.clients[account] = c
	return c, nil
}

func newTest(defaultAccount string) (*Provider, *factory) {
	f := &factory{clients: map[string]*fakeClient{}}
	return newWithFactory(defaultAccount, f.new), f
}

func ref(t *testing.T, raw, account string) provider.Ref {
	t.Helper()
	r, err := provider.ParseRef(raw, account)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestValidate(t *testing.T) {
	p, _ := newTest("")
	valid := []string{
		"op://Vault/Item/field",
		"op://Vault/Item/Section/field",
		"op://Vault/SSH Key/private key?ssh-format=openssh",
	}
	for _, raw := range valid {
		if err := p.Validate(ref(t, raw, "")); err != nil {
			t.Errorf("Validate(%q) = %v", raw, err)
		}
	}
	invalid := []string{
		"op://Vault/Item",
		"op://Vault//field",
		"op://Vault/Item/a/b/field",
		"op://Vault?x=1/Item/field",
	}
	for _, raw := range invalid {
		if err := p.Validate(ref(t, raw, "")); err == nil {
			t.Errorf("Validate(%q) accepted", raw)
		}
	}
}

func TestResolveUsesOneClientPerAccount(t *testing.T) {
	p, f := newTest("Personal")
	ctx := context.Background()

	cases := []struct{ raw, account, want string }{
		{"op://V/I/a", "", "Personal:op://V/I/a"},
		{"op://V/I/b", "", "Personal:op://V/I/b"},
		{"op://V/I/a", "Work", "Work:op://V/I/a"},
	}
	for _, c := range cases {
		v, err := p.Resolve(ctx, ref(t, c.raw, c.account))
		if err != nil {
			t.Fatal(err)
		}
		if got := string(v.Bytes()); got != c.want {
			t.Errorf("Resolve(%s, %q) = %q, want %q", c.raw, c.account, got, c.want)
		}
	}
	if f.created != 2 || len(f.clients["Personal"].refs) != 2 || len(f.clients["Work"].refs) != 1 {
		t.Fatalf("created=%d clients=%+v", f.created, f.clients)
	}
}

func TestResolveErrors(t *testing.T) {
	ctx := context.Background()

	p, _ := newTest("")
	if _, err := p.Resolve(ctx, ref(t, "op://V/I/f", "")); !errors.Is(err, ErrNoAccount) {
		t.Errorf("no account error = %v", err)
	}

	p.SetDefaultAccount("Later")
	if _, err := p.Resolve(ctx, ref(t, "op://V/I/f", "")); err != nil {
		t.Errorf("default set after construction not used: %v", err)
	}

	p, f := newTest("broken")
	if _, err := p.Resolve(ctx, ref(t, "op://V/I/f", "")); err == nil {
		t.Fatal("expected client error")
	}
	if _, err := p.Resolve(ctx, ref(t, "op://V/I/f", "")); err == nil || f.created != 2 {
		t.Fatalf("failed client must not be cached: created=%d err=%v", f.created, err)
	}
}
