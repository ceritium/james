package provider

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ceritium/james/internal/secret"
)

type fakeProvider struct {
	scheme string
	values map[string]string
	fail   map[string]bool
	calls  []Ref
}

func (f *fakeProvider) Scheme() string { return f.scheme }

func (f *fakeProvider) Validate(ref Ref) error {
	if strings.Contains(ref.Path, "bad") {
		return errors.New("bad path")
	}
	return nil
}

func (f *fakeProvider) Resolve(_ context.Context, ref Ref) (secret.Value, error) {
	f.calls = append(f.calls, ref)
	if f.fail[ref.Path] {
		return secret.Value{}, errors.New("backend down")
	}
	return secret.FromString(f.values[ref.Path]), nil
}

func newTestRegistry(t *testing.T) (*Registry, *fakeProvider, *fakeProvider) {
	t.Helper()
	op := &fakeProvider{scheme: "op", values: map[string]string{"v/i/f": "op-value"}}
	bws := &fakeProvider{scheme: "bws", values: map[string]string{"123": "bws-value"}}
	r, err := NewRegistry(op, bws)
	if err != nil {
		t.Fatal(err)
	}
	return r, op, bws
}

func TestParseRef(t *testing.T) {
	ref, err := ParseRef("op://v/i/f", "Work")
	if err != nil {
		t.Fatal(err)
	}
	if ref != (Ref{Scheme: "op", Path: "v/i/f", Account: "Work"}) || ref.String() != "op://v/i/f" {
		t.Fatalf("ref = %+v", ref)
	}
	for _, raw := range []string{"", "op:/v/i/f", "op://", "OP://v", "1p://v", " op://v", "op://v "} {
		if _, err := ParseRef(raw, ""); !errors.Is(err, ErrInvalidRef) {
			t.Errorf("ParseRef(%q) error = %v, want ErrInvalidRef", raw, err)
		}
	}
}

func TestRegistryRoutesByScheme(t *testing.T) {
	r, op, bws := newTestRegistry(t)
	ctx := context.Background()

	opRef, _ := r.Parse("op://v/i/f", "Work")
	bwsRef, _ := r.Parse("bws://123", "")
	if v, err := r.Resolve(ctx, opRef); err != nil || string(v.Bytes()) != "op-value" {
		t.Fatalf("op resolve = %q, %v", v.Bytes(), err)
	}
	if v, err := r.Resolve(ctx, bwsRef); err != nil || string(v.Bytes()) != "bws-value" {
		t.Fatalf("bws resolve = %q, %v", v.Bytes(), err)
	}
	if len(op.calls) != 1 || op.calls[0].Account != "Work" || len(bws.calls) != 1 {
		t.Fatalf("calls op=%+v bws=%+v", op.calls, bws.calls)
	}
}

func TestRegistryParseErrors(t *testing.T) {
	r, _, _ := newTestRegistry(t)
	if _, err := r.Parse("vault://x", ""); !errors.Is(err, ErrUnknownProvider) {
		t.Errorf("unknown scheme error = %v", err)
	}
	if _, err := r.Parse("op://bad", ""); !errors.Is(err, ErrInvalidRef) {
		t.Errorf("provider validation error = %v", err)
	}
}

func TestNewRegistryRejectsDuplicateScheme(t *testing.T) {
	_, err := NewRegistry(&fakeProvider{scheme: "op"}, &fakeProvider{scheme: "op"})
	if !errors.Is(err, ErrDuplicateScheme) {
		t.Fatalf("error = %v", err)
	}
}

func TestResolveAllDedupes(t *testing.T) {
	r, op, _ := newTestRegistry(t)
	ref, _ := r.Parse("op://v/i/f", "Work")
	values, err := r.ResolveAll(context.Background(), map[string]Ref{"A": ref, "B": ref})
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != 1 || len(op.calls) != 1 {
		t.Fatalf("values=%d calls=%d", len(values), len(op.calls))
	}
}

func TestResolveAllWipesOnError(t *testing.T) {
	op := &fakeProvider{scheme: "op", values: map[string]string{"a": "first"}, fail: map[string]bool{"b": true}}
	r, _ := NewRegistry(op)
	a, _ := r.Parse("op://a", "")
	b, _ := r.Parse("op://b", "")

	values, err := r.ResolveAll(context.Background(), map[string]Ref{"A": a, "B": b})
	if err == nil || values != nil {
		t.Fatalf("values=%v err=%v", values, err)
	}
	if !strings.Contains(err.Error(), "B: resolve op://b") {
		t.Errorf("error should name the failing variable and ref: %v", err)
	}
}

func TestResolveAllNamesEveryFailure(t *testing.T) {
	op := &fakeProvider{scheme: "op", values: map[string]string{"a": "first"}, fail: map[string]bool{"b": true, "c": true}}
	r, _ := NewRegistry(op)
	a, _ := r.Parse("op://a", "")
	b, _ := r.Parse("op://b", "")
	c, _ := r.Parse("op://c", "")

	_, err := r.ResolveAll(context.Background(), map[string]Ref{"Z": b, "Y": c, "X": a, "W": b})
	if err == nil {
		t.Fatal("expected an error")
	}
	want := "W: resolve op://b: backend down\nY: resolve op://c: backend down\nZ: resolve op://b: backend down"
	if err.Error() != want {
		t.Errorf("error =\n%v\nwant\n%v", err, want)
	}
	if len(op.calls) != 3 {
		t.Errorf("each distinct ref should be tried once, calls=%d", len(op.calls))
	}
}
