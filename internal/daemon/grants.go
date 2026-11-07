package daemon

import (
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/ceritium/james/internal/peer"
)

// A grant lets processes under one agent process use a profile until it expires.
type grant struct {
	profile string
	anchor  peer.Proc
	granted time.Time
	expires time.Time
	uses    int
	// signers caches the profile's SSH keys from first use until the grant ends.
	signers []ssh.Signer
}

type grantKey struct {
	profile string
	pid     int
	startUS uint64
}

type grants struct {
	mu    sync.Mutex
	m     map[grantKey]*grant
	now   func() time.Time
	alive func(peer.Proc) bool
}

func newGrants(now func() time.Time, alive func(peer.Proc) bool) *grants {
	return &grants{m: map[grantKey]*grant{}, now: now, alive: alive}
}

func key(profile string, anchor peer.Proc) grantKey {
	return grantKey{profile: profile, pid: anchor.PID, startUS: anchor.StartUS}
}

// use returns a live grant and counts the use; ok is false if none applies.
func (g *grants) use(profile string, anchor peer.Proc) (grant, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	gr, ok := g.m[key(profile, anchor)]
	if !ok {
		return grant{}, false
	}
	gr.uses++
	return *gr, true
}

func (g *grants) add(profile string, anchor peer.Proc, ttl time.Duration) grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	gr := &grant{profile: profile, anchor: anchor, granted: now, expires: now.Add(ttl)}
	g.m[key(profile, anchor)] = gr
	return *gr
}

func (g *grants) list() []grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	out := make([]grant, 0, len(g.m))
	for _, gr := range g.m {
		out = append(out, *gr)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].expires.Before(out[j].expires) })
	return out
}

// revoke removes grants for profile, or all grants when profile is empty.
func (g *grants) revoke(profile string) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for k := range g.m {
		if profile == "" || k.profile == profile {
			delete(g.m, k)
			n++
		}
	}
	return n
}

// Grants end when they expire or when their agent process exits.
func (g *grants) pruneLocked() {
	now := g.now()
	for k, gr := range g.m {
		if !now.Before(gr.expires) || !g.alive(gr.anchor) {
			delete(g.m, k)
		}
	}
}

// forChain returns live grants anchored on any process in chain.
func (g *grants) forChain(chain []peer.Proc) []grant {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.pruneLocked()
	var out []grant
	for _, p := range chain {
		for k, gr := range g.m {
			if k.pid == p.PID && k.startUS == p.StartUS {
				out = append(out, *gr)
			}
		}
	}
	return out
}

// signers returns the grant's SSH keys, loading them on first use. Loading
// talks to the provider, so it runs without holding the lock.
func (g *grants) signers(gr grant, load func(profile string) ([]ssh.Signer, error)) ([]ssh.Signer, error) {
	k := key(gr.profile, gr.anchor)
	g.mu.Lock()
	cur, ok := g.m[k]
	if ok && cur.signers != nil {
		g.mu.Unlock()
		return cur.signers, nil
	}
	g.mu.Unlock()
	if !ok {
		return nil, nil
	}
	signers, err := load(gr.profile)
	if err != nil {
		return nil, err
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if cur, ok := g.m[k]; ok {
		cur.signers = signers
	}
	return signers, nil
}
