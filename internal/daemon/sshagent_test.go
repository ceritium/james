package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"math/big"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/ceritium/james/internal/peer"
	"github.com/ceritium/james/internal/protocol"
)

var testKeyPEM, testPub = func() ([]byte, ssh.PublicKey) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		panic(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(block), sshPub
}()

var (
	sshClient = peer.Proc{PID: 300, StartUS: 50, Name: "ssh"}
	gitProc   = peer.Proc{PID: 299, StartUS: 49, Name: "git"}
	stranger  = peer.Proc{PID: 900, StartUS: 10, Name: "zsh"}
)

// agentFor connects an ssh-agent client to an sshAgent that sees chain as the caller's ancestry.
func agentFor(t *testing.T, h *harness, chain []peer.Proc) agent.ExtendedAgent {
	t.Helper()
	server, client := net.Pipe()
	go func() {
		_ = agent.ServeAgent(&sshAgent{s: h.s, pid: chain[0].PID, chain: chain}, server)
		server.Close()
	}()
	t.Cleanup(func() { client.Close() })
	return agent.NewClient(client)
}

func bond(t *testing.T, h *harness, profile string) {
	t.Helper()
	if resp := h.s.Dispatch(context.Background(), 1, protocol.Request{Op: protocol.OpBond, Profile: profile}); resp.Error != "" {
		t.Fatal(resp.Error)
	}
}

func TestSSHAgentServesOnlyGrantedKeysToAgentDescendants(t *testing.T) {
	h := newHarness(t)
	underClaude := []peer.Proc{sshClient, gitProc, claude}

	if keys, err := agentFor(t, h, underClaude).List(); err != nil || len(keys) != 0 {
		t.Fatalf("before grant: keys=%d err=%v", len(keys), err)
	}

	bond(t, h, "github")
	a := agentFor(t, h, underClaude)
	keys, err := a.List()
	if err != nil || len(keys) != 1 || keys[0].Comment != "james:github" {
		t.Fatalf("after grant: keys=%v err=%v", keys, err)
	}
	data := []byte("session data")
	sig, err := a.Sign(testPub, data)
	if err != nil {
		t.Fatal(err)
	}
	if err := testPub.Verify(data, sig); err != nil {
		t.Fatalf("signature does not verify: %v", err)
	}
	if last := h.audit.events[len(h.audit.events)-1]; last.Event != "ssh-sign" || last.Profile != "github" {
		t.Errorf("audit = %+v", last)
	}

	outsider := agentFor(t, h, []peer.Proc{{PID: 901, StartUS: 11, Name: "ssh"}, stranger})
	if keys, _ := outsider.List(); len(keys) != 0 {
		t.Fatalf("outsider sees %d keys", len(keys))
	}
	if _, err := outsider.Sign(testPub, data); err == nil {
		t.Fatal("outsider got a signature")
	}

	h.s.grants.revoke("")
	if keys, _ := agentFor(t, h, underClaude).List(); len(keys) != 0 {
		t.Fatalf("after revoke: %d keys", len(keys))
	}
}

func TestSSHAgentRefusesKeyManagement(t *testing.T) {
	h := newHarness(t)
	a := agentFor(t, h, []peer.Proc{sshClient, claude})
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	if err := a.Add(agent.AddedKey{PrivateKey: priv}); err == nil {
		t.Error("Add accepted")
	}
	if err := a.RemoveAll(); err == nil {
		t.Error("RemoveAll accepted")
	}
}

func TestRunSetsSSHAuthSock(t *testing.T) {
	h := newHarness(t)
	h.s.d.SSHSocket = "/tmp/james-ssh.sock"
	resp := h.s.Dispatch(context.Background(), 1, protocol.Request{Op: protocol.OpRun, Profile: "github", Command: []string{"git", "push"}})
	if resp.Error != "" || resp.Env["SSH_AUTH_SOCK"] != "/tmp/james-ssh.sock" {
		t.Fatalf("resp = %+v", resp)
	}
	if len(h.prompts) != 1 || !strings.Contains(h.prompts[0], "1 SSH key") {
		t.Fatalf("prompts = %q", h.prompts)
	}

	h.anchor = nil
	if resp := h.s.Dispatch(context.Background(), 1, protocol.Request{Op: protocol.OpRun, Profile: "github", Command: []string{"git"}}); resp.Error == "" {
		t.Fatal("ssh-only profile without an agent session should fail")
	}
}

func countSSHResolves(p *fakeProvider) int {
	n := 0
	for _, r := range p.resolved {
		if strings.Contains(r, "sshkey") {
			n++
		}
	}
	return n
}

func TestSSHAgentFetchesPrivateKeyPerSignature(t *testing.T) {
	h := newHarness(t)
	bond(t, h, "github")
	a := agentFor(t, h, []peer.Proc{sshClient, claude})
	if _, err := a.List(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.List(); err != nil {
		t.Fatal(err)
	}
	if n := countSSHResolves(h.prov); n != 1 {
		t.Fatalf("public keys loaded %d times, want 1 (cached)", n)
	}
	for range 2 {
		if _, err := a.Sign(testPub, []byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	if n := countSSHResolves(h.prov); n != 3 {
		t.Fatalf("resolves = %d, want 1 + one per signature", n)
	}

	_, other, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKey(other, "")
	h.prov.keyPEM = pem.EncodeToMemory(block)
	if _, err := a.Sign(testPub, []byte("x")); err == nil {
		t.Fatal("signed after the key was replaced in the provider")
	}
	if last := h.audit.events[len(h.audit.events)-1]; last.Event != "error" || !strings.Contains(last.Error, "changed") {
		t.Fatalf("audit = %+v", last)
	}
}

func TestWipeKey(t *testing.T) {
	_, ed, _ := ed25519.GenerateKey(rand.Reader)
	wipeKey(ed)
	for _, b := range ed {
		if b != 0 {
			t.Fatal("ed25519 key not wiped")
		}
	}

	r, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	wipeKey(r)
	for _, x := range append([]*big.Int{r.D, r.Precomputed.Dp, r.Precomputed.Dq, r.Precomputed.Qinv}, r.Primes...) {
		for _, w := range x.Bits() {
			if w != 0 {
				t.Fatal("rsa key not wiped")
			}
		}
	}
}
