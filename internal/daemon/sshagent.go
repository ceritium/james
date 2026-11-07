package daemon

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/ceritium/james/internal/audit"
	"github.com/ceritium/james/internal/peer"
)

var errManaged = errors.New("james: keys come from profiles; add or remove them in ~/.config/james/config.yaml")

// ServeSSH runs an SSH agent. Each connection sees only the keys of profiles
// granted to an agent process among the client's ancestors.
func (s *Server) ServeSSH(ctx context.Context, l *net.UnixListener) error {
	go func() {
		<-ctx.Done()
		l.Close()
	}()
	for {
		conn, err := l.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			pid, err := s.d.PeerPID(conn)
			if err != nil {
				log.Printf("ssh agent: %v", err)
				return
			}
			_ = agent.ServeAgent(&sshAgent{s: s, pid: pid, chain: s.d.Ancestors(pid)}, conn)
		}()
	}
}

type sshAgent struct {
	s     *Server
	pid   int
	chain []peer.Proc
}

type keyEntry struct {
	signer ssh.Signer
	grant  grant
}

func (a *sshAgent) keys() ([]keyEntry, error) {
	var out []keyEntry
	seen := map[string]bool{}
	for _, gr := range a.s.grants.forChain(a.chain) {
		signers, err := a.s.grants.signers(gr, a.s.loadSigners)
		if err != nil {
			_ = a.s.d.Audit.Write(audit.Event{Event: "error", Profile: gr.profile, Anchor: gr.anchor.String(),
				PeerPID: a.pid, Command: chainNames(a.chain), Error: "load ssh keys: " + err.Error()})
			return nil, fmt.Errorf("profile %q: %w", gr.profile, err)
		}
		for _, sg := range signers {
			blob := string(sg.PublicKey().Marshal())
			if !seen[blob] {
				seen[blob] = true
				out = append(out, keyEntry{signer: sg, grant: gr})
			}
		}
	}
	return out, nil
}

func (a *sshAgent) List() ([]*agent.Key, error) {
	entries, err := a.keys()
	if err != nil {
		log.Printf("ssh agent list for pid %d: %v", a.pid, err)
		return nil, err
	}
	out := make([]*agent.Key, 0, len(entries))
	for _, e := range entries {
		pub := e.signer.PublicKey()
		out = append(out, &agent.Key{Format: pub.Type(), Blob: pub.Marshal(), Comment: "james:" + e.grant.profile})
	}
	return out, nil
}

func (a *sshAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

func (a *sshAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	entries, err := a.keys()
	if err != nil {
		return nil, err
	}
	want := key.Marshal()
	for _, e := range entries {
		if !bytes.Equal(e.signer.PublicKey().Marshal(), want) {
			continue
		}
		sig, err := sign(e.signer, data, flags)
		ev := audit.Event{Event: "ssh-sign", Profile: e.grant.profile, Anchor: e.grant.anchor.String(),
			PeerPID: a.pid, Command: chainNames(a.chain), Refs: []string{ssh.FingerprintSHA256(e.signer.PublicKey())}}
		if err != nil {
			ev.Event, ev.Error = "error", err.Error()
			_ = a.s.d.Audit.Write(ev)
			return nil, err
		}
		if err := a.s.d.Audit.Write(ev); err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		if a.s.d.Notify != nil {
			a.s.d.Notify(fmt.Sprintf("%s → ssh signature for %s", e.grant.profile, chainNames(a.chain)[0]))
		}
		return sig, nil
	}
	return nil, errors.New("james: key not granted to this process")
}

func sign(s ssh.Signer, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	if s.PublicKey().Type() != ssh.KeyAlgoRSA || flags == 0 {
		return s.Sign(rand.Reader, data)
	}
	as, ok := s.(ssh.AlgorithmSigner)
	if !ok {
		return nil, errors.New("rsa key cannot choose a signature algorithm")
	}
	algo := ssh.KeyAlgoRSASHA256
	if flags&agent.SignatureFlagRsaSha512 != 0 {
		algo = ssh.KeyAlgoRSASHA512
	}
	return as.SignWithAlgorithm(rand.Reader, data, algo)
}

// loadSigners fetches and parses a profile's private keys.
func (s *Server) loadSigners(profile string) ([]ssh.Signer, error) {
	pr, err := s.loadProfile(profile)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), resolveTimeout)
	defer cancel()
	signers := make([]ssh.Signer, 0, len(pr.sshKeys))
	for _, ref := range pr.sshKeys {
		v, err := s.d.Registry.Resolve(ctx, ref)
		if err != nil {
			return nil, err
		}
		sg, err := ssh.ParsePrivateKey(v.Bytes())
		v.Wipe()
		if err != nil {
			var missing *ssh.PassphraseMissingError
			if errors.As(err, &missing) {
				return nil, fmt.Errorf("%s is passphrase protected; use ?ssh-format=openssh on a 1Password SSH key item", ref)
			}
			return nil, fmt.Errorf("%s: parse private key: %w", ref, err)
		}
		signers = append(signers, sg)
	}
	return signers, nil
}

func chainNames(chain []peer.Proc) []string {
	names := make([]string, 0, len(chain))
	for _, p := range chain {
		names = append(names, p.Name)
	}
	if len(names) == 0 {
		return []string{"?"}
	}
	return names
}

func (a *sshAgent) Add(agent.AddedKey) error       { return errManaged }
func (a *sshAgent) Remove(ssh.PublicKey) error     { return errManaged }
func (a *sshAgent) RemoveAll() error               { return errManaged }
func (a *sshAgent) Lock([]byte) error              { return errManaged }
func (a *sshAgent) Unlock([]byte) error            { return errManaged }
func (a *sshAgent) Signers() ([]ssh.Signer, error) { return nil, errManaged }
func (a *sshAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
