// Package daemon holds grants in memory and is the only process that talks to
// secret providers. Clients must be the exact same signed james binary.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ceritium/james/internal/approve"
	"github.com/ceritium/james/internal/audit"
	"github.com/ceritium/james/internal/config"
	"github.com/ceritium/james/internal/peer"
	"github.com/ceritium/james/internal/protocol"
	"github.com/ceritium/james/internal/provider"
)

const (
	readTimeout    = 10 * time.Second
	resolveTimeout = 2 * time.Minute
)

type Auditor interface {
	Write(audit.Event) error
}

type Deps struct {
	Verify     func(*net.UnixConn) (pid int, err error)
	FindAnchor func(pid int, names []string) (peer.Proc, bool)
	Alive      func(peer.Proc) bool
	Approve    func(approve.Prompt) (time.Duration, error)
	Notify     func(msg string)
	LoadConfig func() (*config.Config, error)
	Registry   *provider.Registry
	Audit      Auditor
	Now        func() time.Time

	// SSH agent: PeerPID reads the client PID without a signature check, since
	// the client is ssh; Ancestors gives its verified process chain.
	PeerPID   func(*net.UnixConn) (int, error)
	Ancestors func(pid int) []peer.Proc
	SSHSocket string
}

type Server struct {
	d      Deps
	grants *grants
	// Serializes check-grant → prompt → add-grant so concurrent runs prompt once.
	approvalMu sync.Mutex
}

func NewServer(d Deps) *Server {
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Server{d: d, grants: newGrants(d.Now, d.Alive)}
}

func (s *Server) Serve(ctx context.Context, l *net.UnixListener) error {
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
		go s.handle(ctx, conn)
	}
}

func (s *Server) handle(ctx context.Context, conn *net.UnixConn) {
	defer conn.Close()
	pid, err := s.d.Verify(conn)
	if err != nil {
		log.Printf("rejected connection: %v", err)
		return
	}
	_ = conn.SetReadDeadline(time.Now().Add(readTimeout))
	var req protocol.Request
	if err := protocol.Read(conn, &req); err != nil {
		_ = protocol.Write(conn, protocol.Response{Error: "bad request: " + err.Error()})
		return
	}
	resp := s.Dispatch(ctx, pid, req)
	if err := protocol.Write(conn, resp); err != nil {
		log.Printf("write response to pid %d: %v", pid, err)
	}
}

func (s *Server) Dispatch(ctx context.Context, pid int, req protocol.Request) protocol.Response {
	var (
		resp protocol.Response
		err  error
	)
	switch req.Op {
	case protocol.OpPing:
		resp.Message = "ok"
	case protocol.OpList:
		resp.Grants = s.listGrants()
	case protocol.OpRevoke:
		resp, err = s.revoke(pid, req)
	case protocol.OpBond:
		resp, err = s.bond(pid, req)
	case protocol.OpRun:
		resp, err = s.run(ctx, pid, req)
	default:
		err = fmt.Errorf("unknown op %q", req.Op)
	}
	if err != nil {
		return protocol.Response{Error: err.Error()}
	}
	return resp
}

func (s *Server) listGrants() []protocol.Grant {
	var out []protocol.Grant
	for _, g := range s.grants.list() {
		out = append(out, protocol.Grant{
			Profile: g.profile, Anchor: g.anchor.Name, AnchorPID: g.anchor.PID,
			Granted: g.granted, Expires: g.expires, Uses: g.uses,
		})
	}
	return out
}

func (s *Server) revoke(pid int, req protocol.Request) (protocol.Response, error) {
	if req.Profile == "" && !req.All {
		return protocol.Response{}, errors.New("name a profile or use --all")
	}
	n := s.grants.revoke(req.Profile)
	_ = s.d.Audit.Write(audit.Event{Event: "revoked", Profile: req.Profile, PeerPID: pid})
	return protocol.Response{Message: fmt.Sprintf("revoked %d grant(s)", n)}, nil
}

type profileReq struct {
	name    string
	profile config.Profile
	refs    map[string]provider.Ref // env → ref
	sshKeys []provider.Ref
	cfg     *config.Config
}

func (s *Server) loadProfile(name string) (profileReq, error) {
	cfg, err := s.d.LoadConfig()
	if err != nil {
		return profileReq{}, err
	}
	p, ok := cfg.Profiles[name]
	if !ok {
		return profileReq{}, fmt.Errorf("unknown profile %q (have: %s)", name, strings.Join(cfg.ProfileNames(), ", "))
	}
	refs := make(map[string]provider.Ref, len(p.Secrets))
	for env, sec := range p.Secrets {
		ref, err := s.d.Registry.Parse(sec.Ref, sec.Account)
		if err != nil {
			return profileReq{}, err
		}
		refs[env] = ref
	}
	keys := make([]provider.Ref, 0, len(p.SSHKeys))
	for _, k := range p.SSHKeys {
		ref, err := s.d.Registry.Parse(k.Ref, k.Account)
		if err != nil {
			return profileReq{}, err
		}
		keys = append(keys, ref)
	}
	return profileReq{name: name, profile: p, refs: refs, sshKeys: keys, cfg: cfg}, nil
}

func (s *Server) bond(pid int, req protocol.Request) (protocol.Response, error) {
	pr, err := s.loadProfile(req.Profile)
	if err != nil {
		return protocol.Response{}, err
	}
	anchor, ok := s.d.FindAnchor(pid, pr.cfg.Anchors)
	if !ok {
		return protocol.Response{}, fmt.Errorf("no agent process (%s) above this command to bind a grant to; use `james run` to approve a single run",
			strings.Join(pr.cfg.Anchors, ", "))
	}
	s.approvalMu.Lock()
	defer s.approvalMu.Unlock()
	if g, ok := s.grants.use(pr.name, anchor); ok {
		return protocol.Response{Message: fmt.Sprintf("%q already granted to %s until %s", pr.name, anchor, g.expires.Format("15:04"))}, nil
	}
	g, err := s.approveProfile(pid, pr, &anchor, req)
	if err != nil {
		return protocol.Response{}, err
	}
	return protocol.Response{Message: fmt.Sprintf("granted %q to %s until %s", pr.name, anchor, g.expires.Format("15:04"))}, nil
}

// approveProfile prompts and, when an anchor exists, stores the grant. Caller holds approvalMu.
func (s *Server) approveProfile(pid int, pr profileReq, anchor *peer.Proc, req protocol.Request) (grant, error) {
	ttl := pr.profile.EffectiveTTL()
	var b strings.Builder
	p := approve.Prompt{Rows: append(pr.rows(), contextRows(req)...), Quote: shorten(req.Reason, 300)}
	if anchor != nil {
		fmt.Fprintf(&b, "give %s access to %q for %s: %s", anchor, pr.name, formatTTL(ttl), pr.describe())
		p.Title = fmt.Sprintf("%s wants %q", anchor.Name, pr.name)
		p.Subtitle = fmt.Sprintf("Lent to %s and the commands it runs. Ends when time runs out, you revoke it, or %s exits.", anchor, anchor.Name)
		p.TTLs, p.TTL = ttlChoices(ttl), ttl
	} else {
		fmt.Fprintf(&b, "use %q once: %s", pr.name, pr.describe())
		p.Title = fmt.Sprintf("Use %q once", pr.name)
		p.Subtitle = "No agent session above this command, so this covers this run only."
	}
	writeContext(&b, req)
	p.Text = b.String()

	ev := audit.Event{Profile: pr.name, Refs: append(refStrings(pr.refs), refList(pr.sshKeys)...), Env: sortedKeys(pr.refs),
		PeerPID: pid, Command: req.Command, Cwd: req.Cwd, Reason: req.Reason}
	if anchor != nil {
		ev.Anchor = anchor.String()
	}
	chosen, err := s.d.Approve(p)
	if err != nil {
		ev.Event, ev.Error = "denied", err.Error()
		_ = s.d.Audit.Write(ev)
		return grant{}, err
	}
	if chosen <= 0 || chosen > ttl {
		chosen = ttl
	}
	ev.Event = "approved"
	if anchor != nil {
		ev.TTL = formatTTL(chosen)
	}
	if err := s.d.Audit.Write(ev); err != nil {
		return grant{}, fmt.Errorf("audit log: %w", err)
	}
	if anchor == nil {
		return grant{expires: s.d.Now()}, nil
	}
	return s.grants.add(pr.name, *anchor, chosen), nil
}

// ttlChoices offers shorter grants than the profile's maximum.
func ttlChoices(limit time.Duration) []time.Duration {
	var out []time.Duration
	for _, d := range []time.Duration{15 * time.Minute, time.Hour, 4 * time.Hour, 8 * time.Hour} {
		if d < limit {
			out = append(out, d)
		}
	}
	return append(out, limit)
}

func (s *Server) run(ctx context.Context, pid int, req protocol.Request) (protocol.Response, error) {
	if len(req.Command) == 0 {
		return protocol.Response{}, errors.New("no command")
	}
	var (
		refs     map[string]provider.Ref
		profile  string
		notify   = true
		anchorID string
		sshSock  string
		sshRefs  []provider.Ref
		message  string
	)
	switch {
	case req.Profile != "" && len(req.Secrets) > 0:
		return protocol.Response{}, errors.New("use either a profile or one-off secrets, not both")
	case req.Profile != "":
		pr, err := s.loadProfile(req.Profile)
		if err != nil {
			return protocol.Response{}, err
		}
		refs, profile, notify = pr.refs, pr.name, pr.cfg.NotifyEnabled()
		anchor, hasAnchor := s.d.FindAnchor(pid, pr.cfg.Anchors)
		if hasAnchor {
			anchorID = anchor.String()
		}
		if len(pr.sshKeys) > 0 {
			// The SSH agent finds keys through a grant on an ancestor, so without one it has nothing to serve.
			switch {
			case hasAnchor:
				sshSock, sshRefs = s.d.SSHSocket, pr.sshKeys
			case len(pr.refs) == 0:
				return protocol.Response{}, fmt.Errorf("profile %q has only SSH keys, which need an agent session (%s)",
					pr.name, strings.Join(pr.cfg.Anchors, ", "))
			default:
				message = "SSH keys skipped: no agent session to bind them to"
			}
		}

		s.approvalMu.Lock()
		granted := false
		if hasAnchor {
			_, granted = s.grants.use(pr.name, anchor)
		}
		if !granted {
			var ap *peer.Proc
			if hasAnchor {
				ap = &anchor
			}
			if _, err := s.approveProfile(pid, pr, ap, req); err != nil {
				s.approvalMu.Unlock()
				return protocol.Response{}, err
			}
			notify = false // the user just saw the prompt
			if hasAnchor {
				s.grants.use(pr.name, anchor)
			}
		}
		s.approvalMu.Unlock()
	case len(req.Secrets) > 0:
		var err error
		if refs, err = s.oneOff(pid, req); err != nil {
			return protocol.Response{}, err
		}
		notify = false
	default:
		return protocol.Response{}, errors.New("name a profile or pass --secret")
	}

	ctx, cancel := context.WithTimeout(ctx, resolveTimeout)
	defer cancel()
	unique := make([]provider.Ref, 0, len(refs))
	for _, r := range refs {
		unique = append(unique, r)
	}
	values, err := s.d.Registry.ResolveAll(ctx, unique)
	ev := audit.Event{Profile: profile, Refs: append(refStrings(refs), refList(sshRefs)...), Env: sortedKeys(refs), Anchor: anchorID,
		PeerPID: pid, Command: req.Command, Cwd: req.Cwd, Reason: req.Reason}
	if err != nil {
		ev.Event, ev.Error = "error", err.Error()
		_ = s.d.Audit.Write(ev)
		return protocol.Response{}, err
	}
	defer provider.Wipe(values)

	ev.Event = "used"
	if err := s.d.Audit.Write(ev); err != nil {
		return protocol.Response{}, fmt.Errorf("audit log: %w", err)
	}
	env := make(map[string]string, len(refs)+1)
	for name, r := range refs {
		env[name] = string(values[r].Bytes())
	}
	if sshSock != "" {
		env["SSH_AUTH_SOCK"] = sshSock
	}
	if notify && s.d.Notify != nil {
		s.d.Notify(fmt.Sprintf("%s → %s", profile, shorten(strings.Join(req.Command, " "), 80)))
	}
	return protocol.Response{Env: env, Message: message}, nil
}

// oneOff approves refs outside any profile. They are never granted for reuse.
func (s *Server) oneOff(pid int, req protocol.Request) (map[string]provider.Ref, error) {
	refs := make(map[string]provider.Ref, len(req.Secrets))
	for env, raw := range req.Secrets {
		if err := config.ValidateEnvName(env); err != nil {
			return nil, err
		}
		ref, err := s.d.Registry.Parse(raw, req.Account)
		if err != nil {
			return nil, err
		}
		refs[env] = ref
	}
	var b strings.Builder
	parts := make([]string, 0, len(refs))
	rows := make([]approve.Row, 0, len(refs)+3)
	for _, env := range sortedKeys(refs) {
		parts = append(parts, fmt.Sprintf("%s as %s", refs[env], env))
		rows = append(rows, approve.Row{Label: env, Value: refs[env].String(), Mono: true})
	}
	fmt.Fprintf(&b, "read %s once", strings.Join(parts, ", "))
	writeContext(&b, req)
	p := approve.Prompt{
		Title:    fmt.Sprintf("Read %d secret(s) once", len(refs)),
		Subtitle: "Not part of a profile, so this covers this run only.",
		Rows:     append(rows, contextRows(req)...),
		Quote:    shorten(req.Reason, 300),
		Text:     b.String(),
	}

	ev := audit.Event{Refs: refStrings(refs), Env: sortedKeys(refs), PeerPID: pid,
		Command: req.Command, Cwd: req.Cwd, Reason: req.Reason}
	s.approvalMu.Lock()
	_, err := s.d.Approve(p)
	s.approvalMu.Unlock()
	if err != nil {
		ev.Event, ev.Error = "denied", err.Error()
		_ = s.d.Audit.Write(ev)
		return nil, err
	}
	ev.Event = "approved"
	if err := s.d.Audit.Write(ev); err != nil {
		return nil, fmt.Errorf("audit log: %w", err)
	}
	return refs, nil
}

func writeContext(b *strings.Builder, req protocol.Request) {
	if len(req.Command) > 0 {
		fmt.Fprintf(b, "\n\n$ %s", shorten(strings.Join(req.Command, " "), 160))
	}
	if req.Cwd != "" {
		fmt.Fprintf(b, "\nin %s", tildify(req.Cwd))
	}
	if req.Reason != "" {
		fmt.Fprintf(b, "\nreason: %s", shorten(req.Reason, 160))
	}
}

func contextRows(req protocol.Request) []approve.Row {
	var rows []approve.Row
	if len(req.Command) > 0 {
		rows = append(rows, approve.Row{Label: "Command", Value: "$ " + shorten(strings.Join(req.Command, " "), 300), Mono: true})
	}
	if req.Cwd != "" {
		rows = append(rows, approve.Row{Label: "Directory", Value: tildify(req.Cwd), Mono: true})
	}
	return rows
}

func (pr profileReq) rows() []approve.Row {
	var rows []approve.Row
	if len(pr.refs) > 0 {
		rows = append(rows, approve.Row{Label: "Variables", Value: strings.Join(sortedKeys(pr.refs), "\n"), Mono: true})
	}
	switch n := len(pr.sshKeys); {
	case n == 1:
		rows = append(rows, approve.Row{Label: "SSH", Value: "1 key, for ssh and git"})
	case n > 1:
		rows = append(rows, approve.Row{Label: "SSH", Value: fmt.Sprintf("%d keys, for ssh and git", n)})
	}
	return rows
}

func (pr profileReq) describe() string {
	parts := sortedKeys(pr.refs)
	switch n := len(pr.sshKeys); {
	case n == 1:
		parts = append(parts, "1 SSH key")
	case n > 1:
		parts = append(parts, fmt.Sprintf("%d SSH keys", n))
	}
	return strings.Join(parts, ", ")
}

func refList(refs []provider.Ref) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.String())
	}
	return out
}

func sortedKeys(refs map[string]provider.Ref) []string {
	keys := make([]string, 0, len(refs))
	for k := range refs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func refStrings(refs map[string]provider.Ref) []string {
	out := make([]string, 0, len(refs))
	for _, k := range sortedKeys(refs) {
		out = append(out, refs[k].String())
	}
	return out
}

func formatTTL(d time.Duration) string { return approve.FormatDuration(d) }

func shorten(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func tildify(p string) string {
	if h, err := os.UserHomeDir(); err == nil && strings.HasPrefix(p, h) {
		return "~" + strings.TrimPrefix(p, h)
	}
	return p
}
