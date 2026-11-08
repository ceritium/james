// james lends secrets to coding agents for a limited time, approved with Touch ID.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/ceritium/james/internal/client"
	"github.com/ceritium/james/internal/config"
	"github.com/ceritium/james/internal/daemon"
	"github.com/ceritium/james/internal/paths"
	"github.com/ceritium/james/internal/protocol"
	"github.com/ceritium/james/internal/provider"
	"github.com/ceritium/james/internal/provider/onepassword"
)

var version = "dev"

// AppKit, used by the daemon's approval window, must run on the main thread.
func init() { runtime.LockOSThread() }

const usage = `james lends secrets to coding agents, approved with Touch ID.

Usage:
  james bond PROFILE [--reason TEXT]       approve a profile for this agent session
  james run -p PROFILE [--reason TEXT] -- COMMAND [ARG...]
  james run --secret VAR=REF [--secret ...] [--account A] -- COMMAND [ARG...]
  james list                               active grants
  james revoke PROFILE | --all
  james log [-n N] [-p PROFILE] [--event E] [--since DUR] [-f] [--json]
                                           audit log of approvals and uses
  james profiles                           profiles in ` + "~/.config/james/config.yaml" + `
  james skill-install [--dir DIR]          install the agent skill (default ~/.claude/skills)
  james daemon                             run the daemon in the foreground
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch cmd, args := os.Args[1], os.Args[2:]; cmd {
	case "bond":
		err = bond(args)
	case "run":
		err = run(args)
	case "list":
		err = list()
	case "revoke":
		err = revoke(args)
	case "log":
		err = logCmd(args)
	case "profiles":
		err = profiles()
	case "daemon":
		err = daemon.Run(version)
	case "skill-install":
		err = skillInstall(args)
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", cmd, usage)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "james:", err)
		os.Exit(1)
	}
}

func bond(args []string) error {
	fs := flag.NewFlagSet("bond", flag.ExitOnError)
	reason := fs.String("reason", "", "why the agent needs it; shown in the prompt")
	_ = fs.Parse(reorder(args))
	if fs.NArg() != 1 {
		return errors.New("usage: james bond PROFILE")
	}
	cwd, _ := os.Getwd()
	resp, err := client.Do(protocol.Request{Op: protocol.OpBond, Profile: fs.Arg(0), Reason: *reason, Cwd: cwd})
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	return nil
}

type secretFlags map[string]string

func (s secretFlags) String() string { return "" }

func (s secretFlags) Set(v string) error {
	name, ref, ok := strings.Cut(v, "=")
	if !ok || name == "" || ref == "" {
		return errors.New("expected VAR=REF")
	}
	s[name] = ref
	return nil
}

func run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	profile := fs.String("p", "", "profile")
	fs.StringVar(profile, "profile", "", "profile")
	secrets := secretFlags{}
	fs.Var(secrets, "secret", "one-off VAR=REF, approved for this run only (repeatable)")
	account := fs.String("account", "", "provider account for one-off refs")
	reason := fs.String("reason", "", "why the agent needs it; shown in the prompt")
	_ = fs.Parse(args)
	command := fs.Args()
	if len(command) == 0 {
		return errors.New("usage: james run -p PROFILE -- COMMAND [ARG...]")
	}
	path, err := exec.LookPath(command[0])
	if err != nil {
		return err
	}
	cwd, _ := os.Getwd()
	resp, err := client.Do(protocol.Request{
		Op: protocol.OpRun, Profile: *profile, Secrets: secrets, Account: *account,
		Reason: *reason, Command: command, Cwd: cwd,
	})
	if err != nil {
		return err
	}
	if resp.Message != "" {
		fmt.Fprintln(os.Stderr, "james:", resp.Message)
	}
	env, removed := commandEnv(os.Environ(), resp.Env)
	if len(removed) > 0 {
		fmt.Fprintf(os.Stderr, "james: removed %s from the environment: they can make the command run other code\n", strings.Join(removed, ", "))
	}
	return syscall.Exec(path, command, env)
}

func list() error {
	resp, err := client.Do(protocol.Request{Op: protocol.OpList})
	if err != nil {
		return err
	}
	if len(resp.Grants) == 0 {
		fmt.Println("no active grants")
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tAGENT\tEXPIRES\tLEFT\tUSES")
	for _, g := range resp.Grants {
		fmt.Fprintf(w, "%s\t%s (pid %d)\t%s\t%s\t%d\n", g.Profile, g.Anchor, g.AnchorPID,
			g.Expires.Local().Format("15:04"), time.Until(g.Expires).Round(time.Minute), g.Uses)
	}
	return w.Flush()
}

func revoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	all := fs.Bool("all", false, "revoke every grant")
	_ = fs.Parse(reorder(args))
	if (*all) == (fs.NArg() == 1) {
		return errors.New("usage: james revoke PROFILE | --all")
	}
	resp, err := client.Do(protocol.Request{Op: protocol.OpRevoke, Profile: fs.Arg(0), All: *all})
	if err != nil {
		return err
	}
	fmt.Println(resp.Message)
	return nil
}

func profiles() error {
	reg, err := provider.NewRegistry(onepassword.New(onepassword.Options{}))
	if err != nil {
		return err
	}
	cfg, err := config.Load(paths.Config(), reg.Parse)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tTTL\tVARIABLES")
	for _, name := range cfg.ProfileNames() {
		p := cfg.Profiles[name]
		vars := make([]string, 0, len(p.Secrets))
		for v := range p.Secrets {
			vars = append(vars, v)
		}
		slices.Sort(vars)
		switch n := len(p.SSHKeys); {
		case n == 1:
			vars = append(vars, "1 SSH key")
		case n > 1:
			vars = append(vars, fmt.Sprintf("%d SSH keys", n))
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", name, p.EffectiveTTL(), strings.Join(vars, ", "))
	}
	return w.Flush()
}

// reorder lets flags follow positional args: `james bond restic --reason x`.
func reorder(args []string) []string {
	var flags, rest []string
	for i := 0; i < len(args); i++ {
		if strings.HasPrefix(args[i], "-") {
			flags = append(flags, args[i])
			if !strings.Contains(args[i], "=") && args[i] != "--all" && i+1 < len(args) {
				flags = append(flags, args[i+1])
				i++
			}
			continue
		}
		rest = append(rest, args[i])
	}
	return append(flags, rest...)
}
