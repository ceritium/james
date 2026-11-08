package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/ceritium/james/internal/audit"
	"github.com/ceritium/james/internal/paths"
)

type logFilter struct {
	profile string
	event   string
	since   time.Time
}

func (f logFilter) match(e audit.Event) bool {
	return (f.profile == "" || e.Profile == f.profile) &&
		(f.event == "" || e.Event == f.event) &&
		!e.Time.Before(f.since)
}

func logCmd(args []string) error {
	fs := flag.NewFlagSet("log", flag.ExitOnError)
	n := fs.Int("n", 20, "show the last N events (0 = all)")
	var f logFilter
	fs.StringVar(&f.profile, "p", "", "only this profile")
	fs.StringVar(&f.profile, "profile", "", "only this profile")
	fs.StringVar(&f.event, "event", "", "only this event (approved, denied, used, ssh-sign, revoked, error)")
	since := fs.Duration("since", 0, "only events newer than this, e.g. 2h")
	follow := fs.Bool("f", false, "keep printing new events")
	asJSON := fs.Bool("json", false, "print raw JSON lines")
	_ = fs.Parse(args)
	if fs.NArg() != 0 || *n < 0 {
		return errors.New("usage: james log [-n N] [-p PROFILE] [--event E] [--since DUR] [-f] [--json]")
	}
	if *since > 0 {
		f.since = time.Now().Add(-*since)
	}

	file, err := os.Open(audit.Path(paths.LogDir()))
	if errors.Is(err, os.ErrNotExist) {
		if !*follow {
			fmt.Println("no events yet")
			return nil
		}
		for errors.Is(err, os.ErrNotExist) {
			time.Sleep(time.Second)
			file, err = os.Open(audit.Path(paths.LogDir()))
		}
	}
	if err != nil {
		return err
	}
	defer file.Close()

	print := func(e audit.Event) { printEvent(os.Stdout, e, *asJSON) }
	var tail []audit.Event
	partial, err := audit.Lines(file, nil, func(e audit.Event) {
		if !f.match(e) {
			return
		}
		tail = append(tail, e)
		if *n > 0 && len(tail) > *n {
			tail = tail[1:]
		}
	})
	if err != nil {
		return err
	}
	if !*asJSON && len(tail) > 0 {
		fmt.Println(logHeader)
	}
	for _, e := range tail {
		print(e)
	}
	if !*follow {
		if len(tail) == 0 {
			fmt.Println("no matching events")
		}
		return nil
	}
	if !*asJSON && len(tail) == 0 {
		fmt.Println(logHeader)
	}
	for {
		time.Sleep(500 * time.Millisecond)
		if partial, err = audit.Lines(file, partial, func(e audit.Event) {
			if f.match(e) {
				print(e)
			}
		}); err != nil {
			return err
		}
	}
}

var logHeader = fmt.Sprintf("%-15s  %-8s  %-12s  %-20s  %-30s  %s", "TIME", "EVENT", "PROFILE", "AGENT", "COMMAND", "DETAIL")

func printEvent(w io.Writer, e audit.Event, asJSON bool) {
	if asJSON {
		b, _ := json.Marshal(e)
		fmt.Fprintln(w, string(b))
		return
	}
	agent := e.Anchor
	if agent == "" {
		agent = "-"
	}
	profile := e.Profile
	if profile == "" {
		profile = "(one-off)"
		if e.Event == "revoked" {
			profile = "(all)"
		}
	}
	fmt.Fprintf(w, "%-15s  %-8s  %-12s  %-20s  %-30s  %s\n",
		e.Time.Local().Format("Jan 02 15:04:05"), e.Event, clip(profile, 12), clip(agent, 20),
		clip(strings.Join(e.Command, " "), 30), detail(e))
}

func detail(e audit.Event) string {
	var parts []string
	if e.Error != "" {
		parts = append(parts, "error: "+e.Error)
	}
	if len(e.Env) > 0 {
		parts = append(parts, strings.Join(e.Env, ","))
	}
	if e.Event == "ssh-sign" && len(e.Refs) > 0 {
		parts = append(parts, "key "+strings.Join(e.Refs, ","))
	}
	if e.Reason != "" {
		parts = append(parts, fmt.Sprintf("reason: %q", e.Reason))
	}
	return strings.Join(parts, "  ")
}

func clip(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
