package approve

import (
	"encoding/json"
	"strings"
	"time"
)

// Prompt describes one approval request.
type Prompt struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	// Quote is the agent's own reason, shown apart from the facts in Rows.
	Quote string `json:"quote,omitempty"`
	Rows  []Row  `json:"rows,omitempty"`
	// TTLs are the durations the user can pick; empty means a single use.
	TTLs []time.Duration `json:"-"`
	TTL  time.Duration   `json:"-"`
	// Text is the plain-text version for the system Touch ID sheet.
	Text string `json:"-"`
}

type Row struct {
	Label string `json:"label"`
	Value string `json:"value"`
	Mono  bool   `json:"mono,omitempty"`
}

// FormatDuration prints 1h instead of 1h0m0s.
func FormatDuration(d time.Duration) string {
	s := strings.TrimSuffix(d.String(), "0s")
	return strings.TrimSuffix(s, "0m")
}

// dialogJSON is what the AppKit dialog reads.
func dialogJSON(p Prompt) ([]byte, error) {
	ui := struct {
		Prompt
		// omitempty: a JSON null becomes NSNull, which throws on -count.
		TTLs     []string `json:"ttls,omitempty"`
		TTLIndex int      `json:"ttl_index"`
	}{Prompt: p}
	for i, d := range p.TTLs {
		ui.TTLs = append(ui.TTLs, FormatDuration(d))
		if d == p.TTL {
			ui.TTLIndex = i
		}
	}
	return json.Marshal(ui)
}
