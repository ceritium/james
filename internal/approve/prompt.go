package approve

import (
	"strings"
	"time"
)

// Prompt describes one approval request.
type Prompt struct {
	Title    string `json:"title"`
	Subtitle string `json:"subtitle"`
	// Quote is the agent's own reason, shown apart from the facts in Rows.
	Quote string `json:"quote,omitempty"`
	Rows  []Row  `json:"rows"`
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
