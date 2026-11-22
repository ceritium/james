package approve

import (
	"strings"
	"testing"
	"time"
)

func TestDialogJSONHasNoNulls(t *testing.T) {
	for name, p := range map[string]Prompt{
		"single use": {Title: "Run make"},
		"with ttls":  {Title: "Bond", TTLs: []time.Duration{time.Hour, 8 * time.Hour}, TTL: 8 * time.Hour},
	} {
		js, err := dialogJSON(p)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(js), "null") {
			t.Errorf("%s: %s", name, js)
		}
	}
}

func TestDialogJSONSelectsTheDefaultTTL(t *testing.T) {
	js, _ := dialogJSON(Prompt{TTLs: []time.Duration{time.Hour, 8 * time.Hour}, TTL: 8 * time.Hour})
	if !strings.Contains(string(js), `"ttls":["1h","8h"],"ttl_index":1`) {
		t.Error(string(js))
	}
}
