package audit

import (
	"strings"
	"testing"
)

func TestLinesKeepsPartialLine(t *testing.T) {
	var got []string
	fn := func(e Event) { got = append(got, e.Event) }
	partial, err := Lines(strings.NewReader("{\"event\":\"approved\"}\nnot json\n{\"event\":\"us"), nil, fn)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Lines(strings.NewReader("ed\"}\n"), partial, fn); err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "approved,used" {
		t.Fatalf("events = %v", got)
	}
}
