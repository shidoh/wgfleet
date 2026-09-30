package wg

import "testing"

func TestParseShowEndpoints(t *testing.T) {
	out := "keyA=\t203.0.113.1:41234\nkeyB=\t(none)\n\n"
	got := ParseShowEndpoints(out)
	if len(got) != 1 || got["keyA="] != "203.0.113.1:41234" {
		t.Fatalf("ParseShowEndpoints = %v", got)
	}
}
