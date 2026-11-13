package mihomo

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestParseProxyHealth(t *testing.T) {
	js := []byte(`{"proxies":{
	  "exit-de-1":{"alive":true,"history":[{"time":"2026-06-26T10:00:00Z","delay":42}]},
	  "exit-nl-1":{"alive":false,"history":[{"time":"2026-06-26T10:00:01Z","delay":0}]},
	  "wg-best":{"now":"exit-de-1","all":["exit-de-1","exit-nl-1"]}
	}}`)

	got, err := ParseProxyHealth(js, "wg-best", []string{"exit-de-1", "exit-nl-1", "exit-gone"})
	if err != nil {
		t.Fatalf("ParseProxyHealth: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 entries, got %d", len(got))
	}
	de := got[0]
	if de.Name != "exit-de-1" || !de.Alive || de.Delay != 42*time.Millisecond || !de.Selected {
		t.Fatalf("exit-de-1 mismatch: %+v", de)
	}
	if de.LastTest.IsZero() {
		t.Fatalf("exit-de-1 LastTest should be set")
	}
	if nl := got[1]; nl.Alive || nl.Selected {
		t.Fatalf("exit-nl-1 should be down and not selected: %+v", nl)
	}
	if gone := got[2]; gone.Alive || !gone.LastTest.IsZero() {
		t.Fatalf("absent proxy must be down with no test time: %+v", gone)
	}
}

const nestedProxiesJSON = `{"proxies":{
  "wg-best":    {"alive":true,"type":"Fallback","now":"wg-primary","all":["wg-primary","wg-reserve"]},
  "wg-primary": {"alive":true,"type":"LoadBalance","now":"","all":["vn1","vn2"]},
  "wg-reserve": {"alive":true,"type":"LoadBalance","now":"","all":["anz3"]},
  "vn1":  {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":100}]},
  "vn2":  {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":98}]},
  "anz3": {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":201}]}
}}`

func TestParseProxyHealthMarksWholeActiveTier(t *testing.T) {
	got, err := ParseProxyHealth([]byte(nestedProxiesJSON), "wg-best", []string{"vn1", "vn2", "anz3"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vn1": true, "vn2": true, "anz3": false}
	for _, h := range got {
		if h.Selected != want[h.Name] {
			t.Errorf("%s: Selected = %v, want %v", h.Name, h.Selected, want[h.Name])
		}
	}
}

// A dead member of the active tier must not be reported as carrying traffic:
// consistent-hashing has already rehashed its destinations onto its live
// siblings, even though mihomo still lists it in `all`.
func TestParseProxyHealthSkipsDeadTierMember(t *testing.T) {
	const withDeadMember = `{"proxies":{
      "wg-best":    {"alive":true,"type":"Fallback","now":"wg-primary","all":["wg-primary","wg-reserve"]},
      "wg-primary": {"alive":true,"type":"LoadBalance","now":"","all":["vn1","vn2"]},
      "wg-reserve": {"alive":true,"type":"LoadBalance","now":"","all":["anz3"]},
      "vn1":  {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":100}]},
      "vn2":  {"alive":false,"history":[{"time":"2026-07-19T14:00:00Z","delay":0}]},
      "anz3": {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":201}]}
    }}`
	got, err := ParseProxyHealth([]byte(withDeadMember), "wg-best", []string{"vn1", "vn2", "anz3"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vn1": true, "vn2": false, "anz3": false}
	for _, h := range got {
		if h.Selected != want[h.Name] {
			t.Errorf("%s: Selected = %v, want %v", h.Name, h.Selected, want[h.Name])
		}
	}
}

// The pre-ADR-0029 flat shape must keep working: one selected exit, no tiers.
func TestParseProxyHealthFlatGroupUnchanged(t *testing.T) {
	const flat = `{"proxies":{
      "wg-best": {"alive":true,"type":"URLTest","now":"vn2","all":["vn1","vn2"]},
      "vn1": {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":100}]},
      "vn2": {"alive":true,"history":[{"time":"2026-07-19T14:00:00Z","delay":98}]}
    }}`
	got, err := ParseProxyHealth([]byte(flat), "wg-best", []string{"vn1", "vn2"})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range got {
		if want := h.Name == "vn2"; h.Selected != want {
			t.Errorf("%s: Selected = %v, want %v", h.Name, h.Selected, want)
		}
	}
}

// collectCarrying's depth bound (maxGroupDepth) must survive both a genuine
// cycle and a long-but-acyclic chain, and in both cases it must actually stop
// descending — not merely avoid erroring. A prior version of this test only
// asserted "no error", which passes even if maxGroupDepth were deleted
// entirely (a self-referential cycle would still be caught by the `seen` dedup
// map alone). Asserting the returned Selected set catches that: the chain case
// has no cycle at all, so only the depth bound can stop it.
func TestParseProxyHealthDepthBound(t *testing.T) {
	tests := []struct {
		name    string
		json    string
		exits   []string
		want    map[string]bool
		explain string
	}{
		{
			name: "self-referential cycle",
			json: `{"proxies":{
				"wg-best": {"alive":true,"now":"loop","all":["loop"]},
				"loop":    {"alive":true,"now":"wg-best","all":["wg-best"]},
				"vn1":     {"alive":true,"history":[]}
			}}`,
			exits:   []string{"vn1"},
			want:    map[string]bool{"vn1": false},
			explain: "a group cycle must terminate via the seen-set with nothing marked carrying",
		},
		{
			// A strictly linear (non-cyclic) chain of groups longer than
			// maxGroupDepth. Every node is visited exactly once, so only the
			// depth bound — not the `seen` dedup map — can stop the walk
			// before it reaches the leaf exit at the end of the chain.
			name:    "long non-cyclic chain exceeds depth bound",
			json:    longChainJSON(maxGroupDepth + 4),
			exits:   []string{"leaf-exit"},
			want:    map[string]bool{"leaf-exit": false},
			explain: "a chain deeper than maxGroupDepth must be cut off before reaching the leaf",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseProxyHealth([]byte(tt.json), "wg-best", tt.exits)
			if err != nil {
				t.Fatalf("%s: unexpected error: %v", tt.explain, err)
			}
			for _, h := range got {
				if h.Selected != tt.want[h.Name] {
					t.Errorf("%s: %s Selected = %v, want %v", tt.explain, h.Name, h.Selected, tt.want[h.Name])
				}
			}
		})
	}
}

// longChainJSON builds a Clash /proxies payload that is a strictly linear
// chain of n single-`now` groups — "wg-best" -> "hop0" -> "hop1" -> ... ->
// "leaf-exit" — with no repeated name anywhere, so the `seen` dedup map never
// fires and only maxGroupDepth can bound the walk.
func longChainJSON(n int) string {
	var b strings.Builder
	b.WriteString(`{"proxies":{`)
	prev := "wg-best"
	for i := 0; i < n; i++ {
		next := fmt.Sprintf("hop%d", i)
		fmt.Fprintf(&b, `"%s":{"alive":true,"now":"%s","all":["%s"]},`, prev, next, next)
		prev = next
	}
	fmt.Fprintf(&b, `"%s":{"alive":true,"now":"leaf-exit","all":["leaf-exit"]},`, prev)
	b.WriteString(`"leaf-exit":{"alive":true,"history":[]}`)
	b.WriteString(`}}`)
	return b.String()
}

func TestParseProxyHealthGarbage(t *testing.T) {
	if _, err := ParseProxyHealth([]byte("not json"), "wg-best", []string{"x"}); err == nil {
		t.Fatal("expected error on unparseable JSON")
	}
}

func TestFetchProxies(t *testing.T) {
	const body = `{"proxies":{"wg-best":{"now":"exit-de-1"}}}`
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/proxies" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	got, err := FetchProxies(context.Background(), addr, "s3cret")
	if err != nil {
		t.Fatalf("FetchProxies: %v", err)
	}
	if string(got) != body {
		t.Fatalf("body mismatch: %s", got)
	}
	if gotAuth != "Bearer s3cret" {
		t.Fatalf("auth header = %q", gotAuth)
	}
}

func TestFetchProxiesNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer srv.Close()
	if _, err := FetchProxies(context.Background(), strings.TrimPrefix(srv.URL, "http://"), ""); err == nil {
		t.Fatal("expected error on non-2xx")
	}
}

// A dead member of the active tier is still IN the rotation: one failed url-test
// stops its traffic until the next passes, it does not move it to another tier.
// InRotation is what lets the console keep it in place instead of filing it with
// the idle reserve.
func TestParseProxyHealthKeepsDeadTierMemberInRotation(t *testing.T) {
	const withDeadMember = `{"proxies":{
      "wg-best":    {"alive":true,"type":"Fallback","now":"wg-primary","all":["wg-primary","wg-reserve"]},
      "wg-primary": {"alive":true,"type":"LoadBalance","now":"","all":["vn1","vn2"]},
      "wg-reserve": {"alive":true,"type":"LoadBalance","now":"","all":["anz3"]},
      "vn1":  {"alive":true},
      "vn2":  {"alive":false},
      "anz3": {"alive":true}
    }}`
	got, err := ParseProxyHealth([]byte(withDeadMember), "wg-best", []string{"vn1", "vn2", "anz3"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"vn1": true, "vn2": true, "anz3": false}
	for _, h := range got {
		if h.InRotation != want[h.Name] {
			t.Errorf("%s: InRotation = %v, want %v", h.Name, h.InRotation, want[h.Name])
		}
	}
}
