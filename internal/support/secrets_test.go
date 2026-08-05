package support

import (
	"errors"
	"strings"
	"testing"
)

// A real AmneziaWG key. Public and private keys are both 44-char base64 ending
// in "=" and are INDISTINGUISHABLE BY SHAPE, which is why the gate's primary
// check is exact comparison against values the node actually holds rather than
// a regex over shape.
const (
	privKey = "aFakeButWellFormedPrivateKeyForTests1234567="
	pubKey  = "aFakeButWellFormedPublicKeyForTests98765432="
)

// The test this feature exists for: a private key that reached the bundle by ANY
// route must stop the archive being written.
func TestGateRefusesABundleContainingARealSecret(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"state.txt": "line one\nPrivateKey = " + privKey + "\nline three\n"},
	}}
	err := Gate(nodes, []string{privKey})
	if err == nil {
		t.Fatal("gate passed a bundle containing a real private key")
	}
	var le *LeakError
	if !asLeakError(err, &le) {
		t.Fatalf("error is %T, want *LeakError", err)
	}
	if le.File != "exit-de-1/state.txt" {
		t.Errorf("File = %q, want the file the secret landed in", le.File)
	}
	if le.Line != 2 {
		t.Errorf("Line = %d, want 2", le.Line)
	}
	if strings.Contains(err.Error(), privKey) {
		t.Error("the gate printed the secret it was refusing to leak")
	}
}

// The false-positive guard. Public keys are all over a legitimate bundle — awg
// show prints one per peer. A gate that fires on them gets disabled by the first
// person who hits it, and then protects nothing.
func TestGateAllowsPublicKeys(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"network.txt": "peer: " + pubKey + "\n  allowed ips: 10.0.0.2/32\n"},
	}}
	if err := Gate(nodes, []string{privKey}); err != nil {
		t.Errorf("gate rejected a bundle of public keys: %v", err)
	}
}

// Second, coarser layer: an unknown secret-bearing line in uncontrolled text
// (container logs, third-party units) that the exact check cannot know about.
func TestGateCatchesSecretBearingKeysByName(t *testing.T) {
	nodes := []Node{{
		Name:  "master-1",
		Files: map[string]string{"containers.txt": "loaded config\nsecret: hunter2hunter2hunter2\n"},
	}}
	if err := Gate(nodes, nil); err == nil {
		t.Error("gate passed a line whose key names it as a secret")
	}
}

func TestGateAcceptsAlreadyRedactedValues(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"state.txt": "PrivateKey = <redacted>\nsecret: <redacted>\n"},
	}}
	if err := Gate(nodes, nil); err != nil {
		t.Errorf("gate rejected properly redacted output: %v", err)
	}
}

func TestScrubMasksSecretBearingValues(t *testing.T) {
	in := "private-key: " + privKey + "\nlisten-port: 51820\ntoken=abc123\n"
	got := Scrub(in)
	if strings.Contains(got, privKey) {
		t.Error("scrub left a private key in place")
	}
	if !strings.Contains(got, "listen-port: 51820") {
		t.Error("scrub mangled a non-secret line")
	}
	if strings.Contains(got, "abc123") {
		t.Error("scrub left a token in place")
	}
}

// An empty secret must never be searched for: strings.Contains(x, "") is always
// true, so one empty entry would fail every bundle and make the gate useless.
func TestGateIgnoresEmptySecrets(t *testing.T) {
	nodes := []Node{{Name: "n", Files: map[string]string{"a.txt": "nothing sensitive\n"}}}
	if err := Gate(nodes, []string{"", "   "}); err != nil {
		t.Errorf("gate tripped on an empty secret: %v", err)
	}
}

func asLeakError(err error, target **LeakError) bool { return errors.As(err, target) }

// A genuine multi-line PEM, shaped exactly like what pem.EncodeToMemory
// produces (64-column-wrapped body, BEGIN/END banners) and exactly what the
// controller feeds Gate for the fleet CA key and every exit's SSH bootstrap
// key. Every other secret constant in this file is single-line, which is
// precisely why the multi-line gap survived six task-scoped reviews: nothing
// here ever exercised gateContent's old line-by-line strings.Contains, which
// can never match a needle containing its own "\n".
const multiLinePEM = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIKzWJ8v3fAkeGmWJHqxfvNMTvVvyN2R2Vv1QhqfXvTjmoAoGCCqGSM49
AwEHoUQDQgAEfakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFake
Fakefakefakefakefakefakefakefakefakefakefakefakefake==
-----END EC PRIVATE KEY-----`

// The regression this branch's review found: a multi-line secret is invisible
// to the primary (exact-match) check because gateContent used to split
// content on "\n" and test strings.Contains(line, secret) per line — a
// multi-line needle can never be a substring of one line. Reproduced first
// against the pre-fix gateContent (confirmed it let this straight through),
// then fixed by searching the whole content instead of one line at a time.
func TestGateRefusesAMultiLinePEMSecret(t *testing.T) {
	nodes := []Node{{
		Name: "controller",
		Files: map[string]string{
			"secrets.txt": "before\n" + multiLinePEM + "\nafter\n",
		},
	}}
	err := Gate(nodes, []string{multiLinePEM})
	if err == nil {
		t.Fatal("gate passed a bundle containing a real multi-line PEM private key")
	}
	var le *LeakError
	if !asLeakError(err, &le) {
		t.Fatalf("error is %T, want *LeakError", err)
	}
	if le.Line != 2 {
		t.Errorf("Line = %d, want 2 (the PEM's first line, after the leading \"before\" line)", le.Line)
	}
	if strings.Contains(err.Error(), multiLinePEM) || strings.Contains(err.Error(), "BEGIN EC PRIVATE KEY") {
		t.Error("the gate printed the secret it was refusing to leak")
	}
}

// Scrub is the second layer for uncontrolled text. It must not be relied on to
// catch what Gate's exact-match check is the real backstop for: the key-name
// regex requires a `key: value`/`key=value` shape, and a PEM's BEGIN/END
// banners and base64 body lines have neither — confirming Scrub leaves this
// untouched is what makes the exact-match fix in gateContent load-bearing
// rather than redundant.
func TestScrubLeavesAPEMBodyUntouched(t *testing.T) {
	got := Scrub(multiLinePEM)
	if got != multiLinePEM {
		t.Errorf("Scrub altered a PEM it has no business touching:\ngot:  %q\nwant: %q", got, multiLinePEM)
	}
}

// The single-line exact-match path must not regress while fixing the
// multi-line one: gateContent's new whole-content strings.Index still has to
// report the correct line for an ordinary one-line secret, and the earliest
// of several matching secrets when more than one is present.
func TestGateStillReportsTheCorrectLineForASingleLineSecret(t *testing.T) {
	other := "anotherFakeButWellFormedSecretValueXYZ9="
	nodes := []Node{{
		Name: "exit-de-1",
		Files: map[string]string{
			"state.txt": "line one\n" + other + "\nPrivateKey = " + privKey + "\nline four\n",
		},
	}}
	// Both `other` and `privKey` are real secrets this node holds; `other`
	// occurs first in the content, so it must be the one reported.
	err := Gate(nodes, []string{privKey, other})
	if err == nil {
		t.Fatal("gate passed a bundle containing a real secret")
	}
	var le *LeakError
	if !asLeakError(err, &le) {
		t.Fatalf("error is %T, want *LeakError", err)
	}
	if le.Line != 2 {
		t.Errorf("Line = %d, want 2 (the earliest match, not just the first secret in the list)", le.Line)
	}
}

// Regression for a value capture that stopped at the first whitespace: an
// "Authorization: Bearer <jwt>" header has the secret in its SECOND word, and
// a `\S+` value group would mask only "Bearer", leaving the token in the
// clear while Gate — re-checking its own first token, now "<redacted>" —
// waved the whole line through.
func TestScrubMasksMultiWordSecretValues(t *testing.T) {
	in := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.superSecretPayloadDoNotLeak.sig\n"
	got := Scrub(in)
	if strings.Contains(got, "superSecretPayloadDoNotLeak") {
		t.Errorf("scrub left part of a multi-word secret value in place: %q", got)
	}
	if !strings.Contains(got, "Authorization: <redacted>") {
		t.Errorf("scrub did not mask the full multi-word value, got %q", got)
	}
}

func TestGateCatchesMultiWordSecretValues(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"headers.txt": "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.superSecretPayloadDoNotLeak.sig\n"},
	}}
	if err := Gate(nodes, nil); err == nil {
		t.Error("gate passed a multi-word secret value that was not fully masked")
	}
}

// A bundle that has been through Scrub first must pass Gate: the two share
// one regex specifically so Gate cannot fire on a line Scrub already handled.
func TestGateAcceptsAMultiWordValueAfterScrub(t *testing.T) {
	in := "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.superSecretPayloadDoNotLeak.sig\n"
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"headers.txt": Scrub(in)},
	}}
	if err := Gate(nodes, nil); err != nil {
		t.Errorf("gate rejected a line Scrub had already fully redacted: %v", err)
	}
}

// Task 1's renderManifest writes ManifestEntry.Cmd and .Err into MANIFEST.txt,
// and a failing collector's error text can carry command output — so Gate
// must check entries too, not just Files, or a secret can ship ungated.
func TestGateCatchesARealSecretInAManifestEntryCmd(t *testing.T) {
	nodes := []Node{{
		Name:  "exit-de-1",
		Files: map[string]string{"state.txt": "nothing sensitive\n"},
		Entries: []ManifestEntry{
			{File: "state.txt", Name: "dump-keys", Cmd: "wg show wg0 private-key " + privKey},
		},
	}}
	err := Gate(nodes, []string{privKey})
	if err == nil {
		t.Fatal("gate passed a manifest entry command containing a real private key")
	}
	var le *LeakError
	if !asLeakError(err, &le) {
		t.Fatalf("error is %T, want *LeakError", err)
	}
	if le.File != "exit-de-1/MANIFEST.txt" {
		t.Errorf("File = %q, want the manifest path", le.File)
	}
	if strings.Contains(err.Error(), privKey) {
		t.Error("the gate printed the secret it was refusing to leak")
	}
}

func TestGateCatchesASecretBearingKeyInAManifestEntryErr(t *testing.T) {
	nodes := []Node{{
		Name:  "master-1",
		Files: map[string]string{"state.txt": "nothing sensitive\n"},
		Entries: []ManifestEntry{
			{File: "containers.txt", Name: "docker-logs", Err: "failed: secret: hunter2hunter2hunter2"},
		},
	}}
	err := Gate(nodes, nil)
	if err == nil {
		t.Fatal("gate passed a manifest entry error naming a secret-bearing key")
	}
	var le *LeakError
	if !asLeakError(err, &le) {
		t.Fatalf("error is %T, want *LeakError", err)
	}
	if le.File != "master-1/MANIFEST.txt" {
		t.Errorf("File = %q, want the manifest path", le.File)
	}
}

// Round 2 regression: a JSON-quoted key evaded the coarse check entirely.
// `\bsecret\b\s*[:=]` never matches `"secret":` because a closing quote sits
// between the key and the colon — and a JSON-configured collector's log line
// (xray, for one — see Task 3's containers.txt) is exactly the uncontrolled
// text this layer exists for.
func TestScrubMasksJSONQuotedSecretValues(t *testing.T) {
	const leak = "superSecretPayloadDoNotLeak"
	cases := []struct {
		name string
		line string
	}{
		{"double-quoted key and value", `{"secret": "` + leak + `"}`},
		{"space before colon", `{"password" : "` + leak + `"}`},
		{"bare key, quoted value", `password: "` + leak + `"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Scrub(tc.line)
			if strings.Contains(got, leak) {
				t.Errorf("scrub left the secret in place: %q -> %q", tc.line, got)
			}

			nodes := []Node{{Name: "n", Files: map[string]string{"a.txt": tc.line + "\n"}}}
			if err := Gate(nodes, nil); err == nil {
				t.Errorf("gate passed an unmasked JSON-shaped secret: %q", tc.line)
			}
		})
	}
}

// Regression guard over value SHAPE, not position: both round 1 (multi-word)
// and round 2 (JSON-quoted) defects came from a value shape the original
// `\S+` capture — and then the interim `.+` capture — did not anticipate.
// Every case here must have its secret masked by Scrub AND survive a
// Scrub-then-Gate round trip, so the two stay provably consistent as new
// shapes are added later.
func TestScrubAndGateAgreeAcrossValueShapes(t *testing.T) {
	const leak = "superSecretPayloadDoNotLeak"
	cases := []struct {
		name string
		line string
	}{
		{"bare token", "token=" + leak},
		{"key: value", "secret: " + leak},
		{"bearer", "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9." + leak + ".sig"},
		{"basic auth", "Authorization: Basic " + leak},
		{"multi-word password", "password: correct horse battery staple " + leak},
		{"trailing prose", "token=" + leak + " and then started"},
		{"json double-quoted", `{"secret": "` + leak + `"}`},
		{"json space before colon", `{"password" : "` + leak + `"}`},
		{"bare key, quoted value", `password: "` + leak + `"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.line + "\n"

			rawNodes := []Node{{Name: "n", Files: map[string]string{"a.txt": raw}}}
			if err := Gate(rawNodes, nil); err == nil {
				t.Fatalf("gate passed an unmasked value: %q", tc.line)
			}

			scrubbed := Scrub(raw)
			if strings.Contains(scrubbed, leak) {
				t.Fatalf("scrub left the secret in place: %q -> %q", tc.line, scrubbed)
			}

			scrubbedNodes := []Node{{Name: "n", Files: map[string]string{"a.txt": scrubbed}}}
			if err := Gate(scrubbedNodes, nil); err != nil {
				t.Errorf("gate rejected Scrub's own output for %q: %v", tc.line, err)
			}
		})
	}
}
