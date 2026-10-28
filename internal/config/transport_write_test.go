package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

const sampleManifest = `controller:
  listen: "10.20.25.254:8443"
fleet:
  masters:
    - name: master-xa-1
      mgmt_addr: 10.20.25.254
  exits:
    - name: exit-1
      region: sw
      # carries both transports
      transports: [awg, reality-xhttp]
      active_transport: reality-xhttp
      firewall:
        as_blacklist: true
    - name: exit-1cnode004-pl-1
      region: pl
      transports: [awg, reality-xhttp]
      firewall:
        as_blacklist: true
`

// writeManifest writes content to a temp file and returns its path.
func writeManifest(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp manifest: %v", err)
	}
	return p
}

func TestSetExitActiveTransport_ReplaceExisting(t *testing.T) {
	p := writeManifest(t, sampleManifest)

	if err := SetExitActiveTransport(p, "exit-1", domain.TransportAWG); err != nil {
		t.Fatalf("SetExitActiveTransport: %v", err)
	}

	got, _ := os.ReadFile(p)
	out := string(got)
	if !strings.Contains(out, "active_transport: awg") {
		t.Errorf("exit-1 active_transport not switched to awg:\n%s", out)
	}
	if strings.Contains(out, "active_transport: reality-xhttp") {
		t.Errorf("stale reality-xhttp value still present:\n%s", out)
	}
	// Comments and unrelated lines must survive verbatim.
	if !strings.Contains(out, "# carries both transports") {
		t.Errorf("comment was lost:\n%s", out)
	}
	if !strings.Contains(out, "transports: [awg, reality-xhttp]") {
		t.Errorf("transports line mangled:\n%s", out)
	}

	if got := exitActiveTransport(out, "exit-1"); got != "awg" {
		t.Errorf("exit-1 block active_transport = %q, want awg", got)
	}
}

// exitActiveTransport scans rendered manifest text for the active_transport value
// inside the named exit's block (the next active_transport key after `- name: X`).
func exitActiveTransport(manifest, exitName string) string {
	lines := strings.Split(manifest, "\n")
	in := false
	for _, l := range lines {
		s := strings.TrimSpace(l)
		if strings.HasPrefix(s, "- name:") {
			in = strings.Contains(s, exitName)
			continue
		}
		if in && strings.HasPrefix(s, "active_transport:") {
			return strings.TrimSpace(strings.TrimPrefix(s, "active_transport:"))
		}
	}
	return ""
}

func TestSetExitActiveTransport_InsertWhenAbsent(t *testing.T) {
	p := writeManifest(t, sampleManifest)

	// exit-1cnode004-pl-1 has no active_transport line.
	if err := SetExitActiveTransport(p, "exit-1cnode004-pl-1", domain.TransportRealityXHTTP); err != nil {
		t.Fatalf("SetExitActiveTransport: %v", err)
	}

	got, _ := os.ReadFile(p)
	out := string(got)
	// First exit untouched, second now has the inserted reality-xhttp.
	if v := exitActiveTransport(out, "exit-1"); v != "reality-xhttp" {
		t.Errorf("exit-1 active_transport changed unexpectedly: %q", v)
	}
	if v := exitActiveTransport(out, "exit-1cnode004-pl-1"); v != "reality-xhttp" {
		t.Errorf("exit-2 active_transport = %q, want reality-xhttp (inserted)", v)
	}
}

func TestSetExitActiveTransport_TightensManifestPerms(t *testing.T) {
	// A world-readable manifest (0644) must be rewritten owner-only: it holds WG/REALITY
	// private keys. Preserving the mode kept it 0644.
	p := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(p, []byte(sampleManifest), 0o644); err != nil {
		t.Fatalf("seed manifest: %v", err)
	}
	if err := SetExitActiveTransport(p, "exit-1", domain.TransportAWG); err != nil {
		t.Fatalf("SetExitActiveTransport: %v", err)
	}
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("manifest perms = %04o, want 0600 (secret-bearing, must not be group/other-readable)", perm)
	}
}

func TestSetExitActiveTransport_UnknownExit(t *testing.T) {
	p := writeManifest(t, sampleManifest)
	if err := SetExitActiveTransport(p, "exit-ghost", domain.TransportAWG); err == nil {
		t.Fatal("expected error for unknown exit, got nil")
	}
}

func TestSetExitActiveTransport_OnlyTargetBlockChanges(t *testing.T) {
	p := writeManifest(t, sampleManifest)
	if err := SetExitActiveTransport(p, "exit-1", domain.TransportAWG); err != nil {
		t.Fatalf("SetExitActiveTransport: %v", err)
	}
	got, _ := os.ReadFile(p)
	out := string(got)
	// The master block must be untouched and the other exit must gain no
	// active_transport line (it had none).
	if !strings.Contains(out, "- name: master-xa-1") {
		t.Errorf("master block mangled:\n%s", out)
	}
	if v := exitActiveTransport(out, "exit-1cnode004-pl-1"); v != "" {
		t.Errorf("exit-2 gained an active_transport line %q; should be untouched", v)
	}
}
