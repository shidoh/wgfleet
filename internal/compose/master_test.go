package compose

import (
	"strings"
	"testing"

	yaml "go.yaml.in/yaml/v3"

	"github.com/shidoh/wgfleet/internal/domain"
)

func sampleInput() RenderInput {
	return RenderInput{
		MgmtAddr:         "10.20.25.254",
		ClientListenPort: 443,
		ClientPool:       "10.80.0.0/24",
		Compose: domain.ComposeSpec{
			WGEasyImage:      "ghcr.io/wg-easy/wg-easy:15.3.0",
			MihomoImage:      "metacubex/mihomo:v1.18",
			PublicIP:         "203.0.113.20",
			WGEasyWebPort:    44423,
			ClientDNS:        []string{"10.20.4.10", "10.20.4.15"},
			ClientAllowedIPs: "1.0.0.0/8,8.0.0.0/7",
		},
	}
}

func TestRenderMasterComposeStructure(t *testing.T) {
	out, err := RenderMasterCompose(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("rendered compose is not valid YAML: %v\n%s", err, out)
	}
	services, _ := doc["services"].(map[string]any)
	wg, _ := services["wg-easy"].(map[string]any)
	mi, _ := services["mihomo"].(map[string]any)
	if wg == nil || mi == nil {
		t.Fatalf("missing services: %+v", services)
	}

	if wg["image"] != "ghcr.io/wg-easy/wg-easy:15.3.0" || wg["network_mode"] != "host" {
		t.Errorf("wg-easy service wrong: %+v", wg)
	}
	if mi["image"] != "metacubex/mihomo:v1.18" || mi["command"] != "-d /etc/mihomo" {
		t.Errorf("mihomo service wrong: %+v", mi)
	}
	// mihomo depends on wg-easy.
	dep, _ := mi["depends_on"].([]any)
	if len(dep) != 1 || dep[0] != "wg-easy" {
		t.Errorf("mihomo depends_on = %+v", dep)
	}
	// First-run env present and correct.
	env := toStrings(wg["environment"].([]any))
	joined := strings.Join(env, "\n")
	for _, want := range []string{
		"HOST=10.20.25.254", "EXPERIMENTAL_AWG=true", "OVERRIDE_AUTO_AWG=awg",
		"INIT_HOST=203.0.113.20", "INIT_PORT=443", "INIT_IPV4_CIDR=10.80.0.0/24",
		"INIT_DNS=10.20.4.10,10.20.4.15", "INIT_ALLOWED_IPS=1.0.0.0/8,8.0.0.0/7",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("wg-easy env missing %q:\n%s", want, joined)
		}
	}
}

func TestRenderMasterComposeDefaults(t *testing.T) {
	in := RenderInput{MgmtAddr: "10.20.25.254", ClientPool: "10.80.0.0/24"}
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, DefaultWGEasyImage) || !strings.Contains(out, DefaultMihomoImage) {
		t.Errorf("default images not used:\n%s", out)
	}
	if !strings.Contains(out, "PORT=44423") {
		t.Errorf("default web port not used:\n%s", out)
	}
}

func TestRenderMasterComposeDeterministic(t *testing.T) {
	a, _ := RenderMasterCompose(sampleInput())
	b, _ := RenderMasterCompose(sampleInput())
	if a != b {
		t.Error("compose render must be deterministic")
	}
}

func TestRenderMasterComposeRequiresMgmt(t *testing.T) {
	if _, err := RenderMasterCompose(RenderInput{ClientPool: "10.80.0.0/24"}); err == nil {
		t.Fatal("expected error without mgmt address")
	}
}

func TestRenderMasterComposeUnattendedSetup(t *testing.T) {
	in := sampleInput()
	in.AdminUsername = "admin"
	in.AdminPassword = "s3cr3tP4ss"
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatal(err)
	}
	// All four INIT_* required by wg-easy to skip the setup wizard must be present.
	for _, want := range []string{
		"INIT_ENABLED=true", "INIT_USERNAME=admin", "INIT_PASSWORD=s3cr3tP4ss",
		"INIT_HOST=203.0.113.20", "INIT_PORT=443",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("unattended-setup env missing %q:\n%s", want, out)
		}
	}
	// INIT_ENABLED must appear exactly once (no duplicate from the pool + admin paths).
	if n := strings.Count(out, "INIT_ENABLED=true"); n != 1 {
		t.Errorf("INIT_ENABLED should appear once, got %d:\n%s", n, out)
	}
}

func TestRenderMasterComposeUsernameDefault(t *testing.T) {
	in := sampleInput()
	in.AdminPassword = "pw" // username left empty
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "INIT_USERNAME=admin") {
		t.Errorf("empty username should default to admin:\n%s", out)
	}
}

func TestRenderMasterComposeNoAdminNoWizardBypass(t *testing.T) {
	in := sampleInput() // no admin password
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "INIT_USERNAME=") || strings.Contains(out, "INIT_PASSWORD=") {
		t.Errorf("no admin password ⇒ no INIT_USERNAME/INIT_PASSWORD (wizard fallback):\n%s", out)
	}
}

func TestRedactComposeEnv(t *testing.T) {
	in := sampleInput()
	in.AdminPassword = "TOPSECRET123"
	out, err := RenderMasterCompose(in)
	if err != nil {
		t.Fatal(err)
	}
	red := RedactComposeEnv(out)
	if strings.Contains(red, "TOPSECRET123") {
		t.Errorf("redacted output still contains the password:\n%s", red)
	}
	if !strings.Contains(red, "INIT_PASSWORD=<redacted>") {
		t.Errorf("redacted output missing masked marker:\n%s", red)
	}
	// Non-secret env stays visible.
	if !strings.Contains(red, "INIT_USERNAME=admin") {
		t.Errorf("redaction should not touch non-secret env:\n%s", red)
	}
}

func toStrings(s []any) []string {
	out := make([]string, 0, len(s))
	for _, v := range s {
		if str, ok := v.(string); ok {
			out = append(out, str)
		}
	}
	return out
}

// Once the agent owns the client leg, wg-easy must be GONE from the file, not
// merely stopped: `docker compose up -d` on a file that still lists it would
// bring it straight back to race the agent for the client port.
func TestRenderMasterComposeDropsWGEasyWhenManaged(t *testing.T) {
	out, err := RenderMasterCompose(RenderInput{
		Compose:          domain.ComposeSpec{},
		ClientListenPort: 443,
		ClientPool:       "10.80.0.0/24",
		MgmtAddr:         "10.20.0.1",
		AdminPassword:    "secret",
		ClientWGManaged:  true,
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(out, "wg-easy") {
		t.Fatalf("managed master still ships wg-easy:\n%s", out)
	}
	// mihomo must survive, and must not depend on a service that no longer exists.
	if !strings.Contains(out, "mihomo") {
		t.Fatalf("mihomo missing from the managed stack:\n%s", out)
	}
	if strings.Contains(out, "depends_on") {
		t.Fatalf("mihomo still depends on the removed service:\n%s", out)
	}
	// The admin password only ever existed to seed wg-easy; it must not leak into a
	// file that no longer runs it.
	if strings.Contains(out, "secret") {
		t.Fatalf("wg-easy admin password rendered without wg-easy:\n%s", out)
	}
}

// The noisiest container on the master must not write an unbounded log.
//
// Docker's json-file driver does not rotate by default. Measured on the live
// master 2026-09-04: 97787 error lines in 18 days, all of one kind, in a file
// nothing truncates — a slow disk leak on a 2 vCPU box, and the reason reading
// recent lines is expensive (json-file has no index, so `--since` scans from the
// start of the file).
func TestMihomoLogIsRotated(t *testing.T) {
	out, err := RenderMasterCompose(sampleInput())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"logging:", "max-size", "10m", "max-file"} {
		if !strings.Contains(out, want) {
			t.Errorf("the mihomo service has no log bound (%q missing):\n%s", want, out)
		}
	}
}
