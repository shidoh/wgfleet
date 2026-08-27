package web

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

// secretMarkers are unique, obviously-fake values planted in EVERY credential
// field reachable from a NodeSpec. Any of them showing up in the rendered view
// means that field reached an operator's browser.
var secretMarkers = map[string]string{
	"exit AWG 3.0 header-protection key":  "LEAK-hpk-exit",
	"master↔exit AWG 3.0 key":             "LEAK-hpk-tunnel",
	"master↔exit WireGuard preshared key": "LEAK-psk",
	"master↔exit REALITY tunnel UUID":     "LEAK-uuid-tunnel",
	"exit REALITY server UUID":            "LEAK-uuid-reality",
	"end-user VLESS client UUID":          "LEAK-uuid-client",
	"mihomo Clash API secret (overrides)": "LEAK-clash-secret",
	"blocky custom overrides":             "LEAK-dns-override",
	"client interface AWG 3.0 key":        "LEAK-hpk-client",
	"end-user WireGuard preshared key":    "LEAK-client-psk",
}

// loadedSpec is a NodeSpec with every credential field populated with a marker,
// so the leak test cannot pass by accident on a sparse fixture.
func loadedSpec() domain.NodeSpec {
	awg := func(hpk string) *domain.AWGParams {
		return &domain.AWGParams{
			Shared: domain.AWGShared{
				S1: 102, S2: 67, S3: 143, S4: 38,
				H1: domain.AWGHeader{Min: 1, Max: 2}, H2: domain.AWGHeader{Min: 3, Max: 4},
				H3: domain.AWGHeader{Min: 5, Max: 6}, H4: domain.AWGHeader{Min: 7, Max: 8},
				HeaderProtectionKey: hpk,
			},
			Local: domain.AWGLocal{Jc: 5, Jmin: 60, Jmax: 900, I1: "<b 0xde><r 4>"},
		}
	}
	return domain.NodeSpec{
		Role:              domain.RoleMaster,
		Egress:            domain.EgressWARP,
		EnabledTransports: []domain.MasterTransport{domain.TransportAWG, domain.TransportRealityXHTTP},
		ActiveTransport:   domain.TransportRealityXHTTP,
		WARPMTU:           1380,
		WGServer: domain.WGServerSpec{
			ListenPort: 443, AddressPool: "10.73.0.0/24", Address: "10.73.0.1", MTU: 1320,
			AWG: awg(secretMarkers["exit AWG 3.0 header-protection key"]),
		},
		Reality: &domain.RealityServerSpec{
			ListenPort: 443, ServerName: "www.python.org", Dest: "www.python.org:443",
			ShortID: "ab12", XHTTPPath: "/x", XHTTPMode: "auto",
			UUID: secretMarkers["exit REALITY server UUID"],
		},
		Master: &domain.MasterSpec{
			BindAddress: "10.73.0.1", RedirPort: 7895, ExternalController: "10.20.25.254:9090",
			ExitTunnels: []domain.ExitTunnel{{
				Name: "vn0", Endpoint: "1.2.3.4:51820", TunnelIP: "10.81.0.2", MTU: 1380,
				ServerPublicKey: "pubkey-not-a-secret",
				PresharedKey:    secretMarkers["master↔exit WireGuard preshared key"],
				AWG:             awg(secretMarkers["master↔exit AWG 3.0 key"]),
				Transport:       domain.TransportAWG,
				Reality: &domain.RealityTunnel{
					UUID: secretMarkers["master↔exit REALITY tunnel UUID"], ShortID: "cd34",
					ServerName: "www.python.org", PublicKey: "reality-pub",
				},
			}},
			Custom: domain.CustomConfig{Overrides: map[string]any{
				"secret": secretMarkers["mihomo Clash API secret (overrides)"],
			}},
			ClientVLESS: &domain.ClientVLESSServerSpec{
				ListenPort: 8443, ServerName: "www.python.org", Dest: "www.python.org:443",
				Clients: []domain.VLESSClient{{
					Name: "phone", ShortID: "ef56",
					UUID: secretMarkers["end-user VLESS client UUID"],
				}},
			},
			ClientWG: &domain.ClientWGSpec{
				ListenPort: 443, AddressPool: "10.80.0.0/24", ServerAddress: "10.80.0.1",
				MTU: 1360, DNS: []string{"10.20.25.254"}, AllowedIPs: []string{"0.0.0.0/0"},
				AWG: awg(secretMarkers["client interface AWG 3.0 key"]),
				Clients: []domain.WGClientPeer{{
					Name: "laptop", PublicKey: "client-pub-not-a-secret", Address: "10.80.0.2/32",
					PresharedKey: secretMarkers["end-user WireGuard preshared key"],
				}},
			},
		},
		DNS: domain.DNSFilterSpec{
			Enabled: true, MgmtAddr: "10.20.25.254", Upstreams: []string{"1.1.1.1"},
			Custom: domain.CustomConfig{Overrides: map[string]any{
				"blocking": secretMarkers["blocky custom overrides"],
			}},
		},
		Routing:   domain.RoutingSpec{EgressInterface: "wgcf", ClientCIDR: "10.73.0.0/24"},
		Firewall:  domain.FirewallSpec{ASBlacklist: true, WGPort: 443},
		Hardening: &domain.HardeningSpec{SSHD: true, Fail2ban: false},
	}
}

// renderedText flattens every string the view can put on the page, so the leak
// test covers the WHOLE view by construction — a new section added later is
// scanned automatically instead of being forgotten.
func renderedText(v specView) string {
	var b strings.Builder
	write := func(rows []specRow) {
		for _, r := range rows {
			b.WriteString(r.Label + "\x00" + r.Value + "\x00" + r.Hint + "\x00" + r.Badge + "\n")
		}
	}
	write(v.Summary)
	for _, g := range v.Details {
		b.WriteString(g.Title + "\n")
		write(g.Rows)
	}
	for _, t := range v.Tables {
		b.WriteString(t.Title + "\x00" + t.Note + "\x00" + strings.Join(t.Head, "\x00") + "\n")
		for _, row := range t.Rows {
			b.WriteString(strings.Join(row, "\x00") + "\n")
		}
	}
	// The raw manifest is rendered to the page too, so it is part of the surface a
	// credential could escape through — arguably the likeliest one.
	b.WriteString(v.Raw)
	b.WriteString(v.RawErr)
	return b.String()
}

// TestSpecViewLeaksNoCredentials is the guard the operator asked for. The spec is
// rendered into a browser page, and a NodeSpec reaches into several credential
// fields at once — the AWG 3.0 header-protection key on both the interface and
// every master↔exit tunnel, the WireGuard preshared key, REALITY UUIDs on both
// ends, end-user VLESS ids, and the free-form Custom.Overrides maps where the
// mihomo Clash API secret lives. Rendering is allowlist-based precisely so a
// field added later is invisible until someone opts it in; this test proves the
// allowlist holds.
func TestSpecViewLeaksNoCredentials(t *testing.T) {
	text := renderedText(buildSpecView(loadedSpec()))
	for what, marker := range secretMarkers {
		if strings.Contains(text, marker) {
			t.Errorf("the %s reached the page (marker %q found)", what, marker)
		}
	}
}

// TestSpecViewShowsTransport is the gap that made the old block useless: on a
// fleet where most exits run reality-xhttp, the page could not tell you which
// transport a node was actually on. Both the enabled set and the ACTIVE one must
// be visible — the active one is what the operator flips.
func TestSpecViewShowsTransport(t *testing.T) {
	// Enabled/ActiveTransport are exit-side fields — the master's own transport row
	// summarises its proxies instead, which the exit-tunnels section covers.
	s := loadedSpec()
	s.Role = domain.RoleExit
	text := renderedText(buildSpecView(s))
	for _, want := range []string{"reality-xhttp", "awg"} {
		if !strings.Contains(text, want) {
			t.Errorf("transport %q is not shown anywhere", want)
		}
	}
	if !strings.Contains(strings.ToLower(text), "active") {
		t.Error("the ACTIVE transport must be identified, not just the enabled set")
	}
}

// TestSpecViewShowsRealityWithoutUUID — the REALITY inbound was absent from the
// old rendering entirely, so an operator could not check dest/SNI/short-id
// against what a client was configured with. It must appear; its UUID must not.
func TestSpecViewShowsRealityWithoutUUID(t *testing.T) {
	text := renderedText(buildSpecView(loadedSpec()))
	for _, want := range []string{"www.python.org", "ab12"} {
		if !strings.Contains(text, want) {
			t.Errorf("REALITY detail %q missing", want)
		}
	}
	if strings.Contains(text, secretMarkers["exit REALITY server UUID"]) {
		t.Error("REALITY UUID must never be rendered")
	}
}

// TestSpecViewSummaryAnswersTheQuestion — the always-visible card exists to
// answer "what does this node carry" without unfolding anything. MTU is the
// recurring source of black holes here, so it belongs in the summary rather than
// three levels down.
func TestSpecViewSummaryAnswersTheQuestion(t *testing.T) {
	s := loadedSpec()
	s.Role = domain.RoleExit // egress is an exit concept
	v := buildSpecView(s)
	if len(v.Summary) == 0 {
		t.Fatal("the summary card must not be empty")
	}
	var labels []string
	for _, r := range v.Summary {
		labels = append(labels, strings.ToLower(r.Label))
	}
	joined := strings.Join(labels, " ")
	for _, want := range []string{"transport", "mtu", "egress"} {
		if !strings.Contains(joined, want) {
			t.Errorf("summary has no %q row; labels = %v", want, labels)
		}
	}
}

// TestSpecViewShowsPreviouslyMissingFields pins the six NodeSpec fields the old
// text block silently dropped. Each was invisible to the operator despite being
// part of the desired state the controller actually ships.
func TestSpecViewShowsPreviouslyMissingFields(t *testing.T) {
	s := loadedSpec()
	s.EgressThroughputMinBps = 2_000_000
	s.EgressThroughputProbeURL = "https://speed.example/probe"
	text := strings.ToLower(renderedText(buildSpecView(s)))

	for what, want := range map[string]string{
		"hardening policy":     "fail2ban",
		"throughput floor":     "2",
		"throughput probe url": "speed.example",
		"reality inbound":      "python.org",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("%s is not rendered (looked for %q)", what, want)
		}
	}
}

// TestSpecViewDecommissionIsUnmistakable — a node being torn down must not read
// like a healthy one with a lot of config.
func TestSpecViewDecommissionIsUnmistakable(t *testing.T) {
	s := loadedSpec()
	s.Decommission = true
	v := buildSpecView(s)
	text := strings.ToLower(renderedText(v))
	if !strings.Contains(text, "decommission") {
		t.Error("a decommissioning node must say so")
	}
	if len(v.Details) != 0 || len(v.Tables) != 0 || v.Raw != "" {
		t.Errorf("a decommissioning node has no desired data plane to detail, got %d groups / %d tables / raw=%d bytes",
			len(v.Details), len(v.Tables), len(v.Raw))
	}
}
