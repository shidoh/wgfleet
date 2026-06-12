package egress

import (
	"strings"
	"testing"
)

func validWARP() WARPConfig {
	return WARPConfig{
		PrivateKey:    "wARPpRivKeyBase64ExampleValueForTestingOnly12=",
		Address4:      "172.16.0.2/32",
		Address6:      "2606:4700:110:8a:1234::2/128",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		MTU:           1340,
		DNS:           "1.1.1.1",
	}
}

func TestRenderWGCFEnforcesTableOff(t *testing.T) {
	out, err := RenderWGCF(validWARP())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "Table = off") {
		t.Errorf("Table = off is mandatory:\n%s", out)
	}
	if !strings.Contains(out, "MTU = 1340") {
		t.Errorf("computed MTU missing:\n%s", out)
	}
	if !strings.Contains(out, "Endpoint = "+DefaultWARPEndpoint) {
		t.Errorf("default endpoint missing:\n%s", out)
	}
	if !strings.Contains(out, "AllowedIPs = 0.0.0.0/0") {
		t.Errorf("catch-all AllowedIPs missing:\n%s", out)
	}
	// Keepalive keeps the NAT mapping/handshake warm so idle egress does not flap
	// the warp-egress health check.
	if !strings.Contains(out, "PersistentKeepalive = 25") {
		t.Errorf("WARP PersistentKeepalive missing (NAT traversal):\n%s", out)
	}
}

func TestRenderWGCFRequiresComputedMTU(t *testing.T) {
	c := validWARP()
	c.MTU = 0
	if _, err := RenderWGCF(c); err == nil {
		t.Fatal("expected error: MTU must be computed")
	}
}

func TestRenderWGCFRequiresSecrets(t *testing.T) {
	c := validWARP()
	c.PrivateKey = ""
	if _, err := RenderWGCF(c); err == nil {
		t.Fatal("expected error without WARP private key")
	}
}

func TestParseWGCFProfile(t *testing.T) {
	// The exact shape `wgcf generate` writes (verified live on a WARP-registered node).
	profile := `[Interface]
PrivateKey = aPrivKeyBase64ExampleForTestingPurposesOnly=
Address = 172.16.0.2/32
Address = 2606:4700:110:80be:736a:dd9c:cdfb:342/128
DNS = 1.1.1.1, 1.0.0.1
MTU = 1280
[Peer]
PublicKey = bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=
AllowedIPs = 0.0.0.0/0
AllowedIPs = ::/0
Endpoint = engage.cloudflareclient.com:2408
`
	c, err := ParseWGCFProfile([]byte(profile))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.PrivateKey != "aPrivKeyBase64ExampleForTestingPurposesOnly=" {
		t.Errorf("PrivateKey = %q", c.PrivateKey)
	}
	if c.Address4 != "172.16.0.2/32" {
		t.Errorf("Address4 = %q, want 172.16.0.2/32", c.Address4)
	}
	if c.Address6 != "2606:4700:110:80be:736a:dd9c:cdfb:342/128" {
		t.Errorf("Address6 = %q", c.Address6)
	}
	if c.PeerPublicKey != "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=" {
		t.Errorf("PeerPublicKey = %q", c.PeerPublicKey)
	}
	if c.Endpoint != "engage.cloudflareclient.com:2408" {
		t.Errorf("Endpoint = %q", c.Endpoint)
	}
	// The parsed creds must render a valid wgcf.conf once an MTU is set.
	c.MTU = 1440
	if _, err := RenderWGCF(c); err != nil {
		t.Errorf("render from parsed profile: %v", err)
	}
}

func TestParseWGCFProfileIncomplete(t *testing.T) {
	if _, err := ParseWGCFProfile([]byte("[Interface]\nAddress = 172.16.0.2/32\n")); err == nil {
		t.Fatal("expected error for profile missing private/peer keys")
	}
}
