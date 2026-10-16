package xray

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

var updateFixtures = flag.Bool("update-fixtures", false, "rewrite internal/xray/testdata from the current renderers")

// Every exit and every master runs a config rendered here; a byte of drift
// restarts xray on all of them. These fixtures were captured before the
// exit-initiated REALITY renderers were added and must not move with them.
func TestExistingRendersAreByteStable(t *testing.T) {
	const priv = "aGVyZSBpcyBhIGZpeHR1cmUgcHJpdmF0ZSBrZXkgeHg"
	for _, mode := range []string{domain.RealityModeXHTTP, domain.RealityModeVision} {
		for _, mark := range []int{0, EgressMark} {
			for _, v6 := range []bool{false, true} {
				for _, empty := range []bool{false, true} {
					name := fmt.Sprintf("exit-%s-mark%d-v6%v-empty%v.json", mode, mark, v6, empty)
					got, err := RenderConfig(RenderInput{
						Spec: domain.RealityServerSpec{
							ListenPort: 443, UUID: "11111111-2222-4333-8444-555555555555", ShortID: "0a1b2c3d",
							ServerName: "www.python.org", Dest: "www.python.org:443", XHTTPPath: "/0a1b2c3d",
							Mode: mode, AllowEmptySNI: empty, AllowIPv6: v6,
						},
						PrivateKey: priv, EgressMark: mark,
					})
					checkFixture(t, name, got, err)
				}
			}
		}
	}
	clientSets := map[string][]domain.VLESSClient{
		"none": nil,
		"two":  {{Name: "a", UUID: "aaaaaaaa-0000-4000-8000-000000000001", ShortID: "01"}, {Name: "b", UUID: "bbbbbbbb-0000-4000-8000-000000000002", ShortID: "02"}},
	}
	for setName, clients := range clientSets {
		for _, mode := range []string{domain.RealityModeXHTTP, domain.RealityModeVision} {
			for _, v6 := range []bool{false, true} {
				for hostName, host := range map[string]string{"loopback": "", "netns": "100.127.255.1"} {
					name := fmt.Sprintf("client-%s-%s-v6%v-%s.json", setName, mode, v6, hostName)
					got, err := RenderClientConfig(ClientRenderInput{
						Spec: domain.ClientVLESSServerSpec{
							ListenPort: 47252, Clients: clients, ServerName: "www.python.org", Dest: "www.python.org:443",
							Mode: mode, AllowEmptySNI: true, AllowIPv6: v6, SocksPort: domain.ClientVLESSSocksPort,
						},
						PrivateKey: priv, SocksHost: host,
					})
					checkFixture(t, name, got, err)
				}
			}
		}
	}
}

func checkFixture(t *testing.T, name, got string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	path := filepath.Join("testdata", name)
	if *updateFixtures {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s: %v (run with -update-fixtures once)", name, err)
	}
	if string(want) != got {
		t.Errorf("%s drifted:\n--- got\n%s--- want\n%s", name, got, want)
	}
}
