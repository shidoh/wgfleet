package xray

import (
	"encoding/json"
	"reflect"
	"testing"
)

// reality digs the first inbound's realitySettings out of a rendered config.
func reality(t *testing.T, out string) (target string, names []string) {
	t.Helper()
	var cfg struct {
		Inbounds []struct {
			StreamSettings struct {
				RealitySettings struct {
					Target      string   `json:"target"`
					ServerNames []string `json:"serverNames"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal([]byte(out), &cfg); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	r := cfg.Inbounds[0].StreamSettings.RealitySettings
	return r.Target, r.ServerNames
}

func TestCamouflageOpenGateMovesTheTargetAndAddsTheDomain(t *testing.T) {
	out, err := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K",
		Camouflage: &Camouflage{Domain: "e1.example.net", Target: "127.0.0.1:8444"}})
	if err != nil {
		t.Fatal(err)
	}
	target, names := reality(t, out)
	if target != "127.0.0.1:8444" {
		t.Errorf("target = %q, want the local site", target)
	}
	if want := []string{"e1.example.net", "www.microsoft.com"}; !reflect.DeepEqual(names, want) {
		t.Errorf("serverNames = %v, want %v", names, want)
	}
}

// With the gate closed the domain is still accepted — only the target stays.
func TestCamouflageClosedGateKeepsTheDefaultTarget(t *testing.T) {
	s := sampleSpec()
	s.AllowEmptySNI = true
	out, err := RenderConfig(RenderInput{Spec: s, PrivateKey: "K", Camouflage: &Camouflage{Domain: "e1.example.net"}})
	if err != nil {
		t.Fatal(err)
	}
	target, names := reality(t, out)
	if target != "www.microsoft.com:443" {
		t.Errorf("target = %q, want the fleet default", target)
	}
	if want := []string{"", "e1.example.net", "www.microsoft.com"}; !reflect.DeepEqual(names, want) {
		t.Errorf("serverNames = %v, want %v", names, want)
	}
}

func TestCamouflageNilRendersAsBefore(t *testing.T) {
	plain, _ := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K"})
	none, _ := RenderConfig(RenderInput{Spec: sampleSpec(), PrivateKey: "K", Camouflage: &Camouflage{}})
	if plain != none {
		t.Error("an empty camouflage changed the render")
	}
}

func TestCamouflageReachesTheClientInboundAndThePortal(t *testing.T) {
	c := &Camouflage{Domain: "m1.example.net", Target: "127.0.0.1:8444"}
	out, err := RenderClientConfig(ClientRenderInput{Spec: sampleClientSpec(), PrivateKey: "PRIVKEY", Camouflage: c})
	if err != nil {
		t.Fatal(err)
	}
	if target, names := reality(t, out); target != c.Target || names[len(names)-2] != c.Domain {
		t.Errorf("client inbound target %q names %v", target, names)
	}
	in := portalInput()
	in.Camouflage = c
	out, err = RenderPortalConfig(in)
	if err != nil {
		t.Fatal(err)
	}
	if target, names := reality(t, out); target != c.Target || !reflect.DeepEqual(names, []string{c.Domain, "www.python.org"}) {
		t.Errorf("portal target %q names %v", target, names)
	}
}
