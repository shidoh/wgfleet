package provisioner

import (
	"context"
	"strings"
	"testing"
)

func readyRunner() *MockRunner {
	r := NewMockRunner()
	r.Responses["uname -s"] = "Linux\n"
	r.Responses["uname -m"] = "x86_64\n"
	r.Responses["uname -r"] = "6.8.0-40-generic\n"
	r.Responses[". /etc/os-release 2>/dev/null; printf %s \"$ID\""] = "ubuntu"
	// All tools present.
	r.PrefixResponses["command -v "] = "yes"
	// AWG kernel module present.
	r.PrefixResponses["k=$(uname -r)"] = "AWGKMOD=yes (loaded, test)"
	return r
}

func TestCollectFactsReady(t *testing.T) {
	f, err := CollectFacts(context.Background(), readyRunner())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if f.OS != "Linux" || f.Arch != "x86_64" || f.Distro != "ubuntu" {
		t.Errorf("facts mismatch: %+v", f)
	}
	if !f.HasAWGTools || !f.HasAWGKmod || !f.HasNft || !f.HasWgcf || !f.HasZeroTier {
		t.Errorf("expected all tools present: %+v", f)
	}
	if err := f.Preflight(); err != nil {
		t.Errorf("ready node should pass preflight: %v", err)
	}
	if len(f.MissingPackages()) != 0 {
		t.Errorf("expected no missing packages, got %v", f.MissingPackages())
	}
}

func TestPreflightFailsWithoutAWGModule(t *testing.T) {
	r := readyRunner()
	r.PrefixResponses["k=$(uname -r)"] = "AWGKMOD=no (absent, test)" // module absent
	f, err := CollectFacts(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	if f.HasAWGKmod {
		t.Fatal("module should be reported absent")
	}
	err = f.Preflight()
	if err == nil {
		t.Fatal("preflight must fail without the AmneziaWG kernel module")
	}
	if !strings.Contains(err.Error(), "kernel module") {
		t.Errorf("error should mention the kernel module: %v", err)
	}
}

func TestPreflightFailsOnNonLinux(t *testing.T) {
	f := Facts{OS: "Darwin", HasAWGKmod: true}
	if err := f.Preflight(); err == nil {
		t.Fatal("non-Linux node must fail preflight")
	}
}

func TestMissingPackages(t *testing.T) {
	r := NewMockRunner()
	r.Responses["uname -s"] = "Linux"
	r.Responses["uname -m"] = "x86_64"
	r.Responses["uname -r"] = "6.8.0"
	// Only nft present; everything else absent.
	r.PrefixResponses["command -v nft"] = "yes"
	r.DefaultResponse = "no"
	r.PrefixResponses["k=$(uname -r)"] = "AWGKMOD=yes (loaded, test)"

	f, err := CollectFacts(context.Background(), r)
	if err != nil {
		t.Fatal(err)
	}
	missing := strings.Join(f.MissingPackages(), ",")
	for _, want := range []string{"amneziawg-tools", "conntrack", "fail2ban", "age"} {
		if !strings.Contains(missing, want) {
			t.Errorf("expected %q in missing packages, got %v", want, f.MissingPackages())
		}
	}
	if strings.Contains(missing, "nftables") {
		t.Errorf("nftables present, should not be missing: %v", f.MissingPackages())
	}
	// wgcf and docker are NOT apt packages: each has its own bootstrap step, so
	// they must never appear in the apt install list.
	for _, never := range []string{"wgcf", "docker"} {
		if strings.Contains(missing, never) {
			t.Errorf("%q must not be an apt package in MissingPackages: %v", never, f.MissingPackages())
		}
	}
}
