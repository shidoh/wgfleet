package backup

import (
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
)

func cfgWithCAKey(key config.Secret) *config.ControllerConfig {
	c := &config.ControllerConfig{}
	c.Controller.Store = "/var/lib/wgfleet/state.db"
	c.Controller.PKI.CACert = "/etc/wgfleet/pki/ca.crt"
	c.Controller.PKI.CAKey = key
	return c
}

// TestDefaultSourcesResolvesFileCAKey — the CA key is the ONE artifact a fleet
// cannot be rebuilt without: lose it and every node's mTLS identity has to be
// reissued. When it lives on disk behind file://, the backup must carry the file
// itself, not the reference string.
func TestDefaultSourcesResolvesFileCAKey(t *testing.T) {
	src := DefaultSources(cfgWithCAKey("file:///etc/wgfleet/pki/ca.key"), "/etc/wgfleet/controller.yaml")
	if src.CAKey != "/etc/wgfleet/pki/ca.key" {
		t.Errorf("CAKey = %q, want the file:// scheme stripped to a path", src.CAKey)
	}
	if strings.Contains(src.CAKey, "://") {
		t.Error("a scheme leaked into the backup source path — the archive would try to read it as a filename")
	}
}

// TestDefaultSourcesSkipsNonFileCAKey — when the key comes from env:// or
// secret:// there is no file on this host to archive, and treating the reference
// as a path would make the backup either fail or silently store the literal
// string "env://WGFLEET_CA_KEY" where the key should be. Empty is correct: the
// key lives in the operator's secret store and is restored from there.
func TestDefaultSourcesSkipsNonFileCAKey(t *testing.T) {
	for _, ref := range []config.Secret{"env://WGFLEET_CA_KEY", "secret://pki/ca-key"} {
		src := DefaultSources(cfgWithCAKey(ref), "/etc/wgfleet/controller.yaml")
		if src.CAKey != "" {
			t.Errorf("CAKey for %q = %q, want empty (nothing on this host to archive)", ref, src.CAKey)
		}
	}
}

// TestDefaultSourcesKeepsBareDevPath — a bare path is the dev-mode form and must
// still be backed up, or a developer's fleet loses its CA on the first restore.
func TestDefaultSourcesKeepsBareDevPath(t *testing.T) {
	src := DefaultSources(cfgWithCAKey("/tmp/dev-ca.key"), "/etc/wgfleet/controller.yaml")
	if src.CAKey != "/tmp/dev-ca.key" {
		t.Errorf("CAKey = %q, want the bare dev path preserved", src.CAKey)
	}
}

// TestDefaultSourcesCoversEveryUnrecoverableArtifact is a deliberate PIN, not a
// restatement of the code. Backup is only ever exercised in anger, so an artifact
// silently dropped from this list is discovered at restore time — the one moment
// it cannot be fixed. Adding a new unrecoverable file means updating this test on
// purpose, which is the point.
func TestDefaultSourcesCoversEveryUnrecoverableArtifact(t *testing.T) {
	src := DefaultSources(cfgWithCAKey("file:///etc/wgfleet/pki/ca.key"), "/etc/wgfleet/controller.yaml")
	for _, f := range []struct{ name, got string }{
		{"controller.yaml (fleet intent)", src.ControllerYAML},
		{"state.db (node inventory + keys)", src.StateDB},
		{"CA certificate", src.CACert},
		{"CA private key", src.CAKey},
		{"wg-easy database (client configs)", src.WGEasyDB},
		{"wg-easy admin credentials", src.WGEasyAdmin},
		{"master WireGuard key", src.WGKey},
		{"node certificate", src.NodeCert},
		{"node key", src.NodeKey},
		{"agent.yaml", src.AgentYAML},
	} {
		if strings.TrimSpace(f.got) == "" {
			t.Errorf("%s has no backup source — it would be missing from the archive", f.name)
		}
	}
}

// TestDefaultSourcesSOPSOnlyWhenConfigured — an unset SOPS file must stay empty
// rather than expand to the operator's home directory and pull an unrelated file
// into the archive.
func TestDefaultSourcesSOPSOnlyWhenConfigured(t *testing.T) {
	src := DefaultSources(cfgWithCAKey("file:///k"), "/c.yaml")
	if src.SOPSFile != "" {
		t.Errorf("SOPSFile = %q, want empty when unconfigured", src.SOPSFile)
	}
	c := cfgWithCAKey("file:///k")
	c.Controller.Secrets.SOPSFile = "/etc/wgfleet/secrets.yaml"
	if got := DefaultSources(c, "/c.yaml").SOPSFile; got != "/etc/wgfleet/secrets.yaml" {
		t.Errorf("SOPSFile = %q, want the configured path", got)
	}
}
