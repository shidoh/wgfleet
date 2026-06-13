package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/config"
	"github.com/shidoh/wgfleet/internal/controller/pki"
)

// yamlBlock encodes val as a YAML literal block scalar under key — how a SOPS
// secrets file carries a multi-line PEM private key.
func yamlBlock(key string, val []byte) []byte {
	var b strings.Builder
	b.WriteString(key + ": |\n")
	for _, line := range strings.Split(strings.TrimRight(string(val), "\n"), "\n") {
		b.WriteString("  " + line + "\n")
	}
	return []byte(b.String())
}

// TestLoadCAFromSecretReferenceInMemory proves the SOPS/age path: the CA private
// key is delivered through the secret provider and loaded in memory, never
// written to disk. Only the public cert lives on the filesystem.
func TestLoadCAFromSecretReferenceInMemory(t *testing.T) {
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	kp, err := ca.Marshal()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(certPath, kp.CertPEM, 0o644); err != nil {
		t.Fatal(err)
	}

	provider, err := config.NewSOPSProvider(context.Background(), "secrets.yaml",
		func(context.Context, string) ([]byte, error) {
			return yamlBlock("ca-key", kp.KeyPEM), nil
		})
	if err != nil {
		t.Fatal(err)
	}

	cfg := &config.ControllerConfig{}
	cfg.Controller.PKI.CACert = certPath
	cfg.Controller.PKI.CAKey = "secret://ca-key"

	loaded, err := loadCA(cfg, provider)
	if err != nil {
		t.Fatalf("loadCA: %v", err)
	}

	// The loaded CA must be functional — able to sign a node cert.
	if _, err := loaded.IssueNodeCert("exit-de-1"); err != nil {
		t.Fatalf("loaded CA cannot issue: %v", err)
	}

	// The decrypted key must not have leaked to disk: only the public cert is there.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ca.crt" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("decrypted CA key leaked to disk; dir contains %v", names)
	}
}

// TestLoadCAFromFileUnchanged confirms a bare/file:// key path still loads from
// disk (no provider involvement) — the existing setup keeps working.
func TestLoadCAFromFileUnchanged(t *testing.T) {
	ca, err := pki.NewCA("test-ca")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath := filepath.Join(dir, "ca.crt")
	keyPath := filepath.Join(dir, "ca.key")
	if err := pki.SaveCA(ca, certPath, keyPath); err != nil {
		t.Fatal(err)
	}

	cfg := &config.ControllerConfig{}
	cfg.Controller.PKI.CACert = certPath
	cfg.Controller.PKI.CAKey = config.Secret(keyPath) // bare path

	if _, err := loadCA(cfg, config.EnvSecretProvider{}); err != nil {
		t.Fatalf("loadCA from file: %v", err)
	}
}
