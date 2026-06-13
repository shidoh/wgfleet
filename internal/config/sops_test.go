package config

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// fakeDecrypt returns canned plaintext, standing in for the sops CLI so tests
// need neither the binary nor an age key.
func fakeDecrypt(plain string, err error) DecryptFunc {
	return func(context.Context, string) ([]byte, error) {
		if err != nil {
			return nil, err
		}
		return []byte(plain), nil
	}
}

func TestSOPSProviderResolve(t *testing.T) {
	yaml := "ca-key: top-secret-pem\nwarp-token: abc123\n"
	p, err := NewSOPSProvider(context.Background(), "secrets.yaml", fakeDecrypt(yaml, nil))
	if err != nil {
		t.Fatalf("new provider: %v", err)
	}

	got, err := p.Resolve("ca-key")
	if err != nil || got != "top-secret-pem" {
		t.Errorf("Resolve(ca-key) = %q, %v", got, err)
	}
	if _, err := p.Resolve("missing"); err == nil {
		t.Error("expected error for missing secret name")
	}
}

func TestSOPSProviderResolvesViaSecretScheme(t *testing.T) {
	// End-to-end: a secret:// reference resolves through the SOPS provider exactly
	// like it would through the env provider, with no call-site changes.
	p, err := NewSOPSProvider(context.Background(), "s.yaml", fakeDecrypt("ca-key: pem-bytes\n", nil))
	if err != nil {
		t.Fatal(err)
	}
	got, err := Secret("secret://ca-key").Resolve(p)
	if err != nil || got != "pem-bytes" {
		t.Errorf("Secret resolve via SOPS = %q, %v", got, err)
	}
}

func TestSOPSProviderMultilinePEM(t *testing.T) {
	// A CA private key is a multi-line PEM; it must survive as a YAML block scalar.
	pem := "-----BEGIN EC PRIVATE KEY-----\nMHcCAQ...\nAwEHoUQDQ...\n-----END EC PRIVATE KEY-----"
	yaml := "ca-key: |\n  -----BEGIN EC PRIVATE KEY-----\n  MHcCAQ...\n  AwEHoUQDQ...\n  -----END EC PRIVATE KEY-----\n"
	p, err := NewSOPSProvider(context.Background(), "s.yaml", fakeDecrypt(yaml, nil))
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Resolve("ca-key")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != pem {
		t.Errorf("multiline PEM round-trip mismatch:\ngot  %q\nwant %q", got, pem)
	}
}

func TestSOPSProviderDecryptErrorIsFailFast(t *testing.T) {
	_, err := NewSOPSProvider(context.Background(), "s.yaml", fakeDecrypt("", errors.New("bad age key")))
	if err == nil || !strings.Contains(err.Error(), "decrypt") {
		t.Fatalf("want fail-fast decrypt error, got %v", err)
	}
}

func TestSOPSProviderRejectsNestedYAML(t *testing.T) {
	// A secrets file is a flat name→value table; a nested structure is a mistake
	// that must fail loudly, not silently drop a secret.
	nested := "group:\n  ca-key: x\n"
	if _, err := NewSOPSProvider(context.Background(), "s.yaml", fakeDecrypt(nested, nil)); err == nil {
		t.Fatal("expected error for nested (non-flat) YAML")
	}
}

func TestSOPSProviderScalarCoercion(t *testing.T) {
	p, err := NewSOPSProvider(context.Background(), "s.yaml", fakeDecrypt("port: 8443\nenabled: true\n", nil))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := p.Resolve("port"); got != "8443" {
		t.Errorf("int coercion: got %q", got)
	}
	if got, _ := p.Resolve("enabled"); got != "true" {
		t.Errorf("bool coercion: got %q", got)
	}
}

func TestNewSecretProviderSelectsBackend(t *testing.T) {
	// No sops_file ⇒ env provider.
	cfg := &ControllerConfig{}
	p, err := NewSecretProvider(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := p.(EnvSecretProvider); !ok {
		t.Errorf("want EnvSecretProvider, got %T", p)
	}

	// A configured (but unreadable) sops_file surfaces its error at startup
	// rather than returning a silently-empty provider.
	cfg.Controller.Secrets.SOPSFile = "/nonexistent/secrets.enc.yaml"
	if _, err := NewSecretProvider(context.Background(), cfg); err == nil {
		t.Error("expected error for unreadable sops_file")
	}
}
