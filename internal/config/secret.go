package config

import (
	"fmt"
	"os"
	"strings"
)

// Secret is a config value that must never be committed to git. In YAML it is
// written as a reference (e.g. "secret://ca-key" or "env://WGFLEET_CA_KEY" or
// "file:///etc/wgfleet/ca.key"), and the literal secret is resolved at load
// time via Resolve. A bare string with no scheme is treated as an inline value
// — discouraged, but supported for local development.
//
// Supported schemes:
//
//	env://NAME      read from environment variable NAME
//	file://PATH     read the (trimmed) contents of PATH (must be 0600)
//	secret://NAME   read via the configured secret provider (SOPS/age hook);
//	                falls back to env var WGFLEET_SECRET_<NAME> on MVP.
type Secret string

// SecretProvider resolves a named secret. The MVP wires an env-backed provider;
// a SOPS/age provider can be substituted without touching call sites.
type SecretProvider interface {
	Resolve(name string) (string, error)
}

// Resolve returns the literal secret value referenced by s, using provider for
// the secret:// scheme. An empty Secret resolves to "".
func (s Secret) Resolve(provider SecretProvider) (string, error) {
	raw := string(s)
	switch {
	case raw == "":
		return "", nil
	case strings.HasPrefix(raw, "env://"):
		name := strings.TrimPrefix(raw, "env://")
		v, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("secret: env var %q is not set", name)
		}
		return v, nil
	case strings.HasPrefix(raw, "file://"):
		path := strings.TrimPrefix(raw, "file://")
		return readSecretFile(path)
	case strings.HasPrefix(raw, "secret://"):
		if provider == nil {
			return "", fmt.Errorf("secret: %q requires a secret provider, none configured", raw)
		}
		return provider.Resolve(strings.TrimPrefix(raw, "secret://"))
	default:
		// Inline value (dev only). Callers may warn on this.
		return raw, nil
	}
}

// IsReference reports whether s uses a scheme rather than an inline literal.
func (s Secret) IsReference() bool {
	for _, scheme := range []string{"env://", "file://", "secret://"} {
		if strings.HasPrefix(string(s), scheme) {
			return true
		}
	}
	return false
}

func readSecretFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("secret file %q: %w", path, err)
	}
	// Refuse group/other-readable secret files; a leaked 0644 key is a finding.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return "", fmt.Errorf("secret file %q has permissions %o, want 0600", path, perm)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("secret file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// EnvSecretProvider resolves secret://NAME from WGFLEET_SECRET_<UPPER_NAME>.
// It is the MVP default until a SOPS/age provider is wired in.
type EnvSecretProvider struct{}

// Resolve implements SecretProvider.
func (EnvSecretProvider) Resolve(name string) (string, error) {
	envName := "WGFLEET_SECRET_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
	v, ok := os.LookupEnv(envName)
	if !ok {
		return "", fmt.Errorf("secret %q not found (looked up %s)", name, envName)
	}
	return v, nil
}
