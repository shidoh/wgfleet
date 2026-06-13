package config

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// DecryptFunc decrypts the SOPS-encrypted file at path and returns the plaintext
// bytes. It is injectable so tests run without the sops binary or a real age key.
type DecryptFunc func(ctx context.Context, path string) ([]byte, error)

// SOPSProvider resolves secret://NAME by decrypting a SOPS-encrypted YAML file
// and looking NAME up among its top-level keys. Decryption is delegated to the
// `sops` CLI (recipients: age/PGP/KMS), keeping wgfleet free of the heavy sops
// Go dependency tree — consistent with how the platform orchestrates other proven
// tools (wgcf, nft, docker). The whole file is decrypted once at construction
// (fail-fast: a missing key file or wrong age key surfaces at startup, not
// mid-reconcile) and the resulting name→value map is cached for the provider's
// life. The decrypted secrets stay in memory and are never written to disk.
type SOPSProvider struct {
	path    string
	secrets map[string]string
}

// NewSOPSProvider decrypts path with decrypt (defaulting to the sops CLI) and
// parses the plaintext as a flat YAML map of secret name → value.
func NewSOPSProvider(ctx context.Context, path string, decrypt DecryptFunc) (*SOPSProvider, error) {
	if path == "" {
		return nil, fmt.Errorf("sops provider: file path is required")
	}
	if decrypt == nil {
		decrypt = sopsCLIDecrypt
	}
	plain, err := decrypt(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("sops decrypt %q: %w", path, err)
	}
	secrets, err := parseFlatYAML(plain)
	if err != nil {
		return nil, fmt.Errorf("sops file %q: %w", path, err)
	}
	return &SOPSProvider{path: path, secrets: secrets}, nil
}

// Resolve implements SecretProvider.
func (p *SOPSProvider) Resolve(name string) (string, error) {
	v, ok := p.secrets[name]
	if !ok {
		return "", fmt.Errorf("secret %q not found in sops file %q", name, p.path)
	}
	return v, nil
}

// NewSecretProvider builds the SecretProvider backing secret:// references. When
// controller.secrets.sops_file is set it returns a SOPS/age-backed provider
// (decrypted once at startup); otherwise the env-backed MVP provider. ctx bounds
// the initial decryption.
func NewSecretProvider(ctx context.Context, cfg *ControllerConfig) (SecretProvider, error) {
	if f := cfg.Controller.Secrets.SOPSFile; f != "" {
		return NewSOPSProvider(ctx, ExpandPath(f), nil)
	}
	return EnvSecretProvider{}, nil
}

// sopsDecryptTimeout bounds a single sops CLI invocation.
const sopsDecryptTimeout = 30 * time.Second

// sopsCLIDecrypt shells out to `sops -d --output-type yaml <path>`. The operator
// supplies the age identity via SOPS_AGE_KEY_FILE / SOPS_AGE_KEY (or PGP/KMS) in
// the controller's environment; wgfleet never handles the age private key itself.
func sopsCLIDecrypt(ctx context.Context, path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, sopsDecryptTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sops", "-d", "--output-type", "yaml", path)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return nil, fmt.Errorf("run sops: %w: %s", err, msg)
		}
		return nil, fmt.Errorf("run sops: %w", err)
	}
	return out, nil
}

// parseFlatYAML parses a flat YAML mapping of string keys to scalar values. A
// secrets file is a flat name→value table; nested maps or sequences are rejected
// so a structural mistake fails loudly instead of silently dropping a secret.
// Multi-line block scalars (e.g. a PEM private key) are supported as values.
func parseFlatYAML(data []byte) (map[string]string, error) {
	var raw map[string]any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	out := make(map[string]string, len(raw))
	for k, v := range raw {
		switch val := v.(type) {
		case string:
			out[k] = val
		case int, int64, float64, bool:
			out[k] = fmt.Sprintf("%v", val)
		case nil:
			out[k] = ""
		default:
			return nil, fmt.Errorf("key %q: value must be a scalar, got %T", k, v)
		}
	}
	return out, nil
}
