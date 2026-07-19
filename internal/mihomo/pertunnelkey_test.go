package mihomo

import (
	"fmt"
	"strings"
	"testing"

	"github.com/shidoh/wgfleet/internal/domain"
)

func perTunnelInput(t domain.ExitTunnel, resolver func(string) (string, error)) RenderInput {
	return RenderInput{
		Spec: domain.MasterSpec{
			BindAddress: "10.80.0.1",
			ExitTunnels: []domain.ExitTunnel{t},
		},
		PrivateKey:       "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=",
		TunnelPrivateKey: resolver,
	}
}

func awgTunnel(name, keyTunnel string) domain.ExitTunnel {
	return domain.ExitTunnel{
		Name:            name,
		Endpoint:        "198.51.100.1:51820",
		ServerPublicKey: "n1YvVJqTJfJ0pxTQFvVYqNFhKlCcm4dGZUZ8oVLPjHM=",
		TunnelIP:        "10.81.0.3",
		MTU:             1360,
		Transport:       domain.TransportAWG,
		MasterKeyTunnel: keyTunnel,
	}
}

func TestRenderUsesPerTunnelKeyWhenAsked(t *testing.T) {
	const derived = "SFdvvVJqTJfJ0pxTQFvVYqNFhKlCcm4dGZUZ8oVLPjE="
	var askedFor []string
	cfg, err := RenderConfig(perTunnelInput(awgTunnel("exit-de-1", "exit-de-1"),
		func(tunnel string) (string, error) {
			askedFor = append(askedFor, tunnel)
			return derived, nil
		}))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if len(askedFor) != 1 || askedFor[0] != "exit-de-1" {
		t.Fatalf("resolver called with %v, want [exit-de-1]", askedFor)
	}
	if !strings.Contains(cfg, derived) {
		t.Fatal("rendered config does not carry the per-tunnel private key")
	}
	// The shared key must be gone from this proxy entirely — leaving it in would
	// defeat the point (the exit would still be linkable by it).
	if strings.Contains(cfg, "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=") {
		t.Fatal("rendered config still carries the shared master key")
	}
}

func TestRenderUsesSharedKeyWhenNoTunnelRequested(t *testing.T) {
	// Back-compat: MasterKeyTunnel empty is the pre-ADR-0030 path and must not call
	// the resolver at all.
	cfg, err := RenderConfig(perTunnelInput(awgTunnel("exit-de-1", ""),
		func(tunnel string) (string, error) {
			t.Fatalf("resolver called for a tunnel with no MasterKeyTunnel (%q)", tunnel)
			return "", nil
		}))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(cfg, "FmJoBTB+ew7wVUxXhRs6xCNPjPi9SQJRU6vIVW4Igyc=") {
		t.Fatal("rendered config does not carry the shared master key")
	}
}

func TestRenderFailsRatherThanSilentlyFallingBack(t *testing.T) {
	// A spec that asks for a per-tunnel key it cannot get must be a hard error: in
	// the `on` phase the exit no longer accepts the shared key, so falling back
	// would render a dead tunnel that looks perfectly configured.
	tests := []struct {
		name     string
		resolver func(string) (string, error)
	}{
		{"no resolver supplied", nil},
		{"resolver errors", func(string) (string, error) { return "", fmt.Errorf("boom") }},
		{"resolver returns empty", func(string) (string, error) { return "", nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := RenderConfig(perTunnelInput(awgTunnel("exit-de-1", "exit-de-1"), tc.resolver)); err == nil {
				t.Fatal("expected an error, got nil")
			}
		})
	}
}

func TestRedactHidesPerTunnelKey(t *testing.T) {
	const derived = "SFdvvVJqTJfJ0pxTQFvVYqNFhKlCcm4dGZUZ8oVLPjE="
	cfg, err := RenderConfig(perTunnelInput(awgTunnel("exit-de-1", "exit-de-1"),
		func(string) (string, error) { return derived, nil }))
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	// Plan output goes to the operator's terminal and the reconcile report; a
	// derived key is exactly as secret as the shared one.
	if strings.Contains(RedactConfig(cfg), derived) {
		t.Fatal("redacted plan output still leaks the per-tunnel private key")
	}
}
