package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func examplePath(name string) string {
	return filepath.Join("..", "..", "deploy", "examples", name)
}

// The shipped examples are the first thing a new operator copies, and until now
// nothing loaded them: a stale key, a YAML typo or a value that fails validation
// would have reached operators intact. Load each one exactly as the binaries do
// (parse + env overlay + Validate).
func TestShippedExamplesLoad(t *testing.T) {
	t.Run("controller.yaml", func(t *testing.T) {
		cfg, err := Load(examplePath("controller.yaml"), &ControllerConfig{})
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if len(cfg.Fleet.Masters) == 0 || len(cfg.Fleet.Exits) == 0 {
			t.Errorf("reference manifest declares %d masters / %d exits; it should show both",
				len(cfg.Fleet.Masters), len(cfg.Fleet.Exits))
		}
	})

	t.Run("agent.yaml", func(t *testing.T) {
		if _, err := Load(examplePath("agent.yaml"), &AgentConfig{}); err != nil {
			t.Fatalf("load: %v", err)
		}
	})
}

// examplePlaceholders fills in the deliberately-sanitized <angle-bracket> values in
// the task-oriented examples, so they can be validated for real. A NEW placeholder
// makes this test fail until it is mapped here — which is the point: the substitute
// has to be a value that actually passes validation, proving the placeholder
// documents a real, fillable field rather than a shape nothing accepts.
var examplePlaceholders = map[string]string{
	"<zt-network-id>":                 "8056c2e21c000001",
	"<mgmt-zt-ip>":                    "10.20.25.254",
	"<exit-mgmt-zt-ip>":               "10.20.0.5",
	"<master-public-ip>":              "203.0.113.1",
	"<exit-public-ip>":                "198.51.100.7",
	"<generate-a-long-random-string>": "not-a-real-secret",
	"<placeholder>":                   "example",
}

// The RU split-tunnel example ships with placeholders instead of real infra, so it
// cannot be loaded as-is. Substitute them and validate the result: that catches a
// YAML typo or an invalid structure in a file operators are told to copy, which
// "it has placeholders" must not be an excuse to leave unchecked.
func TestSplitRUExampleIsValidOnceFilledIn(t *testing.T) {
	raw, err := os.ReadFile(examplePath("controller-split-ru.yaml"))
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	filled := string(raw)
	for ph, val := range examplePlaceholders {
		filled = strings.ReplaceAll(filled, ph, val)
	}
	if i := strings.Index(filled, "<"); i >= 0 {
		if end := strings.Index(filled[i:], ">"); end > 0 && end < 40 {
			t.Fatalf("unmapped placeholder %q — add it to examplePlaceholders", filled[i:i+end+1])
		}
	}

	path := filepath.Join(t.TempDir(), "controller.yaml")
	if err := os.WriteFile(path, []byte(filled), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, &ControllerConfig{}); err != nil {
		t.Fatalf("split-RU example is invalid once filled in: %v", err)
	}
}

// Every key a shipped example uses must be one the binaries read: --check-config
// warns about the rest, and an example that draws that warning teaches operators
// to ignore it.
func TestShippedExamplesHaveNoUnknownKeys(t *testing.T) {
	for name, out := range map[string]any{
		"controller.yaml": &ControllerConfig{},
		"agent.yaml":      &AgentConfig{},
	} {
		got, err := UnknownKeys(examplePath(name), out)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if len(got) != 0 {
			t.Errorf("%s uses keys nothing reads: %v", name, got)
		}
	}
}
