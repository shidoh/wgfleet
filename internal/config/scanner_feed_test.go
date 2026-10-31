package config

import (
	"strings"
	"testing"
)

func scannerFeedConfig(mode string) ControllerConfig {
	m := MasterConfig{Name: "m1", MgmtAddr: "10.20.0.1", ASBlacklist: mode}
	return ControllerConfig{Fleet: FleetSection{Masters: []MasterConfig{m}}}
}

func hasScannerFeedErr(c ControllerConfig) bool {
	err := c.Validate()
	return err != nil && strings.Contains(err.Error(), "as_blacklist")
}

// The exit's knob is a bool, so `true` is the likeliest typo here. It must fail
// loudly rather than resolve to off and leave the operator believing the master
// is protected.
func TestMasterScannerFeedModeValidation(t *testing.T) {
	for _, ok := range []string{"", "off", "observe", "enforce", "OBSERVE", " enforce "} {
		if hasScannerFeedErr(scannerFeedConfig(ok)) {
			t.Errorf("as_blacklist %q should be accepted", ok)
		}
	}
	for _, bad := range []string{"true", "false", "1", "on", "drop", "count"} {
		if !hasScannerFeedErr(scannerFeedConfig(bad)) {
			t.Errorf("as_blacklist %q should fail validation", bad)
		}
	}
}

func TestMasterScannerFeedResolves(t *testing.T) {
	for in, want := range map[string]ScannerFeedMode{
		"": ScannerFeedOff, "off": ScannerFeedOff, "nonsense": ScannerFeedOff,
		"observe": ScannerFeedObserve, " Observe ": ScannerFeedObserve,
		"enforce": ScannerFeedEnforce, "ENFORCE": ScannerFeedEnforce,
	} {
		if got := (MasterConfig{ASBlacklist: in}).ScannerFeed(); got != want {
			t.Errorf("ScannerFeed(%q) = %q, want %q", in, got, want)
		}
	}
}
