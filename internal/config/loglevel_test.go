package config

import (
	"strings"
	"testing"
)

// A mistyped level is refused at startup, not read as info: an operator who
// wrote "debgu" while chasing an incident must learn it from the exit code, not
// from a journal that stayed quiet.
func TestLogLevelIsValidated(t *testing.T) {
	a := AgentConfig{Agent: AgentSection{Role: "exit", Controller: "c:1", NodeID: "n", LogLevel: "debgu"}}
	if err := a.Validate(); err == nil || !strings.Contains(err.Error(), "agent.log_level") {
		t.Errorf("agent: bad level accepted or misreported: %v", err)
	}
	for _, ok := range []string{"", "trace", "debug", "info", "warn", "error"} {
		a.Agent.LogLevel = ok
		if err := a.Validate(); err != nil && strings.Contains(err.Error(), "log_level") {
			t.Errorf("agent: level %q refused: %v", ok, err)
		}
	}
	c := ControllerConfig{Controller: ControllerSection{Listen: "l", Store: "s", LogLevel: "loud"}}
	if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "controller.log_level") {
		t.Errorf("controller: bad level accepted or misreported: %v", err)
	}
}
