package domain

import "testing"

func TestMasterTransportOrDefault(t *testing.T) {
	if got := MasterTransport("").OrDefault(); got != TransportAWG {
		t.Errorf("empty transport OrDefault = %q, want %q", got, TransportAWG)
	}
	if got := TransportRealityXHTTP.OrDefault(); got != TransportRealityXHTTP {
		t.Errorf("set transport OrDefault = %q, want itself", got)
	}
}

func TestMasterTransportValid(t *testing.T) {
	for _, tr := range []MasterTransport{TransportAWG, TransportRealityXHTTP} {
		if !tr.Valid() {
			t.Errorf("%q should be valid", tr)
		}
	}
	for _, tr := range []MasterTransport{"", "vless", "wireguard"} {
		if tr.Valid() {
			t.Errorf("%q should be invalid", tr)
		}
	}
}

func TestNodeSpecTransportsDefaultsToAWG(t *testing.T) {
	// An exit with no declared transports is AWG-only (back-compat, pre-ADR-0025).
	var s NodeSpec
	ts := s.Transports()
	if len(ts) != 1 || ts[0] != TransportAWG {
		t.Fatalf("default transports = %v, want [awg]", ts)
	}
	if !s.HasTransport(TransportAWG) {
		t.Error("empty spec should have AWG transport")
	}
	if s.HasTransport(TransportRealityXHTTP) {
		t.Error("empty spec must not claim the reality transport")
	}
}

func TestNodeSpecHasTransportTreatsEmptyAsAWG(t *testing.T) {
	// An explicit empty entry in the set is the zero value == AWG.
	s := NodeSpec{EnabledTransports: []MasterTransport{""}}
	if !s.HasTransport(TransportAWG) {
		t.Error("an empty transport entry should match AWG")
	}
}
