package egress

import "testing"

func TestLastPMTU(t *testing.T) {
	out := ` 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                              0.5ms
 2:  no reply
 3:  162.159.192.1                        12ms pmtu 1440
     resume: pmtu 1440`
	if got := lastPMTU(out); got != 1440 {
		t.Errorf("lastPMTU = %d, want 1440", got)
	}
	if got := lastPMTU("no pmtu here"); got != 0 {
		t.Errorf("lastPMTU(none) = %d, want 0", got)
	}
}
